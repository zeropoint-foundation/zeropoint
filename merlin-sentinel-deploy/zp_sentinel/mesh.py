"""
ZeroPoint Mesh Client — AgentAnnounce + heartbeat over zp-mesh wire format.

Implements the client side of the zp-mesh discovery protocol so the Sentinel
can participate in the trust mesh as a first-class peer. Speaks the same
wire format as the Rust MeshEnvelope / AgentCapabilities types.

Rust source of truth:
  crates/zp-mesh/src/identity.rs   → MeshIdentity, PeerIdentity
  crates/zp-mesh/src/transport.rs  → AgentCapabilities, PeerInfo
  crates/zp-mesh/src/envelope.rs   → MeshEnvelope, EnvelopeType

Protocol flow:
  1. Generate or load Ed25519 keypair (persistent identity)
  2. Compute destination hash: SHA-256(signing_pub ‖ encryption_pub)[:16]
  3. Build AgentCapabilities payload (name, version, skills, trust_tier)
  4. Send AgentAnnounce envelope to Core (HTTP bridge or WebSocket)
  5. Maintain heartbeat on configured interval

The Sentinel uses HTTP POST to /api/mesh/announce as a bridge into the
Rust-side MeshNode. The server converts this into a native AgentAnnounce
envelope and adds the peer to its table. This HTTP bridge exists because
the Sentinel runs on constrained ARM32 hardware (ASUS Merlin router)
where a full Reticulum stack isn't practical.
"""

import hashlib
import json
import logging
import os
import struct
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable, Tuple

logger = logging.getLogger(__name__)

# Ed25519 support — optional on constrained hardware
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder, RawEncoder
    HAS_NACL = True
except ImportError:
    HAS_NACL = False
    logger.info("PyNaCl not available — using HMAC-SHA256 fallback for signing")

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# =============================================================================
# ENVELOPE TYPES — Mirrors zp-mesh::envelope::EnvelopeType
# =============================================================================

ENVELOPE_TYPE_AGENT_ANNOUNCE = 0x05


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class MeshConfig:
    """Mesh registration configuration."""
    core_url: str = ""                          # HTTP bridge to Core
    core_ws_url: str = ""                       # WebSocket (future)
    key_path: str = "/opt/var/zp-sentinel/identity.key"
    component_name: str = "ZP Sentinel"
    heartbeat_interval_sec: int = 30
    heartbeat_threshold: int = 3
    auto_register: bool = True
    protocol_version: str = "0.1.0"
    advertise_address: str = ""
    advertise_port: int = 0


# =============================================================================
# IDENTITY — Ed25519 keypair, destination hash addressing
#
# Mirrors zp-mesh::identity::MeshIdentity
# =============================================================================

class MeshIdentity:
    """
    Persistent Ed25519 identity for mesh participation.

    The keypair is generated once and stored at key_path. The combined
    public key (signing ‖ encryption) produces a 128-bit destination hash
    via SHA-256 — the canonical mesh address.

    On ARM32 without PyNaCl, falls back to HMAC-SHA256 for signing and
    derives a synthetic "public key" from the secret. The destination hash
    is still computed the same way.
    """

    def __init__(self, key_path: str):
        self.key_path = key_path
        self._signing_secret: bytes = b""
        self._signing_public: bytes = b""
        self._encryption_public: bytes = b""  # Synthetic on fallback
        self._destination_hash: bytes = b""
        self._load_or_generate()

    def _load_or_generate(self):
        """Load existing keypair or generate a new one."""
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                self._signing_secret = f.read(32)
            logger.info(f"Loaded identity from {self.key_path}")
        else:
            self._signing_secret = os.urandom(32)
            os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
            with open(self.key_path, "wb") as f:
                f.write(self._signing_secret)
            os.chmod(self.key_path, 0o600)
            logger.info(f"Generated new identity at {self.key_path}")

        if HAS_NACL:
            sk = SigningKey(self._signing_secret)
            self._signing_public = bytes(sk.verify_key)
            # Derive X25519 from Ed25519 via HKDF (matching Rust side)
            import hmac as hmac_mod
            hk = hmac_mod.new(
                b"zp-mesh-x25519-derive-v1",
                self._signing_secret,
                hashlib.sha256,
            ).digest()
            self._encryption_public = hk  # Simplified — real X25519 would use curve ops
        else:
            self._signing_public = hashlib.sha256(self._signing_secret).digest()
            self._encryption_public = hashlib.sha256(
                self._signing_secret + b"x25519"
            ).digest()

        # Destination hash: SHA-256(signing_pub ‖ encryption_pub)[:16]
        combined = self._signing_public + self._encryption_public
        self._destination_hash = hashlib.sha256(combined).digest()[:16]

    @property
    def address(self) -> str:
        """Hex destination hash — the mesh address."""
        return self._destination_hash.hex()

    @property
    def signing_public_hex(self) -> str:
        """Ed25519 public key, hex-encoded."""
        return self._signing_public.hex()

    @property
    def encryption_public_hex(self) -> str:
        """X25519 public key, hex-encoded."""
        return self._encryption_public.hex()

    @property
    def fingerprint(self) -> str:
        """First 8 bytes of destination hash, colon-separated."""
        h = self.address
        return ":".join(h[i:i+2] for i in range(0, 16, 2))

    def sign(self, data: bytes) -> bytes:
        """Sign data. Returns 64-byte signature (or 32-byte HMAC fallback)."""
        if HAS_NACL:
            sk = SigningKey(self._signing_secret)
            return bytes(sk.sign(data).signature)
        else:
            import hmac as hmac_mod
            return hmac_mod.new(
                self._signing_secret, data, hashlib.sha256
            ).digest()


# =============================================================================
# AGENT CAPABILITIES — Mirrors zp-mesh::transport::AgentCapabilities
# =============================================================================

def build_capabilities(config: MeshConfig) -> Dict[str, Any]:
    """
    Build the AgentCapabilities payload.

    Matches the Rust struct in crates/zp-mesh/src/transport.rs:
      AgentCapabilities { name, version, receipt_types, skills, actor_type, trust_tier }
    """
    return {
        "name": config.component_name,
        "version": "0.3.0",
        "receipt_types": ["execution", "approval"],
        "skills": [
            "dns-filtering",
            "dns-monitoring",
            "device-access-control",
            "anomaly-detection",
            "mac-blocking",
            "rate-limiting",
            "alert-notification",
        ],
        "actor_type": "sentinel",
        "trust_tier": "D",  # Always starts untrusted
    }


# =============================================================================
# MESH ENVELOPE — Mirrors zp-mesh::envelope::MeshEnvelope
# =============================================================================

def build_envelope(
    identity: MeshIdentity,
    envelope_type: int,
    payload: bytes,
    seq: int,
) -> Dict[str, Any]:
    """
    Build a MeshEnvelope-compatible JSON structure.

    The Rust MeshEnvelope uses msgpack on the wire, but the HTTP bridge
    accepts JSON with the same field names. The server converts to native
    format internally.

    Fields match crates/zp-mesh/src/envelope.rs:
      MeshEnvelope { envelope_type, sender, seq, ts, payload, signature }
    """
    ts = int(time.time())
    sender = identity.address

    # Build signing material: envelope_type ‖ sender ‖ seq ‖ ts ‖ payload
    sign_data = bytearray()
    sign_data.append(envelope_type)
    sign_data.extend(sender.encode())
    sign_data.extend(struct.pack(">Q", seq))
    sign_data.extend(struct.pack(">q", ts))
    sign_data.extend(payload)

    signature = identity.sign(bytes(sign_data))

    return {
        "envelope_type": envelope_type,
        "sender": sender,
        "seq": seq,
        "ts": ts,
        "payload": payload.hex(),     # Hex-encoded for JSON transport
        "signature": signature.hex(),  # Hex-encoded for JSON transport
    }


# =============================================================================
# MESH CLIENT — Announce + heartbeat
# =============================================================================

class MeshClient:
    """
    Handles AgentAnnounce and heartbeat via the HTTP bridge to zp-server.

    The HTTP bridge exists because the Sentinel runs on constrained
    ARM32 hardware where a full Reticulum transport isn't practical.
    The server receives the announce, converts it to a native MeshEnvelope,
    and adds the Sentinel to its peer table — making it visible in the
    dashboard topology view.

    Lifecycle:
      1. __init__() — load identity
      2. register() — POST AgentAnnounce to Core
      3. start_heartbeat() — background re-announce on interval
      4. stop() — clean shutdown
    """

    def __init__(self, config: MeshConfig, stats_provider: Optional[Callable] = None):
        self.config = config
        self.identity = MeshIdentity(config.key_path)
        self.stats_provider = stats_provider

        self._registered = False
        self._seq: int = 0
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_stop = threading.Event()

        logger.info(
            f"Mesh client initialized — address: {self.identity.address}, "
            f"fingerprint: {self.identity.fingerprint}, "
            f"core: {config.core_url or '(not configured)'}"
        )

    @property
    def registered(self) -> bool:
        return self._registered

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # ── Registration (AgentAnnounce) ──────────────────────────────────

    def register(self) -> bool:
        """
        Send an AgentAnnounce envelope to Core via HTTP bridge.

        POST /api/mesh/announce with:
          - envelope: MeshEnvelope (JSON)
          - identity: { signing_key, encryption_key }
        """
        if not self.config.core_url:
            logger.warning("Mesh registration skipped — no core_url configured")
            return False

        capabilities = build_capabilities(self.config)
        payload = json.dumps(capabilities, sort_keys=True).encode()

        envelope = build_envelope(
            self.identity,
            ENVELOPE_TYPE_AGENT_ANNOUNCE,
            payload,
            self._next_seq(),
        )

        request_body = {
            "envelope": envelope,
            "identity": {
                "signing_key": self.identity.signing_public_hex,
                "encryption_key": self.identity.encryption_public_hex,
            },
        }

        try:
            url = f"{self.config.core_url.rstrip('/')}/api/mesh/announce"
            logger.info(f"Sending AgentAnnounce to {url}")
            resp = _http_post(url, request_body)

            if resp.get("accepted", False):
                self._registered = True
                logger.info(
                    f"Announce accepted — address: {self.identity.address}"
                )
                return True
            else:
                reason = resp.get("reason", "unknown")
                logger.warning(f"Announce rejected: {reason}")
                return False

        except Exception as e:
            logger.error(f"Announce failed: {e}")
            return False

    # ── Heartbeat (periodic re-announce) ──────────────────────────────

    def start_heartbeat(self):
        """Start background heartbeat thread (periodic re-announce)."""
        if not self._registered:
            logger.warning("Cannot start heartbeat — not registered")
            return

        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="zp-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()
        logger.info(f"Heartbeat started — interval: {self.config.heartbeat_interval_sec}s")

    def stop(self):
        """Stop heartbeat and clean up."""
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
        logger.info("Mesh client stopped")

    def _heartbeat_loop(self):
        """Background heartbeat — re-announces periodically."""
        while not self._heartbeat_stop.is_set():
            try:
                self._send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
            self._heartbeat_stop.wait(self.config.heartbeat_interval_sec)

    def _send_heartbeat(self):
        """Send a heartbeat (re-announce with fresh capabilities)."""
        if not self.config.core_url:
            return

        capabilities = build_capabilities(self.config)

        # Enrich with live stats if available
        if self.stats_provider:
            gate_stats, dns_stats, device_stats, anomaly_stats = self.stats_provider()
            if gate_stats:
                capabilities["metadata"] = {
                    "gate": gate_stats,
                    "dns": dns_stats,
                    "device": device_stats,
                    "anomaly": anomaly_stats,
                }

        payload = json.dumps(capabilities, sort_keys=True).encode()
        envelope = build_envelope(
            self.identity,
            ENVELOPE_TYPE_AGENT_ANNOUNCE,
            payload,
            self._next_seq(),
        )

        request_body = {
            "envelope": envelope,
            "identity": {
                "signing_key": self.identity.signing_public_hex,
                "encryption_key": self.identity.encryption_public_hex,
            },
        }

        try:
            url = f"{self.config.core_url.rstrip('/')}/api/mesh/announce"
            _http_post(url, request_body)
            logger.debug(f"Heartbeat sent — seq: {envelope['seq']}")
        except Exception as e:
            logger.warning(f"Heartbeat delivery failed: {e}")

    # ── Status ────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get mesh client status for the CLI."""
        return {
            "registered": self._registered,
            "address": self.identity.address,
            "fingerprint": self.identity.fingerprint,
            "signing_public": self.identity.signing_public_hex[:16] + "...",
            "core_url": self.config.core_url or "(not configured)",
            "heartbeat_running": (
                self._heartbeat_thread is not None
                and self._heartbeat_thread.is_alive()
            ),
            "signing": "ed25519" if HAS_NACL else "hmac-sha256",
            "seq": self._seq,
        }


# =============================================================================
# HTTP HELPERS — stdlib only (no requests library on Merlin)
# =============================================================================

def _http_post(url: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """POST JSON to a URL and return parsed response."""
    data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "ZP-Sentinel/0.3.0")

    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        logger.error(f"HTTP {e.code}: {body_text[:200]}")
        raise
    except URLError as e:
        logger.error(f"Connection error: {e.reason}")
        raise
