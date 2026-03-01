#!/usr/bin/env python3
"""
ZeroPoint Agent Bridge → Reticulum
====================================

Simulates a ZeroPoint agent that generates receipts (intent → design →
approval → execution chain) and sends them over a Reticulum link to
the echo node.

This is the "initiator" side of the integration test.

Usage:
    # First start the echo node and note its destination hash:
    python3 v2/tests/reticulum/rns_echo_node.py

    # Then connect to it:
    python3 v2/tests/reticulum/zp_agent_bridge.py <echo_node_destination_hash>

Prerequisites:
    pip install rns msgpack PyNaCl
"""

import os
import sys
import time
import json
import hashlib
import argparse
import traceback
from datetime import datetime, timezone

# --- Dependencies -----------------------------------------------------------

try:
    import RNS
except ImportError:
    print("ERROR: Reticulum not installed. Run: pip install rns")
    sys.exit(1)

try:
    import msgpack
except ImportError:
    print("ERROR: msgpack not installed. Run: pip install msgpack")
    sys.exit(1)

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.public import PrivateKey as X25519PrivateKey
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("WARNING: PyNaCl not available — signing disabled")
    print("  Install with: pip install PyNaCl")

# --- Constants --------------------------------------------------------------

APP_NAME = "zeropoint"
ASPECTS   = ["agent", "receipt"]

ENVELOPE_TYPE_RECEIPT        = 0x01
ENVELOPE_TYPE_AGENT_ANNOUNCE = 0x05

# Trust grade names for display
TRUST_GRADES = {"A": "Human-verified", "B": "Automated", "C": "Agent-generated", "D": "Unverified"}

# Receipt types for the chain
CHAIN_TYPES = ["intent", "design", "approval", "execution"]

# --- ZeroPoint Identity (mirrors zp-mesh MeshIdentity) ----------------------

class ZPIdentity:
    """
    A ZeroPoint mesh identity — Ed25519 signing + X25519 encryption.

    Mirrors the Rust MeshIdentity struct in zp-mesh/src/identity.rs.
    Uses PyNaCl for the cryptographic operations.
    """

    def __init__(self, signing_key=None):
        if NACL_AVAILABLE:
            if signing_key is None:
                self._signing_key = SigningKey.generate()
            else:
                self._signing_key = signing_key

            # Derive X25519 key deterministically from Ed25519 secret
            # This mirrors from_ed25519_secret() in identity.rs:
            #   HKDF(salt="zp-mesh-x25519-derive-v1", ikm=ed25519_secret)
            #   → expand("x25519-static-secret")
            import hmac as hmac_mod
            secret_bytes = bytes(self._signing_key)

            # HKDF-Extract
            salt = b"zp-mesh-x25519-derive-v1"
            prk = hmac_mod.new(salt, secret_bytes, "sha256").digest()

            # HKDF-Expand (single block, 32 bytes)
            info = b"x25519-static-secret"
            x_secret = hmac_mod.new(prk, info + b"\x01", "sha256").digest()

            # PyNaCl X25519 private key from raw bytes
            self._encryption_key = X25519PrivateKey(x_secret)
        else:
            self._signing_key = None
            self._encryption_key = None

    @property
    def signing_public_key(self) -> bytes:
        """Ed25519 public key — 32 bytes."""
        return bytes(self._signing_key.verify_key)

    @property
    def encryption_public_key(self) -> bytes:
        """X25519 public key — 32 bytes."""
        return bytes(self._encryption_key.public_key)

    @property
    def combined_public_key(self) -> bytes:
        """64-byte combined key (Ed25519 ‖ X25519)."""
        return self.signing_public_key + self.encryption_public_key

    @property
    def destination_hash(self) -> bytes:
        """128-bit destination hash — SHA-256(combined_key)[0:16]."""
        return hashlib.sha256(self.combined_public_key).digest()[:16]

    @property
    def address(self) -> str:
        """Hex destination hash string."""
        return self.destination_hash.hex()

    def sign(self, data: bytes) -> bytes:
        """Ed25519 signature — 64 bytes."""
        if not NACL_AVAILABLE:
            return b"\x00" * 64
        signed = self._signing_key.sign(data)
        return signed.signature  # 64 bytes

    def verify(self, data: bytes, signature: bytes, public_key: bytes = None) -> bool:
        """Verify an Ed25519 signature."""
        if not NACL_AVAILABLE:
            return True
        try:
            key = public_key or self.signing_public_key
            vk = VerifyKey(key)
            vk.verify(data, signature)
            return True
        except Exception:
            return False


# --- Receipt Generation -----------------------------------------------------

def make_receipt(agent_name: str, receipt_type: str, index: int,
                parent_id: str = None, trust_grade: str = "C") -> dict:
    """Create a ZeroPoint receipt (mirrors zp_receipt::Receipt)."""
    now = int(time.time())

    # Generate deterministic receipt ID
    id_material = f"{agent_name}:{receipt_type}:{index}:{now}"
    receipt_id = f"rcpt-{hashlib.sha256(id_material.encode()).hexdigest()[:16]}"

    # Content hash (Blake2b, like zp-receipt hasher)
    content = f"{receipt_type}:{agent_name}:{index}:{now}"
    content_hash = hashlib.blake2b(content.encode(), digest_size=32).hexdigest()

    receipt = {
        "id": receipt_id,
        "rt": receipt_type,
        "st": "success",
        "tg": trust_grade,
        "ch": content_hash,
        "ts": now,
        "pd": "allow",
        "ra": f"ZP agent bridge task {index}",
    }

    if parent_id:
        receipt["pr"] = parent_id

    return receipt


def make_receipt_chain(agent_name: str, chain_length: int = 4,
                       start_index: int = 0) -> list:
    """Generate a chain of receipts: intent → design → approval → execution."""
    chain = []
    parent_id = None

    for i in range(chain_length):
        receipt_type = CHAIN_TYPES[i % len(CHAIN_TYPES)]
        # Trust grade degrades through the chain (human intent → agent execution)
        grades = ["A", "A", "B", "C"]
        trust_grade = grades[i % len(grades)]

        receipt = make_receipt(
            agent_name, receipt_type, start_index + i,
            parent_id=parent_id, trust_grade=trust_grade,
        )
        chain.append(receipt)
        parent_id = receipt["id"]

    return chain


# --- Envelope ---------------------------------------------------------------

def build_signing_material(envelope_type: int, sender: str, seq: int,
                           ts: int, payload: bytes) -> bytes:
    """Build canonical signing material (matches envelope.rs)."""
    material = bytearray()
    material.append(envelope_type)
    material.extend(sender.encode("utf-8"))
    material.extend(seq.to_bytes(8, "big"))
    material.extend(ts.to_bytes(8, "big", signed=True))
    material.extend(payload)
    return bytes(material)


def make_envelope(identity: ZPIdentity, receipt: dict, seq: int,
                  envelope_type: int = ENVELOPE_TYPE_RECEIPT) -> bytes:
    """Create a signed MeshEnvelope and encode to msgpack.

    Mirrors MeshEnvelope::receipt() in envelope.rs.
    """
    payload = msgpack.packb(receipt, use_bin_type=True)
    sender = identity.address
    ts = int(time.time())

    # Build and sign
    material = build_signing_material(envelope_type, sender, seq, ts, payload)
    signature = identity.sign(material)

    envelope = {
        "envelope_type": envelope_type,
        "sender": sender,
        "seq": seq,
        "ts": ts,
        "payload": payload,
        "signature": signature,
    }

    return msgpack.packb(envelope, use_bin_type=True)


def make_announce_envelope(identity: ZPIdentity, capabilities: dict,
                           seq: int) -> bytes:
    """Create an agent announce envelope.

    The payload contains: combined_public_key(64) + capabilities_json + signature(64).
    This is the same format as AgentTransport::announce() in transport.rs.
    """
    caps_json = json.dumps(capabilities).encode("utf-8")
    inner_payload = identity.combined_public_key + caps_json
    inner_sig = identity.sign(inner_payload)
    full_payload = inner_payload + inner_sig

    return make_envelope(identity, {}, seq, envelope_type=ENVELOPE_TYPE_AGENT_ANNOUNCE)


# --- Reticulum Bridge -------------------------------------------------------

class AgentBridge:
    """Connects a ZP agent identity to a Reticulum echo node."""

    def __init__(self, echo_dest_hash: str, config_path=None, verbose=False):
        self.verbose = verbose
        self.echo_dest_hash = echo_dest_hash
        self.receipts_sent = 0
        self.acks_received = 0
        self.chain_count = 0
        self.start_time = time.time()
        self.link = None
        self.link_ready = False
        self.seq = 0

        # Create ZeroPoint identity
        self.zp_identity = ZPIdentity()

        print("═" * 60)
        print("  ZeroPoint Agent Bridge → Reticulum")
        print("═" * 60)
        print()
        print(f"  ZP Agent Address: {self.zp_identity.address}")
        print(f"  Target Echo Node: {echo_dest_hash}")
        print()

        # Initialize Reticulum
        print("Initializing Reticulum...")
        self.reticulum = RNS.Reticulum(config_path)

        # Create our RNS identity
        self.rns_identity = RNS.Identity()

        # We need to know the echo node's identity to request a link
        # The destination hash is enough to look it up if it has announced
        if len(echo_dest_hash) != 32:
            print(f"ERROR: Destination hash must be 32 hex characters, got {len(echo_dest_hash)}")
            sys.exit(1)

        self.target_hash = bytes.fromhex(echo_dest_hash)

        print("  Reticulum initialized")
        print()

    def connect(self, timeout: float = 15.0):
        """Establish a Reticulum link to the echo node."""
        print("Requesting path to echo node...")

        # Request path (works for direct local connections too)
        RNS.Transport.request_path(self.target_hash)
        print("  Path requested, waiting for resolution...")

        # Wait for the path
        deadline = time.time() + timeout
        while not RNS.Transport.has_path(self.target_hash):
            time.sleep(0.1)
            if time.time() > deadline:
                print("  ✗ Path resolution timed out")
                print("    Is the echo node running? Is the destination hash correct?")
                return False

        print("  ✓ Path resolved")

        # Resolve the destination identity
        remote_identity = RNS.Identity.recall(self.target_hash)
        if remote_identity is None:
            print("  ✗ Could not recall remote identity")
            return False

        # Create the destination
        remote_destination = RNS.Destination(
            remote_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
            *ASPECTS,
        )

        # Request link
        print("Establishing link...")
        self.link = RNS.Link(remote_destination)
        self.link.set_link_established_callback(self.on_link_established)
        self.link.set_link_closed_callback(self.on_link_closed)
        self.link.set_packet_callback(self.on_packet)

        # Wait for link
        deadline = time.time() + timeout
        while not self.link_ready:
            time.sleep(0.1)
            if time.time() > deadline:
                print("  ✗ Link establishment timed out")
                return False

        return True

    def on_link_established(self, link):
        """Called when the link to the echo node is active."""
        self.link_ready = True
        print(f"  ✓ Link established (RTT: {link.rtt:.3f}s)" if hasattr(link, 'rtt') and link.rtt else "  ✓ Link established")
        print()

    def on_link_closed(self, link):
        """Called when the link is torn down."""
        self.link_ready = False
        elapsed = time.time() - self.start_time
        print(f"\n⟐ Link closed (sent: {self.receipts_sent}, "
              f"acks: {self.acks_received}, uptime: {elapsed:.1f}s)")

    def on_packet(self, message, packet):
        """Handle acknowledgment receipts coming back from the echo node."""
        try:
            ack = msgpack.unpackb(message, raw=False)
            self.acks_received += 1

            ack_id = ack.get("id", "???")
            parent = ack.get("pr", "???")
            print(f"  📥 ACK #{self.acks_received}: {ack_id}")
            print(f"      Acknowledges: {parent}")
            print(f"      Trust grade:  {ack.get('tg', '?')}")
        except Exception as e:
            print(f"  ⚠ Failed to decode ack: {e}")

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def send_receipt(self, receipt: dict) -> bool:
        """Sign, envelope, and send a receipt over the link."""
        if not self.link or not self.link_ready:
            print("  ✗ No active link")
            return False

        seq = self.next_seq()
        envelope_data = make_envelope(self.zp_identity, receipt, seq)

        try:
            pkt = RNS.Packet(self.link, envelope_data)
            rns_receipt = pkt.send()
            self.receipts_sent += 1
            return True
        except Exception as e:
            print(f"  ✗ Send error: {e}")
            return False

    def send_announce(self):
        """Send our agent capabilities to the echo node."""
        capabilities = {
            "name": "zp-agent-bridge",
            "version": "0.1.0",
            "receipt_types": ["intent", "design", "approval", "execution"],
            "skills": ["shell", "python", "mesh-transport"],
            "actor_type": "agent",
            "trust_tier": "tier0",
        }

        # Build announce payload: combined_key + caps_json + signature
        caps_json = json.dumps(capabilities).encode("utf-8")
        inner = self.zp_identity.combined_public_key + caps_json
        sig = self.zp_identity.sign(inner)
        payload = inner + sig

        # Wrap in an envelope
        seq = self.next_seq()
        envelope_data = make_envelope(
            self.zp_identity, {},  seq,
            envelope_type=ENVELOPE_TYPE_AGENT_ANNOUNCE,
        )
        # Actually, for announces, embed the payload directly
        announce_envelope = {
            "envelope_type": ENVELOPE_TYPE_AGENT_ANNOUNCE,
            "sender": self.zp_identity.address,
            "seq": seq,
            "ts": int(time.time()),
            "payload": payload,
            "signature": self.zp_identity.sign(
                build_signing_material(
                    ENVELOPE_TYPE_AGENT_ANNOUNCE,
                    self.zp_identity.address,
                    seq,
                    int(time.time()),
                    payload,
                )
            ),
        }
        wire = msgpack.packb(announce_envelope, use_bin_type=True)

        try:
            pkt = RNS.Packet(self.link, wire)
            pkt.send()
            print("📋 Agent announce sent")
            print(f"   Combined key: {self.zp_identity.combined_public_key.hex()[:32]}...")
            print(f"   Capabilities: {capabilities['name']} v{capabilities['version']}")
            print()
            return True
        except Exception as e:
            print(f"  ✗ Announce failed: {e}")
            return False

    def run_chain_test(self, num_chains: int = 5, delay: float = 0.5):
        """Send multiple receipt chains — the core integration test."""
        print(f"{'═' * 50}")
        print(f"  Receipt Chain Test: {num_chains} chains × 4 receipts")
        print(f"{'═' * 50}")
        print()

        total_receipts = 0

        for chain_idx in range(num_chains):
            chain = make_receipt_chain(
                "zp-agent-bridge",
                chain_length=4,
                start_index=chain_idx * 4,
            )

            print(f"Chain #{chain_idx + 1}:")
            for receipt in chain:
                rt = receipt["rt"]
                tg = receipt["tg"]
                rid = receipt["id"]
                parent = receipt.get("pr", "—")

                print(f"  → {rt:<12s} [{tg}] {rid}")
                if parent != "—":
                    print(f"    ↳ parent: {parent}")

                if self.send_receipt(receipt):
                    total_receipts += 1
                else:
                    print(f"    ✗ FAILED to send")

                time.sleep(delay)

            self.chain_count += 1
            print()

        # Wait for acks to come back
        print("Waiting for acknowledgments...")
        deadline = time.time() + 10.0
        while self.acks_received < total_receipts and time.time() < deadline:
            time.sleep(0.2)

        # Results
        elapsed = time.time() - self.start_time
        print()
        print(f"{'═' * 50}")
        print(f"  Results")
        print(f"{'═' * 50}")
        print(f"  Chains sent:     {self.chain_count}")
        print(f"  Receipts sent:   {self.receipts_sent}")
        print(f"  ACKs received:   {self.acks_received}")
        print(f"  Success rate:    {self.acks_received}/{self.receipts_sent} "
              f"({100*self.acks_received/max(1,self.receipts_sent):.0f}%)")
        print(f"  Elapsed:         {elapsed:.2f}s")
        if self.receipts_sent > 0 and elapsed > 0:
            print(f"  Throughput:      {self.receipts_sent / elapsed:.1f} receipts/sec")
        print(f"{'═' * 50}")

        return self.acks_received == self.receipts_sent

    def run_load_test(self, num_receipts: int = 100, delay: float = 0.05):
        """High-throughput receipt burst — tests mesh under sustained load."""
        print(f"{'═' * 50}")
        print(f"  Load Test: {num_receipts} receipts, {delay}s interval")
        print(f"{'═' * 50}")
        print()

        start = time.time()
        sent_before = self.receipts_sent

        for i in range(num_receipts):
            receipt = make_receipt(
                "zp-load-test", "execution", i,
                trust_grade="C",
            )
            if not self.send_receipt(receipt):
                print(f"  ✗ Send failed at receipt {i}")
                break

            if (i + 1) % 25 == 0:
                elapsed = time.time() - start
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                print(f"  Progress: {i+1}/{num_receipts} ({rate:.0f} receipts/sec)")

            time.sleep(delay)

        burst_sent = self.receipts_sent - sent_before
        elapsed = time.time() - start

        # Wait for acks
        print("\nWaiting for acknowledgments...")
        ack_start = self.acks_received
        deadline = time.time() + 30.0
        while (self.acks_received - ack_start) < burst_sent and time.time() < deadline:
            time.sleep(0.2)

        burst_acks = self.acks_received - ack_start

        print()
        print(f"  Load Test Results:")
        print(f"  Sent:       {burst_sent} receipts in {elapsed:.2f}s")
        print(f"  ACKs:       {burst_acks}/{burst_sent}")
        print(f"  Throughput: {burst_sent / elapsed:.1f} receipts/sec")
        print(f"  Avg RTT:    {elapsed / max(1, burst_sent) * 1000:.1f}ms")
        print()

        return burst_acks == burst_sent


# --- Main -------------------------------------------------------------------

def default_config_path():
    """Use the bundled testnet config (no multicast, shared instance only)."""
    return os.path.join(os.path.dirname(__file__), "testnet_config")


def main():
    parser = argparse.ArgumentParser(
        description="ZeroPoint Agent Bridge → Reticulum",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Generates ZeroPoint receipt chains and sends them over Reticulum to an echo node.

Example:
    python3 zp_agent_bridge.py a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
        """,
    )
    parser.add_argument(
        "destination",
        help="Destination hash of the echo node (32 hex characters)",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to Reticulum config directory (default: bundled testnet_config)",
        default=None,
    )
    parser.add_argument(
        "-n", "--chains",
        type=int, default=5,
        help="Number of receipt chains to send (default: 5)",
    )
    parser.add_argument(
        "--load-test",
        type=int, default=0, metavar="N",
        help="Run load test with N receipts after chain test",
    )
    parser.add_argument(
        "-d", "--delay",
        type=float, default=0.5,
        help="Delay between receipts in seconds (default: 0.5)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    args = parser.parse_args()

    config = args.config or default_config_path()
    bridge = AgentBridge(
        echo_dest_hash=args.destination,
        config_path=config,
        verbose=args.verbose,
    )

    # Connect
    if not bridge.connect():
        print("\nFailed to establish link. Exiting.")
        sys.exit(1)

    # Send announce first (so echo node has our public key)
    bridge.send_announce()
    time.sleep(1)

    # Run chain test
    chain_ok = bridge.run_chain_test(num_chains=args.chains, delay=args.delay)

    # Optionally run load test
    if args.load_test > 0:
        print()
        load_ok = bridge.run_load_test(
            num_receipts=args.load_test,
            delay=args.delay / 5,  # Faster for load test
        )
    else:
        load_ok = True

    # Summary
    print()
    if chain_ok and load_ok:
        print("✓ All tests passed — ZeroPoint receipts verified over Reticulum mesh")
    else:
        print("✗ Some tests failed — check output above")
        sys.exit(1)


if __name__ == "__main__":
    main()
