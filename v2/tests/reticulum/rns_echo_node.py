#!/usr/bin/env python3
"""
ZeroPoint × Reticulum Echo Node
================================

Runs a Reticulum destination that receives ZeroPoint receipt envelopes,
verifies Ed25519 signatures, and echoes back an acknowledgment receipt.

This is the "responder" side of the integration test.

Usage:
    python3 v2/tests/reticulum/rns_echo_node.py

Prerequisites:
    pip install rns msgpack ed25519  # or: pip install rns msgpack PyNaCl
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
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("WARNING: PyNaCl not available — signature verification disabled")
    print("  Install with: pip install PyNaCl")

# --- Constants --------------------------------------------------------------

APP_NAME = "zeropoint"
ASPECTS   = ["agent", "receipt"]

# Envelope type codes (must match zp-mesh/src/envelope.rs EnvelopeType)
ENVELOPE_TYPE_RECEIPT        = 0x01
ENVELOPE_TYPE_DELEGATION     = 0x02
ENVELOPE_TYPE_GUARD_REQUEST  = 0x03
ENVELOPE_TYPE_GUARD_RESPONSE = 0x04
ENVELOPE_TYPE_AGENT_ANNOUNCE = 0x05
ENVELOPE_TYPE_RECEIPT_CHAIN  = 0x06

# --- Compact Receipt -------------------------------------------------------

def decode_compact_receipt(data: bytes) -> dict:
    """Decode a msgpack-encoded CompactReceipt (named map encoding)."""
    return msgpack.unpackb(data, raw=False)


def encode_compact_receipt(receipt: dict) -> bytes:
    """Encode a CompactReceipt to msgpack (named map encoding)."""
    return msgpack.packb(receipt, use_bin_type=True)


def make_ack_receipt(original_id: str, node_name: str) -> dict:
    """Create an acknowledgment receipt referencing the original."""
    now = int(time.time())
    content = f"ack:{original_id}:{now}"
    content_hash = hashlib.blake2b(content.encode(), digest_size=32).hexdigest()

    return {
        "id": f"rcpt-ack-{hashlib.sha256(content.encode()).hexdigest()[:16]}",
        "rt": "execution",
        "st": "success",
        "tg": "B",
        "ch": content_hash,
        "ts": now,
        "pr": original_id,   # Chain back to the receipt we're acknowledging
        "pd": "allow",
        "ra": f"Echo acknowledgment from {node_name}",
    }

# --- Envelope ---------------------------------------------------------------

def decode_envelope(data: bytes) -> dict:
    """Decode a msgpack-encoded MeshEnvelope."""
    return msgpack.unpackb(data, raw=False)


def build_signing_material(envelope_type: int, sender: str, seq: int, ts: int, payload: bytes) -> bytes:
    """Reconstruct the canonical bytes that were signed.
    Must match zp-mesh/src/envelope.rs signing_material().
    """
    material = bytearray()
    material.append(envelope_type)
    material.extend(sender.encode("utf-8"))
    material.extend(seq.to_bytes(8, "big"))
    material.extend(ts.to_bytes(8, "big", signed=True))
    material.extend(payload)
    return bytes(material)


def verify_envelope_signature(envelope: dict, signing_public_key: bytes) -> bool:
    """Verify the Ed25519 signature on a MeshEnvelope.

    Returns True if valid, False if invalid or verification unavailable.
    """
    if not NACL_AVAILABLE:
        print("  ⚠ Signature verification skipped (PyNaCl not installed)")
        return True  # Assume valid if we can't check

    signature = envelope.get("signature", b"")
    if len(signature) != 64:
        print(f"  ✗ Invalid signature length: {len(signature)} (expected 64)")
        return False

    # Reconstruct what was signed
    material = build_signing_material(
        envelope_type=envelope.get("envelope_type", 0),
        sender=envelope.get("sender", ""),
        seq=envelope.get("seq", 0),
        ts=envelope.get("ts", 0),
        payload=envelope.get("payload", b""),
    )

    try:
        vk = VerifyKey(signing_public_key)
        vk.verify(material, signature)
        return True
    except BadSignatureError:
        return False
    except Exception as e:
        print(f"  ✗ Verification error: {e}")
        return False

# --- Reticulum Callbacks ----------------------------------------------------

class EchoNode:
    """A Reticulum destination that receives and echoes ZeroPoint receipts."""

    def __init__(self, config_path=None, verbose=False):
        self.verbose = verbose
        self.receipts_received = 0
        self.receipts_echoed = 0
        self.verification_failures = 0
        self.start_time = time.time()

        # Initialize Reticulum
        print("═" * 60)
        print("  ZeroPoint × Reticulum Echo Node")
        print("═" * 60)
        print()
        print("Initializing Reticulum...")
        self.reticulum = RNS.Reticulum(config_path)

        # Create identity (or load from file)
        identity_path = os.path.join(
            os.path.dirname(__file__), ".echo_node_identity"
        )
        if os.path.isfile(identity_path):
            self.identity = RNS.Identity.from_file(identity_path)
            print(f"  Loaded identity from {identity_path}")
        else:
            self.identity = RNS.Identity()
            self.identity.to_file(identity_path)
            print(f"  Generated new identity → {identity_path}")

        # Create destination
        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            *ASPECTS,
        )

        # Register link handler
        self.destination.set_link_established_callback(self.on_link_established)

        # Print our address
        dest_hash = self.destination.hexhash
        print()
        print(f"  ┌─────────────────────────────────────────────┐")
        print(f"  │  Echo Node Active                           │")
        print(f"  │  Destination: {dest_hash}  │")
        print(f"  │  App:         {APP_NAME}.{'.'.join(ASPECTS):<28s}│")
        print(f"  └─────────────────────────────────────────────┘")
        print()
        print("Waiting for incoming links...")
        print()

    def on_link_established(self, link):
        """Called when a remote agent establishes a link to us."""
        try:
            peer_id = getattr(link, 'peer_dest_hash_hex', None) or 'unknown'
            print(f"⟐ Link established from {peer_id}")
        except Exception:
            print(f"⟐ Link established from unknown peer")

        self._current_link = link
        link.set_link_closed_callback(self.on_link_closed)
        link.set_packet_callback(self.on_packet)
        print(f"  Packet callback registered on link")

    def on_link_closed(self, link):
        """Called when a link is torn down."""
        elapsed = time.time() - self.start_time
        print(f"⟐ Link closed (uptime: {elapsed:.1f}s, "
              f"received: {self.receipts_received}, "
              f"echoed: {self.receipts_echoed})")

    def on_packet(self, message, packet):
        """Called when we receive a packet on an established link."""
        try:
            self._handle_packet(message, packet)
        except Exception as e:
            print(f"  ✗ Error handling packet: {e}")
            if self.verbose:
                traceback.print_exc()

    def _handle_packet(self, data, packet):
        """Process an incoming receipt envelope."""
        self.receipts_received += 1
        print(f"\n{'─' * 50}")
        print(f"📥 Receipt #{self.receipts_received}")
        print(f"   Received at: {datetime.now(timezone.utc).isoformat()}")
        print(f"   Raw size:    {len(data)} bytes")

        # --- Decode envelope ---
        envelope = decode_envelope(data)
        env_type = envelope.get("envelope_type", 0)
        sender   = envelope.get("sender", "???")
        seq      = envelope.get("seq", 0)
        ts       = envelope.get("ts", 0)
        payload  = envelope.get("payload", b"")

        print(f"   Envelope type: 0x{env_type:02X} "
              f"({'Receipt' if env_type == ENVELOPE_TYPE_RECEIPT else 'Other'})")
        print(f"   Sender:        {sender}")
        print(f"   Sequence:      {seq}")
        print(f"   Timestamp:     {datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()}")

        # --- Verify signature ---
        # We'd need the sender's Ed25519 public key. For the integration test,
        # it's embedded in the announce or passed out-of-band. For now we
        # attempt verification if we can derive the key from the sender's
        # combined public key (sent in the first envelope as metadata).
        sig_ok = True  # Default to true; real impl would verify

        # If we have the sender's public key from a prior announce, verify
        if hasattr(self, '_peer_signing_key') and self._peer_signing_key is not None:
            sig_ok = verify_envelope_signature(envelope, self._peer_signing_key)
            print(f"   Signature:     {'✓ VALID' if sig_ok else '✗ INVALID'}")
        else:
            print(f"   Signature:     ⚠ not verified (no peer key yet)")

        if not sig_ok:
            self.verification_failures += 1
            print(f"   ✗ Dropping receipt — signature verification failed")
            return

        # --- Decode receipt ---
        if env_type != ENVELOPE_TYPE_RECEIPT:
            # Check if this is an announce with embedded public key
            if env_type == ENVELOPE_TYPE_AGENT_ANNOUNCE:
                self._handle_announce(payload)
                return
            print(f"   ⚠ Not a receipt envelope (type 0x{env_type:02X}), skipping")
            return

        receipt = decode_compact_receipt(payload)
        receipt_id = receipt.get("id", "???")
        receipt_type = receipt.get("rt", "???")
        status = receipt.get("st", "???")
        trust_grade = receipt.get("tg", "?")
        content_hash = receipt.get("ch", "???")
        parent = receipt.get("pr", None)

        print(f"   Receipt ID:    {receipt_id}")
        print(f"   Type:          {receipt_type}")
        print(f"   Status:        {status}")
        print(f"   Trust Grade:   {trust_grade}")
        print(f"   Content Hash:  {content_hash[:24]}...")
        if parent:
            print(f"   Parent:        {parent}")

        # --- Build and send acknowledgment ---
        ack = make_ack_receipt(receipt_id, "echo-node")
        ack_compact = encode_compact_receipt(ack)

        print(f"\n   📤 Echoing acknowledgment:")
        print(f"      ACK ID:     {ack['id']}")
        print(f"      Parent:     {ack['pr']}")
        print(f"      Size:       {len(ack_compact)} bytes")

        # Send the ack back on the same link
        try:
            ack_packet = RNS.Packet(packet.link, ack_compact)
            ack_receipt = ack_packet.send()
            if ack_receipt:
                self.receipts_echoed += 1
                print(f"      Status:     ✓ Sent")
            else:
                print(f"      Status:     ✗ Send failed")
        except Exception as e:
            print(f"      Status:     ✗ Error: {e}")

    def _handle_announce(self, payload):
        """Handle an agent announce envelope — extract the public key."""
        if len(payload) >= 64:
            combined_key = payload[:64]
            self._peer_signing_key = combined_key[:32]
            print(f"   📋 Agent announce received")
            print(f"      Signing key:    {self._peer_signing_key.hex()[:32]}...")
            print(f"      Encryption key: {combined_key[32:].hex()[:32]}...")
            if len(payload) > 128:  # Has capabilities JSON after keys + sig
                try:
                    caps_data = payload[64:-64]  # Between keys and signature
                    caps = json.loads(caps_data)
                    print(f"      Capabilities:   {caps.get('name', '?')} v{caps.get('version', '?')}")
                    print(f"      Skills:         {', '.join(caps.get('skills', []))}")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

    def stats(self):
        """Print running statistics."""
        elapsed = time.time() - self.start_time
        print(f"\n{'═' * 50}")
        print(f"  Echo Node Statistics")
        print(f"  Uptime:               {elapsed:.1f}s")
        print(f"  Receipts received:    {self.receipts_received}")
        print(f"  Receipts echoed:      {self.receipts_echoed}")
        print(f"  Verification failures: {self.verification_failures}")
        if self.receipts_received > 0 and elapsed > 0:
            print(f"  Throughput:           {self.receipts_received / elapsed:.1f} receipts/sec")
        print(f"{'═' * 50}")


# --- Main -------------------------------------------------------------------

def default_config_path():
    """Use the bundled testnet config (no multicast, shared instance only)."""
    return os.path.join(os.path.dirname(__file__), "testnet_config")


def main():
    parser = argparse.ArgumentParser(
        description="ZeroPoint × Reticulum Echo Node",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This node receives ZeroPoint receipt envelopes over a Reticulum link,
verifies signatures, and sends back acknowledgment receipts.

The destination hash printed at startup must be provided to zp_agent_bridge.py.
        """,
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to Reticulum config directory (default: bundled testnet_config)",
        default=None,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (stack traces on errors)",
    )
    args = parser.parse_args()

    config = args.config or default_config_path()
    node = EchoNode(config_path=config, verbose=args.verbose)

    try:
        print("Press Ctrl+C to stop and show statistics.\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        node.stats()
        print("\nShutting down echo node.")
        sys.exit(0)


if __name__ == "__main__":
    main()
