#!/usr/bin/env python3
"""
HDLC Wire-Format Interop Server
=================================

Proves that ZeroPoint's Rust HDLC codec is byte-for-byte compatible
with Reticulum's Python HDLC codec.

Architecture:
  - This Python script acts as a TCP server using Reticulum's *exact*
    HDLC escape/unescape logic (copied from RNS/Interfaces/TCPInterface.py).
  - The Rust interop test connects as a client.
  - Both sides exchange known test vectors through HDLC framing.
  - Both sides verify the decoded payloads match.

Protocol:
  1. Python sends N HDLC-framed test payloads → Rust
  2. Rust verifies decoded payloads match expected vectors
  3. Rust sends N HDLC-framed test payloads → Python
  4. Python verifies decoded payloads match expected vectors
  5. Python sends a final "PASS" or "FAIL" summary frame

Usage:
    python3 hdlc_interop_server.py [--port 7331]
"""

import os
import sys
import json
import socket
import struct
import time
import argparse
import hashlib

# =============================================================================
# HDLC — Reticulum's exact implementation
# =============================================================================
# These constants and functions are taken directly from
# RNS/Interfaces/TCPInterface.py in the Reticulum source code.

class HDLC:
    FLAG     = 0x7E
    ESC      = 0x7D
    ESC_MASK = 0x20

    @staticmethod
    def escape(data: bytes) -> bytes:
        """Reticulum's exact escape function."""
        # Order matters: escape ESC first, then FLAG
        data = data.replace(bytes([HDLC.ESC]), bytes([HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK]))
        data = data.replace(bytes([HDLC.FLAG]), bytes([HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK]))
        return data

    @staticmethod
    def unescape(data: bytes) -> bytes:
        """Reticulum's exact unescape function."""
        # Order matters: unescape FLAG first, then ESC
        data = data.replace(bytes([HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK]), bytes([HDLC.FLAG]))
        data = data.replace(bytes([HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK]), bytes([HDLC.ESC]))
        return data

    @staticmethod
    def frame(data: bytes) -> bytes:
        """Wrap data in HDLC frame: [FLAG] [escaped_data] [FLAG]."""
        return bytes([HDLC.FLAG]) + HDLC.escape(data) + bytes([HDLC.FLAG])


# =============================================================================
# Test Vectors — shared between Python and Rust
# =============================================================================

def generate_test_vectors():
    """
    Generate deterministic test vectors that exercise all edge cases
    in HDLC escaping. Both Python and Rust must produce identical outputs.
    """
    vectors = []

    # 1. Simple ASCII — no escaping needed
    vectors.append(b"hello reticulum")

    # 2. Contains FLAG byte (0x7E) — must be escaped
    vectors.append(bytes([0x01, 0x02, 0x7E, 0x03, 0x04]))

    # 3. Contains ESC byte (0x7D) — must be escaped
    vectors.append(bytes([0x10, 0x7D, 0x20, 0x30]))

    # 4. Contains BOTH FLAG and ESC — double trouble
    vectors.append(bytes([0x7E, 0x7D, 0x7E, 0x7D]))

    # 5. All special bytes consecutively
    vectors.append(bytes([0x7E, 0x7E, 0x7E, 0x7D, 0x7D, 0x7D]))

    # 6. Bytes that look like escaped sequences but aren't
    #    0x5E = FLAG ^ ESC_MASK, 0x5D = ESC ^ ESC_MASK
    vectors.append(bytes([0x5E, 0x5D, 0x5E, 0x5D]))

    # 7. All 256 byte values (comprehensive)
    vectors.append(bytes(range(256)))

    # 8. Empty-ish — single byte
    vectors.append(bytes([0x42]))

    # 9. Reticulum-realistic: simulated packet header + payload
    #    2-byte header + 16-byte destination hash + data
    header = bytes([0b00000000, 0x07])  # Type1, data, broadcast, 7 hops
    dest_hash = hashlib.sha256(b"test-destination").digest()[:16]
    payload = b"ZeroPoint receipt data with special \x7e\x7d bytes"
    vectors.append(header + dest_hash + payload)

    # 10. Maximum Reticulum MTU (500 bytes) with deterministic content.
    #     Uses SHA-256 based PRNG so both Python and Rust generate identical bytes:
    #     byte[i] = SHA256(b"interop-mtu-vector" || i_as_4_byte_little_endian)[0]
    mtu_data = bytearray(500)
    for i in range(500):
        h = hashlib.sha256(b"interop-mtu-vector" + i.to_bytes(4, byteorder="little"))
        mtu_data[i] = h.digest()[0]
    vectors.append(bytes(mtu_data))

    return vectors


# =============================================================================
# HDLC Stream Decoder (Python side — matches Reticulum's read_loop logic)
# =============================================================================

class HdlcStreamDecoder:
    """
    Stateful HDLC stream decoder matching Reticulum's TCPInterface.read_loop.
    """
    def __init__(self):
        self.buffer = b""

    def feed(self, data: bytes) -> list:
        """Feed raw TCP bytes, return list of decoded frames."""
        self.buffer += data
        frames = []

        while True:
            # Find opening FLAG
            start = self.buffer.find(bytes([HDLC.FLAG]))
            if start == -1:
                self.buffer = b""
                break

            # Find closing FLAG
            end = self.buffer.find(bytes([HDLC.FLAG]), start + 1)
            if end == -1:
                # Incomplete frame — keep buffer from start
                self.buffer = self.buffer[start:]
                break

            # Extract and unescape
            raw_frame = self.buffer[start + 1:end]
            if len(raw_frame) > 0:
                decoded = HDLC.unescape(raw_frame)
                if len(decoded) > 0:
                    frames.append(decoded)

            # Advance past the closing FLAG
            self.buffer = self.buffer[end:]

        return frames


# =============================================================================
# Interop Server
# =============================================================================

def run_server(port: int):
    """Run the HDLC interop test server."""
    vectors = generate_test_vectors()
    n_vectors = len(vectors)

    print(f"╔══════════════════════════════════════════════════════════════╗")
    print(f"║   HDLC Wire-Format Interop Server (Reticulum Python)       ║")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Port:         {port:<45}║")
    print(f"║  Test vectors: {n_vectors:<45}║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print()

    # Print vector summaries
    for i, v in enumerate(vectors):
        special = sum(1 for b in v if b in (0x7E, 0x7D))
        print(f"  Vector {i+1:2d}: {len(v):4d} bytes, {special:3d} special bytes"
              f"  [{v[:16].hex()}{'...' if len(v) > 16 else ''}]")
    print()

    # Open TCP server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", port))
    server_sock.listen(1)
    server_sock.settimeout(30.0)

    print(f"Listening on 127.0.0.1:{port}...")
    print(f"Waiting for Rust client to connect...\n")

    try:
        conn, addr = server_sock.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f"✓ Client connected from {addr}")
    except socket.timeout:
        print("✗ TIMEOUT: No client connected within 30 seconds")
        server_sock.close()
        sys.exit(1)

    results = {"py_sent": 0, "py_recv": 0, "py_verified": 0, "errors": []}
    decoder = HdlcStreamDecoder()

    # ── Phase 1: Python → Rust ──────────────────────────────────────────
    print(f"\n── Phase 1: Python → Rust ({n_vectors} vectors) ──")

    for i, payload in enumerate(vectors):
        frame = HDLC.frame(payload)
        conn.sendall(frame)
        results["py_sent"] += 1
        escaped_len = len(frame)
        print(f"  Sent vector {i+1:2d}: {len(payload):4d} raw → {escaped_len:4d} framed")

    # Small delay to let TCP flush
    time.sleep(0.2)

    # Send a sentinel frame so Rust knows all vectors have been sent
    sentinel = b"__PHASE1_COMPLETE__"
    conn.sendall(HDLC.frame(sentinel))
    print(f"  Sent phase-1 sentinel")

    # ── Phase 2: Rust → Python ──────────────────────────────────────────
    print(f"\n── Phase 2: Rust → Python ({n_vectors} vectors) ──")

    received_payloads = []
    deadline = time.time() + 15.0  # 15 second timeout

    while len(received_payloads) < n_vectors and time.time() < deadline:
        conn.settimeout(max(0.1, deadline - time.time()))
        try:
            data = conn.recv(65536)
            if not data:
                print("  ✗ Connection closed by client")
                break
            frames = decoder.feed(data)
            for frame in frames:
                # Skip sentinel frames
                if frame == b"__PHASE2_COMPLETE__":
                    continue
                received_payloads.append(frame)
                results["py_recv"] += 1
        except socket.timeout:
            continue

    # Verify received payloads match test vectors
    print(f"\n── Verification ──")

    if len(received_payloads) != n_vectors:
        msg = f"Expected {n_vectors} vectors, received {len(received_payloads)}"
        results["errors"].append(msg)
        print(f"  ✗ {msg}")
    else:
        for i, (expected, actual) in enumerate(zip(vectors, received_payloads)):
            if expected == actual:
                results["py_verified"] += 1
                print(f"  Vector {i+1:2d}: ✓ MATCH ({len(actual)} bytes)")
            else:
                msg = f"Vector {i+1}: MISMATCH (expected {len(expected)} bytes, got {len(actual)} bytes)"
                results["errors"].append(msg)
                print(f"  Vector {i+1:2d}: ✗ {msg}")
                # Show first difference
                for j in range(min(len(expected), len(actual))):
                    if expected[j] != actual[j]:
                        print(f"             First diff at byte {j}: expected 0x{expected[j]:02x}, got 0x{actual[j]:02x}")
                        break

    # ── Send results summary ────────────────────────────────────────────
    summary = {
        "python_sent": results["py_sent"],
        "python_received": results["py_recv"],
        "python_verified": results["py_verified"],
        "errors": results["errors"],
        "pass": len(results["errors"]) == 0 and results["py_verified"] == n_vectors
    }
    summary_frame = HDLC.frame(json.dumps(summary).encode("utf-8"))
    conn.sendall(summary_frame)

    # Final summary
    print(f"\n{'═' * 62}")
    if summary["pass"]:
        print(f"  ✓ INTEROP TEST PASSED")
        print(f"    Python sent:     {results['py_sent']}/{n_vectors} vectors")
        print(f"    Python received: {results['py_recv']}/{n_vectors} vectors")
        print(f"    Python verified: {results['py_verified']}/{n_vectors} vectors")
        print(f"    Wire format:     COMPATIBLE")
    else:
        print(f"  ✗ INTEROP TEST FAILED")
        for err in results["errors"]:
            print(f"    Error: {err}")
    print(f"{'═' * 62}\n")

    conn.close()
    server_sock.close()
    sys.exit(0 if summary["pass"] else 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HDLC Wire-Format Interop Server")
    parser.add_argument("--port", type=int, default=7331, help="TCP port (default: 7331)")
    args = parser.parse_args()
    run_server(args.port)
