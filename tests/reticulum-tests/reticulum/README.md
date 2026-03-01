# ZeroPoint × Reticulum Integration Test

Demonstrates ZeroPoint agents exchanging cryptographic receipts over the
Reticulum mesh network stack. Uses TCP loopback — no radio hardware required.

## Architecture

```
┌──────────────────────┐     TCP 127.0.0.1:4242     ┌──────────────────────┐
│  ZP Agent Bridge     │◄──────────────────────────►│  ZP Echo Node        │
│  (Python)            │     Reticulum Link          │  (Python)            │
│                      │                             │                      │
│  ┌────────────────┐  │                             │  ┌────────────────┐  │
│  │ ZPIdentity     │  │                             │  │ RNS Identity   │  │
│  │ Ed25519+X25519 │  │     Encrypted Channel       │  │ Ed25519 verify │  │
│  │ receipt chain  │──┼────(ECDH + HKDF + AES)──────┼──│ echo service   │  │
│  │ envelope sign  │  │                             │  │ ack generator  │  │
│  └────────────────┘  │                             │  └────────────────┘  │
└──────────────────────┘                             └──────────────────────┘
```

## Files

| File                      | Role                                           |
|---------------------------|-------------------------------------------------|
| `rns_echo_node.py`       | Responder — receives receipts, verifies, echoes |
| `zp_agent_bridge.py`     | Initiator — generates chains, sends, validates  |
| `reticulum_test_config`  | Reticulum TCP loopback config (no radio needed) |
| `run_test.sh`            | Automated test runner (both sides)              |

## Prerequisites

```bash
pip install rns msgpack PyNaCl
```

## Running

### Automated (single command)

```bash
./tests/reticulum-tests/reticulum/run_test.sh

# With load test (100 rapid-fire receipts after chain test)
./tests/reticulum-tests/reticulum/run_test.sh --load 100
```

### Manual (two terminals)

```bash
# Terminal 1: Start the echo node (note the destination hash it prints)
python3 tests/reticulum-tests/reticulum/rns_echo_node.py

# Terminal 2: Connect the agent bridge to the echo node
python3 tests/reticulum-tests/reticulum/zp_agent_bridge.py <DESTINATION_HASH>

# With options:
python3 tests/reticulum-tests/reticulum/zp_agent_bridge.py <DEST> -n 10 --load-test 200 -d 0.2
```

## What It Tests

1. **Identity interop**: ZeroPoint Ed25519 keys + HKDF-derived X25519, matching `zp-mesh` identity model
2. **Link establishment**: Full Reticulum encrypted link over TCP loopback
3. **Receipt transport**: Compact receipts serialized to msgpack, wrapped in signed envelopes
4. **Signature verification**: Echo node verifies Ed25519 envelope signatures using ZP public key
5. **Bidirectional exchange**: Echo node sends back acknowledgment receipts with chain linkage
6. **Chain integrity**: intent → design → approval → execution chains with parent receipt IDs preserved
7. **Agent announce**: Capabilities broadcast with combined public key for peer discovery
8. **Load tolerance**: Sustained receipt throughput with ack tracking and success rate

## Test Flow

```
Agent Bridge                          Echo Node
    │                                     │
    │──── Link Request ──────────────────►│
    │◄─── Link Proof ────────────────────│
    │──── RTT Confirmation ──────────────►│
    │                                     │
    │──── Agent Announce (pub key) ──────►│  ← echo node caches signing key
    │                                     │
    │──── Receipt Chain #1 ──────────────►│
    │  intent  [A] ──────────────────────►│  → verify sig → decode receipt
    │  design  [A] ──────────────────────►│  → verify sig → decode receipt
    │  approval [B] ─────────────────────►│  → verify sig → decode receipt
    │  execution [C] ────────────────────►│  → verify sig → decode receipt
    │                                     │
    │◄──── ACK (parent=intent) ──────────│
    │◄──── ACK (parent=design) ──────────│
    │◄──── ACK (parent=approval) ────────│
    │◄──── ACK (parent=execution) ───────│
    │                                     │
    │  ... repeat for N chains ...        │
    │                                     │
    │  [optional load test burst]         │
    │──── 100× execution receipts ───────►│
    │◄──── 100× ACKs ───────────────────│
```

## Cryptographic Details

The Python ZPIdentity class mirrors the Rust `MeshIdentity` exactly:

- **Signing**: Ed25519 via PyNaCl (`nacl.signing.SigningKey`)
- **Encryption**: X25519 derived from Ed25519 secret via HKDF
  - Salt: `zp-mesh-x25519-derive-v1`
  - Info: `x25519-static-secret`
  - This matches `MeshIdentity::from_ed25519_secret()` in `zp-mesh/src/identity.rs`
- **Envelope signature**: Ed25519 over `(type ‖ sender ‖ seq ‖ ts ‖ payload)`
  - Matches `signing_material()` in `zp-mesh/src/envelope.rs`
- **Content hash**: Blake2b-256 (same as `zp-receipt` hasher)
