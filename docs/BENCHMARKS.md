# ZeroPoint Performance Benchmarks

**Date:** 2026-04-26
**Hardware:** APOLLO — Apple M4 Pro (14 cores), macOS Darwin 25.3.0 (arm64)
**Rust:** rustc 1.93.0 (254b59607 2026-01-19)
**Build:** Criterion default (`cargo bench`) — release profile, LTO off
**Bench harness:** `crates/zp-bench/benches/governance_gate.rs`

Run yourself with:

```sh
cargo bench -p zp-bench
```

This is adaptation **F4** from `docs/ARCHITECTURE-2026-04.md` Part VII —
the published per-operation cost of the verifiability primitives that sit
on the hot path. Each row is the Criterion `[lower mean upper]` triple,
collapsed to a single mean. Variance is small — see the raw HTML reports
under `target/criterion/` for distributions.

## Results

### (a) Receipt emission

| Operation | Mean | Throughput |
|-----------|------|------------|
| assemble (1 claim) | 4.59 µs | 218 K rcpt/s |
| sign-only (1 claim) | 9.62 µs | 104 K rcpt/s |
| emit signed (1 claim) | 14.06 µs | 71 K rcpt/s |
| assemble (4 claims, typical) | 7.04 µs | 142 K rcpt/s |
| sign-only (4 claims, typical) | 9.81 µs | 102 K rcpt/s |
| emit signed (4 claims, typical) | 16.40 µs | 61 K rcpt/s |
| assemble (12 claims, heavy) | 12.98 µs | 77 K rcpt/s |
| sign-only (12 claims, heavy) | 10.55 µs | 95 K rcpt/s |
| emit signed (12 claims, heavy) | 22.36 µs | 45 K rcpt/s |

A typical signed receipt is ~16 µs end-to-end. Signing dominates and is
roughly claim-count-independent (it operates on the 64-char Blake3 digest,
not on the serialized receipt). The growth comes from canonical hashing,
which scales linearly with receipt size.

### (b) Content hashing (Blake3)

| Payload | Mean | Throughput |
|---------|------|------------|
| 256 B (tool result) | 198 ns | 1.20 GiB/s |
| 4 KB (page) | 1.77 µs | 2.15 GiB/s |
| 64 KB (document) | 27.5 µs | 2.22 GiB/s |
| canonical_hash, 1-claim receipt | 2.86 µs | — |
| canonical_hash, 4-claim receipt | 4.16 µs | — |
| canonical_hash, 12-claim receipt | 7.44 µs | — |

Raw Blake3 saturates around 2.2 GiB/s on M4 Pro. The `canonical_hash`
numbers include `serde_json::to_string` of the entire receipt — that
serialization is the dominant cost at small sizes, not the hash itself.

### (c) Chain verification (`zp verify`)

Synthetic chains, all entries signed with one key. Verification runs P1
(genesis), M3 (parent-link continuity), M4 (timestamp monotonicity), P2
(content-hash recomputation flag), and S1 (Ed25519 signature check) on
every entry.

| Chain length | Mean wall time | Sustained rate | Per-entry |
|---|---|---|---|
| 10 | 207 µs | 48.4 K entries/s | 20.7 µs |
| 100 | 2.07 ms | 48.3 K entries/s | 20.7 µs |
| 1 000 | 21.0 ms | 47.6 K entries/s | 21.0 µs |
| 10 000 | 211 ms | 47.5 K entries/s | 21.1 µs |

Rate is flat across four orders of magnitude, which is what you want
from a chain verifier — no quadratic blowup, no cache cliffs. Every
~21 µs is dominated by the per-entry Ed25519 verify (~18.7 µs raw),
plus base64 decode and link checks.

### (d) Ed25519 atomic operations

| Operation | Mean | Throughput |
|-----------|------|------------|
| keygen | 8.69 µs | 115 K keys/s |
| sign (256 B) | 8.92 µs | 27.4 MiB/s |
| verify (256 B) | 18.69 µs | 13.0 MiB/s |
| verify with base64 decode | 18.34 µs | 13.3 MiB/s |

The base64-decode wrapper does not measurably increase verify cost —
decode is ns-scale next to ed25519's curve math. Verify is ~2× sign,
which matches the published ed25519-dalek profile.

### (e) F3 tool content scanner

| Workload | Mean | Per-tool |
|----------|------|----------|
| clean tool (best case) | 7.47 µs | 7.47 µs |
| hostile tool (every falsifier fires) | 11.70 µs | 11.70 µs |
| batch of 10 clean tools | 62.44 µs | 6.24 µs |

The scanner is fast enough to run on every canonicalization (≤ 12 µs
even when every falsifier hits). The amortized batch cost (6.24 µs/tool)
is below the single-tool cost because some setup is shared across the
loop and the JIT-warm path is hotter.

### (f) Canonicalization receipt assembly

This excludes the audit-store append (SQLite + locking + idempotency
check). It measures only the receipt-shaped portion of bead-zero
emission — the signing work F3 newly puts on the canon path.

| Operation | Mean |
|-----------|------|
| assemble CanonicalizedClaim receipt | 4.37 µs |
| assemble + sign | 13.76 µs |

## What These Numbers Mean

**Measured.** Every figure above is in-process work: Rust function calls
operating on already-deserialized objects, with no I/O between
`b.iter()` and the criterion sample boundary. Synthetic chains are held
in memory; `BenchEntry` implements `VerifiableEntry` directly so the
benchmark exercises exactly the same `Verifier::verify` code path that
`zp verify` runs in production.

**Not measured.**

- **Disk I/O.** Receipts in production land in a SQLite audit store
  (`zp_audit::AuditStore`). Append cost includes a `BEGIN IMMEDIATE`
  transaction, prepared-statement bind, and fsync. On the same hardware
  this is on the order of hundreds of microseconds per append — much
  larger than the receipt-emission cost itself. The integration cost
  is what an operator actually pays; the per-receipt floor measured
  here is what the cryptographic primitives contribute.
- **Network.** Mesh fan-out, agent-to-substrate, and tool proxy hops
  each add their own latency budget, which depends on topology and is
  not a property of the substrate itself.
- **Policy module evaluation.** The `policies/default-gate` WASM and
  the constitutional rules in `zp-policy` are intentionally
  benchmarked separately; F4 is about the verifiability primitives.
- **Schema validation.** `try_finalize()` runs per-type validation;
  `finalize()` warns instead of erroring. The benchmark uses
  `finalize()` to measure the steady-state path. The well-formedness
  cost of `try_finalize()` would add ~µs but is outside the gate's
  hot path.

**Microbenchmark caveats.** Criterion's mean is not a clock-time SLA.
Real per-receipt latency in production is dominated by the audit-store
fsync (≈100–500 µs typical, more on slow storage). Use these numbers to
reason about the *fraction* of latency the verifiability layer
contributes (small) and the *throughput ceiling* of cryptographic work
on a single core (~70 K signed receipts/sec, ~48 K entry verifies/sec).
End-to-end throughput will be lower; these are upper bounds.

## Comparison Context

Microsoft AGT publishes 0.012 ms p50 for single-rule policy evaluation
and 35 K ops/sec under 50-agent concurrency. ZeroPoint's governance gate
includes Ed25519 signing (~9 µs) and Blake3 canonical hashing (~3 µs)
on every receipt — operations AGT does not perform per evaluation. The
comparison is architectural, not competitive:

- **AGT optimizes for evaluation speed.** A policy decision is a fast
  predicate; the cost of recording that decision later is a different
  problem.
- **ZP optimizes for verifiability.** Every gate decision is sealed
  into a hash-linked, signed audit chain so it can be re-verified
  cold, by anyone, at any later time. That property has a non-zero
  per-receipt cost: ~16 µs to emit a typical signed receipt, ~21 µs
  per entry to re-verify a chain. The relevant question is whether
  that cost is acceptable, not whether it is lower than AGT's.

For a 50-agent workload that produces one receipt per agent-second, ZP
spends roughly 50 × 16 µs = 0.8 ms/sec on the verifiability gate (under
0.1 % of a single core). For a verifier auditing a 10 000-entry chain,
the cold-walk cost is ~210 ms — well within an interactive budget for
operator-level audit.
