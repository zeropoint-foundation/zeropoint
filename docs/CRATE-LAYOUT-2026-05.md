# ZeroPoint Crate Layout — Port/Adapter Classification

*Companion to `docs/ARCHITECTURE-2026-05.md` Part II.0 (contracts singular; implementations plural). This document classifies every crate in the workspace under the meta-principle and identifies cases where ports and adapters are commingled in a way that future refactors should address.*

*Status: draft, working tree only. Classifications validated against current `crates/*/Cargo.toml` descriptions; any corrections welcome.*

---

## How this classification works

Every crate is classified into one of four categories:

- **Port-bearing** — defines a contract: a trait, schema, format, ceremony, or canonical primitive. Singular by design. Adding a second port for the same concern is a warning sign.
- **Adapter-bearing** — implements a port for a specific environment, external dependency, or operator class. Plural by design. Multiple adapters of the same port are expected; adding one requires per-instance justification.
- **Both** — contains both a port (the trait/schema) and one or more adapters of that port in the same crate. Common when the port and its default adapters are tightly coupled or when the port's adapters are small.
- **Service / domain** — does computation but doesn't fit the port/adapter taxonomy. Compute libraries, engines, test infrastructure, course content. Neither shapes a contract nor adapts one for a specific environment.

The classification reflects current state. Where a crate's classification doesn't match the principle's discipline (e.g. a port commingled with adapters where they should be separated), it's flagged in the *Refactor candidates* section.

---

## Classification table

### Port-bearing crates

These crates define ZP's contracts. They are singular by design — there should not be a second crate doing the same job for the same concern.

| Crate | Port(s) it bears | Notes |
|---|---|---|
| `zp-core` | Foundational types, paths, identity primitives | The bedrock port crate. Cycle-safe (other crates depend on it). |
| `zp-receipt` | Receipt format, `canonical_bytes_of`, `Signable` trait, `verify_signature` | The signing-discipline port (Seam 5, Seam 17, Seam 20). |
| `zp-audit` | Audit chain format, `AuditStore::append` interface | Chain-integrity port (Seam 1). |
| `zp-policy` | Policy module loading, gate-evaluation entry point | Gate semantics port (Seam 2). |
| `zp-config` | Configuration schema (`ZpConfig`), `ConfigResolver`, provenance tracking | Config-read port (Seam 12). |
| `zp-trust` | Trust-tier model, capability grants | Trust-tier port. |
| `zp-verify` | Verification primitives, M3/M4 invariant checks | Verifier port (Seam 5 sub-discipline). |
| `zp-pipeline` | Receipt-issuing pipeline | The path from gate→engine→receipt is the contract. |
| `zp-discipline` | Discipline-pin framework (`Discipline` builder + scanner) | Meta-port: the framework that enforces other ports. |
| `zp-introduction` | Cross-node trust-establishment protocol | Introduction protocol port. |
| `zp-skills` | Skill registry and matching | Skill-discovery port. |
| `zp-configure` | "Semantic Sed" tool-configuration library | Configuration-mutation port. |
| `zp-observation` | Receipt-backed observational memory | Observation port. |

### Adapter-bearing crates

These crates implement ports for specific environments, external dependencies, or operator classes. Plural by design.

| Crate | Port(s) it adapts | What environment / dep |
|---|---|---|
| `zp-cloudflare` | Multiple ZP ports → Cloudflare primitives | Canonical adapter crate; created May 6 to anchor the port/adapter discipline at the external-integration boundary. |
| `zp-cli` | Verb-set port (when defined) → CLI delivery | Operator-environment delivery 4.3 / 4.4 candidate. |
| `zp-preflight` | Installation lifecycle | Pre-install verification adapter. |

### Both — port + adapter(s) in one crate

These crates contain a port trait/schema AND one or more adapter implementations of that port. This is acceptable when the port and its default adapters are tightly coupled or each adapter is small enough that splitting would produce net friction. Each entry has a brief note on whether splitting is worth considering.

| Crate | Port | Adapters in same crate | Splitting worth it? |
|---|---|---|---|
| `zp-keys` | `SovereigntyProvider` trait, key derivation primitives | Touch ID, fingerprint, Windows Hello, Trezor, YubiKey, Ledger, OnlyKey, file-based, login-password, mock | **No.** Each adapter is small (hundreds of lines), feature-flagged (`hw-trezor`, `os-keychain`, etc.), and benefits from being co-located with the trait. The feature flag system already provides per-adapter compilation. |
| `zp-mesh` | `Interface` trait, mesh `MeshEnvelope` schema, `SignedAnnounce`, `check_and_record_announce_freshness` | Reticulum interface, TCP interface, Loopback interface | **No** for now; **Yes** when libp2p adapter lands (task #49) and the crate would otherwise hold three transports' worth of code. At that point, consider splitting Reticulum / TCP / libp2p / loopback into adapter crates. |
| `zp-anchor` | DLT abstraction trait | (per-DLT adapters — current count?) | **Maybe.** Depends on adapter count. Two or three adapters, keep co-located. Five or more, split. |
| `zp-llm` | LLM provider trait, risk-based router | Multiple LLM provider adapters (Anthropic, OpenAI, etc.) | **Maybe.** Per-provider client crates would cleanly express the port/adapter split, but the providers are small enough today that co-location is fine. Revisit when adapter count grows. |
| `zp-server` | (Currently mixed) | HTTP-delivery adapter; dashboard host; audit/identity/stats endpoint handlers; tool launcher | **Yes** — see Refactor Candidates. This crate is the largest violation of the principle in the current layout. Under Architecture II.2 (verb set + plural deliveries), it splits into a verb-set-defining crate + per-delivery adapter crates. |
| `zp-memory` | Memory-promotion abstractions | Implementations on top | **No** for now; small enough. |

### Service / domain crates (neither port nor adapter)

These do computation but don't fit the port/adapter taxonomy. They're domain libraries, engines, test scaffolding, or course content. The principle doesn't classify them; they exist for other reasons.

| Crate | Purpose |
|---|---|
| `execution-engine` | Generic execution engine for receipt-emitting workflows |
| `mle-star-engine` | MLE-Star ML reasoning engine |
| `monte-carlo-engine` | Monte Carlo simulation engine |
| `trust-triangle` | Trust-triangle modeling library |
| `zp-engine` | Shared engine: scan / configure / vault / provider logic used by both server and CLI |
| `zp-bench` | Benchmark binaries |
| `zp-hardening-tests` | Hardening / security test infrastructure |
| `course-examples` | Course content examples |
| `zp-learning` | Learning support |

These are the "compute" layer of ZP — they don't define contracts and they don't adapt to specific environments. They're invoked by ports and adapters but exist as domain libraries in their own right.

---

## Refactor candidates

The cases where the current layout doesn't match the principle's discipline cleanly enough:

### Highest priority — `zp-server` is overloaded

`zp-server` currently contains:
- HTTP-delivery handlers (adapter behavior)
- Dashboard hosting (will be retired under Architecture II.4)
- Audit/identity/stats endpoint handlers (will become verb-set adapters)
- Tool launcher (`tool_launch.rs` — port-bearing; defines `ToolSpec`)
- WebRTC signaling (when added — will be a delivery 4.2 adapter)
- Fleet auth handlers (uses Seam 3 port)

Under Architecture II.2 (verb set + plural deliveries), this crate's natural split is:

1. **`zp-verbs/`** — defines the verb-set port (the `proto/zp_v1.proto`-derived types, the verb dispatcher trait). Singular per the principle.
2. **`zp-tool-launch/`** — port. `ToolSpec` and friends migrate here from `zp-server::tool_launch`. Already port-shaped; just needs separation.
3. **`zp-delivery-http/`** — adapter. The HTTP/JSON delivery for the verb set (only what survives the 109-route retirement; probably the SSE event stream and a small set of REST endpoints that are explicitly allowlisted infrastructure resources).
4. **`zp-delivery-grpc/`** — adapter. The gRPC/tonic delivery (Architecture II.8).
5. **`zp-delivery-stream/`** — adapter. The WebRTC signaling + Selkies bridge (Architecture II.9).
6. **`zp-fleet/`** — service. Fleet-coordination logic that uses the Seam 3 port.

This is a substantial refactor and not for today. It belongs as part of the verb-set implementation arc (tasks 48, 49, and successors). Recording it here so the shape is in front of us when that work begins.

### Medium priority — `zp-mesh` will need splitting when libp2p lands

Currently `zp-mesh` holds the `Interface` port trait and three adapters (Reticulum, TCP, Loopback). When the libp2p adapter (task #49) lands, the crate will hold the port plus four adapters. That's the threshold where splitting starts paying off:

- **`zp-mesh-core/`** — port. `Interface` trait, `MeshEnvelope` schema, `SignedAnnounce`, the shared replay-check carrier.
- **`zp-mesh-reticulum/`** — adapter.
- **`zp-mesh-tcp/`** — adapter.
- **`zp-mesh-libp2p/`** — adapter (the new one from task #49).
- **`zp-mesh-loopback/`** — adapter (used for tests; could stay in `zp-mesh-core` as test-support).

Recommendation: do the split *as part of* task #49 rather than before. The libp2p adapter lands directly into its own crate; the existing adapters stay in `zp-mesh` until splitting is forced; eventually the rename happens. Less churn than splitting first then adding.

### Low priority — `zp-anchor` and `zp-llm` watch for adapter-count growth

Both currently hold a port + small number of adapters. Acceptable today. Set a soft threshold: when either has ≥5 adapters, split into port + per-adapter crates.

### No action — `zp-keys`, `zp-memory`, `zp-pipeline`, `zp-policy`, `zp-trust`, `zp-verify`

Each holds a port, sometimes with co-located adapters or default impls. Each is small enough that separation would cost more than it earns. Feature flags handle per-adapter compilation where needed (`zp-keys` is the canonical example).

---

## Naming conventions

The classification suggests naming conventions that, if adopted consistently, make port/adapter status visible at the crate level:

- **`zp-<noun>`** — port crate. Defines a contract. Singular per concern.
- **`zp-<noun>-<adjective>`** — adapter for a specific environment. E.g. `zp-mesh-libp2p`, `zp-mesh-reticulum`.
- **`zp-<external-name>`** — adapter for an external dependency. E.g. `zp-cloudflare`. Named after the external thing because that's what makes it an adapter.
- **`zp-delivery-<medium>`** — adapter for a specific operator-environment delivery. E.g. `zp-delivery-http`, `zp-delivery-grpc`, `zp-delivery-stream`.

Today's layout follows the first convention reasonably well; the second and third are inconsistent (some adapters are co-located with their ports — `zp-mesh` instead of `zp-mesh-reticulum`); the fourth is unused (everything is in `zp-server`). Future refactors should adopt all four consistently.

---

## What this document does NOT decide

- **Specific timing** for any of the proposed splits. Each refactor lands when the work that justifies it begins (e.g. `zp-server` split happens with the verb-set implementation arc; `zp-mesh` split happens with the libp2p adapter).
- **Naming of new crates exactly**. The conventions above are the shape; specific names are decided when each crate is created.
- **Whether service / domain crates need any further classification**. They're not port- or adapter-shaped; the principle doesn't require they be. Their organization can follow whatever local discipline serves them.

---

## Companion to the discipline pin

Task #53 (documented-adapters discipline pin) takes this classification into account. The pin's initial scope:

- Every adapter implementation in an `Both` or pure-adapter crate must carry a doc comment naming the port it adapts and the operator class / external dep / use case it serves.
- The pin scans the crates classified above as `Both` or `Adapter-bearing`.
- The pin does not scan `Port-bearing` crates (port traits don't need to document themselves as adapters; they're the contracts being adapted).
- The pin does not scan `Service / domain` crates (they don't fit the taxonomy).

This makes the classification machine-checkable: drift in any direction (a port crate growing adapter behavior; an adapter crate without per-instance documentation) is detected at build time.

---

*End of layout doc. Open for review.*
