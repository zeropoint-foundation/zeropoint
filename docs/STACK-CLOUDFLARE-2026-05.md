# ZeroPoint × Cloudflare — Reference Integration (May 2026)

Companion to `STRUCTURAL-AUDIT-2026-05.md` (the seam map),
`STRUCTURAL-HARDENING-LESSONS-2026-05.md` (lessons from the hardening
work), and `TEST-DISCIPLINE-2026-05.md` (the discipline framework).

**This document is the canonical reference implementation for ZeroPoint
on Cloudflare's platform.** It is not a possibility space. It defines
the ports (ZP-side traits and contracts), the adapters (Cloudflare-side
implementations), the wires between them (receipt-attested boundaries),
and the discipline pins that keep the separation honest.

ZP runs on Cloudflare today, and it is the deployment target the
foundation has chosen. But ZP itself never knows Cloudflare exists.
The crates in `crates/` reference no Cloudflare types. The integration
lives in a single adapter layer — `crates/zp-cloudflare/` (to be
authored as Phase 1.0) — that implements ZP-defined traits with
Cloudflare primitives. Swap the adapter, run on AWS or self-hosted;
the substrate above is unchanged.

## Thesis

ZeroPoint's runtime today is two boxes: a Hetzner-hosted `zp-server`
(audit chain, governance gates, mesh runtime) and a Cloudflare Workers
deployment of `zeropoint.global` (the public site) plus
`zeropointfoundation.org` (the foundation workspace). The two are
loosely coupled — the workspace calls the server's HTTP API for
attestation issuance and analytics; otherwise they don't share state.

Cloudflare's broader platform — Workers AI, Vectorize, Workflows,
Queues, Tunnels, Containers — is a substrate that overlaps significantly
with where ZeroPoint is heading. The opportunity is not "host more
things on Cloudflare." The opportunity is structural: every Cloudflare
primitive that lands inside the audit boundary becomes governable
*through a port ZP owns*. Inference, knowledge storage, message
routing, durable execution — these become receipt-emitting
capabilities rather than external black-box dependencies, AND they
become substitutable.

The discipline lens applies. Every external dependency that gets
pulled inside the boundary is one more carrier we can crystallize as
an invariant. Today: "we always use Workers AI for inference if it's
available" (convention). Tomorrow: a discipline pin that forbids raw
HTTP calls to LLM endpoints from anywhere except the adapter
(invariant). The adapter is the *only* place that knows about
`env.AI.run(...)`; everything upstream sees an `Inference` trait.

## The composite stack map

The single most important artifact of this integration is the picture
of what a governed agentic stack actually looks like — what each
layer needs to provide, who provides which layer, and where the
contracts cross.

This map answers the question this doc gets asked most: *"Why
ZeroPoint and not just Cloudflare?"* Cloudflare alone gives you
compute, storage, inference, durable execution, networking — a
serverless platform. It does not give you cryptographic identity,
capability grants, signed audit chains, governance gates, or trust
tiers. Those are layers Cloudflare has nothing in. **Cloudflare alone
is not a governed agentic stack. Cloudflare + ZeroPoint is.** The
map shows where each provides what, where the gaps are, and where
they compose.

```text
                    ─── GOVERNED AGENTIC STACK ───

  ┌──────────────────────────────────────────────────────────────┐
  │  L7  APPLICATIONS                                            │
  │      Foundation workspace, public site, agent operators,     │
  │      autonomous fleets, third-party integrations.            │
  │      (Application-specific. Composes everything below.)      │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  L6  GOVERNANCE                                              │
  │      ▓ Guard → Policy → Audit pipeline    (zp-policy)        │
  │      ▓ Capability grants + delegation     (zp-core)          │
  │      ▓ Receipts                           (zp-receipt)       │
  │      ▓ Signed audit chain                 (zp-audit)         │
  │      ▓ Reputation + Consensus             (zp-mesh)          │
  │      ─────────                                               │
  │      Entirely ZP. Cloudflare has nothing here. This is the   │
  │      "governed" in "governed agentic" — without it you have  │
  │      compute that cannot attest to itself.                   │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  L5  DURABLE EXECUTION                                       │
  │      ⬛ GovernedWorkflow trait             (zp-pipeline)     │
  │      ◯ Cloudflare Workflows               (CfWorkflowAdapter)│
  │      ─────────                                               │
  │      ZP defines the receipt-emitting wrapper; CF provides    │
  │      durable scheduling + checkpointing.                     │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  L4  COGNITIVE                                               │
  │      ⬛ Inference trait                    (zp-cognitive)    │
  │      ⬛ VectorIndex trait                  (zp-cognitive)    │
  │      ◯ Workers AI                         (WorkersAIInferenceAdapter)│
  │      ◯ Vectorize                          (VectorizeIndexAdapter)│
  │      ◯ AI Search                                              │
  │      ─────────                                               │
  │      ZP defines the receipt-emitting ports; CF provides the  │
  │      inference + vector storage substrate. The Layer-3       │
  │      cognitive accountability vision lives here.             │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  L3  COMMUNICATIONS                                          │
  │      ▓ Reticulum mesh + web discovery     (zp-mesh)          │
  │      ▓ SignedAnnounce envelopes           (zp-mesh)          │
  │        — replay-protected per-(peer, source)                 │
  │      ⬛ FleetBus trait                     (zp-mesh)          │
  │      ◯ Cloudflare Queues                  (CfQueueFleetBusAdapter)│
  │      ◯ Cloudflare Email                                       │
  │      ─────────                                               │
  │      ZP defines the wire formats and signing discipline; CF  │
  │      provides at-least-once delivery for fleet messages.     │
  │      Reticulum stays as the decentralized mesh option.       │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  L2  STORAGE                                                 │
  │      ⬛ AuditStore trait                   (zp-audit)         │
  │      ◯ Cloudflare D1                      (D1AuditStoreAdapter)│
  │      ◯ Cloudflare R2  (object storage)                        │
  │      ◯ Cloudflare KV  (transient kv)                          │
  │      ─────────                                               │
  │      ZP defines hash-chained signed-entry semantics + the    │
  │      append-only invariants; CF provides the durable store.  │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  L1  IDENTITY & SOVEREIGNTY                                  │
  │      ▓ Genesis → Operator → Agent hierarchy  (zp-keys)       │
  │      ▓ Sovereignty providers                 (zp-keys/sovereignty)│
  │        — Touch ID, YubiKey, Trezor, Ledger, Login Password   │
  │      ▓ Audit signer derivation               (zp-keys)       │
  │        — derive_audit_signer_seed via BLAKE3-keyed-hash      │
  │      ▓ Canonical verify primitive            (zp-receipt)    │
  │      ─────────                                               │
  │      Entirely ZP. Cloudflare has nothing here, and shouldn't.│
  │      Identity keys never leave the sovereignty boundary —    │
  │      not into D1, not into Secrets Store, not into KV. The   │
  │      sovereignty provider unlocks them in-memory at startup. │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  L0  INFRASTRUCTURE                                          │
  │      ◯ Cloudflare Workers   (edge compute)                   │
  │      ◯ Cloudflare Tunnel    (zero-trust ingress)             │
  │      ◯ Cloudflare Containers (edge runtime)                  │
  │      ◯ Cloudflare Secrets Store  (app secrets, NOT identity) │
  │      ─────────                                               │
  │      Entirely Cloudflare. ZP has nothing here — and          │
  │      shouldn't. The substrate question is "where does        │
  │      compute happen"; ZP answers "wherever, as long as the   │
  │      boundary above is honest."                              │
  └──────────────────────────────────────────────────────────────┘

  LEGEND
  ──────
   ▓  Pure ZP. No Cloudflare dependency.
   ⬛ ZP port / trait. Defines the contract; lives in crates/zp-*.
   ◯  Cloudflare adapter or primitive. Implements the contract;
      lives in crates/zp-cloudflare/ or in foundation Worker code.
```

**Reading the map:**

- **L0 and L1 are the mirror layers.** L0 is pure Cloudflare —
  compute, ingress, runtime. L1 is pure ZP — identity, sovereignty,
  the canonical verify primitive. Each owns its layer entirely; they
  do not overlap. This is the architectural reason ZP is portable:
  identity has nothing to do with where compute happens.

- **L6 is the governance layer.** It is also entirely ZP. This is
  what makes the stack *governed*. Compute alone — even fast,
  cheap, durable, well-distributed compute — does not give you
  capability grants, delegation chains, signed audit trails, or
  graduated policy decisions. Cloudflare is silent at L6. ZP is
  the answer to that silence.

- **L2 through L5 are composite.** ZP defines the contracts (the ⬛
  ports). Cloudflare provides the implementations (the ◯ adapters
  and primitives). The contracts are receipt-emitting, the wires
  are typed, the adapters are substitutable. This is where the
  reference-implementation discipline applies hardest: the boundary
  is mechanically enforced by `no_cloudflare_imports_in_zp_crates`,
  every transition emits a receipt, every adapter has a fallback
  documented.

- **L7 is the application layer.** Foundation workspace lives there.
  Public site lives there. Agent operators live there. The whole
  point of the stack is to make L7 trivially auditable — every
  application-layer action is governed by L6, persisted by L2,
  and signed by L1.

**The gaps ZP fills, made explicit:**

1. *Identity that survives runtime relocation.* Cloudflare can move
   your Worker between POPs at any moment; the audit chain doesn't
   care because identity is keyed, not hosted (L1).
2. *Capability grants the platform can't override.* Cloudflare gives
   you mTLS and IAM; it doesn't give you "agent X may call API Y at
   most 100 times per hour with cost ceiling $0.50, expiring in 24h"
   (L6).
3. *Audit chains that survive the platform.* If Cloudflare lost your
   D1 database tomorrow, the audit chain — exported, hash-chained,
   signed — would still verify under the operator's Genesis key (L2,
   L6, L1).
4. *Governance pipelines composable across vendors.* The Guard →
   Policy → Audit pipeline at L6 is platform-agnostic. Move the
   audit store from D1 to Postgres; the pipeline doesn't change.
   The discipline pins enforce that this stays true.
5. *Trust tiers that mean something.* Cloudflare can authorize a
   Worker to call an API; it cannot reason about whether the *agent
   running inside the Worker* should be trusted to call that API.
   Trust tiers + reputation + delegation chains do (L6, L3).

These are the gaps. Anywhere you see a ▓ on the map, that's a gap
Cloudflare has and ZP fills.

## Surface mapping

Each Cloudflare primitive named against the ZeroPoint layer it
extends and the seam it touches.

| Cloudflare primitive | ZP layer | Seam(s) | Status |
|---|---|---|---|
| **D1** (SQLite) | Storage | — | In use (foundation workspace `zpmail` DB) |
| **R2** (object storage) | Storage | — | In use (`zp-storage` bucket) |
| **Workflows** (durable execution) | Governance / pipelines | Receipt emission | In use (foundation `src/workflows/*.js`) |
| **Email** (routing + handler) | Comms | — | In use (foundation email worker) |
| **Workers AI** (LLM inference) | Cognitive | Future Layer 3 (cognitive accountability) | Not yet wired |
| **Vectorize** (vector DB) | Cognitive / knowledge | Future Layer 3, LARQL integration | Not yet wired |
| **Queues** (at-least-once message bus) | Comms / fleet | Seam 3 (fleet auth), Seam 8 (announce) | Not yet wired |
| **Tunnel** (zero-trust ingress) | Infra | — | Not yet wired (zp-playground exposed via public IP today) |
| **Containers** (edge runtime) | Infra | All seams (would relocate zp-server itself) | Not yet wired |
| **AI Search** (RAG) | Cognitive / docs | — | Not yet wired |
| **Secrets Store** | Infra / sovereignty | Seam 7 (atomic secret writes — local equivalent), Seam 11 (keychain namespace — local equivalent) | Not yet wired |
| **Pipelines** (data) | Storage / observability | — | Open beta, not yet evaluated |
| **Hyperdrive** (Postgres pool) | Storage | — | Not applicable (ZP is SQLite-first) |
| **VPC**, **mTLS certs** | Networking | — | Out of scope short-term |
| **Dispatch namespaces** | Multi-tenancy | — | Future (when foundation hosts third-party agents) |

## Boundaries: ports, adapters, wires

The integration is a hexagonal architecture. Three layers, with
explicit contracts between them.

```text
┌──────────────────────────────────────────────────────────┐
│  PORTS (ZP-side)                                         │
│  ─────────────────                                       │
│  Pure ZP. Lives in crates/. Knows nothing about          │
│  Cloudflare. Defines traits + receipt-emitting types.    │
│                                                          │
│  zp_audit::AuditStore        (storage port)              │
│  zp_cognitive::Inference     (inference port — new)      │
│  zp_cognitive::VectorIndex   (knowledge port — new)      │
│  zp_pipeline::Workflow       (durable-exec port — new)   │
│  zp_mesh::FleetBus           (broadcast port — new)      │
└──────────────────────────────────────────────────────────┘
                            │
                            │ ZP types in, ZP types out.
                            │ Receipts cross the boundary.
                            ▼
┌──────────────────────────────────────────────────────────┐
│  ADAPTERS (the bridge)                                   │
│  ──────────────────────                                  │
│  Lives in crates/zp-cloudflare/ (or compiled into        │
│  Workers code in foundation/). Implements ZP ports       │
│  using Cloudflare primitives. Translates types,          │
│  emits adapter-side receipts, surfaces failures as       │
│  ZP error types.                                         │
│                                                          │
│  D1AuditStoreAdapter        impl AuditStore              │
│  WorkersAIInferenceAdapter  impl Inference               │
│  VectorizeIndexAdapter      impl VectorIndex             │
│  CfWorkflowAdapter          impl Workflow                │
│  CfQueueFleetBusAdapter     impl FleetBus                │
└──────────────────────────────────────────────────────────┘
                            │
                            │ Cloudflare bindings: env.AI,
                            │ env.DB, env.STORAGE, env.AI_INDEX,
                            │ env.QUEUE, etc.
                            ▼
┌──────────────────────────────────────────────────────────┐
│  CLOUDFLARE PRIMITIVES                                   │
│  ─────────────────────                                   │
│  Workers, D1, R2, Workers AI, Vectorize, Queues,         │
│  Workflows, Tunnels, Containers, Email.                  │
│                                                          │
│  Configured in wrangler.toml. Accessed only through      │
│  the adapter layer.                                      │
└──────────────────────────────────────────────────────────┘
```

**Three rules govern the boundary:**

1. **No Cloudflare types upstream of the adapter.** The `zp-*` crates
   in `crates/` must not import anything Cloudflare-specific.
   `wrangler::*`, `worker::*`, `cloudflare_*` types stop at the
   adapter layer. A discipline pin enforces this:
   `no_cloudflare_imports_in_zp_crates` (Phase 1.0).

2. **All ZP↔CF transitions emit receipts.** The adapter is a
   trust-boundary crossing. Each adapter method emits a receipt
   describing the call: which port, which adapter, which Cloudflare
   primitive, the canonical hash of the request and response. This
   is the same convention as every other ZP boundary — receipts as
   the wire.

3. **Adapters are substitutable.** Every Cloudflare adapter has at
   least one fallback implementation documented (self-hosted or
   another vendor). The fallback need not be production-ready
   today, but the *port* must be defined such that a fallback
   adapter is a finite engineering project, not a rewrite.

**Wire contracts — what crosses the boundary:**

| Port | Wire (request) | Wire (response) | Receipt action |
|---|---|---|---|
| `AuditStore` | `UnsealedEntry` | `AuditEntry` (sealed) | already exists in zp-audit |
| `Inference` | `InferenceRequest { model, prompt, params }` | `InferenceResponse { text, tokens, model_id }` | `Action::InferenceCall { provider, model, prompt_hash, response_hash }` |
| `VectorIndex` | `IndexQuery { embedding, top_k, filter }` or `IndexUpsert { id, embedding, metadata }` | `IndexResult { matches: Vec<Match> }` or `()` | `Action::VectorIndex { op, index_id, vector_hash }` |
| `Workflow` | `WorkflowStart { kind, input }` | `WorkflowHandle` | `Action::WorkflowStart { kind, input_hash }`; per-step receipts emitted by the adapter at every transition |
| `FleetBus` | `SignedMessage<T: Signable>` | `()` (producer); `Vec<SignedMessage<T>>` (consumer) | `Action::FleetBroadcast { topic, message_hash }` and `Action::FleetReceive { topic, message_hash }` |

These wire types live in `crates/zp-cloudflare/src/wire/` (one
module per port). They are pure Rust — the adapter is what binds
them to Cloudflare bindings via `worker-rs` or by compiling adapter
code directly into the Worker bundle.

**Where adapter code physically lives:**

- **`crates/zp-cloudflare/`** — the canonical adapter crate. Compiles
  to a library that workers can depend on. This is where the
  port-implementing types live.
- **`zeropointfoundation.org/src/`** — Worker entry points that wire
  bindings (`env.AI`, `env.DB`, …) into adapter constructors. Thin.
- **Future: `crates/zp-cloudflare-mock/`** — in-memory adapter
  implementations for unit testing port-using code without an actual
  Cloudflare runtime.

## Why this shape

Three primitives stand out as substrate-shifting for the architectural
trajectory ZP has already committed to:

- **Workers AI** — inference inside the audit boundary. Today receipts
  attest to "the agent invoked an LLM"; tomorrow they can attest to
  "the agent invoked LLM `model_id` running on Cloudflare AI" with a
  cryptographically anchored execution context.

- **Vectorize** — managed vector storage for knowledge graphs. The
  cognitive-accountability layer described in
  `docs/future-work/cognitive-accountability.md` and the LARQL
  integration in `docs/design/larql-integration.md` both need this
  substrate. Without Vectorize (or equivalent), Layer 3 of the
  three-layer accountability stack stays theoretical.

- **Workflows** — durable execution with built-in checkpoint state.
  The Governed Agent Runtime concept in
  `docs/design/governed-agent-runtime.md` is essentially a workflow
  engine that emits receipts at every transition. Cloudflare
  Workflows is closer to this than anything we'd build from scratch.

The rest are useful but not architecture-changing.

## Phase 1 — Days (immediate possibilities)

Smallest pieces that ship visible value and exercise the integration
patterns we'll use later.

### 1.0 Scaffold the `zp-cloudflare` adapter crate

Prerequisite for every later phase. Without the adapter crate, every
Cloudflare integration grows organically inside Worker source files
and the boundary blurs.

**Work:** create `crates/zp-cloudflare/` with the standard layout —
`src/lib.rs` re-exporting the modules, `src/wire/` for wire types
(empty until ports start landing), `src/adapter/` for adapter impls
(empty until ports start landing), `Cargo.toml` with `zp-core`,
`zp-receipt`, `zp-audit` deps. No logic yet; structure only.

**Port:** none — this is the home for ports' adapter implementations.
**Wire:** none.
**Receipts emit:** none.

**Discipline pin (Phase 1.0 — landed simultaneously):**
`no_cloudflare_imports_in_zp_crates`. Forbids `worker::*`,
`wrangler::*`, `cloudflare_*`, and `cf_*` imports in `crates/zp-*`
EXCEPT `crates/zp-cloudflare/`. The pin makes the boundary
mechanically enforced from day one — before any adapter code lands,
the framework already refuses to let it leak upstream.

### 1.1 Cloudflare Tunnel for `zp-playground`

The remote `zp-playground` (per `CLAUDE.md`) currently serves the
playground demo via public IP. A Cloudflare Tunnel replaces the
public ingress with a zero-trust connector that the playground host
opens outbound to Cloudflare's edge. No open ports, DDoS protection
included, and Cloudflare Access can sit in front for authenticated
demos.

**Work:** install `cloudflared` on the playground host, register
the tunnel via `wrangler tunnel`, point `playground.zeropoint.global`
DNS at the tunnel.

**Port:** none — this is pure infra; no ZP code touches it.
**Adapter:** none.
**Wire:** none.
**Receipts emit:** none. Pure infra.

**Discipline pin candidate:** `no_public_ip_in_playground_config` —
forbids hardcoded public IPs in playground deployment configs.

### 1.2 Workers AI for one foundation workflow

Pick the smallest foundation workflow that calls an LLM (probably
the email triage workflow at `src/workflows/inquiry.js`) and route
its inference through `wrangler ai` instead of an external endpoint.
This proves the pattern end-to-end: audit-chain receipts now attest
to inference that ran on infrastructure we control.

**Work:** add `[ai]` binding to `zeropointfoundation.org/wrangler.toml`,
swap the external LLM client for `env.AI.run(model, input)` *via the
adapter*, emit a receipt with the model ID and Cloudflare AI's
response metadata.

**Port:** new — `zp_cognitive::Inference` trait (in a new
`crates/zp-cognitive/` crate or initially in `crates/zp-receipt/` if
we want to defer the new-crate decision).
```rust
pub trait Inference {
    async fn run(&self, req: InferenceRequest) -> Result<InferenceResponse, InferenceError>;
}
pub struct InferenceRequest { pub model: String, pub prompt: String, pub params: InferenceParams }
pub struct InferenceResponse { pub text: String, pub tokens_in: u32, pub tokens_out: u32, pub model_id: String }
```
**Adapter:** `zp_cloudflare::adapter::WorkersAIInferenceAdapter`.
Wraps a Workers `env.AI` binding; translates `InferenceRequest` →
`env.AI.run(...)` call → `InferenceResponse`. Emits the receipt at
the boundary crossing.
**Wire:** `InferenceRequest` / `InferenceResponse` / `InferenceError`.
Pure ZP types. Define them in `crates/zp-cognitive/src/wire.rs`.

**Receipts emit:** every inference call. New `Action` variant in
`zp-receipt`: `Action::InferenceCall { provider: "cloudflare-ai",
model: String, prompt_hash: String, response_hash: String }`.
The adapter is what emits the receipt; upstream callers receive a
plain `InferenceResponse` and don't know about it.

**Discipline pin candidate:** `no_external_llm_fetch_in_foundation` —
forbids raw `fetch` to `api.openai.com`, `api.anthropic.com`, etc.,
in `zeropointfoundation.org/src/` and any `crates/zp-*` outside the
adapter. Once Workers AI is wired, all inference flows through the
`Inference` trait, which flows through the adapter, which is the
only place that knows about `env.AI`.

**Fallback adapter (documented, not implemented):**
`OpenAiInferenceAdapter` against `api.openai.com`. The trait shape
is identical; the adapter constructor takes an API key instead of a
binding. Demonstrates substitutability.

### 1.3 Wrangler Secrets Store migration

The foundation workspace today uses `wrangler secret put` for things
like `RESEND_API_KEY` and `DKIM_PRIVATE_KEY`. Cloudflare's newer
Secrets Store provides centralized secret management with rotation,
audit logs, and cross-worker sharing.

**Work:** create a Secrets Store namespace, migrate the four secrets
named in `zeropointfoundation.org/wrangler.toml`, remove the
deprecated per-worker secrets.

**Port:** none — secret resolution happens in the Worker startup
path before any ZP-side code runs. The boundary is the
`wrangler.toml` config schema.
**Adapter:** none (configuration only).
**Wire:** none.
**Receipts emit:** none directly. Secret rotation events become
auditable in the Cloudflare Secrets Store audit log; if we want
those rotations in the ZP audit chain, a future webhook adapter
can convert Secrets Store events into `Action::SecretRotated`
audit entries.

**Discipline pin candidate:** `no_wrangler_secret_in_foundation` —
forbids `wrangler secret put` patterns and direct `env.SECRET_NAME`
references in foundation Worker code; force Secrets Store usage
through a small `secrets::get(name)` helper.

## Phase 2 — Weeks (near-term)

Pieces that take more design but unlock real architectural moves.

### 2.1 Vectorize index for receipt similarity

A Vectorize index over receipt content hashes plus a small embedding
of the action description. Use case: "find receipts similar to this
one" for audit-chain investigations and policy-tuning workflows.

This is also the storage layer for the LARQL/MEDS work in
`docs/design/larql-integration.md`. Building the index now puts the
substrate in place for the cognitive-accountability layer later.

**Work:** schema design (vector dim, metadata fields), embedding
pipeline (Workers AI for embeddings → Vectorize for storage), HTTP
API on `zp-server` exposing nearest-neighbor queries.

**Port:** new — `zp_cognitive::VectorIndex` trait.
```rust
pub trait VectorIndex {
    async fn upsert(&self, item: IndexUpsert) -> Result<(), IndexError>;
    async fn query(&self, q: IndexQuery) -> Result<IndexResult, IndexError>;
}
```
**Adapter:** `zp_cloudflare::adapter::VectorizeIndexAdapter`.
Wraps a Workers `env.AI_INDEX` binding (or whatever name we choose
for the Vectorize binding).
**Wire:** `IndexUpsert`, `IndexQuery`, `IndexResult`, `IndexError`
in `crates/zp-cognitive/src/wire.rs`. Embedding generation is a
*separate* `Inference` call (chained at the application layer, not
inside the VectorIndex adapter — keeps the boundaries clean).

**Receipts emit:** indexing events (every embedded receipt) and
query events. New `Action` variant: `Action::VectorIndex { op,
index_id, vector_hash }`.

**Discipline pin candidate:** `vectorize_index_writes_must_emit_receipt`
— no `VectorIndex::upsert` calls outside the receipt-emitting helper
in `crates/zp-cognitive/`.

**Fallback adapter (documented):** `QdrantVectorAdapter` against a
self-hosted Qdrant instance. Same trait, different binding.

### 2.2 Queues for federated fleet coordination

For ZP deployments that don't need Reticulum-grade decentralization,
Cloudflare Queues provides an at-least-once message bus with dead-
letter handling. Use case: fleet-wide announcements that need
delivery guarantees the mesh layer doesn't provide (e.g., "Genesis
key has been rotated; all delegates re-attest now").

This is complementary to the Presence Plane, not a replacement. The
mesh handles peer discovery; Queues handle reliable broadcast within
a known fleet.

**Work:** design the message schema (signed envelopes, like
`SignedAnnounce` but for fleet messages), queue producers in
`zp-server`, queue consumers in delegate workers.

**Port:** new — `zp_mesh::FleetBus` trait.
```rust
pub trait FleetBus {
    async fn publish<T: Signable + Serialize>(&self, topic: &str, msg: &SignedMessage<T>) -> Result<(), BusError>;
    async fn consume<T: Signable + DeserializeOwned>(&self, topic: &str) -> Result<Vec<SignedMessage<T>>, BusError>;
}
```
**Adapter:** `zp_cloudflare::adapter::CfQueueFleetBusAdapter` over
Workers Queues binding.
**Wire:** `SignedMessage<T>` in `crates/zp-mesh/src/fleet_bus.rs`.
Reuses the `Signable` trait (Seam 20). Same envelope discipline as
`SignedAnnounce`: the canonical preimage is what's signed.

**Receipts emit:** producer-side (`Action::FleetBroadcast`) and
consumer-side (`Action::FleetReceive`) receipts. The audit chain
spans the queue boundary — every fleet message has a producer
receipt linked to its consumer receipt(s) by `message_hash`.

**Discipline pin candidate:** `queue_message_envelopes_must_be_signable`
— all `T` parameters to `FleetBus::publish` / `consume` must
`impl Signable`. Enforced at the trait bound in code; the discipline
pin is a belt-and-suspenders sweep over fleet-bus call sites for
plain `serde_json::to_vec` patterns that bypass the canonical
preimage.

**Fallback adapter (documented):** `NatsFleetBusAdapter` against a
self-hosted NATS broker.

### 2.3 Workflows expansion: governed pipelines as canonical receipt sources

Foundation already has six Workflow files. The next step is naming
them as "governed pipelines" — every workflow step emits a receipt,
every state transition is auditable. This formalizes the GAR
(Governed Agent Runtime) concept on Cloudflare's substrate.

**Work:** define the `GovernedWorkflow` wrapper that auto-emits
receipts at workflow start, each step entry/exit, terminal state.
Refactor existing workflows to use the wrapper.

**Port:** new — `zp_pipeline::GovernedWorkflow` trait (in
`crates/zp-pipeline/`, which already exists for receipt pipelines —
extend its remit).
```rust
pub trait GovernedWorkflow {
    type Input: Signable + DeserializeOwned;
    type Output: Serialize;
    async fn run(&self, input: Self::Input, ctx: &mut WorkflowCtx) -> Result<Self::Output, WorkflowError>;
}
pub struct WorkflowCtx { /* receipt emitter, current step ID, parent receipt linkage */ }
```
**Adapter:** `zp_cloudflare::adapter::CfWorkflowAdapter`. Wraps
Cloudflare Workflows' native `WorkflowEntrypoint`; provides the
`WorkflowCtx` to the user's `run` impl, intercepts the user's
`step()` calls to wrap them in receipt-emitting decorators.
**Wire:** `WorkflowStart`, `WorkflowHandle`, `WorkflowError` in
`crates/zp-pipeline/src/workflow.rs`. The user's `Input` and
`Output` types are application-defined but constrained by the
`Signable` bound on input.

**Receipts emit:** workflow start (`Action::WorkflowStart`), every
step (`Action::WorkflowStep`), terminal (`Action::WorkflowComplete`
or `Action::WorkflowFailed`). The chain forms a tree: workflow
start receipt is the parent; step receipts link via `parent` to it;
terminal receipt links to the last step.

**Discipline pin candidate:** `workflow_must_use_governed_wrapper`
— in `zeropointfoundation.org/src/workflows/`, every workflow
class/struct must extend `GovernedWorkflow`. Bare Cloudflare
`WorkflowEntrypoint` extension is forbidden (the adapter is the
only thing allowed to do that).

**Fallback adapter (documented):** `LocalWorkflowAdapter` —
Tokio-based in-process workflow runner for local testing without
the Cloudflare runtime. Same trait shape; lighter checkpoint
guarantees.

## Phase 3 — Months (future)

Architectural shifts that take real planning.

### 3.1 Containers: zp-server at the edge

Today `zp-server` runs on one Hetzner box. With Cloudflare Containers
(currently rolling out), it could run at every Cloudflare edge POP,
sharing audit-chain state via R2-backed SQLite or via D1.

The architectural question is *which* parts of zp-server should run
at the edge. The audit chain wants strong consistency; mesh routing
wants edge-locality; the governance gate is somewhere in between.
This is a design exercise, not just a deployment change.

**Work:** scope study, then phased migration. Start with the parts
that are read-mostly (audit chain inspection, public attestation
verification) and move to the edge first.

**Receipts emit:** N/A — this is a relocation, not a new capability.

### 3.2 AI Search over the docs tree

Cloudflare's AI Search gives you RAG over a content corpus. Pointing
it at `docs/` would let students and operators ask questions
("how does verify_signature work?", "what's the signed audit chain
format?") and get answers grounded in canonical documentation.

**Work:** corpus pipeline (docs → embeddings → AI Search index),
chat endpoint on `zeropoint.global`, optional surface in the course
player.

**Receipts emit:** none directly. Could optionally attest to
"answer was generated from canonical docs version X."

### 3.3 Multi-region D1 for the audit chain

D1 is moving toward read replicas in multiple regions. For the
audit chain, this would mean local-region reads for verification and
inspection, while writes still funnel through one region. Lower
read latency, no consistency loss because the chain is hash-linked
end-to-end.

**Work:** wait for the feature to mature past beta; design the
write-region selection and replica topology.

## Pins to add

A consolidated list of discipline pins that follow from the phase
plan above. Each pin closes a class of drift the Cloudflare
integration could otherwise introduce.

| Pin name | Phase | Crystallizes |
|---|---|---|
| `no_cloudflare_imports_in_zp_crates` | 1.0 | Hard ZP↔CF boundary; Cloudflare types stop at the adapter crate |
| `no_public_ip_in_playground_config` | 1.1 | Tunnel-first ingress |
| `no_external_llm_fetch_in_foundation` | 1.2 | Inference port routes through `Inference` trait + adapter |
| `no_wrangler_secret_in_foundation` | 1.3 | Secrets Store as the secret carrier |
| `vectorize_index_writes_must_emit_receipt` | 2.1 | Receipt-attested index updates through `VectorIndex` port |
| `queue_message_envelopes_must_be_signable` | 2.2 | `FleetBus` payloads route through `Signable` trait |
| `workflow_must_use_governed_wrapper` | 2.3 | All foundation workflows extend `GovernedWorkflow` |

These join the existing six pins (`no_serde_preserve_order`,
`no_raw_keychain_service_strings`, `no_std_fs_write_in_keyring`,
`no_non_strict_ed25519_verify`, `no_direct_verify_strict_outside_helper`,
`no_raw_home_lookup`) to bring the discipline framework's pin count
toward double digits.

## The arc: invariantization roadmap

The convention-vs-invariant thesis says every convention should
become an invariant where structurally possible. The May 2026
hardening work converted six conventions; this doc names six more
that the Cloudflare integration unlocks.

Looking further:

- **Seam 3** (fleet auth) — currently convention. The Queues +
  Vectorize work would give us the substrate to convert it.
- **Seam 8** (announce replay) — converted by the work in
  `8aa6712`. Pin pending follow-up.
- **Cognitive accountability layer (Layer 3)** — entirely future
  work. The Workers AI + Vectorize substrate makes it tractable.
- **Trust-tier transitions** — currently policy-driven, not
  cryptographically attested. A future seam.

Each conversion follows the same shape: name the convention, find
the carrier, sweep callers, pin the rule. The framework is now
mature enough that the rate-limiting factor is design clarity, not
mechanism.

## How this doc gets used

Read this doc when:
- Planning a new Cloudflare integration (does it fit the phase plan?)
- Adding a new external dependency (could it be a Cloudflare
  primitive instead?)
- Authoring a new discipline pin (does it relate to one named here?)
- Onboarding to the foundation workspace (this is the architectural
  context for what's deployed where)

Update this doc when:
- A phase ships (move from "Not yet wired" to "In use" in the
  surface mapping table)
- A new pin lands (move from "candidate" to enforced; cross-link
  the test file)
- The Cloudflare surface meaningfully changes (new primitives, new
  ZP-relevant features)

This is a living document. The May 2026 dating is the snapshot, not
the lifetime.

## What this doc does not commit

- A timeline. Phase 1 / 2 / 3 are difficulty-and-impact ordered, not
  calendar-ordered. We do them when they make sense.
- Vendor lock-in. Every Cloudflare primitive named here has a
  fallback path documented in the relevant phase section: Workers AI
  ↔ external LLM, Vectorize ↔ self-hosted vector DB, Queues ↔ NATS
  or self-hosted message broker. The discipline pins are about
  *consistency* (use the carrier we picked), not about Cloudflare
  being the only allowed carrier forever.
- Replacement of zp-server. The Hetzner box stays. Phase 3.1
  explores edge distribution, but the canonical audit chain stays
  one place until consistency models for D1 read-replicas mature.
