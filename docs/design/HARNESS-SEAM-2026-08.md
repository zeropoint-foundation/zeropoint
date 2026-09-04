# HARNESS-SEAM-2026-08 — Inner/Outer Declaration

**Status:** RATIFIED by the operator, 2026-08-09
**Date:** 2026-08-09
**Rulings:** §2.3 Regent — inner mechanism, outer content.
§3-C1 — `zp-config` is the sole model-election authority; `officer-inference.toml`
survives as operating parameters only. §4 — sensors are build-failing in CI and
boot-failing in production, with no warn-only tier.
**Occasion:** the coherence audit of 2026-08-09, in which five independent
declarations of "which local model runs" were found, `zp config set` was
observed reporting success while changing nothing, and the provider pool was
found to have never been populated in the entire history of the substrate.

---

## 0. Why this document exists

Harness engineering splits an agent system into an **inner harness** (shipped
by a vendor) and an **outer harness** (assembled by an operator). The split is
defined by *who built it*, which makes it observer-relative. ZeroPoint has
never declared its position on that line, because from where the Foundation
stands ZeroPoint is outer harness — assembled around rented models — while from
where an adopter stands it is inner harness, the thing they build upon.

Both readings are true. That ambiguity is not a labelling inconvenience. Every
incoherence found in the 2026-08-09 audit sits precisely on the undeclared
seam:

| Defect | Seam failure |
|---|---|
| Five declarations of the local model | Inner and outer both claimed model choice |
| `zp config set` silently shadowed | Layer precedence between inner and outer never declared |
| Regent's direct `inference_endpoint` | Outer component reaching around the inner boundary |
| `init_providers` failing non-fatally | Inner degrading without telling outer |
| Empty pool since inception | No assertion that the crossing was ever made |

Undeclared boundaries are where duplicates and orphans breed, because each side
assumes the other owns the ground. This document declares the ground.

---

## 1. The rule

> **Inner ships the mechanism. Outer supplies the content.
> Every config file is a boundary crossing.**

`zp-skills` is an inner registry holding outer skills. `zp-llm` is an inner
pool holding outer-configured providers. `zp-policy` is an inner gate enforcing
outer policies. The pattern is consistent once named: registry vs entries, pool
vs providers, gate vs rules, engine vs corpus.

Three corollaries follow, and they are the whole of the discipline:

1. **A mechanism must never carry a default that competes with its content.**
   A compiled-in model name inside an inner crate is an inner component
   pretending to be outer. It is the single most common source of duplication
   in this codebase.
2. **A crossing must be observable.** If content enters and nothing records
   that it entered — or that it failed to — the substrate cannot tell a
   configured system from an unconfigured one. This is what allowed an empty
   provider pool to survive undetected.
3. **Outer must not bypass inner.** An outer component that reaches the backend
   directly has left the harness. The receipts it should have generated do not
   exist, and no later audit can reconstruct them.

---

## 2. Crate assignment

### 2.1 INNER — mechanism the substrate ships

Adopters receive these and do not author them. They must be free of
domain content, free of competing defaults, and must emit receipts across
every boundary they mediate.

| Crate | Mechanism it provides |
|---|---|
| `zp-core` | Shared types, traits, error definitions |
| `zp-keys` | Genesis → operator → agent key derivation and signing |
| `zp-receipt` | Portable verifiable proof of execution |
| `zp-audit` | Hash-chained always-on audit trail |
| `zp-verify` | Receipt and chain verification |
| `zp-anchor` | Pluggable DLT abstraction for external chain verification |
| `zp-trust` | Trust infrastructure primitives |
| `zp-gate-envelope` | Per-request Genesis-signed request envelopes (ZP-Sig) |
| `zp-host` | The typed contract all privileged side effects pass through |
| `zp-policy` | Rule engine + WASM policy runtime (**engine only**) |
| `zp-llm` | Provider pool and routing (**pool only**) |
| `zp-pipeline` | Request orchestration loop |
| `zp-server` | HTTP surface, proxy, gateway |
| `zp-cli` | Terminal interface |
| `zp-config` | Configuration resolution with provenance |
| `zp-content` | Content-addressed storage |
| `zp-artifacts` | Signed, lifecycle-managed renderings |
| `zp-mesh` | Sovereign agent transport |
| `zp-net` | Loopback networking primitives |
| `zp-introduction` | Governed cross-node trust establishment |
| `zp-verbs` | Generated protobuf verb types |
| `zp-memory-index` | Vector index wrapper |
| `zp-engine` | Shared scan/configure/vault/provider logic |
| `zp-configure` | Semantic-Sed tool configuration library |
| `execution-engine` | Sandboxed polyglot execution |

### 2.2 OUTER — content the operator assembles

These are the operator's asset. They encode domain judgement and are expected
to diverge between deployments. They may be shipped as *examples*, never as
silent defaults.

| Component | Content it supplies |
|---|---|
| `policies/` | The rules `zp-policy` enforces |
| Skill definitions | The entries `zp-skills` registers |
| `officer-inference.toml` | Model election per officer task |
| `~/ZeroPoint/config/routing.toml` | Tier → provider/model routes |
| `~/ZeroPoint/config.toml` | Operator configuration |
| `./zeropoint.toml` | Project configuration |
| `.zp-configure.toml` | Tool configuration corpus (19 read sites) |
| `providers.toml`, `watchers.toml`, `lease.toml` | Operator-declared inventories |
| `model_dossier.toml` | Model characterisation |
| `CLAUDE.md`, discipline pins | Operator conventions |

### 2.3 STRADDLING — must be resolved, not left ambiguous

These are the ones that produced today's defects. Each needs an explicit
ruling; a proposed one is given.

| Component | Ambiguity | Proposed ruling |
|---|---|---|
| `zp-regent` | Shipped inside the repo, configured like an outer component. Reads `inference_endpoint` and calls Ollama directly, bypassing the proxy. | **RULED: inner mechanism, outer content.** The Regent loop, gossip and emission-coherence heuristics are substrate. Model election is outer content read from `zp-config`, and the Regent routes through the proxy like every other consumer. The direct `inference_endpoint` is deleted, not deprecated — the receipts it should have emitted do not exist and cannot be reconstructed. S6 applies to it with no exemption. |
| `zp-officers` | Described as "dormant monitors" — mechanism — but each officer encodes domain judgement. | **Inner cadre, outer charters.** The scheduler and lifecycle are inner; what each officer looks for is outer content. |
| `zp-skills` | Registry vs skills. | Registry inner, skills outer. Already correct; state it. |
| `zp-observation`, `zp-inference-observer`, `zp-sensors` | Sensors by function (outer per the taxonomy), shipped by the substrate (inner). | **Inner sensor mechanism, outer thresholds.** The substrate ships the ability to observe; the operator declares what constitutes a signal. |
| `zp-memory`, `zp-ontology`, `zp-learning` | Cognition plane — derive content from the chain. | Inner. They read the chain, they do not accept outer content. |
| `zp-emission-coherence`, `zp-gossip` | Regent-specific heuristics. | Inner, following the Regent ruling. |
| `zp-discipline`, `zp-hardening-tests`, `zp-bench`, `zp-preflight` | Test and diagnostic harness. | **Inner meta-harness.** They assert on the substrate itself; see §4. |
| `trust-triangle`, `course-examples`, `mle-star-engine`, `monte-carlo-engine`, `zp-cloudflare` | Reference implementations and adapters. | Outer exemplars shipped in-tree. Must never be depended upon by inner crates. |

---

## 3. Declared crossings

A crossing is any point where outer content enters inner mechanism. Each one
gets a name, a single authority, and an assertion.

| # | Crossing | Authority | Currently |
|---|---|---|---|
| C1 | Model election | `zp-config` `llm.*` | **VIOLATED** — 5 declarants |
| C2 | Provider registry | `zp-server::proxy::provider_base_url` | OK — fixed allowlist |
| C3 | Policy rules | `policies/` → `zp-policy` | OK |
| C4 | Skills | skill files → `zp-skills` | OK |
| C5 | Officer charters | `officer-inference.toml` → `zp-officers` | Partial — file is also read by the bench |
| C6 | Tool configuration | `.zp-configure.toml` → `zp-configure` | OK |
| C7 | Config layering | defaults → `~/ZeroPoint/config.toml` → `./zeropoint.toml` → env → flags | **VIOLATED** — `set` writes to a layer that may be shadowed |
| C8 | Identity | `genesis.json` → `zp-keys` | OK — 50 read sites, single authority |

### C1 resolution — model election

`zp-config` `llm.provider` / `llm.model` / `llm.escalation_model` is the single
authority. Consequently:

- `get_routing_config()`'s compiled `local` tier (`ollama`/`mistral`) is
  **deleted**. It is an inner mechanism carrying competing outer content, and
  it points at a model that is not installed — a dead route.
- `routing.toml` remains authoritative for *cloud tier* routing only, and must
  not declare a local model.
- `officer-inference.toml` becomes a **consumer** — officers read model
  election from `zp-config`, and the file retains only per-task operating
  parameters (format/think/timeout), which are genuinely officer content.
- `[regent] reasoning_model` / `routing_model` are removed. The Regent elects
  through `zp-config` like every other consumer.

---

## 4. Boundary sensors

The audit produced a task list. A task list rots. These are the same findings
expressed as standing assertions — computational sensors, per the harness
discipline, run at boot and in CI. `zp-discipline` is the natural home: it
already enforces structural conventions as build-failing tests.

| Sensor | Asserts | Catches |
|---|---|---|
| **S1 · provider resolves** | Every configured `llm.provider` is a key in the proxy registry | Silent 400 at first request |
| **S2 · model installed** | Every configured model appears in the backend's model list | Today's `mistral` dead route |
| **S3 · pool non-empty** | `llm.enabled` ⇒ `pool.len() > 0` after init | The empty pool that survived since inception |
| **S4 · single declarant** | Exactly one authority declares each crossing in §3 | The five-way model split |
| **S5 · no shadowed writes** | `config set` refuses, or warns, when a higher layer overrides the value written | Today's silent no-op |
| **S6 · no bypass** | No crate outside `zp-server::proxy` holds a backend inference endpoint | Regent's direct path |

S3 and S6 are the two that would have caught the most damage, and neither
requires new infrastructure — only the decision to assert.

### Failure discipline

A boundary sensor that fails must **fail loudly**. The `init_providers` error
path added on 2026-08-09 logged and continued, allowing the server to report
healthy while holding an empty pool — the exact half-state this document
forbids. Corrected: pool state is reported on the health surface, and a failed
crossing at boot is a boot failure.

#### The invariant

> **No verb silently degrades.** A crossing that failed must produce the same
> diagnostic wherever it is first depended upon.

Note what this does *not* say. It does not require every process to die at
start. The first attempt at symmetry got this wrong in both directions: the
server was made to warn and continue (too weak), and the CLI was briefly
considered for boot-failure (too strong, and for the wrong reason).

The resolution is that **the server and the CLI differ in where the point of
use is, not in what rule applies**:

| Entry point | Point of use | Behaviour on failed crossing |
|---|---|---|
| `zp-server` | Process start — it exists to serve | Refuse to boot, with full diagnostic |
| `zp-cli` | The verb — most verbs never touch inference | Silent at start; full diagnostic from `PipelineError::NoProvider` at the moment a verb depends on it |

Symmetry of principle, asymmetry of moment. This is recorded as a rule and not
an exception, deliberately: the Regent bypass and the compiled `local` tier
both began as reasonable-sounding exceptions that nobody wrote down.

Two consequences worth stating outright, because both were violated by the
first implementation:

1. **A startup warning is not compliance.** Printing a caution on every
   invocation that does not care about inference is noise, and noise is how a
   half-state hides. The diagnostic belongs at the dependency, not the door.
2. **The diagnostic is derived, not remembered.** `no_provider_diagnostic`
   reads live pool state rather than echoing configuration back, so it cannot
   drift from what is actually true. A diagnostic that reports intent rather
   than reality is a sensor that lies.

Verified 2026-08-09: `Commands::Cfg` short-circuits at `zp-cli/src/main.rs:4577`,
before pipeline construction, so no configuration verb can be locked out by a
failed inference crossing. This property must be preserved — a substrate whose
repair tools depend on the thing being repaired cannot be repaired.

---

## 5. Why the seam is the product

For every other practitioner of this discipline, inner/outer is a documentation
convention — a taxonomy in a README, enforced by good intentions.

ZeroPoint is the only substrate in which the boundary can be **cryptographically
enforced**. Inner can prove to outer what it did, via signed receipts. Outer can
be granted narrow, revocable scope by inner, via delegation. The seam is
attestable rather than conventional.

This resolves the apparent strategic tension in shipping a harness as open
infrastructure. If the outer harness is the moat, then giving away inner harness
looks like giving away the asset. It is not, because the product is neither
side — it is the enforceable boundary between them. Adopters bring their own
sensors, guides and charters. What they cannot build for themselves is a seam
that proves what crossed it.

Which is why this document is not housekeeping. An undeclared seam in a
substrate whose product *is* the seam is a defect in the thesis, not the
codebase.

---

## 6. Ratification

Ratified by the operator on 2026-08-09. The three straddling judgements are
settled; the sensors in §4 now follow mechanically.

| # | Question | Ruling |
|---|---|---|
| 1 | Regent inner or outer? | **Inner mechanism, outer content.** Loop is substrate; model election is outer via `zp-config`; direct `inference_endpoint` deleted; S6 applies with no exemption. |
| 2 | Fate of `officer-inference.toml`? | **Survives, operating parameters only.** Retains per-task format / think / timeout and the bench annotations that justify them. Model election moves to `zp-config`. Its header must be amended to state it no longer elects models. |
| 3 | Sensor severity? | **Build-failing in CI, boot-failing in production. No warn-only tier.** |

**Finding on Q2, recorded 2026-08-26.** `officer-inference.toml`'s header was
amended and its `[models]` table removed per the ruling above. But "officers
read model election from `zp-config`" (the second half of Q2's premise) has
no wiring to redirect: `zp-officers` has no dependency on `zp-llm`,
`zp-pipeline`, or `zp-config`, and does no LLM dispatch of any kind — it is a
rule-based monitor cadre. There was never a read of `officer-inference.toml`
from `zp-officers` to begin with; the file's only real consumer has always
been `scripts/bench-local-models.py` (see C5's "Partial" note above). The
truthful state: the one Rust pipeline that *does* elect a model
(`zp-server`'s provider-pool construction, feeding `zp-pipeline`) already
reads `llm.provider` / `llm.model` / `llm.escalation_model` from `zp-config`
correctly — that part of C1 holds. Wiring officers themselves to `zp-config`
is blocked on a prerequisite that doesn't exist yet: an officer-cycle
LLM-dispatch path. See W4's status for the resulting split.

### 6.1 Derived work

In dependency order. Items marked ⊘ are half-states introduced on 2026-08-09
by the provider-pool wiring and are corrections, not new work.

| # | Work | Crossing / sensor |
|---|---|---|
| # | Work | Crossing / sensor | Status |
|---|---|---|---|
| W1 ⊘ | `init_providers` failure becomes boot-fatal; pool state joins the health surface | S3 | **done** 2026-08-09 |
| W2 ⊘ | Wire `zp-cli` so both entry points populate the pool identically | S3 | **done** 2026-08-09 |
| W3 | Delete the compiled `local` tier from `get_routing_config()` | C1, S4 | open |
| W4 | Amend `officer-inference.toml` header; officers read election from `zp-config` | C1, C5 | **partial**: file cleaned up 2026-08-26; officer→LLM wiring deferred pending officer-dispatch design |
| W5 | Route the Regent through the proxy — see §6.1.1 | C1, S6 | **in progress** |
| W6 | `config set` refuses or warns when writing to a shadowed layer | C7, S5 | open |
| W7 | Implement S1–S6 in `zp-discipline` | all | **partial** 2026-08-26: S1, S3, S6 fully asserted (S3 pre-existed as W1; S6 satisfied by the pre-existing loopback pin, untouched); S2 boot-fatal but scoped to the local (ollama) provider only; S4 landed but does not yet cover RegentConfig's independent reasoning_model/routing_model election, nor officer-inference.toml (outside the discipline scanner's `crates/`-only reach); S5 implemented as a boot-time warning rather than boot-fatal, by deliberate judgement call. See the W7 report for detail. |

W7 last: the sensors assert the invariants W1–W6 establish, and landing them
first would only produce a red build with nothing to point at.

#### 6.1.1 W5 decomposition

W5 was scoped as "point `inference_endpoint` at the proxy." Reading the code
showed it to be a protocol migration. Four sub-steps, discovered in order:

| Step | Work | Status |
|---|---|---|
| 3a | Recognise the ZP proxy in `ProviderProfile::detect` rather than sniffing it | **done** 2026-08-10, 6 tests |
| 2 | Probes `api/tags` → `v1/models` (3 sites, incl. a response-shape change in `model_available`) | **done** 2026-08-10 |
| 3b | Regent holds a `GateRequestSigner` | **done** 2026-08-12, 4 tests |
| 3c | `inference_endpoint` → proxy; native `/api/chat` path retires | **next** — scoped in `W5-STEP-3C-SESSION-BRIEF.md` |
| 4 | Extend `no_raw_provider_http_outside_canonical_layer` to loopback URLs | last |

**Hard constraint: 3b before 3c.** `ProviderProfile::zp_proxy()` carries
`auth: AuthStrategy::None`, because ZP-Sig is per-request and body-bound and
cannot be expressed as a static `AuthStrategy`. Pointing the endpoint at the
proxy before the Regent can sign would 401 every call and take Regent
inference offline entirely. Fail-closed and correct, but unforgiving.

**3b thread, as landed.** The gate signer is derived in `AppState::init`
beside `expected_kid` from one sovereign-root load. It was a local there; it is
now a field on `AppStateInner`, and travels:

```
AppState::init  →  AppStateInner.gate_signer     zp-server/src/lib.rs
                →  ServerRegentConfig.gate_signer zp-server/src/lib.rs
                                                  zp-server/src/regent.rs
                →  InferenceBackend::new(&config, signer)
                                                  zp-server/src/regent.rs   (executor's backend)
                →  Regent::new(…, signer)         zp-server/src/regent.rs
                   → InferenceBackend::new        zp-regent/src/regent.rs   (Regent's own backend)
                →  sign when the profile is zp_proxy
```

Constructs are named rather than located. Every prior revision of this block
carried line numbers, and every one of them had drifted by the time the step it
described was executed — `ServerRegentConfig` by 2, `fallback_endpoint` by 43,
the auto-start probe by 43. The names do not drift.

**It stops at `ServerRegentConfig` — it does not reach `RegentConfig`.** The
plan routed it through both config structs. `RegentConfig` derives `Serialize`,
`Deserialize` and `Debug`, so an `Option<Arc<dyn RequestSigner>>` field there
would need `#[serde(skip)]` — a live capability that vanishes on a round-trip
without saying so — plus a `Debug` supertrait on `RequestSigner` and a
hand-written `Debug` for `GateRequestSigner` that redacts its own key. The
signer is a capability, not configuration, and is passed as a parameter to the
two backends instead. `RegentConfig` is untouched.

`zp-regent` already depends on `zp-core`, so `RequestSigner` needed no new
dependency edge.

**Also landed in 3b:** `chat_ollama_at` and `chat_openai` used `.json(request)`,
which re-serialises independently of any hash taken over the body. ZP-Sig binds
a BLAKE3 of the exact wire bytes, so the body is now serialised once and those
bytes both hashed and sent — the same correction made to `ProxyLlmProvider` on
2026-08-09. Signing in `chat_ollama_at` is conditioned on the endpoint actually
being called, not on the profile alone: the fallback path posts to raw Ollama
while the configured provider may be `zp-proxy`, and an envelope addressed to a
backend that cannot verify it is noise.

**Confirmed live 2026-08-12.** Both `InferenceBackend::new` call sites report
`gate_signer=true` at startup. The endpoint did not move, which is correct 3b
behaviour — the capability is present and unused until 3c.

**Out of scope, deliberately.** `fallback_endpoint` (compiled literal in
`zp-regent/src/inference.rs`) is not relocated to config: 3c collapses both
endpoints onto one proxy base with the provider varying per request, so a config
field introduced now would be deleted then. The auto-start probe in
`ensure_ollama_running` stays pointed at `11434` directly — the proxy cannot
answer whether the process behind it is running.

**Related, not part of W5.** `ensure_ollama_running()` spawns processes without
a grant, without passing `zp-host` (the typed boundary `ExecutionEngine`
already honours), without a receipt, and confirms success by an 8-second timeout
rather than by observation. The ruling is that the Regent *should* hold
lifecycle authority — attested, scoped, revocable — not that it should lose it.
Tracked separately; `regent:hardware:` and `observation:hardware:` are already
reserved receipt families and may be the intended carriers.

### 6.2 Standing rule

This document is amended, never appended to by a second document. A seam
declaration that acquires a successor has reproduced the defect it exists to
prevent.
