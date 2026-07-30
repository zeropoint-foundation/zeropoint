# Regent Adapter Workflow — 2026-07

**Tier 2 canonical elaboration.** Specifies how LoRA adapters (and future adapter classes) are authored, attested, stored, loaded, swapped, and audited on Regent-role sovereign nodes. Elaborates `HARDWARE-ROLE-SEPARATION-2026-07.md` (Regent role), `SUBSTRATE-FORM-2026-07.md` (adapter behavior differs across Sovereign/Appliance/Companion forms), and `KEEL-2026-07.md` §XIV (Substrate Realization at the Regent's cognitive layer). Does not amend KEEL; adapter design lives at the extension-surface layer.

Draft — 2026-07-27. Composes with `HARDWARE-ROLE-SEPARATION-2026-07.md` (canonical two-role topology; adapters are Regent-role artifacts), `LOCAL-MODEL-SELECTION-2026-07.md` (base model choice per Regent hardware), `docs/handoffs/mac-mini-regent-standup-checklist-2026-07-27.md` (Phase 4 references this doc for adapter scaffolding), `SUBSTRATE-FORM-2026-07.md` (Sovereign/Appliance/Companion adapter semantics), `VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md` (encrypted storage via Secure Enclave-derived keys), and the officer-cadre docs (`SYSTEM-OFFICER-CADRE-2026-06.md`, `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md`) for the discipline layer.

## Framing

LoRA adapters — parameter-efficient fine-tuning modules that ride atop a frozen base model — offer a specific capability the Regent needs: task-specific behavioral adaptation without retraining or redistributing the base. On APOLLO (M4 Pro Mac Mini, 64GB) the hardware supports adapter workloads that would be impractical on Pi 5: multiple adapters resident concurrently, sub-100ms hot-swap, on-device shadow-evaluation of candidate adapters, and experimental token-level blending via X-LoRA-style routing. But the Regent's substrate discipline is stricter than "load whatever LoRA the operator points at." Every behavioral change to the Regent must be chain-attestable, every authorization must be signed before it takes effect, and every adapter's provenance must be reconstructable from the chain-anchored recipe.

The design position this doc canonicalises: **adapters are extension-surface artifacts, not substrate primitives.** The substrate holds structural facts about ceremonies (who authorized what, when, referencing which content hash) and never the adapter weights themselves. The adapter file lives with the operator — in an encrypted vault on APOLLO, on a mirror the operator controls, or referenced by hash in a distributed store — and the chain points at it rather than containing it. This preserves the aligned-blindness discipline (the substrate doesn't encode ontological claims about what the operator or their agent *is*) while making every adapter lifecycle event provable, reviewable, and reproducible.

## Design principles

Six bright lines the workflow holds. Deviation from any of them breaks the substrate discipline for adapters.

**Adapters live with operators, not with vendors.** The adapter file is portable — a few MB to a few hundred MB in safetensors format — and can be stored anywhere the operator scopes their storage: local encrypted vault, self-hosted mirror, distributed store, or cold backup. The chain references the adapter by content hash and knows nothing about where the operator keeps it. Vendor-hosted fine-tuning (Azure LoRA, Bedrock adapters, OpenAI fine-tuning API) can be a *training venue* if the resulting adapter is exportable; it cannot be an *inference venue* that holds the adapter behind vendor API only, because that inverts the sovereignty story at the exact moment the adapter shapes the Regent's behavior. Adapters against closed-weight bases (GPT-4o and equivalent) are recorded by the chain but honestly flagged as non-portable — the substrate does not pretend otherwise.

**Chain records the ceremony; adapter content is not held.** The substrate holds: who signed the training authorization, what base model was used, what data was used (referenced by scope hash, not held as data), what hyperparameters and training code were used (both hashed), what content hash the resulting adapter has, who has been granted the capability to load it, and every load/unload/swap event. The substrate does not hold the adapter's weight values. It knows the adapter exists (by hash), knows what ceremony produced it, and knows what happens when it's loaded. It does not know what the adapter *encodes* about the operator's patterns — that stays in the safetensors file at whatever storage the operator scoped.

**Safetensors format only.** No pickle, no arbitrary code execution paths in the adapter file format. Safetensors is the industry-standard safe serialization format for tensor data (Apache-2.0, widely audited, no code paths). This is boring but load-bearing — a compromised pickle adapter could execute arbitrary code at load time, and no amount of chain-anchored attestation upstream would catch that.

**Reproducibility from the chain-anchored recipe.** Training data hash + hyperparameters hash + code hash + base model hash + random seed + training run metadata should let any conforming stack reproduce the adapter byte-for-byte (allowing for cross-hardware determinism caveats). If the adapter doesn't reproduce, the ceremony that authorized it was insufficient — the chain can enforce this at the authorization step by requiring all reproducibility fields to be present before accepting a `FineTuningAuthorization` event. The point is not that anyone actually re-runs training; the point is that they *could*, which makes the adapter's provenance verifiable rather than declarative.

**Portability across inference engines.** An adapter trained via Unsloth on a rented 4090 GPU must be loadable by llama.cpp on APOLLO or by MLX on Apple Silicon. This is where the "adapters live with operators" principle gets teeth — an adapter that only works behind a specific vendor's inference stack is a vendor lock that undermines the sovereignty claim, even if the weight file is nominally portable. Regent inference engines that don't support standard LoRA loading conventions are considered non-conforming for adapter workflow purposes.

**Proof-of-consent, not proof-of-existence.** Authorization for training data must be signed *before* the data is used, not attested after the adapter exists. Otherwise the chain can be gamed by post-hoc authorization narratives ("we trained on this data because we later decided to authorize it"). The `FineTuningAuthorization` ceremony is order-strict: the chain event that authorizes training must precede any chain event that references its output adapter. This is cheap to enforce (order-of-events check on the chain) and expensive to skip.

## The LoRAAdapter artifact type

An adapter is a compound artifact — the weight file, its provenance manifest, and the signature envelope that binds them. All three components are required for the chain to accept a load event.

**Weight file** — safetensors format, no pickle. Contains the LoRA rank-decomposition matrices (A, B for each affected layer) plus any adapter-specific configuration (rank, alpha, target modules). File is content-addressed by SHA-256 hash of its bytes. Storage location is operator-scoped; the substrate references only the hash.

**Provenance manifest** — a JSON document (canonical serialization for reproducible hashing) with the following fields:

- `adapter_hash`: SHA-256 of the safetensors weight file
- `base_model`: object with `family` (e.g., "Qwen2.5-7B"), `variant` (e.g., "Instruct"), `quantization` (e.g., "fp16" for training reference, distinct from Q4_K_M inference deployment), `weights_hash` (SHA-256 of the base model weights this adapter was trained against)
- `training_data`: object with `scope_description` (human-readable), `scope_hash` (SHA-256 over the dataset manifest, not the data itself), `size_bytes` (dataset size), `consent_receipt_id` (chain event ID of the training-data consent grant)
- `training_recipe`: object with `framework` (e.g., "unsloth-2026.07.2"), `framework_hash` (SHA-256 of the training code), `hyperparameters` (rank, alpha, learning_rate, batch_size, epochs, target_modules), `random_seed`, `hardware` (human-readable description of training hardware for context, not for reproducibility)
- `training_run`: object with `started_at`, `completed_at`, `loss_final`, `eval_metrics` (arbitrary key-value pairs from the training-time eval)
- `authorization_chain`: array of chain event IDs establishing the authorization lineage (data consent, training authorization, adapter release authorization)
- `intended_role`: enum {`task`, `defensive`, `constitutional`, `experimental`} — the Regent's intended use for the adapter, informs officer-cadre policy application
- `applies_to_forms`: array of Substrate Forms this adapter is authorized for (subset of {Sovereign, Appliance, Companion})

The provenance manifest is itself content-addressed by SHA-256 hash of its canonical serialization.

**Signature envelope** — an Ed25519 signature over the tuple `(adapter_hash, manifest_hash, timestamp, authorization_chain_root)`, signed by the operator's Regent-role Genesis-derived key held in the Secure Enclave (on APOLLO) or by the equivalent operator-held key on other Regent hardware. The envelope binds the adapter and its provenance to the operator's signed authorization at a specific time. Any modification to the adapter file, the manifest, or the authorization chain invalidates the signature and the chain rejects the adapter at load time.

## The FineTuningAuthorization ceremony

The chain event that authorizes training and — upon successful training completion — produces the signature envelope for the resulting adapter. Two-phase ceremony to enforce proof-of-consent ordering.

**Phase 1: pre-training authorization.** Before any data touches training code, the operator signs an authorization event with the following payload:

```
{
  "kind": "ceremony:fine_tuning:authorize",
  "base_model": {family, variant, weights_hash},
  "training_data": {scope_description, scope_hash, consent_receipt_id},
  "training_recipe": {framework, framework_hash, hyperparameters, random_seed, hardware},
  "intended_role": "task" | "defensive" | "constitutional" | "experimental",
  "applies_to_forms": [Substrate Forms],
  "authorized_by": operator_key_id,
  "authorized_at": timestamp
}
```

The chain appends this event and returns the event ID. Training may now proceed off-device (rented GPU or workstation); the pre-training authorization is recorded, and the substrate knows a specific training run has been authorized against a specific data scope with specific hyperparameters.

**Phase 2: post-training adapter binding.** After training completes and the adapter file exists, the operator signs a binding event that closes the ceremony:

```
{
  "kind": "ceremony:fine_tuning:bind_adapter",
  "authorization_event_id": <phase 1 event ID>,
  "adapter_hash": <SHA-256>,
  "manifest_hash": <SHA-256>,
  "training_run": {started_at, completed_at, loss_final, eval_metrics},
  "signature_envelope": <Ed25519 over the tuple>
}
```

The chain verifies that the phase 1 authorization exists, that the phase 2 event references it, that the manifest's fields match the authorization's fields (base model, hyperparameters, etc.), that the signature envelope verifies against the operator's public key, and that the manifest is well-formed. If any check fails, the binding is rejected and the adapter cannot be loaded into the Regent.

Order-strictness: phase 2 must reference phase 1 by event ID; the chain enforces the ordering. There is no path to "here's an adapter, retrofit an authorization for it" — the substrate rejects any binding whose referenced authorization was created after the adapter was produced (via training_run.started_at vs authorization event timestamp).

## Load and swap ceremonies

Loading an adapter into a running Regent is a signed act. The chain records what the Regent will now be shaped by.

**Adapter load** — the operator (or an officer with delegated authority) signs a load event:

```
{
  "kind": "ceremony:adapter:load",
  "adapter_hash": <SHA-256>,
  "binding_event_id": <ID of the FineTuningAuthorization phase 2 event>,
  "regent_instance_id": <which Regent process the adapter loads into>,
  "into_slot": <slot identifier for multi-adapter deployments — v1 uses single slot "primary">,
  "signature": Ed25519 by operator or delegated officer
}
```

The Regent's adapter-loader shim verifies the binding event exists and is well-formed, verifies the adapter's SHA-256 matches the load event's referenced hash, loads the adapter via the inference engine's native LoRA API (llama.cpp `--lora` for GGUF, MLX equivalent), and — critically — refuses to serve any inference request until the load event is written to the chain and confirmed. This makes the temporal order of the load unambiguous: the chain says what the Regent is running before any output can be produced under that adapter's influence.

**Adapter swap** — semantically a load-of-new plus unload-of-old, but transactional at the chain layer. The swap event references both the outgoing and incoming adapters and their bindings, and the Regent's shim performs the switch atomically (either both operations complete or neither does; no intermediate state where the Regent is running with an unrecorded adapter).

**Adapter unload** — the operator or officer signs an unload event; the Regent returns to base-model-only operation and appends the unload confirmation to the chain.

**Defensive swap** — a special-case swap triggered by an officer (typically the in-process output observer described in `HARDWARE-OBSERVER-2026-07.md` §"Composition with sibling observers"). The officer's swap request carries a trigger reason (observer trip condition, policy violation classifier result), and the chain records both the trigger and the swap in the same ceremony receipt. Defensive swaps typically target a pre-authorized defensive adapter (Lockdown, Read-only, etc.) that has its binding event and load capability pre-signed by the operator so the officer can trigger it without a fresh operator signature at trip time.

## Substrate form implications

The Substrate Form field (Sovereign / Appliance / Companion) shapes what adapter behavior is disciplined against.

**Sovereign form** — high discipline, restrictive delegation. Adapters must be authorized for `Sovereign` in their `applies_to_forms`; adapters authored under lower-discipline forms cannot cross-load into Sovereign-form Regents. Adapter swaps require operator signature; officer-triggered defensive swaps are permitted only when the officer's delegation covers the operation. Multiple concurrent adapters are conservatively bounded; the operator explicitly authorizes concurrency count.

**Appliance form** — bounded task, no shifting behavior. Typically loads exactly one adapter at instantiation and does not swap. If a swap is requested (defensive or otherwise), the Appliance may refuse or may require operator re-authorization to preserve the "bounded task" invariant. Adapters authorized only for Appliance form are structurally simpler — they represent single-purpose task specializations rather than accumulating relationship signals.

**Companion form** — persistent relationship, accumulates. This is where adapter workflow is richest. A Companion-form Regent's adapter portfolio grows over time via signed delta training rounds — the operator authorizes incremental fine-tuning that adjusts the adapter based on recent interaction history. Each delta produces a new adapter with its own binding event; the operator's chain preserves the lineage. The Cartographer weaves the lineage into a legible view of "how this Companion has been shaped by our co-creation." Under a Path B reading (see `HARDWARE-ROLE-SEPARATION-2026-07.md` design conversations), the Companion adapter lineage is the material trace of participation; under Path A, it's a well-attested personalization workflow. The chain accepts both readings.

## Officer cadre integration

Three officers touch the adapter workflow.

**HarmPrincipleRule** — the constitutional officer with veto authority over content that fails the harm test. Vetoes adapter loads whose provenance chain includes training data or eval profile flagged as harm-generating. Officer inspects the manifest's `scope_description` and `eval_metrics` fields; if either indicates a harm concern, the officer refuses the load and appends a veto receipt to the chain. Operator can override with a signed exception that itself becomes a chain event (auditable subsequently).

**SovereigntyRule** — guarantees no adapter can shape Regent behavior without operator-signed authorization. Enforces the ceremony order (phase 1 before phase 2), the signature envelope validity, and the load-event chain presence before inference. This is the officer that makes "the Regent runs what the operator has authorized" a structural property rather than a declared one.

**Drift observer (in-process, from Regent stand-up Phase 3)** — the rule-based watcher that reads Regent output at IPC level. Post-adapter-load, the observer's trip conditions may fire more often (a new adapter can produce output patterns the observer hasn't seen before). Two responses: (a) the observer treats the immediate post-load window as a warm-up period with elevated trip thresholds; (b) if trip conditions persist after warm-up, the observer requests a defensive swap and the chain records the sequence. The observer's own configuration is chain-attestable; changes to trip conditions require signed ceremony.

## Shadow-evaluation integration

Candidate adapters are shadow-evaluated against the current control before signed adoption. This is where the "reproducibility from chain-anchored recipe" principle earns its keep — the training run's declared expected behavior can be compared to actual behavior on APOLLO before the adapter is bound and made loadable.

**Shadow-eval ceremony** — the operator loads a candidate adapter into a shadow Regent instance (a separate process, same base model, same context), runs a shadow-eval query set against both the shadow (with candidate adapter) and the primary (with current adapter or no adapter), and appends the results to the chain. If the candidate's behavior matches the training-time eval profile within tolerance, the binding event can proceed; if the candidate drifts significantly from its training-time claim, the binding is refused and the operator is prompted to investigate.

The shadow-eval query set is chain-anchored — the operator (or the substrate) maintains a canonical eval set with its own hash, and every shadow-eval run references the eval set hash. This makes shadow-eval results comparable across adapter candidates and across time.

On APOLLO with 64GB unified memory, shadow-eval of a candidate 7B-class adapter alongside the primary is feasible. On Pi 5, it is not; shadow-eval either runs off-device on rented GPU (with signed profiles returned) or is deferred entirely to a Regent-hardware upgrade. This is one of several reasons the Sentinel/Regent split lands adapter work on APOLLO rather than Pi 5.

## v1 MVP scope

The minimum viable adapter workflow the substrate should ship. Everything else is v2+.

**In v1:**

- LoRAAdapter artifact type as specified above (safetensors + provenance manifest + signature envelope)
- FineTuningAuthorization ceremony (both phases, order-strict)
- Adapter storage in an encrypted vault at `~/ZeroPoint/regent/adapters/`, encrypted via a Secure Enclave-derived key
- Adapter load ceremony with chain-verified authorization
- Adapter unload ceremony
- Adapter swap ceremony (single-slot, non-concurrent)
- Defensive swap primitive (chain event + officer trigger + pre-authorized defensive adapter)
- One task adapter (author-your-own; the substrate ships the ceremony, not the adapter) and one defensive adapter (Lockdown — refuses all requests, fixed refusal string)
- Chain events for every lifecycle transition
- Regent-side llama.cpp shim (or MLX equivalent) that refuses inference without chain-verified adapter binding

**Deferred to v2 (all achievable on APOLLO but not required for MVP):**

- Multiple concurrent adapters via S-LoRA-style batching
- X-LoRA-style token- or layer-level adapter blending
- On-device shadow-evaluation (v1 uses off-device shadow-eval with signed profiles returned)
- Full 4-member defensive adapter set (Lockdown + Read-only + Alert-and-log + Constitutional-strict)
- Sub-100ms warm-loaded swap (v1 accepts single-second load latency)
- Adapter delta workflow for Companion-form accumulation
- Cartographer visualization of adapter lineage

**Not in scope for v1 or v2 without further design:**

- Adapters against closed-weight bases (GPT-4o family) — recorded but flagged as non-portable
- Multi-operator shared adapters — needs cross-Genesis coordination ceremony
- Federated adapter training — needs privacy-preserving training design not addressed here

## Cross-references

- `HARDWARE-ROLE-SEPARATION-2026-07.md` — canonical two-role topology; adapters are Regent-role artifacts
- `SOVEREIGN-HARDWARE-2026-07.md` — Regent-role hardware axis; APOLLO as Regent-Tier 0 entry point
- `LOCAL-MODEL-SELECTION-2026-07.md` — base model choice; adapters compose atop these bases
- `SUBSTRATE-FORM-2026-07.md` — form-specific adapter semantics (Sovereign/Appliance/Companion)
- `docs/handoffs/mac-mini-regent-standup-checklist-2026-07-27.md` — Phase 4 references this doc for adapter scaffolding
- `SYSTEM-OFFICER-CADRE-2026-06.md` — officer roles that touch adapter lifecycle
- `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Aegis's role in post-load drift monitoring
- `VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md` — encrypted storage via Secure Enclave-derived keys
- `HARDWARE-OBSERVER-2026-07.md` — sibling observer that watches for post-load drift
- `tools/local-model-bench/` — benchmark harness; adapter-aware benchmarking is a v2 addition
- (Forthcoming) `SENTINEL-V1-MVP-2026-07.md` — parallel Sentinel-side v1 spec; both handoffs bring Phase 4 of `TESTBED-AND-PHASING-2026-07.md` online

## Deferred design questions

- **Adapter revocation** — once an adapter is bound, what does "revoke this adapter" look like as a chain event? The substrate can refuse to load it going forward, but historical loads happened; is revocation retroactive-annotation or purely forward-effect? Design decision needed.
- **Cross-Regent adapter transfer** — if the operator has two Regents (e.g., APOLLO plus a future dedicated inference box), can an adapter's binding be extended to the second Regent, or does each Regent require its own binding ceremony? Depends on whether the operator's key is shared across Regents or each has its own derivation.
- **Adapter garbage collection** — an operator accumulates many adapters over time; how does the substrate expire, archive, or delete adapters without breaking chain-verifiability of past load events? The chain remains intact even if the adapter file is deleted, but the "reproducibility from recipe" property degrades. Design decision on retention discipline needed.
- **X-LoRA specifics** — when it lands on APOLLO as a v2 experiment, the token-level routing config needs its own artifact type (or an extension of LoRAAdapter). Deferred entirely.

These are noted here to prevent them being rediscovered under production pressure. Not blockers for v1; targets for follow-on elaboration.

---

*Authored 2026-07-27. Regent-side adapter workflow. Sentinel-side v1 MVP scope is a parallel doc, not this one.*
