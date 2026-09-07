# Substrate Boot Invariant Ceremony

**Document type:** Tier 2 canonical elaboration.
**Elaborates:** KEEL §II.6 (officer signing keys), §II.10 (composition contracts), §II.13 (nine design principles as verification targets — P1 signing-is-gravity, P4 every-bit-counts, P8 one-canonical-path, P9 substrate-proposes-operator-signs), §II.19 (extension surface composition), §III.19 (detectability — silence is the enemy), §III.20 (forward-only recovery — chain is truth), §III.22 (evidence-based ceremony), §III.25 (autonomic coordination), Part V (composition contract), Part VII (peer verification).
**Date:** 2026-07-18. Motivated by the sovereignty-provider ↔ vault-key composition drift discovered same day, and Ken's explicit intent: *"make this class of failure structurally impossible by the time YubiKey and other providers are wired."*
**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Living discipline. Ships alongside SUBSTRATE-READINESS-CONTRACT-2026-07.md as the empirical, boot-time layer above readiness's declarative layer. Implementation lands as follow-up substrate work referenced by this spec.

---

## Part I — What this addresses

Where SUBSTRATE-READINESS-CONTRACT declares what "operationally ready" means (subsystem-declares-readiness, boot-time verification of stated claims), this ceremony **empirically proves the substrate's structural invariants at every boot before load-bearing subsystems run.** Readiness catches *silent-disable* at boot. This ceremony catches *silent-drift* at capability change — the class where adding a new provider, extension, or subsystem breaks composition with existing surfaces without any subsystem noticing.

Concretely: on 2026-07-18, adding Trezor as a sovereignty provider composed cleanly with the audit-signing path (which had been migrated to the sovereignty provider layer) but drifted silently against six other Genesis-consumer surfaces (`vault_key`, `zp emit`, `zp health`, `zp doctor`, `resolve_vault_key`, CLI `load_operator` call sites). Nothing in the substrate noticed until the operator hit each surface manually. The audit-signer worked. Everything else silently degraded. `zp doctor` reported "healthy (4 warnings)."

**The failure class named:** capability addition (new sovereignty provider, new inference provider, new extension surface, new ontology projector, new chain-watcher pattern) can introduce composition drift against N existing consumer surfaces without any structural check forcing the operator to verify against those surfaces.

**Boot-invariant ceremony makes the drift class impossible.** Every capability's implementation declares which dependent surfaces it must be verified against; the ceremony runs those verifications at build time AND at every boot; drift fails the ceremony and refuses to ship or refuses to boot.

**Failure class NOT addressed by this document:**
- Semantic correctness of a subsystem's behavior (composes with COGNITIVE-SELF-OBSERVER, CLAIM-VERIFIER, SHADOW-EVALUATION-PRIMITIVE).
- Runtime drift after successful boot (composes with CHAIN-READ-CANARY-DISCIPLINE, OBSERVER-COHERENCE-DISCIPLINE).
- Malicious substrate modification (composes with SUBSTRATE-HARDENING-CEREMONY, REPRODUCIBILITY-CEREMONY — but this ceremony provides the boot-time chain evidence the hardening ceremony verifies against).

Honest scope. This ceremony covers boot-time and build-time verification of structural invariants across composition boundaries. Composition with the detectability disciplines covers the rest.

---

## Part II — Bootstrap phases

The ceremony runs in bright-line phases. Each phase has its own reduced invariant set. Nothing above phase N runs until phase N-1's invariants are chain-anchored as verified.

### Phase B0 — Pre-chain bootstrap

State before the audit chain is even readable. The absolute minimum: kernel measured, storage decrypted, process running, environment sane. Cannot chain-anchor anything (chain not accessible yet); invariants that fail here abort the process before any log line is written.

**Phase B0 invariants:**
- Filesystem paths resolvable (`zp_core::paths::*`).
- Genesis certificate readable (`~/ZeroPoint/keys/genesis.json`).
- Sovereignty descriptor readable (`~/ZeroPoint/genesis.json`).
- Genesis certificate signature verifies against declared public key.
- Sovereignty mode is recognized (registered in the sovereignty provider registry at build time).

**Exit gate:** all above pass, else exit with structured error to stderr.

### Phase B1 — Sovereignty proof

Sovereignty root loaded and verified. Chain is now accessible but not yet trusted.

**Phase B1 invariants:**
- `load_sovereign_root(sovereignty_descriptor_path)` returns `Ok`. This is the first physical ceremony (may include Trezor confirmation, Touch ID prompt, YubiKey PIN, etc.).
- Loaded Genesis material's public key matches the certificate.
- Chain database opens; last entry hash-links to prior; hash chain internally consistent from genesis.
- Audit signer derives from Genesis and can produce a test signature verifying against its declared public key.

**Exit chain-anchor:** `substrate:invariant:B1:verified <run_id> <sovereignty_mode> <chain_head_hash>`. Any B1 invariant failure → `substrate:invariant:B1:violated` with structured reason; substrate refuses to serve any operator input; enters `readiness:blocked` state per SUBSTRATE-READINESS-CONTRACT §Part V.

### Phase B2 — Composition proof

Each active capability's composition matrix is verified against the currently declared dependent surfaces. This is where tonight's failure class is caught.

**Phase B2 invariants (parameterized by active capability set):**
- For each active sovereignty provider (there's exactly one at boot): every declared dependent surface passes its verification test under this provider.
- For each active inference provider: every declared dependent surface (Regent cognitive loop, shadow evaluation, model dossier validation, cost budget discipline) passes.
- For each admitted extension surface: capability declaration composes with substrate's current authorization set.
- For each active ontology projector: (once Cartographer exists) composition with observation plane holds.

Each per-capability check produces a chain-anchored receipt. Failure produces `substrate:invariant:B2:violated:<capability>:<surface>` and blocks the substrate.

**Exit chain-anchor:** `substrate:invariant:B2:verified <run_id> <capability_manifest_hash>`.

### Phase B3 — Subsystem readiness

Per SUBSTRATE-READINESS-CONTRACT, each subsystem runs its declared readiness contract. This ceremony consumes the composed readiness envelope as evidence; it does not re-implement readiness. Readiness is the declarative layer; B0-B2 above have already provided empirical grounding for the claims readiness declares.

**Exit chain-anchor:** the `substrate:readiness:v0` receipt from SUBSTRATE-READINESS-CONTRACT.

### Phase B4 — Operator surface

Substrate accepts operator input. All prior phases' receipts are chain-anchored evidence; officer sweeps begin; Regent cognitive loop starts if enabled; canary discipline begins periodic probes.

**Anything above B4 runs only after B0–B3 verified.**

---

## Part III — Invariant catalog (seed)

Structured as a catalog because it grows. New invariants land here as design work identifies them.

### Invariants seeded from tonight's discoveries

**Invariant `vault_key_composes_with_provider`** — verified in B2.

Under any hardware-Genesis sovereignty mode (Trezor, YubiKey, Ledger, OnlyKey), `resolve_vault_key()` MUST return `Ok` with `source = SovereigntyProvider`. Under OS-credential-store mode, `Ok` with `source = SovereigntyProvider | CredentialStore` is acceptable. Under legacy env-var mode, `Ok` with `source = LegacyEnvVar` is acceptable and produces a `substrate:degraded:vault_key:legacy_env_var` receipt.

Test executes `resolve_vault_key(&keyring)` on the live substrate and inspects `source`. Chain receipt: `invariant:vault_key_composes_with_provider:verified <mode> <source>` or `:violated`.

**Invariant `cli_operator_load_composes_with_provider`** — verified in B2 AND enforced structurally in B_build.

Every CLI verb that loads the operator key routes through `load_sovereign_root` + `load_operator_with_genesis_secret`. Direct calls to `keyring.load_operator()` from CLI code paths are forbidden by discipline pin `singular_sovereign_root_cli`.

Build-time enforcement: static analysis over `crates/zp-cli/**/*.rs` fails CI on unwrapped `keyring.load_operator()` calls (with declared exemptions inside `sovereignty::hardware/*`). Boot-time verification: `zp preflight` (invoked by substrate boot ceremony) exercises the representative CLI signing path against the active sovereignty provider.

**Invariant `default_config_boots_functional`** — verified in B_build.

Fresh install with no config file produces a substrate whose composed readiness envelope is `Ready`, not `Degraded`. Specifically: no subsystem enumerated in the readiness catalog defaults to `Degraded { reason: "not enabled" }` under absent-config state. The operator opts *out* of functionality via config, not *in* to it.

Build-time enforcement: test harness synthesizes an absent-config boot and asserts `readiness.composed_status == Ready`. Regressions fail CI.

### Invariants for the four architectural claims

These come from EMPIRICAL-PROGRAM-2026-07.md Part II and become boot-verified rather than one-off validations.

**Invariant `chain_integrity`** (Claim 1) — verified in B1.

Full chain hash-link verification from genesis to head. Under debug builds this is skipped for speed but the boot ceremony explicitly emits `substrate:invariant:chain_integrity:skipped:debug_build` — no silent skip. Under release builds, full verify runs.

**Invariant `collective_audit_available`** (Claim 2) — verified in B2.

Peer trust anchors declared for this substrate are reachable; at least one peer can be queried for reciprocal chain view; peer-verification protocol handshake completes. Chain receipt: `invariant:collective_audit_available:verified <peer_count> <handshake_evidence>`.

**Invariant `gate_enforcement_wired`** (Claim 3) — verified in B2.

At boot, a synthetic gate probe runs: attempt a receipt-emission action requiring capability `test:gate_probe`; verify the gate returns `Denied` (because no delegation exists for that capability); verify the denial produces a chain receipt. This proves the gate is wired end-to-end. If the gate returns anything but `Denied`, or if no receipt lands, the invariant fails.

**Invariant `delegation_narrows_structurally`** (Claim 4) — verified in B2.

Load the active delegation set from chain, verify each delegation's capability envelope is a subset of its parent's. Cycle detection; monotonic decrease over depth. Chain receipt: `invariant:delegation_narrows_structurally:verified <delegation_count> <max_depth>`.

### Invariants for later scope (placeholders)

- `hardware_observer_present_when_declared` (per HARDWARE-OBSERVER-2026-07.md, when Substrate Form = Sovereign with hardware self-observer)
- `observation_plane_scope_matches_delegations` (per OBSERVATION-PLANE-2026-07.md)
- `aligned_blindness_holds` (per SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md — verify no code path exposes blind-class data through observation surfaces)
- `officer_signing_keys_derive_from_genesis` (per SYSTEM-OFFICER-CADRE-2026-06.md §3.5)
- `regent_delegation_active_and_bounded` (per REGENT-ORCHESTRATION-ARCHITECTURE-2026-07.md)

Each of these lands with concrete test implementation as its parent design doc's implementation ships.

---

## Part IV — Composition matrix

The load-bearing artifact that makes tonight's failure class structurally impossible for future capability additions.

**Location:** `capability_composition_matrix.toml` at the workspace root, or `crates/zp-composition/matrix.toml` (not yet written; neither location exists and the choice is open). Amended via SUPERSESSION-FRAMEWORK-2026-07.md ceremony.

**Schema:**

```toml
[capability_matrix.<capability_class>]
dependent_surfaces = ["<surface_a>", "<surface_b>", ...]

# Each surface has a verification test defined:
[verification.<surface>]
runs_at = ["build" | "boot" | "capability_add"]
under_capability = "*" | "<specific_capability>"
test_symbol = "<crate>::<module>::<fn>"
receipt = "invariant:<name>:<verb>"

# Each concrete implementation of a capability class must have an entry:
[provider.<name>]
class = "<capability_class>"
verified_against = "capability_matrix.<capability_class>"
verification_hash = "sha256:<hex>"
last_verified_commit = "<git_sha>"
```

**Seeded catalog:**

```toml
[capability_matrix.sovereignty_provider]
dependent_surfaces = [
  "audit_signer",           # server-side; verified 2026-07-18
  "vault_key_derivation",   # verified 2026-07-18
  "cli_operator_load",      # verified 2026-07-18 (emit.rs; others pending)
  "cli_emit_signing",       # verified 2026-07-18
  "cli_health_diagnosis",   # PENDING
  "cli_doctor_diagnosis",   # PENDING
  "backup_recovery",        # PENDING
  "peer_verification",      # PENDING
  "operator_death_ceremony", # PENDING (per OPERATOR-DEATH-AND-LEGACY)
  "form_graduation",        # PENDING (per SUBSTRATE-FORM Part XIV.3)
]

[capability_matrix.inference_provider]
dependent_surfaces = [
  "regent_cognitive_loop",
  "shadow_evaluation_primitive",
  "model_dossier_validation",
  "cost_budget_discipline",
  "inference_routing_chain_anchoring",
]

[capability_matrix.extension_surface]
dependent_surfaces = [
  "capability_declaration_language",
  "chain_anchored_delegation",
  "wasm_sandboxing",
  "content_addressability",
  "distribution_reputation",
]

[capability_matrix.ontology_projector]
dependent_surfaces = [
  "cartographer_materialization",
  "chain_read_canary_freshness",
  "observer_coherence_cross_verification",
]

[provider.trezor]
class = "sovereignty_provider"
verified_against = "capability_matrix.sovereignty_provider"
verification_hash = "sha256:<pending>"
last_verified_commit = "<pending>"

# When YubiKey lands, this entry MUST exist and its verification_hash MUST
# derive from actual test runs under YubiKey mode.
[provider.yubikey]
class = "sovereignty_provider"
verified_against = "capability_matrix.sovereignty_provider"
verification_hash = "sha256:<pending>"
last_verified_commit = "<pending>"
```

**CI enforcement:**

1. Every `[provider.<name>]` entry MUST have `class`, `verified_against`, `verification_hash`, `last_verified_commit`. Missing fields fail CI.
2. Every `class` value MUST match an existing `[capability_matrix.<capability_class>]` entry. Unknown classes fail CI.
3. Every `dependent_surface` listed in a matrix MUST have a `[verification.<surface>]` entry with `test_symbol` pointing at a real function. Dangling references fail CI.
4. Every provider's `verification_hash` MUST derive from actually running the tests declared in `dependent_surfaces` under that provider. Mismatch between hash and actual test-run evidence fails CI. (Recomputable via `zp verify --composition`.)
5. Adding a new dependent surface to a matrix requires running verification tests against every existing provider in that class, updating each provider's `verification_hash`. Partial update fails CI.

**When a composition gap is known but tolerated** (e.g., migration in progress, per SUBSTRATE-READINESS-CONTRACT §Surface 4 semantics), an explicit `capability:composition:known_gap` receipt is chain-anchored with a declared remediation window. CI accepts the entry only if the receipt is present AND the remediation window is unexpired.

---

## Part V — Receipt schema

**Per-invariant receipt:**

```
invariant:<name>:<verb>
  run_id: uuid                    # groups all receipts from one boot ceremony
  phase: B0 | B1 | B2 | B3 | B4 | B_build
  verb: verified | violated | skipped | tolerated
  substrate_commit: git_sha
  invariant_name: string          # e.g., "vault_key_composes_with_provider"
  context: {                      # invariant-specific fields
    ...
  }
  evidence_hash: sha256           # optional — hash of the test's raw output
```

**Composed ceremony receipt:**

```
substrate:boot_ceremony:complete
  run_id: uuid
  boot_id: uuid                   # matches SUBSTRATE-READINESS-CONTRACT's boot_id
  invariants_verified: [<invariant_name>, ...]
  invariants_violated: [{name, reason}, ...]
  invariants_skipped: [{name, reason}, ...]
  composed_status: passed | passed_with_degradation | blocked
  next_phase: B4 | halt
```

**Composition-matrix verification receipt (build time):**

```
discipline:composition_matrix:verified
  matrix_hash: sha256
  substrate_commit: git_sha
  providers_verified: [<provider_name>, ...]
  surfaces_covered: [<surface_name>, ...]
  gaps_declared: [<known_gap_receipt_ref>, ...]
  ci_run_id: string
```

Emitted at the end of every successful CI build. Chain-anchored via the build ceremony per BUILD-PROCESS-DESIGN-2026-07.md.

---

## Part VI — Composition with existing disciplines

- **SUBSTRATE-READINESS-CONTRACT-2026-07.md** — this ceremony provides the empirical layer beneath readiness's declarative layer. Readiness envelope's "vault operations enabled" claim is trustable ONLY if `invariant:vault_key_composes_with_provider:verified` receipt exists in the current boot ceremony. Readiness projects from ceremony evidence.
- **SUBSTRATE-HARDENING-CEREMONY-2026-07.md** — hardening is a certification state; boot invariant ceremony is what a certified substrate proves at every boot to maintain that state. Full-certified substrate MUST pass all invariants for the four architectural claims plus all currently-active-capability composition invariants.
- **REPRODUCIBILITY-CEREMONY-2026-07.md** — two substrates verifying identical invariants against identical chain state MUST produce identical verification receipts (up to per-run UUIDs). Divergence in `invariant:<name>:verified` receipts across peers = drift discovery. Peer verification of substrate binaries now includes peer verification of composition-matrix receipts.
- **IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md** — adding a new invariant to the boot ceremony is itself a chain-anchored arc: proposed → evaluated → landed → verified → possibly regressed. New invariants ship via improvement-loop discipline.
- **CHAIN-READ-CANARY-DISCIPLINE-2026-07.md** — the canary discipline provides continuous post-boot verification; the boot ceremony provides discrete boot-time verification. Together: the substrate's structural claims hold at every boot AND continuously between boots.
- **OBSERVER-COHERENCE-DISCIPLINE-2026-07.md** — the boot ceremony's invariant tests ARE observers of substrate state. Cross-observer coherence applies: two independent verification tests observing the same invariant must agree.
- **SUPERSESSION-FRAMEWORK-2026-07.md** — the invariant catalog is versioned. Amendments (adding an invariant, changing a test's semantics, retiring an invariant) go through supersession ceremony.
- **BUILD-PROCESS-DESIGN-2026-07.md** — every CI build produces `discipline:composition_matrix:verified` and per-invariant B_build receipts. Build ceremony consumes them.

---

## Part VII — Bootstrap paradox handling

Some invariants can't be verified until later stages. The B0/B1/B2/B3/B4 phasing enumerates what's verifiable when.

**B0 has no chain access.** Failures produce structured stderr and process exit. No chain evidence possible; the failure is inherently invisible to future substrate observation. Compensating discipline: B0 invariants are minimal (paths, file existence, signature well-formedness) and independently reproducible via `zp verify --pre-chain` for post-hoc diagnosis.

**B1 has chain access but not verified trust in it.** Chain-integrity verification IS a B1 invariant; it must pass before any B1 receipt is considered trustable. Bootstrap: the chain-integrity verification result is the first chain-anchored receipt of the boot; subsequent B1 receipts cite it.

**B2 requires B1 verified.** Composition tests depend on Genesis material (B1) and chain state (B1). Attempting B2 with B1 unverified is architecturally forbidden.

**B3 (readiness) requires B2 verified.** Readiness's declarative claims are trustable only when their empirical grounding (B2) has been verified.

**B4 requires B3 verified.** Operator surface is unavailable until every prior phase's evidence is chain-anchored.

Any attempt to serve operator input while a prior phase is unverified is a discipline violation — receives a `discipline:violated:premature_operator_surface` receipt and halts the substrate. The `premature_operator_surface` receipt is itself a boot-invariant failure worth catching.

---

## Part VIII — Verifiable outcomes

Testable claims that must hold post-implementation:

**Claim BC1:** every boot chain-anchors exactly one `substrate:boot_ceremony:complete` receipt whose `composed_status` reflects reality.

**Claim BC2:** for each declared invariant, either an `invariant:<name>:verified` or `invariant:<name>:violated` or `invariant:<name>:skipped` receipt exists in the current boot's ceremony run. No silent invariant.

**Claim BC3:** adding a new sovereignty provider (say, a hypothetical `PassphraseProvider`) fails CI until each entry in the `sovereignty_provider` composition matrix has a passing verification test under `PassphraseProvider` mode, AND the provider's `[provider.passphrase]` entry contains a `verification_hash` derived from actual test runs.

**Claim BC4:** applying the discipline retroactively to today's Trezor failure — the vault-key composition drift — would have caused Trezor's `[provider.trezor]` entry's `verification_hash` to fail the `vault_key_derivation` verification test at the moment Trezor was added, blocking the merge until vault-key derivation was migrated to route through `load_sovereign_root`.

**Claim BC5:** operator can inspect the last N boots' ceremony receipts via `zp chain query "substrate:boot_ceremony:complete" --last 10` and see composed status, invariants covered, invariants degraded, invariants tolerated — for each boot in a stable structured format.

**Claim BC6:** two peer substrates running identical binaries against identical chain state produce identical `invariant:<name>:verified` receipts (up to per-run UUID). Divergence across peers = drift discovery per REPRODUCIBILITY-CEREMONY.

**Claim BC7:** the ceremony itself is chain-anchorable — its own invariants, catalog amendments, and matrix changes flow through SUPERSESSION-FRAMEWORK-2026-07.md. Meta-loop terminates because every amendment is itself an arc.

---

## Part IX — What this does NOT decide

- **Which invariants are boot-time vs build-time vs both.** The seed catalog names some as boot, some as build; the boundary is per-invariant judgment. Migrated over time as substrate matures.
- **Failure mode escalation.** Whether a specific invariant failure blocks-boot or degrades-boot is per-invariant policy declared in the invariant's schema. Composes with SUBSTRATE-READINESS-CONTRACT §Part V's blocking-vs-degraded semantics.
- **Operator override of ceremony failure.** An emergency operator ceremony to force-boot a substrate whose invariants failed needs its own spec — composes with RECOVERY-CEREMONY-UX-2026-07.md.
- **Cross-substrate composition-matrix federation.** Whether one substrate's composition matrix can compose with another's under kinship scope is a Layer B question with its own follow-up.
- **Runtime post-boot invariant re-verification cadence.** How often chain-read canary and observer coherence re-check invariant claims between boots is per-invariant policy. Some ceremonies revalidate quickly (chain integrity); others rarely (composition matrix, since it changes at capability-addition time not runtime).

---

## Part X — Follow-up work

Enumerated so future arcs can pick up cleanly.

**Immediate (blocks first shipping ceremony):**
- Implement `zp verify --composition` — validates composition_matrix.toml integrity, checks referenced test symbols exist, recomputes provider verification hashes.
- Implement B0–B2 phase runners in `zp-server` boot path.
- Migrate the four architectural claims from EMPIRICAL-PROGRAM to boot-invariant status with implementations.
- Author test implementations for the three tonight-discovered invariants (vault_key composes, cli operator load composes, default config boots functional).
- Populate `[provider.trezor]` with verified hash after test runs.

**Near-term:**
- Migrate remaining zp-cli surfaces (25+ call sites per VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md) so `cli_operator_load_composes_with_provider` invariant passes across all verbs, not just `emit`.
- Add invariant tests for the placeholder invariants named in Part III.
- Wire `discipline:pin:sovereign_root_composition` build-time check.
- Wire `discipline:pin:no_silent_degradation` from SUBSTRATE-READINESS-CONTRACT.

**Longer-term (deferred):**
- Compose with hardware observer discipline once HARDWARE-OBSERVER-2026-07.md implementation lands.
- Compose with substrate-form-graduation ceremony (SUBSTRATE-FORM Part XIV.3 — form graduation must include invariant re-verification under new form).
- Boot-time compositional performance profiling — some invariants are expensive; caching (per capability_manifest_hash) needs discipline.

---

## Composes with / connects to

- **SUBSTRATE-READINESS-CONTRACT-2026-07.md** — declarative layer above; readiness receipts derive from ceremony evidence.
- **SUBSTRATE-HARDENING-CEREMONY-2026-07.md** — certification state that this ceremony maintains at every boot.
- **VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md** — the finding whose fix invariant BC4 makes structurally impossible to regress.
- **EMPIRICAL-PROGRAM-2026-07.md** — the four architectural claims migrate here as boot-verified invariants.
- **REPRODUCIBILITY-CEREMONY-2026-07.md** — peer verification of ceremony receipts.
- **BUILD-PROCESS-DESIGN-2026-07.md** — build ceremony emits `discipline:composition_matrix:verified`.
- **CHAIN-READ-CANARY-DISCIPLINE-2026-07.md** — post-boot continuous verification.
- **OBSERVER-COHERENCE-DISCIPLINE-2026-07.md** — cross-observer agreement on invariant state.
- **SUPERSESSION-FRAMEWORK-2026-07.md** — invariant catalog amendments.
- **IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md** — new invariants as chain-anchored arcs.
- **RECOVERY-CEREMONY-UX-2026-07.md** — operator interface for boot-blocked substrate.

## CLAUDE.md workflow heuristics this exercises

- *Silence is the enemy, not compromise. Detectability over invulnerability.* — KEEL invariant this discipline serves at the strongest tier: at boot, before any silence is possible.
- *Verify before commit.* — every substrate claim is verified against actual state before it becomes chain-anchored evidence. Ceremony IS this heuristic elevated to structural discipline.
- *When two reasonable architectural models conflict over the same surface, half-state is the failure mode.* — composition tests catch half-state at capability addition, not at operator discovery.
- *Operational configuration with multiple write paths is structural drift waiting to happen.* — invariants covering "single-source-of-truth" claims turn this heuristic into structural check.
- *Singular sovereign root: one authentication, everything derived.* — the `sovereign_root_composition` discipline pin structurally enforces the heuristic across every Genesis-consumer surface.
- *Substrate operational state is chain-anchored evidence, not inferred silence.* (nominated in SUBSTRATE-READINESS-CONTRACT) — the boot ceremony is where this heuristic operationalizes.

## Proposed new heuristic (nomination for CLAUDE.md)

**Composition is proven at ceremony time, not discovered at operator time.**

*If capability C composes with N existing dependent surfaces, the composition MUST be verified — via runnable tests, chain-anchored receipts, cryptographic hashes — before C ships to any operator. Discovery of composition drift by an operator hitting a surface manually is a substrate defect: not the operator's problem, not tomorrow's improvement, not "we'll add tests later." The discipline pin catches drift structurally; the boot ceremony catches drift empirically; both compose so composition drift class becomes impossible-to-ship.*

*Applies whenever a capability class (sovereignty provider, inference provider, extension surface, ontology projector, chain-watcher pattern, kinship scope, cognitive input source) gains a new implementation. First implementation of a class establishes the matrix; every subsequent implementation must be verified against every surface the matrix names.*

*Composes with `verify before commit` (P) at the ceremony layer, `signing is gravity` (P1) at the chain layer, and `one canonical path per substrate concern` (P8) at the discipline-pin layer.*
