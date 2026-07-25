# Operator Death and Legacy

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §III.20 (forward-only recovery), §III.23 (coordination not oversight), Part VII (Peer-Verification Contract), Part XI (Genesis ceremony). Specifies the substrate's discipline for the transition from active-sovereign to memorial-sovereign state when an operator dies. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `GENESIS-ROTATION-CEREMONY-2026-07.md` (rotation and death are structurally related — both are Genesis-authority transitions; death is one-way and forward-authority-terminating), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kindred notifications, care sovereign activation), `CRISIS-RESPONSE-CEREMONY-2026-07.md` (death is one class of crisis; some early-detection paths compose), `PEER-TRUST-ANCHOR-2026-07.md` (peer notification and trust anchor updates), `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (pre-death operator preferences).

## Framing

The substrate is designed to be someone's sovereign infrastructure across years and decades. It holds their Genesis, their chain, their kinships, their commitments, their observations, their extensions, their Regent's accumulated context. When operator dies, all of this remains as chain-anchored truth — but the operator no longer signs forward. The substrate needs a coherent story for that transition.

The failure mode without discipline: substrate continues emitting under presumption-of-liveness (peer sync, officer heartbeats, chain-watcher firings) while operator is dead. Extensions continue running. Regent continues attempting to serve. Kindred sovereigns' Regents receive stale coordination signals. Chain accumulates receipts that no operator can meaningfully attest to. Eventually peers notice silence and infer death, but ad-hoc; heirs cannot access anything the operator hadn't explicitly given them; care sovereigns learn through non-substrate channels; and the substrate infrastructure itself becomes an unmaintained artifact accumulating operational debt.

Operator Death and Legacy discipline addresses this structurally. Three properties frame it:

1. **Chain is truth; death does not modify chain.** Forward-only recovery (KEEL III.20) applies universally. Old signatures remain valid as historical evidence forever. The death declaration is itself a chain-anchored ceremony receipt that marks the transition from active-sovereign to memorial-sovereign state — it does not delete or invalidate anything.

2. **Detection is ceremony-based, not surveillance-based.** Coordination-not-oversight (KEEL III.23) applies here strongly. Substrate does not autonomously monitor operator biometrics for death indicators. Death is declared through pre-designated protocols: dead man's switch heartbeat cessation, executor declaration, kindred attestation, or official record — all requiring ceremony rather than pattern-matching.

3. **Legacy is pre-declared by operator, not inherited by default.** Operator declares in advance who has access to what after death — specific chain-slice scopes to specific beneficiaries. Without pre-declaration, chain is preserved but no legacy access is authorized. Substrate does not autonomously distribute operator's chain content to kindred; the operator's choices about what to share, and with whom, are honored.

## Pre-death declarations

Operator declares in advance via chain-anchored ceremony. Declarations are revocable and can be updated as circumstances change (new executors, changed beneficiaries, evolved preferences).

### Executor designation

Operator designates one or more executors — sovereigns with pre-authorized narrow scope to handle post-death substrate concerns. Executor is not a successor sovereign; executor holds specific chain-anchored capabilities delegated in advance.

Receipt: `legacy:executor_designated:<executor_id>:<designation_id>`. Fields:
- Executor sovereign identity (Genesis public key)
- Priority in executor set (if multiple)
- Scoped capabilities delegated to executor (see below)
- Optional conditions on activation
- Requires operator Genesis signature and executor's acceptance signature

Executor capabilities are narrow by design. Canonical set:
- `legacy:capability:declare_death` — authority to emit death declaration receipt
- `legacy:capability:notify_kindred` — authority to trigger kindred notifications
- `legacy:capability:notify_peers` — authority to trigger peer trust anchor updates
- `legacy:capability:activate_legacy_scopes` — authority to activate pre-declared legacy access scopes for beneficiaries
- `legacy:capability:dispose_hardware` — authority to make chain-anchored decisions about substrate hardware disposition (retain, archive, destroy)
- `legacy:capability:conclude_extensions` — authority to gracefully shut down running extensions

Executors do NOT get:
- Authority to sign forward as the operator (that's structurally impossible — operator's Genesis is not held by executors)
- Authority to modify chain history (forward-only invariant)
- Authority to modify operator's pre-declarations (only operator could, and operator is dead)
- Access to legacy scopes not designated for them (executor is not automatically a beneficiary)

Multi-executor thresholds (M-of-N): for high-consequence executor actions, operator can require M-of-N executor signatures. Prevents single-executor abuse.

### Legacy access scope declarations

Operator declares in advance what parts of chain become accessible to whom after death. Declarations are chain-anchored via `legacy:scope_declared:<scope_id>` receipts.

Canonical legacy scope classes:

- `legacy:scope:chain_read_access` — beneficiary gains read access to chain content within specified time range or receipt-class filter
- `legacy:scope:correspondence` — beneficiary gains access to preserved communications (chat logs, message threads, cross-Regent narrations they were party to)
- `legacy:scope:kinship_history` — beneficiary can review kinship narrations they were part of (not other kinships they weren't part of — that would exceed operator's original grant to them)
- `legacy:scope:artifact_access` — beneficiary can access created artifacts (documents, media, code, etc.)
- `legacy:scope:memorial_public` — designated chain content becomes publicly readable for memorial purposes (published works, public communications, biographical timeline)
- `legacy:scope:private_family` — specific content accessible only to designated beneficiary set (family archives, personal writings, private correspondence within family)
- `legacy:scope:trajectory_access` — beneficiaries can review specific Trajectories from operator's life (per ontology; trajectories operator chose to make accessible)

Each scope has:
- Beneficiary(ies)
- Content selector (what part of chain is accessible)
- Activation condition (default: death declaration; optional: additional gates like waiting period, executor confirmation, memorial ceremony completion)
- Optional expiry
- Optional access modality (read-only vs read-plus-annotate for legacy tributes)

Beneficiaries may be:
- Specific sovereigns (their Genesis public keys)
- Sovereign classes (kindred at specific labels — "chosen family")
- Community-defined groups (via commons)
- Public (memorial_public class only)

### Memorial preferences

Operator declares memorial preferences via chain-anchored receipts:

- `legacy:memorial_preference:notification_scope` — who should be notified beyond automatic kindred notifications (extended community, professional connections, etc.)
- `legacy:memorial_preference:ceremony_authorization` — whether community memorial ceremonies chain-anchored on operator's chain are authorized (some operators want quiet transitions; others want community memorial as chain-anchored artifact)
- `legacy:memorial_preference:hardware_disposition` — preferred disposition of substrate hardware (heir, archive, destroy, gift)
- `legacy:memorial_preference:regent_transition` — how Regent should transition (immediate memorial state, gradual with executor-authorized final narrations, etc.)

### Standing corrections about death

Operator can declare specific corrections about how their death should be handled — e.g., "if death is declared and I've been diagnosed with cognitive decline, prefer earlier executor activation" or "if death is declared with active kinships in high-scope-sharing state, notify each kindred sovereign individually rather than via broadcast."

These are standing corrections per STANDING-CORRECTION-RECEIPT-SCHEMA, in the domain `legacy.death_handling`.

## Detection mechanisms

Detection is ceremony-based. Substrate does not autonomously monitor for death indicators via biometric surveillance. The substrate has structural mechanisms to notice possible death and trigger appropriate response ceremonies.

### Dead man's switch (liveness heartbeat)

Operator's substrate emits regular liveness heartbeats — chain-anchored receipts confirming operator is present and substrate is operational under operator authority. Cadence declared by operator (typical: daily, weekly, or monthly per operator preference; some may prefer no heartbeat).

Heartbeat mechanism:
- Substrate emits `sovereign:liveness_heartbeat:<timestamp>` receipt at declared cadence
- Chain-watcher on heartbeat cadence: if heartbeat missed by more than N intervals (operator-declared threshold), watcher fires `sovereign:liveness_concern:<detection_id>` receipt
- Concern receipt notifies designated executors and care sovereigns per operator's preferences
- Executors investigate via out-of-band means (call operator, check in, verify status)

Heartbeat is not "operator is fine" attestation — it's just "substrate is operating under operator authority." Operator being alive but temporarily offline (vacation, illness, hospital stay without substrate access) can trigger heartbeat cessation without indicating death. Operator can declare in advance: extended-absence exemptions (heartbeat pause receipts operator emits before periods of expected offline), variable-cadence based on context, or graceful-degradation thresholds.

### Executor-initiated declaration

Executor, having verified operator's death via out-of-band means (medical confirmation, direct observation, official notification), can emit death declaration ceremony. Executor's authority comes from pre-designation.

Emit `sovereign:death_declared:<operator_id>:<declaration_id>` receipt with:
- Reference to executor designation receipt
- Executor's Genesis signature
- Timestamp of declared death (may differ from timestamp of declaration)
- Verification method (medical, direct observation, official record, etc.)
- Optional supporting evidence (if operator authorized inclusion)

Multi-executor threshold (M-of-N) applies if operator declared it. Death declaration receiving M signatures becomes authoritative.

### Kindred sovereign attestation

Kindred sovereigns with `emergency_notification` scope on the kinship can emit attestation receipts if they witness or learn of operator's death. Attestations do not themselves declare death; they contribute to the declaration ceremony as evidence.

Emit `sovereign:death_attestation:<attester_id>:<attestation_id>` referencing the kinship declaration. Executor considers attestations alongside their own verification.

### Official record integration

In jurisdictions with civil death registries, external attestation (via peer notification from official registry peer trust anchor) can be one signal. Operator can pre-authorize official records as an accepted verification method.

## Death declaration ceremony

Once death is declared, the ceremony proceeds through structured phases. Chain-anchored at each step.

### Phase 1 — Declaration

Executor(s) emit `sovereign:death_declared` receipt per Detection Mechanisms. If M-of-N required, ceremony pauses until threshold is met. Chain-anchors the declaration.

### Phase 2 — Forward-authority cessation

From the declaration receipt forward, no new signatures under operator's Genesis are accepted as authoritative. This is structural — operator's Genesis is not physically held by executors, so no forward signing was possible anyway; the ceremony makes the cessation explicit.

Substrate emits `sovereign:forward_authority_ceased:<declaration_id>` receipt. All in-flight operations under operator authority complete or are gracefully aborted per delegation.

### Phase 3 — Kindred notification

Kindred sovereigns notified per operator's declared preferences. Notification content is bounded per each kinship's scope; care sovereigns receive earlier and more directly than distant kindred.

Emit `sovereign:kindred_notified:<kinship_id>:<notification_id>` receipts per each notification. Care sovereigns can then engage the family/community through human channels.

Cross-Regent narrations for death notification are strictly scope-compliant per Cognitive Self-Observer. Kindred sovereign's Regent decides how to surface to their operator per their own cognitive input plane discipline.

### Phase 4 — Extension conclusion

Extensions running under operator authority signaled to conclude. Some extensions may have graceful shutdown protocols; others may need forced termination. Each extension emits `extension:concluded:<extension_id>:<reason>` receipt.

Extensions holding state peers depend on may transition to memorial-preservation mode (chain state remains queryable; no forward operations).

### Phase 5 — Peer notification

Federated peers receive death notification via peer distribution protocol. Peers update their trust anchors for the deceased sovereign: no new peer-verified signatures from this sovereign; historical signatures remain valid; peer's chain records the transition.

Emit `peer:sovereign_deceased_acknowledged:<sovereign_id>` receipts on peers' chains.

### Phase 6 — Legacy scope activation

Executor with `activate_legacy_scopes` capability activates pre-declared legacy access scopes. Beneficiaries receive access to declared chain content per operator's declarations.

Emit `legacy:scope_activated:<scope_id>:<activation_id>` receipts per scope. Beneficiaries can then query per their granted access.

### Phase 7 — Regent memorial transition

Regent transitions from serving-operator to memorial state. No new dispatches accepted. Existing cognitive state preserved (chain-anchored per REGENT-ORCHESTRATION-ARCHITECTURE) for legacy-scope access to Regent's accumulated narrations, cross-Regent familiarity summaries, and operator's Regent-visible context.

Emit `regent:memorial_state:<sovereign_id>` receipt.

### Phase 8 — Hardware disposition

Executor with `dispose_hardware` capability makes chain-anchored decision per operator's pre-declaration. Options:
- **Retain**: heir or executor retains substrate hardware for legacy chain access. Hardware continues to hold chain; no forward substrate operations. Physical Genesis token may be held per operator's preference (some prefer heir holds it as memorial artifact; some prefer destruction to prevent misuse).
- **Archive**: hardware and chain preserved by community archival network (federation of archivists, historical societies, family archives) per operator's declaration.
- **Destroy**: hardware physically destroyed. Chain replicated to designated archival copies before destruction (per peer distribution).
- **Gift**: hardware gifted to designated recipient with chain preserved but Genesis token separately handled per operator's preference.

Emit `legacy:hardware_disposition:<disposition_type>:<disposition_id>` receipt.

### Phase 9 — Community memorial (if authorized)

If operator authorized community memorial per `legacy:memorial_preference:ceremony_authorization`, community can emit chain-anchored memorial ceremony record on the substrate's chain (via executor-authorized memorial ceremony receipts) or on community commons. This is optional and per operator preference.

### Phase 10 — Substrate to memorial-sovereign state

Substrate emits final ceremony receipt: `sovereign:memorial_state:<sovereign_id>:<final_declaration_id>`. From this receipt, the substrate is in memorial-sovereign state:
- Chain read-only for future queries
- No forward operations
- Legacy scopes remain active per their declarations
- Peer trust anchors updated
- Hardware handled per disposition ceremony

## The graduated response ladder

Death detection may not be immediate or unambiguous. Substrate supports graduated response between pre-death, suspected-death, and confirmed-death states.

- **Pre-death (active)**: substrate operates normally under operator authority
- **Liveness concern**: heartbeat missed; executors notified; substrate continues but ambient signal indicates concern
- **Suspected death**: executor confirmation absent; some evidence suggests but not conclusive; substrate reduces forward operations to essentials; kindred sovereigns notified of concern (not death) per operator preference
- **Confirmed death**: full ceremony proceeds
- **Rescinded**: operator returns; Genesis rotation ceremony re-establishes authority; chain records both the death sequence and rescission

Each level has clear chain-anchored transitions. Operator's pre-declarations govern thresholds between levels.

## The "died without pre-declarations" case

Operators who die without pre-declared executors or legacy scopes create a difficult case. Substrate handling:

- Heartbeat cessation triggers standard concern receipt
- Without designated executors, no one has substrate-authorized authority to declare death
- Peer-consensus death declaration is possible under federated protocol: after extended heartbeat cessation (multi-month threshold), multiple peers can jointly emit consensus-death receipt. This triggers minimum ceremony: forward-authority cessation, peer trust anchor updates, kindred notifications per whatever emergency_notification scope existed.
- Chain becomes read-only under peer-consensus declaration
- No legacy scopes activate (nothing pre-declared)
- Chain content becomes inaccessible except via broader legal mechanisms (probate, family law, community mediation) outside substrate scope

Substrate cannot solve this case unilaterally — pre-declaration is required for meaningful legacy handling. Operator UX should encourage but never require pre-declaration; encouragement is legitimate (Regent may propose reviewing legacy declarations periodically, dashboard may surface as recommended action), coercion is not.

## Rescinding death declaration

Operator returns after being declared dead. Rare but possible (near-death recovery, mistaken identification, communication delays with executor).

Rescission process:
1. Operator emits Genesis-signed rescission ceremony receipt via Genesis rotation protocol (GENESIS-ROTATION-CEREMONY-2026-07.md)
2. Executors verify via out-of-band means (direct meeting, medical verification)
3. Rescission ceremony receipts chain-anchor both the original death declaration and the rescission
4. Forward authority re-established: operator's new signatures accepted as authoritative from rescission forward
5. Legacy scopes deactivated (chain records both activation and deactivation)
6. Peers notified; trust anchors re-updated
7. Extensions may need re-activation via operator ceremony
8. Regent transitions from memorial state back to active-serving

Chain preserves the full arc: pre-death → concern → suspected → declared → memorial → rescinded → active. Nothing is deleted; everything is documented.

## Attack model

- **Attacker forges death declaration to seize substrate**: multi-executor thresholds (M-of-N) prevent single-executor abuse. Peer verification requirements. Kindred sovereign attestations as corroboration. Operator can review executor designations while alive.
- **Attacker manipulates heartbeat to trigger false liveness concern**: heartbeats are Genesis-signed by operator's substrate; forgery requires Genesis compromise. Extended-absence exemptions require operator ceremony to authorize.
- **Attacker gains executor authority to access legacy scopes**: executor role does not automatically grant legacy access. Executor with `activate_legacy_scopes` capability can activate declared scopes for their declared beneficiaries — beneficiaries designated by operator, not chosen by executor.
- **Attacker suppresses death notifications to delay legacy activation**: peer-consensus death declaration provides fallback; multiple peers noticing sustained heartbeat cessation trigger consensus mechanism after threshold.
- **Attacker forges rescission to reactivate authority under compromised Genesis**: rescission requires Genesis rotation ceremony protocol; Genesis rotation itself requires either operator's Genesis material or M-of-N recovery quorum. Compromised Genesis handled by rotation ceremony.
- **Attacker manipulates operator's pre-declarations before death**: pre-declarations are chain-anchored via operator's Genesis. Modification requires operator's Genesis signature. Attacker cannot silently alter beneficiaries without leaving chain evidence.
- **Attacker acts as false executor via impersonation**: executor designations reference specific Genesis public keys. Impersonation requires target executor's Genesis compromise.
- **Attacker forges community memorial receipts to modify perception**: memorial receipts chain-anchor on either operator's chain (require executor authorization) or on community commons (chain-verifiable per commons trust anchor discipline).

## Failure modes

- **Executor unavailable during declaration**: multi-executor threshold cannot be met. Substrate holds at suspected-death; peer-consensus fallback activates after extended threshold.
- **Peer-consensus threshold too high or low**: too high delays legitimate declarations; too low enables false declarations. Federation working spec calibration per empirical observation.
- **Operator dies with active legacy scopes for now-deceased beneficiaries**: scope activation fails for deceased beneficiaries; executor can propose remediation (redirect to their heirs per operator's intent, if declared) or leave scope dormant.
- **Extension shutdown fails during Phase 4**: extension holds state indefinitely; graceful degradation timers eventually force shutdown; chain records the extended shutdown period.
- **Regent memorial state accidentally receives dispatches**: substrate rejects; emits `regent:dispatch_rejected:memorial_state:<dispatch_id>` receipt.
- **Peer disagreement about death declaration**: some peers accept; others don't. Sovereign appears as dead-to-some, alive-to-others temporarily. Peer coordination convergence via chain evidence over time.
- **Rescission after extensive legacy activation**: activated legacy scopes deactivated but chain records that beneficiaries had access during the interval. May have real consequences (beneficiary already accessed content, made copies, shared with others). Substrate cannot un-do; only records the sequence.
- **Community memorial dispute**: some community members want memorial ceremonies; others don't. Operator's declared preference is authoritative for chain-anchored ceremonies; commons-hosted alternate ceremonies can exist outside substrate.

## Non-goals

- **Not autonomous death detection via biometrics**. Substrate does not surveil operator biometrics for death indicators. Coordination-not-oversight applies. Detection is ceremony-based.
- **Not substitute for legal death registration**. Substrate death declaration handles substrate concerns; civil registration, probate, and legal death handling are separate legal processes.
- **Not enforced legacy planning**. Operator can choose not to pre-declare. Substrate handles gracefully-degraded case without imposing pre-declaration as mandatory.
- **Not the memorial ceremony itself**. Substrate chain-anchors record of memorial if authorized; the memorial ceremony is a human event conducted by community.
- **Not enforcement of legacy scope access**. Substrate governs chain-anchored access; parties who have physical access to substrate hardware or backup copies may still access outside substrate discipline. Physical security is complementary.
- **Not resurrection ceremony for symbolic purposes**. Rescission is for actually-alive operators mistakenly declared dead, not for symbolic continuation of a deceased operator's identity.
- **Not universal executor availability guarantee**. If operator's designated executors all die before operator does, operator must re-declare or peer-consensus fallback applies.

## Open positions

- **Pre-declaration UX**. How does operator explore and declare executors, legacy scopes, memorial preferences? Dashboard flow? Regent-assisted declaration ceremony? Periodic review prompt?
- **Heartbeat cadence defaults**. What's reasonable default heartbeat cadence? Daily may be excessive; monthly may be too infrequent for meaningful liveness signal. Operator-tunable.
- **Peer-consensus death threshold**. What multi-month period without heartbeat before peer-consensus can declare? Trade-off: legitimate extended-offline vs stale sovereigns.
- **Extended-absence exemption mechanism**. Format for operator's pre-departure heartbeat pause receipts.
- **Legacy scope UI for beneficiaries**. How do beneficiaries discover their inherited access? How do they query legacy content? Substrate primitives + user-space applications.
- **Cross-cultural memorial norms**. Different cultures have different expectations about who is notified, ceremony forms, hardware disposition. Substrate primitives should compose with cultural norms via commons.
- **Legacy scope revocation by operator's family**. Some cultures allow family to modify beneficiary access after death. Substrate default: pre-declarations are authoritative. Extension for family-authorized modifications via multi-executor ceremony?
- **Ancestor sovereignty**. Long-dead sovereigns whose chains are historical archives — how does substrate handle century-scale chain preservation? Compose with archival federation.
- **Regent memorial state semantics**. Regent's accumulated cognitive context is potentially valuable historical resource. Under what legacy scope can beneficiaries interact with Regent's memorial state? Regent as memoirist for beneficiaries?
- **Substrate wills / notarized declarations**. Should legacy declarations require additional verification (peer witness, notary equivalent)? Trade-off: friction vs trustworthiness.

## What composes from here

Immediate design work:

1. **Pre-declaration schemas** — executor designation, legacy scope, memorial preference receipts
2. **Heartbeat mechanism spec** — cadence, verification, cessation detection
3. **Ceremony flow per phase** — receipt structures, transition rules, verification requirements
4. **Peer-consensus fallback protocol** — federation working spec for extended-offline handling
5. **Rescission ceremony spec** — how alive-operators reactivate after mistaken declaration
6. **Legacy scope query API** — how beneficiaries access their granted content

Near-term implementation:

1. Legacy state manager in `crates/zp-server/src/legacy/`
2. Heartbeat emitter and cessation detector
3. Executor designation runtime
4. Legacy scope declaration and activation runtime
5. Death declaration ceremony coordinator
6. Extension conclusion protocol
7. Peer notification distribution
8. Regent memorial state transition
9. Dashboard: legacy planning panel (executors, scopes, memorial preferences)
10. CLI verbs: `zp legacy executor|scope|preference|heartbeat|declare|rescind`

## Framing note

Operator death and legacy discipline addresses the substrate's most consequential lifetime-scale transition — the shift from active-sovereign to memorial-sovereign state. Same principle as chain-anchored discipline elsewhere: chain is truth; forward-only recovery; ceremony over surveillance; operator authorization for consequential state changes; coordination not oversight.

The load-bearing insight: **death does not modify chain; death terminates forward-authority.** Chain preserves everything that happened — operator's kinships, their commitments, their observations, their Regent's accumulated narrations, their created artifacts. Death is a chain-anchored ceremony marking transition, not deletion. Legacy access is operator-declared in advance; executors have narrow scoped capabilities pre-authorized by operator, not inherited sovereignty. Kindred are notified per operator's declared preferences; extensions conclude gracefully; peers update trust anchors; Regent transitions to memorial state; hardware disposition per operator's declaration. Nothing autonomous. Nothing surveillance-derived. Everything ceremony-anchored to operator's own pre-declarations while operator was alive.

Combined with the substrate's structural discipline across every trust boundary, operator death and legacy discipline completes the temporal envelope for lifetime-scale sovereignty. What was previously implicit — someone dies, their digital infrastructure decays, heirs navigate ad-hoc — becomes structural: pre-declared executors act within pre-declared capabilities; pre-declared legacy scopes activate for pre-declared beneficiaries; chain preserves the transition as truth; peers acknowledge the sovereignty change; substrate operates in memorial-sovereign state honoring the operator's life without allowing their identity to be forged forward. Sovereignty extends across a lifetime and honors what came before it. Everyone lives — and dies — better when their sovereignty transitions are chain-anchored to their own choices.
