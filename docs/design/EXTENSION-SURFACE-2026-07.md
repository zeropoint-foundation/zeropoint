# Extension Surface

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` Part V (Composition Contract) with the specific application of extending the substrate via third-party WASM modules. Introduces trait families, capability declaration language, delegation ceremony specialization, and composition rules for extensions. Canonical claims live in KEEL; this doc provides implementation-level detail and design rationale.

Draft — 2026-07-10 — internal audience only. Composes with `QUARANTINE-PLANE-2026-07.md` (extensions are the primary application of executable-artifact admission), `OBSERVATION-PLANE-2026-07.md` (extensions can add observation sources with delegation), `COGNITIVE-INPUT-PLANE-2026-07.md` (extensions can be matrix input providers), `CIRCUIT-BREAKER-2026-07.md` (extensions arrestable at scope), `BLAST-RADIUS-AND-RECOVERY-2026-07.md` (extensions have declared dependencies and cascade discipline), `SUBSTRATE-FORM-2026-07.md` (Form determines capability envelope).

## Framing

Every mature computing ecosystem eventually grows an extension mechanism. Chrome has extensions; VS Code has extensions; Kubernetes has operators; Home Assistant has integrations; Emacs has packages. The pattern is universal because operating systems, editors, and platforms cannot ship every capability their users need — capability composition through third-party contribution is how ecosystems scale.

Every mainstream extension mechanism gets one of two things wrong. Either the vendor gates all extensions (App Store model — trust flows through the vendor, extension developers are subordinates, users cannot install what the vendor disapproves of), or the vendor doesn't gate extensions at all (browser extension free-for-all — no meaningful trust discipline, malicious extensions common, permission dialogs users don't read). The tension is between vendor control (safer but restrictive) and user freedom (permissive but unsafe).

The extension surface is the substrate's structural discipline against this tension. Extensions in ZP are:

1. **WASM modules implementing trait interfaces** — capability extensions, not standalone apps. They plug into the substrate's existing surfaces (officer cadre, Regent's verbs, observation surfaces, ontology, gate policy). They don't replace anything; they extend what the substrate can do.
2. **Chain-anchored delegation** — operator IS the gate. No app store. No vendor approval. Extension developer signs their WASM; operator signs delegation receipt granting declared capabilities. Trust flows through operator Genesis, not through an external authority.
3. **Bounded by canonical trait contracts** — extensions cannot invent new host interfaces. They implement declared trait families; substrate publishes trait contracts; changes to contracts happen via canonicalization ceremony.

The unifying insight: **an extension is just a WASM module with a canonical trait interface, chain-anchored delegation, and Genesis-derived signing authority.** Officers, policy modules, apps, protocol adapters — all instances of the same architectural primitive at different trust delegations. The only difference between an internal officer and a third-party extension is *who signed it* and *what delegation the operator granted*. Same machinery all the way down.

This is a stronger claim than "we have an app ecosystem." It's: **the substrate has one composition primitive, and everything — foundation-shipped, community, personal — is an instance of it.** No architectural distinction between "core" and "extensions." Just different delegations from operator Genesis.

## Trait families

The substrate publishes canonical trait interfaces. Extensions implement one or more; delegation ceremony grants capability scope for the implemented trait.

### OfficerExtension

Extension implements the Officer trait. Adds a new officer to the cadre.

- **Purpose**: domain-specific concerns not covered by Steward/Sentinel/Forge/Cleo/Aegis
- **Examples**: financial-hygiene officer (monitors credential rotation cadence, expense pattern anomalies), health-officer (with delegation to observe local sensor data), legal-review officer (monitors contract lifecycle receipts)
- **Trait interface**: same as internal officers per SYSTEM-OFFICER-CADRE-2026-06.md §II.10 (KEEL) — `sweep(chain, vault_keys) → Vec<Finding>`, watch patterns, activation modes
- **Capability declarations**: chain read scopes, observation surface subscriptions, finding-emission authority
- **Composition**: emitted findings flow to officer-cadre same as internal officers; no ordering guarantees among officers of same rank

### VerbExtension

Extension implements a new verb usable by Regent (or by CLI). Adds to the operator's delegable capability surface.

- **Purpose**: extend Regent's tool set with capabilities not in the base substrate
- **Examples**: analyze_dataset verb, transcribe_audio verb, translate_text verb, review_diff verb, generate_image verb (with operator-declared model provider)
- **Trait interface**: `dispatch(params: json, delegation_scope: DelegationScope) → Result<Output, Error>`; declared parameter schema; declared output schema
- **Capability declarations**: host interfaces needed (network egress to specific endpoints, filesystem read/write scopes, inference-backend usage, memory bounds, compute-time bounds)
- **Composition**: appears in Regent's tool vocabulary when active delegation grants use; multiple verbs on same name resolved by delegation precedence

### ObservationSurfaceExtension

Extension implements a new observation surface. Adds a new source of chain-anchored observations.

- **Purpose**: extend observation plane beyond the six canonical surfaces (processes, network, filesystem, persistent, credentials, application state) with substrate-relevant external signals
- **Examples**: home-automation sensor bridge (temperature, motion, occupancy), wearable device bridge (biometrics with strict operator delegation), external service state observer (upstream API status, third-party incident feeds)
- **Trait interface**: `sample() → Vec<ObservationReceipt>` per sensor primitives; `subscribe(pattern) → Stream<ObservationReceipt>` for event-driven surfaces
- **Capability declarations**: what surface class it observes, sample cadence bounds, chain-write scope
- **Composition**: extends `OBSERVATION-PLANE-2026-07.md` §"The six observation surfaces" with new declared surfaces; delegation follows the same pattern

### OntologyExtension

Extension implements a new ontology object type. Adds structured objects the Cartographer materializes.

- **Purpose**: enrich the Cartographer's ontology with domain-specific object types
- **Examples**: FinancialAccount object (tracks credential-scoped account state), HomeDevice object (tracks devices observed via home-automation bridge), Vehicle object (tracks vehicle state via external observer)
- **Trait interface**: `materialize(chain_slice: ChainSlice) → Vec<OntologyObject>`; declared object schema; declared relationships to existing objects
- **Capability declarations**: chain-read scopes, cartographer cache-write scope
- **Composition**: officers can query new object types via extended ontology; Regent's cognitive input plane can reference new objects; new objects can be linked to existing Trajectories/Decisions/Insights/Artifacts/Frictions

### CognitiveInputSourceExtension

Extension implements a new source class for Regent's cognitive input plane matrix.

- **Purpose**: extend Regent's cycle input with domain-specific context sources
- **Examples**: external knowledge base bridge (Wikipedia lookup, RFC index), personal knowledge context (Obsidian vault contents with strict operator delegation), specialized filter for officer findings (domain-specific noise suppression)
- **Trait interface**: `compose_for_cycle(matrix_config: MatrixConfig, cycle_context: CycleContext) → SourceOutput`; declared priority tier eligibility; declared filter behavior
- **Capability declarations**: chain-read scopes, external-data-source scopes, prompt-length bounds
- **Composition**: extends `COGNITIVE-INPUT-PLANE-2026-07.md` §"The composition matrix" with new source classes; matrix specification (Layer B canonical) declares which extensions provide sources at which tiers

### ProtocolAdapterExtension

Extension implements a bridge to an external protocol. Translates external protocol messages into substrate-native ontology + emits chain receipts for outbound.

- **Purpose**: substrate participates in external ecosystems without those ecosystems needing to know about ZP
- **Examples**: Matrix bridge, ActivityPub adapter, Bluesky adapter, IMAP/SMTP bridge for email, Slack bridge, WhatsApp bridge (with proper attention to end-to-end encryption), NNTP bridge, RSS reader
- **Trait interface**: `inbound(external_msg) → Vec<OntologyObject>`; `outbound(intent: OutboundIntent) → Result<ExternalConfirmation, Error>`; declared protocol identifier
- **Capability declarations**: network scopes, external-authentication (protocol-specific auth), chain-write scope, ontology-write scope
- **Composition**: inbound messages arrive as chain-anchored observations; outbound intents pass through gate; substrate becomes a first-class citizen of external protocols without the ZP substrate leaking to those protocols

### PolicyExtension

Extension implements new policy modules for the gate.

- **Purpose**: extend gate policy language with domain-specific rules
- **Examples**: rate-limit policy per delegation class, geographic-scope policy for network egress, business-hours policy for automated actions
- **Trait interface**: `evaluate(action: Action, context: PolicyContext) → PolicyDecision`
- **Capability declarations**: chain-read scopes for policy state, deterministic-execution constraint (policy evaluation must be deterministic per KEEL §II.9)
- **Composition**: gate policy engine chains configured policy modules; constitutional rules (HarmPrincipleRule, SovereigntyRule) always evaluate first per KEEL §II.3; extension policies evaluate in declared order

### CeremonyExtension

Extension implements a new ceremony flow.

- **Purpose**: custom canonicalization ceremonies, custom Form-graduation flows, custom recovery ceremonies, custom key-rotation ceremonies
- **Examples**: multi-operator quorum ceremony (M-of-N Genesis signature aggregation), external-anchor ceremony (chain anchoring to public blockchain), community-vote ceremony (collective decision-making with reputation weighting)
- **Trait interface**: `initiate(ceremony_params) → CeremonyState`; `advance(state, participant_action) → CeremonyState`; `complete(state) → Result<CeremonyReceipt, Error>`
- **Capability declarations**: chain scopes, participant-identification methods, timeout bounds
- **Composition**: extends `KEEL-2026-07.md` Part XI (Genesis Ceremony) and Part VI (Canonicalization Ceremony) with new ceremony flows; each new ceremony is chain-anchored as a specific ceremony class

## Capability declaration language

Extensions declare their required capabilities in a manifest that ships alongside the WASM binary. Declaration is fine-grained — not "network access" but "network egress to specific endpoints"; not "chain read" but "chain read matching specific filter patterns."

### Declaration structure

```toml
[extension]
name = "example-extension"
version = "1.0.0"
author_key = "ed25519:abc123..."
wasm_hash = "blake3:def456..."
substrate_min_version = "2026-07"
trait_implementations = ["VerbExtension", "OntologyExtension"]

[capabilities.chain_read]
scopes = [
  { filter = "trajectory:*", justification = "Reads trajectory state to compose recommendations" },
  { filter = "artifact:*", justification = "References artifacts in recommendations" },
]

[capabilities.chain_write]
scopes = [
  { receipt_type = "example:recommendation:*", justification = "Emits recommendation receipts" },
]

[capabilities.network_egress]
endpoints = [
  { host = "api.example.com", port = 443, protocol = "https", justification = "Fetches external data for analysis" },
]

[capabilities.filesystem]
read_scopes = [
  { path_pattern = "~/Documents/*.md", justification = "Reads user notes for context" },
]
write_scopes = []

[capabilities.inference_backend]
usage_bounds = { max_calls_per_hour = 100, max_tokens_per_call = 4000, justification = "LLM analysis of user input" }

[capabilities.host_functions]
imported = ["substrate.chain_read", "substrate.emit_receipt", "substrate.inference_dispatch"]
```

### Fine-grained principles

- **No wildcard authority**. Extensions cannot declare "all chain scopes." They declare specific filter patterns; substrate audits declared vs actually-used.
- **Justification per capability**. Every declared capability has an operator-readable justification. When operator reviews the delegation ceremony, they see WHY each capability is requested.
- **Bounded rather than infinite**. Rate limits, token bounds, request-per-hour ceilings. Extensions cannot request unbounded resource usage.
- **Explicit endpoints, not "network access"**. Egress declarations name hosts and ports. Substrate can enforce at the network layer.
- **Declared trait implementations**. Extensions cannot implement traits not declared; substrate audits WASM imports vs manifest.

### Audit mechanism

Quarantine plane's verification step (per QUARANTINE-PLANE §Step 2) includes capability audit for extensions:

1. Parse manifest declarations
2. Parse WASM module's actual imports (declared vs used check)
3. If imports don't match declarations, `quarantine:verification_failed:capability_mismatch`
4. If manifest declares wildcard patterns (`*` alone in filters), `quarantine:verification_failed:overly_broad_capability`
5. If host functions in imports don't match trait implementations, `quarantine:verification_failed:trait_import_mismatch`

Structural audit — not policy-based. Extensions physically cannot import host functions not declared, and declarations must be fine-grained.

## Delegation semantics

Extension admission ceremony (per QUARANTINE-PLANE §Step 3) is specialized for extensions:

### Operator review surface

Dashboard panel presents:
- Extension name, author, version
- Trait implementations
- Capability declarations with per-capability justifications
- WASM hash and build reproducibility check (if source available, can rebuild and hash-check)
- Author's signing key and trust chain to any operator-trusted anchor (Genesis-derivable? Or specific author previously trusted?)
- Related receipts: prior extensions from same author (if any), operator's history of delegations to this author

Operator can:
- **Grant all requested capabilities** — sign delegation with declared scope
- **Grant a subset** — sign delegation narrower than requested; extension may fail at runtime if narrowed scope prevents core function; substrate emits `extension:capability_denied:<extension>:<capability>` when narrowed capability is invoked
- **Refuse** — sign quarantine:rejected with reason
- **Defer** — leave in quarantine, decide later

### Grant syntax

```
delegation:granted:extension:<wasm_hash> {
  granted_by: operator_genesis,
  granted_at: timestamp,
  capabilities: {
    chain_read: [ filter_patterns_granted ],
    chain_write: [ receipt_types_granted ],
    network_egress: [ endpoints_granted ],
    filesystem: { read: [...], write: [...] },
    inference_backend: { max_calls_per_hour: N, max_tokens_per_call: M },
    host_functions: [ list_granted ],
  },
  scope_narrowing_notes: "Narrowed from wildcard *.example.com to api.example.com only",
  expiry: optional_timestamp,
  revocation_priority: high | normal,
  justification: "operator's note on why this delegation was granted",
}
```

### Runtime enforcement

- Layer A observes delegation state
- When extension is invoked, gate checks each host function call against delegation
- Undeclared or ungranted calls: `gate:blocked:extension_over_delegation:<extension>:<call>` receipt, function returns error to WASM
- Extension can recover gracefully or fail; either way, chain records the attempt

### Revocation

- Standard delegation revocation: `delegation:revoked:extension:<wasm_hash>` — extension unloaded, in-memory state discarded, chain retains history
- Circuit breaker trip at extension scope (per CIRCUIT-BREAKER §"Trip scopes"): emergency arrest, terminated per BLAST-RADIUS §"Termination semantics"
- Extension uninstall: separate ceremony that revokes delegation AND deletes the extension from quarantine store

## Composition rules

Multiple extensions can implement the same trait. Composition rules declare how conflicts resolve.

### Officer composition

Multiple OfficerExtensions active simultaneously — no conflict. Each officer sweeps independently; findings flow to officer-cadre; no coordination required beyond the chain-anchored composition contract per SYSTEM-OFFICER-CADRE.

### Verb composition (name conflicts)

Two extensions register verb with same name (e.g., both provide `analyze_dataset`). Resolution:

- Delegation precedence: most recent operator delegation for that verb name wins
- Operator can explicitly declare precedence in delegation: `preferred_provider = "extension_hash_X"`
- Substrate emits `extension:verb_conflict:<name>` observation so operator sees the conflict

Both extensions remain admitted; Regent's tool vocabulary shows only the winning provider.

### Observation surface composition

Multiple surfaces adding observations of the same domain — no conflict. Chain-anchored receipts flow; officers aggregate. Multiple sources with the same or overlapping observations is fine (may indicate corroboration or may indicate redundancy — officers can reason about the pattern).

### Ontology composition

Multiple extensions declaring the same object type — must have identical schema, or substrate rejects the later admission with `quarantine:verification_failed:ontology_schema_conflict`. If two extensions want to materialize similar concepts differently, they must use distinct object names.

### Policy composition

Multiple policy extensions in the gate — chain-anchored order determines evaluation sequence. Constitutional rules always first. Operator sees the order in delegation ceremony and can reorder via subsequent ceremony.

### Ceremony composition

Ceremonies are specific-purpose; no name conflict expected. If it happens (two extensions declare the same ceremony class), later admission rejected with schema conflict per ontology composition rule.

## Extension lifecycle

### Install

1. Extension arrives at quarantine plane (via `zp extension install <path>` or `zp extension install <url>` or from delegated distribution source)
2. Quarantine ceremony per QUARANTINE-PLANE §"The admission ceremony"
3. Operator delegation ceremony
4. Extension moved to `$ZP_DATA/extensions/<wasm_hash>/`
5. Layer A loads WASM, verifies trait implementations, registers with substrate
6. Emit `extension:installed:<wasm_hash>` receipt
7. Extension is active

### Update

1. New version arrives at quarantine plane (different hash, same author key or explicitly delegated update authority)
2. Full quarantine ceremony (verification, capability audit)
3. Operator delegation ceremony — reviews capability delta (what's new vs old)
4. On admission, old version's delegation is superseded but not revoked; old version can be kept for rollback
5. Emit `extension:updated:<old_hash>:<new_hash>` with capability delta

### Revoke

1. Operator or circuit breaker fires revocation
2. Extension's WASM instance is arrested per BLAST-RADIUS termination semantics
3. Delegation marked revoked; chain retains history
4. Extension stays in `$ZP_DATA/extensions/` (available for re-admission if operator changes mind) unless explicit uninstall

### Uninstall

1. Operator signs uninstall ceremony receipt
2. Any active delegations revoked (uninstall implies revocation)
3. Extension WASM deleted from `$ZP_DATA/extensions/`
4. Ontology objects materialized by the extension: preserved (they exist on chain); no longer updated
5. Chain retains full history of the extension's lifetime

## Distribution model

Extensions ship via multiple channels; none are exclusive.

### Peer-to-peer

Sovereign operators can share extensions with each other via mesh/network per DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md. Extensions are content-addressed; receiver verifies hash + author signature + quarantine ceremony independently.

Reputation composes: extensions from peers with high reputation admit faster (precedent-based auto-verification for known-good authors); low-reputation-source extensions go through full manual ceremony.

### Ordinary web

Author publishes on their website; operator downloads; imports to substrate. Same quarantine ceremony regardless of source.

### Physical media

Extensions can ship on USB drives, printed QR codes (small WASM), etc. Fully offline installation possible. Same ceremony.

### Foundation-shipped

Foundation may ship canonical extensions (reference implementations, protocol adapters for major protocols, etc.). These arrive via canonicalization ceremony (Layer B change) and quarantine ceremony (executable admission). Foundation is not privileged — its extensions are admitted by same discipline as any other. Operator can refuse.

### Extension registries

Third parties may run extension registries (indexes of available extensions, reputation aggregation, review). Registries are advisory only — substrate does not trust the registry, only the individual extension signature + author.

## Form implications

Extension capabilities depend on Substrate Form.

### Sovereign Form

Full extension capability envelope. Extensions can:
- Observe host processes, network, filesystem (with delegation)
- Access all six observation surfaces
- Extend cognitive input plane with matrix inputs
- Extend gate policy modules
- Run WASM at maximum performance
- Access hardware self-observer (with narrow delegation)

### Appliance Form

Same as Sovereign on the appliance. Extensions running on appliance have full capability envelope. Daily-driver client can request extension actions but the actions run on appliance where the delegation lives.

### Companion Form

Extension capabilities bounded by vendor permissions. Form Disclosure names the reductions:
- Observation surfaces limited to vendor-permitted subsets
- Network egress bounded by vendor restrictions (some corporate MDM environments block outbound entirely)
- Filesystem scopes limited by TCC (macOS) or equivalent

Extension developer targets a specific Form for their extension. Cross-Form extensions declare capability sets per Form. Substrate refuses admission on Form where declared capabilities aren't achievable.

## Sandboxing details

WASM sandbox is one layer. For high-risk capability classes, additional isolation:

### WASM sandbox (default for all extensions)

- Extensions cannot access memory outside their declared linear memory
- Extensions cannot access host functions not declared in manifest
- Extensions cannot spawn threads (WASI-experimental only, requires explicit capability declaration)
- Extensions cannot execute native code

### Process isolation (optional per extension class)

For extensions handling high-value credentials or accessing sensitive host resources:
- Extension runs in dedicated OS process
- Communication with substrate via chain-anchored IPC
- Compromise of one extension does not affect substrate process
- Higher resource cost; enabled per operator delegation ceremony

Declared via `[isolation]` section in extension manifest; operator sees the isolation level in delegation ceremony.

### Network egress via mediated proxy

Extensions declaring network egress route through substrate-mediated proxy:
- Substrate observes every outbound request
- Endpoint enforcement (extensions cannot connect to endpoints not in delegation)
- Response inspection possible for known-content-type endpoints
- Chain-anchored `extension:network_egress:<extension>:<endpoint>` receipts

Prevents extensions from bypassing delegation via DNS tricks or IP manipulation.

## Content addressability

Every extension is content-addressed by BLAKE3 hash of the WASM module. This is:
- Uniquely identifying (different builds of same source are different hashes)
- Verifiable (anyone can rebuild and hash to check)
- Immutable (hash change = new extension identity, requires re-admission)

Extension versioning:
- Same-author, same-name, different hash = version update per Extension Lifecycle §"Update"
- Different author, same name = distinct extensions; operator distinguishes via author key
- Same hash = literally same extension; deduplication in storage

Reproducible builds:
- Manifest can include `source_url` and `build_command` for verification
- Substrate can optionally run `zp extension verify <hash>` to rebuild and check
- Reproducibility is not mandatory but strengthens trust

## UI surface (for extensions that need it)

Most extensions don't need their own UI — they extend Regent's response, dashboard panels, or officer findings. But some extensions genuinely need a dedicated UI surface (personal data organizers, visualization tools, custom dashboards).

Options ordered by isolation:

### Dashboard panel injection

Extension declares a dashboard panel (HTML fragment) that renders inside the substrate's dashboard. Fragment is served from the extension's static assets; runs in dashboard's origin with strict CSP. Communication with extension WASM via defined message-passing interface.

Cheapest option; suitable for most extension UI needs.

### Regent verb output as UI

Extension provides verb that returns structured UI descriptor; Regent renders it as part of her response. Extension has no separate UI surface; UI lives in the operator-Regent conversation.

Cleanest option; suitable when extension's job is conversational.

### Bundled web-view (last resort)

Extension bundles a full web-view (HTML/CSS/JS assets), rendered in substrate-mediated iframe or dedicated window. Isolation stronger; substrate mediates all network egress from the web-view; substrate can enforce content policies.

Highest isolation cost; suitable for extensions that need rich UI (visualization tools, editors).

Form Disclosure covers UI implications — Companion Form may have UI reductions per vendor restrictions.

## Composition with the substrate architecture

- **Quarantine Plane**: extension admission specialized per §"Delegation semantics"
- **Observation Plane**: ObservationSurfaceExtensions extend the six canonical surfaces
- **Cognitive Input Plane**: CognitiveInputSourceExtensions extend the matrix; extension state can be composed into Regent's context
- **Circuit Breaker**: extension scopes are first-class; extensions arrestable at extension:<hash> scope; graduated escalation applies
- **Blast Radius**: extension dependency graph declared; cascade discipline applies; termination semantics per extension class
- **Substrate Form**: capability envelope varies by Form; extensions declare Form-specific capability sets
- **Genesis**: extension author signs; operator delegation is Genesis-signed; trust chain is verifiable

## Attack model

- **Malicious extension declaring benign capabilities**: WASM audit at admission catches import mismatch. If declared and used capabilities match but the used capabilities are being weaponized, circuit breaker triggers on anomalous behavior; operator reviews.
- **Extension attempting to bypass delegation**: gate enforces every host function call against delegation. WASM cannot import undeclared functions. Attempts to exceed delegation are structural failures.
- **Compromised extension developer signing key**: prior delegations to compromised author remain valid (chain history is truth); operator can revoke via ceremony; future extensions from same key face operator skepticism. Reputation composes.
- **Extension consuming excessive resources**: resource bounds declared in manifest; substrate enforces at runtime; excess triggers circuit breaker escalation.
- **Extension colluding with other extensions to bypass individual delegations**: cross-extension communication is chain-anchored; substrate observes patterns; officers can propose findings on collusion patterns.
- **Extension exfiltrating data via network egress**: egress endpoints declared; enforcement at proxy layer; chain-anchored observation of egress.
- **Extension exploiting WASI sandbox escape**: WASI evolves; substrate updates as sandbox escapes are patched; layered defenses (process isolation for high-risk capability classes) mitigate.
- **Extension registry poisoning**: registries are advisory only; individual extension signature + author key are what substrate trusts.

## Non-goals

- **Not standalone apps**. Extensions plug into substrate; they don't replace substrate surfaces. If a use case genuinely requires a standalone app, that's a different substrate consumer (a tenant framework), not an extension.
- **Not a monetization framework**. Extensions can charge for themselves via any external payment mechanism their author chooses; substrate doesn't mediate transactions. This is deliberate — payment mediation is a trust boundary too big for substrate to bear.
- **Not an app store**. Substrate is not a directory of extensions. Operator finds extensions via ordinary means (author websites, peer recommendation, mesh discovery); operator installs deliberately.
- **Not exclusive to the substrate ecosystem**. Extensions can bridge external protocols. Substrate operators can participate in external ecosystems via ProtocolAdapterExtensions.

## Open positions

- **Extension packaging format**. WASM binary + manifest + optional static assets. What's the canonical archive format? `.zpx` extension? Standard tar+gzip? Uncompressed directory? Design choice.
- **Reproducible-build verification cost**. Rebuilding an extension to verify hash is expensive. When should substrate do it? Every admission? First time only? Never (trust author signature)? Configurable per operator preference.
- **Cross-Form extension declarations**. Should extensions declare Form-specific capability sets in single manifest, or separate manifests per Form? Prefer single with Form-conditional sections for simplicity.
- **Extension update authority**. Author key updates its own extension. Should operator implicitly trust updates from same author, or require ceremony per update? Currently: full ceremony per update; may relax with reputation.
- **Composition ordering for policy extensions**. Chain-anchored order is explicit. UX for reordering — dashboard panel with drag-drop? CLI verb? Design work.
- **UI surface CSP defaults**. Dashboard panel injection has strict CSP; what specific policies? Case-by-case per capability class or unified?
- **Extension-to-extension communication**. Should extensions be able to call each other's verbs? If yes, delegation semantics for extension-to-extension trust. If no, all cross-extension coordination happens via chain-anchored receipts only. Prefer no for simplicity.

## What composes from here

Immediate design work:

1. **Trait interface specifications** — precise Rust trait signatures for each of the eight extension trait families
2. **Capability declaration schema** — canonical TOML/JSON schema for extension manifests
3. **Delegation grant schema** — receipt shape for `delegation:granted:extension:*`
4. **Composition rules per trait** — explicit rules for name conflicts, precedence, ordering
5. **Distribution primitives** — CLI verbs and chain receipts for install/update/revoke/uninstall
6. **Isolation modes** — declared per extension class in the manifest; enforcement at Layer A

Near-term implementation:

1. Extension loader in `crates/zp-server/src/extensions/` — reads manifest, loads WASM, verifies capabilities, registers with substrate
2. Extension-scoped delegation enforcement at gate
3. Extension-scoped observation-plane emission with per-extension signing key derived from operator's delegation
4. Extension arrest infrastructure per BLAST-RADIUS termination semantics
5. Dashboard panel for extension management (list installed, delegation review, install/uninstall)
6. CLI verbs: `zp extension install|update|revoke|uninstall|list|verify`

## Framing note

The extension surface completes the substrate's composition story. Officers, policy modules, ontology types, ceremony flows, cognitive input sources, observation surfaces, protocol adapters, Regent verbs — all instances of the same primitive at different trust delegations. The substrate has one composition primitive; everything is an instance of it. No architectural distinction between "core" and "extension." Just Genesis-derived delegation.

This is the antidote to the vendor-gatekeeper model that plagues every mainstream extension ecosystem. Operator IS the gate. Extensions ship via any channel; operator admits via chain-anchored delegation ceremony; substrate enforces structurally. No approval bottleneck; no gatekeeper rent-extraction; no vendor-controlled trust model. Trust flows through operator sovereignty, always.

Combined with the three planes (observation, quarantine, cognitive input), the circuit breaker with graduated escalation and forward-only recovery, the two observer patterns (hardware, cognitive), and the delegable-safety heuristic, the substrate now has full structural discipline for the entire trust envelope: normal operations, deliberate composition, emergency response, and open ecosystem participation. One canonical discipline; multiple applications; every boundary chain-anchored, Genesis-derived, structurally enforced.
