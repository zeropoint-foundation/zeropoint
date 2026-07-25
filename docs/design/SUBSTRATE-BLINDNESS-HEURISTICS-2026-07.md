# Substrate Blindness Heuristics

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.15 (substrate boundary planes), §II.17 (cognitive discipline sandwich), §III.18 (delegable safety), §III.23 (coordination not oversight), §III.24 (aligned blindness). Specifies the substrate's designed-blindness discipline: data classes an aligned substrate has no business observing or retaining, four-layer refusal model, canonical blind classes, and operator-declared extensions. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `OBSERVATION-PLANE-2026-07.md` (observation-scope delegation now composes with blindness discipline), `COGNITIVE-INPUT-PLANE-2026-07.md` (cognitive-layer boundary as one blindness layer), `WIFI-SENSING-AND-RF-SURVEILLANCE-2026-07.md` (raw CSI cognitive-layer boundary as prior instance of pattern), `CRISIS-RESPONSE-CEREMONY-2026-07.md` (mental-state trigger discipline as prior instance), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (coordination-not-oversight as prior instance), `QUARANTINE-PLANE-2026-07.md` (default-deny shape applied to data classes rather than artifacts), `EXTENSION-SURFACE-2026-07.md` (extension capability declarations checked against blindness).

## Framing

An aligned substrate has no business observing or retaining certain classes of data. This is not privacy configuration layered on top of a permissive baseline; it is a moral property of what the substrate is. Holding a keystroke stream, a live camera feed, or a chain-anchored medical diagnosis creates only harm — either directly (data breach exposes secrets no substrate should have held) or downstream (chain-anchored records used against operator's interests in circumstances the operator can't foresee). The substrate's alignment is partly constituted by what it structurally refuses to see, even under operator authorization.

The discipline has been implemented piecemeal across earlier specs — WIFI-SENSING's raw-CSI cognitive-layer boundary, CRISIS-RESPONSE's mental-state trigger discipline, SOVEREIGN-KINSHIP-PRIMITIVES' coordination-not-oversight, vault's encrypted-only-storage — without being named as a first-class principle. This spec pulls the discipline out explicitly: designed blindness is the substrate's structural refusal to see what it has no business seeing. Different from privacy-by-default (which is about disclosure); different from data minimization (which is about collection scope); different from encryption (which is about protection in transit and at rest). Substrate blindness is about **not creating the observation in the first place** — even under operator authorization, even for well-intentioned use cases, even when the technical mechanism exists.

Three properties frame the discipline:

1. **Blindness is an alignment property, not a privacy feature.** The question is not "would the operator want us to observe this?" or "could we usefully observe this?" — the question is "does an aligned substrate have any legitimate business seeing this class of data?" For some classes, the honest answer is no.
2. **Blindness is layered.** Some classes the substrate structurally cannot see (baseline substrate lacks the observation mechanism). Some the substrate could see but refuses by default (extension declaring the capability gets flagged prominently at admission, operator ceremony required to authorize). Some pass through observation surfaces incidentally and are scrubbed before chain-anchoring. Some reach cognitive layer only as findings, never as raw. Four layers of refusal composing into structural blindness.
3. **Blindness is operator-extensible but not fully operator-overridable.** Operator can declare additional blind classes for their specific concerns. Operator can grant limited authorization for specific classes when compelling use case exists. But canonical blind classes cannot be structurally overridden — the substrate's alignment properties are invariant across operator preferences.

## The four-layer refusal model

Different data classes warrant different refusal mechanisms. Substrate discipline categorizes each blind class into one of four refusal layers.

### Layer 1 — Structural inability

Substrate literally does not have the observation mechanism. No keylogger primitive; no full-screen capture primitive; no clipboard-monitoring primitive; no camera stream ingestion path. Even if operator asked for it, adding the capability would require modifying the substrate itself (extension surface admission of an extension declaring this capability class) — not a configuration change, a substrate change.

Extensions declaring Layer-1 blind class capabilities are flagged at Quarantine Plane admission ceremony with maximum prominence. Admission requires explicit operator ceremony acknowledging the alignment concern; typical operator ceremony is refusal.

### Layer 2 — Default refusal, delegable with elevated ceremony

Substrate could technically observe (mechanism exists, perhaps for adjacent legitimate purposes) but refuses by default. Operator can authorize for narrow use case via ceremony that specifically acknowledges the alignment concern. Not silently on/off — every observation of Layer-2 blind data is chain-anchored with ceremony reference so the arc is visible.

Example: continuous fine-grain location history is Layer-2 blind by default. Operator can authorize location observation for declared emergency triggers (hiking-safety-check, medical-crisis-response) via ceremony that names the specific trigger and scope. Substrate never observes location for background telemetry.

### Layer 3 — Scrubbing before chain-anchoring

Some data passes through observation surfaces incidentally — a process name might include command-line arguments that contain secrets; a network connection log might include URLs with embedded credentials; a filesystem observation might include filenames revealing sensitive content. Substrate has pattern-based scrubbing that redacts known-sensitive patterns before chain-anchoring the observation event.

Scrubbing patterns are chain-anchored (operator-declared or default) so the scrub discipline is auditable. Chain-anchored evidence shows "observation occurred, sensitive pattern scrubbed" rather than either "observation occurred with raw content" (privacy failure) or "no observation occurred" (audit failure).

### Layer 4 — Cognitive-layer boundary

Certain classes pass through observation and extension surfaces to produce chain-anchored evidence, but never reach the cognitive layer as raw content — Regent's context contains only high-level findings derived from the data, not the data itself. Cognitive Self-Observer verifies that Regent's outputs don't leak raw content that shouldn't be in her context.

Example (from WIFI-SENSING): raw CSI is captured by sensing extensions, produces chain-anchored biometric findings, but never enters Regent's context as raw signal. Findings like "operator's respiratory pattern is regular" reach Regent; the raw CSI stream does not.

Four layers composing per class: some data is blocked at Layer 1 entirely; some is Layer 2 refusable-with-ceremony; some passes through with Layer 3 scrubbing; some reaches cognitive layer as Layer 4 findings only. Operator dashboard surfaces the applicable layer for each declared observation scope.

## Canonical blind classes

The following classes are canonical blind — the substrate refuses to observe or retain them per the specified layer. These classes are alignment invariants; they cannot be structurally overridden even by operator authorization (Layer 1 classes) or can be authorized only under narrow-ceremony (Layer 2 classes).

### Layer 1 — Structural inability

- **Keystroke content**. Substrate does not include a keylogger primitive. Even operator's own text is not observed at keystroke granularity. Extension declaring keystroke-observation capability gets maximum-prominence flag at admission.
- **Full-screen capture as substrate operational data**. Screenshots for user-initiated documentation are fine (operator generates them explicitly); continuous screen observation as substrate telemetry is not.
- **Full clipboard monitoring**. Clipboard access for operator-initiated paste operations happens through OS mechanisms; substrate does not observe clipboard content as background telemetry.
- **Cryptographic private key material in the clear**. Vault handles encrypted storage; substrate never observes private key content directly. Sovereign root operations (per SINGULAR-SOVEREIGN-ROOT-2026-05.md) touch derived material only.
- **Raw camera/microphone stream ingestion as substrate operational data**. Extensions producing findings from camera/microphone are fine (Layer 4 handling); raw stream storage is not.
- **Sexual/intimate content**. Substrate does not observe content classified as intimate. Extensions handling intimate-content generation for operator's own use may exist under strict extension discipline; substrate baseline has no observation.
- **Content of communications with dependent sovereigns**. Per DEPENDENT-SOVEREIGNTY, guardian scope includes coordination authority but not communication content surveillance. Communication between operator and dependent is not substrate-observed.

### Layer 2 — Default refusal, delegable with elevated ceremony

- **Continuous fine-grain location history**. Location for declared emergency triggers is authorized under CRISIS-RESPONSE-CEREMONY; continuous location observation for background context is not. Operator ceremony required for any location observation, scoped to declared purpose.
- **Financial transactions at individual-transaction granularity**. Household coordination on high-level state ("groceries done" / "budget in range") is fine; individual transaction observation is default-blind. Operator can authorize for specific tools with narrow scope.
- **Medical diagnoses of operator or kindred**. Care coordination via kinship scopes handles findings ("kindred needs check-in"); specific diagnoses stored as chain content are default-blind. Operator can authorize for medical-record-adjacent tools with strict scope.
- **Mental health / addiction / substance use state**. Per CRISIS-RESPONSE-CEREMONY, Regent is not therapy; substrate does not surveil for mental-state indicators; specific diagnoses are default-blind. Operator can authorize crisis-trigger declarations that reference these states without embedding them in chain content.
- **Immigration status, criminal history, protected class information**. Not observed as substrate data. Operator ceremony required for any observation, and even then only under narrow declared use case.
- **Legally privileged communications** (attorney-client, therapist-patient, spousal privilege). Content of privileged communications is default-blind. Metadata about occurrence (that a legal consultation happened) may be observable under narrow authorization; content is not.

### Layer 3 — Scrubbing before chain-anchoring

- **Command-line arguments containing secrets**. Substrate observes process states; sensitive-looking argument patterns (`--password=X`, environment variables named `*_SECRET`, `*_KEY`, `*_TOKEN`) are scrubbed before chain-anchoring.
- **URLs with embedded credentials**. Network observation happens; URLs matching `user:pass@` patterns are scrubbed.
- **Filenames revealing sensitive content**. Filesystem observation happens; specific patterns matching operator-declared sensitivity classes are scrubbed.
- **API request bodies passing through governed tools**. Governed tool audit records tool calls; request body content matching sensitive-pattern scrubbing rules is redacted before chain-anchoring.

### Layer 4 — Cognitive-layer boundary

- **Raw sensing signals (CSI, audio, motion streams)**. Per WIFI-SENSING; extensions produce findings, Regent sees findings.
- **Raw content of communications observed via metadata surfaces**. Communication metadata may reach cognitive layer under coordination scope; message body content does not.
- **Vault credential values**. Vault handles credential access; Regent's context never contains credential values, only handles/references.
- **Detailed medical/psychological state signals from sensing extensions**. Findings like "operator's activity level is low today" reach Regent; specific medical inferences do not.

## Operator-declared blind classes

Operator can declare additional blind classes via chain-anchored ceremony. Format:

```
substrate:blindness:declared_class
  fields:
    class_name: <operator_chosen_identifier>
    layer: <1|2|3|4>
    scope: <what surfaces this applies to>
      - observation_plane_scope
      - extension_capability_class
      - chain_content_pattern
      - cognitive_input_source
    patterns: <if layer 3, redaction patterns>
    rationale: <operator's declared reasoning>
    signature: <operator Genesis signature>
```

Operator-declared blind classes compose with canonical set. Operator can strengthen (Layer 2 canonical class can be declared Layer 1 for their substrate) but cannot weaken (Layer 1 canonical class cannot be operator-declared to Layer 2).

## What the substrate does NOT blind

Some observation classes are essential to substrate operation and are not candidates for blindness. Explicit enumeration prevents "let's blind everything" drift:

- **Chain integrity metadata** — chain-tail hashes, receipt signatures, hash-linkage state. Substrate must observe these to verify chain integrity.
- **Officer findings** — per OBSERVATION-PLANE, findings are the substrate's discipline for reporting state; not candidates for blindness.
- **Operator's explicit declarations to Regent** — operator's direct communication with Regent is Tier 4 cognitive input by design; the operator is explicitly directing substrate attention.
- **Security-critical anomalies detected by Sentinel** — Sentinel's role is detection; classes it must observe to fulfill role are not candidates for blindness.
- **Substrate's own operational state** — process states, port bindings, extension activity — substrate self-observes to maintain the lsof-test discipline.
- **Ceremony receipts** — operator ceremony events are explicitly chain-anchored; not candidates for blindness.

## Composition with existing specs

- **OBSERVATION-PLANE-2026-07.md**: observation-scope delegation now composes with blindness discipline. Delegation attempts for classes on canonical blind list are Layer 1 refused (mechanism absent) or Layer 2 refused (default-deny with elevated ceremony required).
- **QUARANTINE-PLANE-2026-07.md**: extension admission checks capability declarations against blindness discipline. Extensions declaring Layer 1 blind class capabilities are refused; extensions declaring Layer 2 classes flagged prominently at admission.
- **COGNITIVE-INPUT-PLANE-2026-07.md**: cognitive-layer boundary is Layer 4 of blindness. Regent's input assembly filters out classes flagged as cognitive-layer-blind before assembling context.
- **WIFI-SENSING-AND-RF-SURVEILLANCE-2026-07.md**: raw CSI cognitive-layer boundary is one specific instance of Layer 4. This spec generalizes the pattern.
- **CRISIS-RESPONSE-CEREMONY-2026-07.md**: mental-state trigger discipline is one specific instance of Layer 2 for mental-health-adjacent state. This spec generalizes the pattern.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md**: coordination-not-oversight (KEEL III.23) is the cross-sovereign application of blindness discipline — substrate refuses categorical review of another sovereign's life regardless of grant.
- **SHARED-SPACE-SENSING-ETIQUETTE-2026-07.md**: strangers-in-shared-spaces treatment is a specific blindness class — no identification, no relationship graphs, no categorical retention.
- **EXTENSION-SURFACE-2026-07.md**: capability class declarations are checked against blindness discipline. Extensions declaring blind capability classes go through elevated admission ceremony.
- **CognitiveSelf-Observer**: verifies Regent's outputs don't leak classes that should be cognitive-layer-blind. Extends existing scope-compliance discipline.

## Attack model

- **Attacker declares extension with hidden blind-class observation**: capability declarations are inspected; extensions attempting to observe blind classes fail admission ceremony or land as violation receipts.
- **Attacker attempts to induce operator to authorize Layer 2 blind class observation**: elevated ceremony requirement makes authorization deliberate; Cognitive Self-Observer flags proposed authorizations that would broaden observation surface into blind classes.
- **Attacker compromises extension to smuggle blind-class content into chain**: chain-anchored evidence includes source extension; anomalous content patterns detectable via scrubbing checks and cognitive self-observer post-emission verification.
- **Attacker exploits Layer 3 scrubbing gap**: known unscrub patterns produce chain-visible sensitive content. Community-declared scrubbing pattern catalog per DISTRIBUTED-KNOWLEDGE-COMMONS enables federation-wide scrubbing improvements.
- **Attacker manipulates operator to declare blindness weakening**: operator ceremony cannot weaken canonical blind classes; ceremony attempts inconsistent with canonical layer produce validation failure receipts.
- **Attacker uses covert channel via metadata to reconstruct blind-class content**: metadata scope for coordination purposes is bounded; substantial metadata that would enable content reconstruction violates the metadata scope discipline.
- **Attacker triggers observation via edge-case surface not covered by blindness classification**: substrate community catalogs edge cases as they're discovered; blindness canonical set expands via ceremony over time.

## Failure modes

- **Legitimate operational need for observation in blind class**: operator must weigh alignment concern against operational need. Layer 2 classes have ceremony authorization path; Layer 1 classes structurally do not. When operational need is compelling for a Layer 1 class, community-level substrate design ceremony (per SUPERSESSION-FRAMEWORK) can propose reclassification with full corpus review.
- **Scrubbing false positive**: legitimate content redacted as sensitive-pattern match. Operator can declare unscub patterns for specific known-safe cases; substrate community catalogs common false-positive patterns.
- **Scrubbing false negative**: sensitive content passes through unscrubbed. Post-hoc detection triggers scrubbing pattern refinement; historical chain content is not retroactively scrubbed (chain is truth) but future observations use refined patterns.
- **Cognitive Self-Observer misses blind-class leak in Regent output**: post-emission verification is best-effort; missed leaks are chain-visible artifacts that operator can identify. Standing correction discipline (Task #55) enables operator to teach observer more precisely.
- **Operator ceremony to authorize Layer 2 class becomes routine**: authorization ceremonies are chain-visible; over-authorization patterns detectable. Substrate can surface pattern to operator for reflection.
- **Extension in good faith requires capability that composes with blind class**: extension admission surfaces the composition explicitly; operator judgment resolves whether the operational benefit justifies the observation.

## Non-goals

- **Not universal data minimization**. Substrate observes what's necessary for operation; blindness discipline is about specific classes with high harm potential.
- **Not privacy compliance certification**. Blindness aligns with typical privacy frameworks but is not defined by them. Substrate discipline is stronger where alignment concerns warrant.
- **Not encryption discipline**. Vault handles encryption. Blindness is about not observing in the first place; encryption is about protecting observations that legitimately exist.
- **Not consent management**. Consent frameworks assume observation happens with authorization; blindness structurally refuses observation regardless of consent path.
- **Not automatic policy adjustment**. Blindness classes are ceremony-declared and ceremony-modified; substrate does not autonomously add or remove classes based on observed patterns.
- **Not absolute against determined adversary**. Substrate blindness raises attacker cost significantly but is not impenetrable. Physical access to devices, coercion of operators, and other out-of-substrate attacks may bypass blindness discipline.
- **Not retroactive to existing chain content**. Chain is truth; historical content is not scrubbed. Blindness applies forward from declaration.

## Open positions

- **Federation-wide scrubbing pattern catalog**. Cross-operator collaboration on effective scrubbing patterns; commons-hosted pattern library with reputation flow.
- **Extension-declared blindness compositions**. Extensions may declare that their capability composes with blindness in specific ways; standardized declaration schema.
- **Blindness inspection UX**. Operator dashboard for reviewing which classes are blind, at which layer, under what authorization. Currently-active Layer 2 authorizations, recent scrubbing events, cognitive-layer boundary compliance.
- **Cross-operator blindness convention**. Community-declared standards for which classes are blind in "good practice" substrates. Reputation flow for operators who adhere.
- **Enterprise blindness inheritance**. Team or organization-level blindness declarations that individual operator substrates inherit by default.
- **Blindness in cross-operator interactions**. Kindred sovereign's substrate holds blind classes about their own operator; when interacting with our substrate, blindness composition rules across sovereigns.
- **Post-hoc audit of blindness compliance**. Verification tools for chain-review to confirm blindness discipline was honored across a substrate's history.
- **Scrubbing pattern testing**. Test corpus for scrubbing patterns to validate false positive / false negative rates before deployment.

## What composes from here

Immediate design work:

1. **Canonical blind class registry** — chain-anchored canonical list with per-class layer assignments
2. **Operator-declared blind class schema** — receipt structure for operator extensions
3. **Layer 3 scrubbing pattern registry** — canonical patterns and operator-declarable additions
4. **Cognitive-layer boundary enforcement integration** — Cognitive Input Plane filters against blind class list
5. **Extension admission integration** — capability declarations checked against blindness at Quarantine Plane admission

Near-term implementation:

1. **Blindness registry runtime** in `crates/zp-server/src/blindness/`
2. **Layer 3 scrubbing pipeline** integrated with chain-anchoring emission paths
3. **Cognitive Input Plane filter for Layer 4 classes**
4. **Extension admission checks against blindness discipline**
5. **Cognitive Self-Observer extension for blind-class leak detection**
6. **Dashboard blindness panel**: canonical classes, operator declarations, recent scrubbing events, Layer 2 authorizations, boundary compliance status
7. **CLI verbs**: `zp blindness list|declare|revoke`, `zp blindness scrubbing pattern|test`, `zp blindness audit`

## Framing note

Substrate blindness heuristics pull out an alignment discipline the corpus has been implementing piecemeal into a first-class named principle. Same substrate structural approach as elsewhere: chain-anchored, layered, operator-declarable within bounds, ceremony-visible.

The load-bearing insight: **an aligned substrate has no business observing certain data classes, regardless of technical capability or operator authorization for adjacent purposes.** Blindness is not privacy configuration layered on top of a permissive baseline; it's a moral property of what the substrate is. What the substrate structurally refuses to see is part of its alignment identity — as constitutive as what it does see and how it acts on what it sees.

Combined with the substrate's structural discipline across every trust boundary, blindness heuristics complete the alignment envelope. What was previously implicit — that a well-designed substrate would refuse to hold keystroke logs, or intimate content, or chain-anchored medical diagnoses, because holding them creates only harm — becomes structural: canonical blind classes declared, refusal layers assigned, extension admission gated, cognitive-layer boundary enforced, scrubbing pipeline discipline. Sovereignty is preserved because operator can extend blindness for their specific concerns and can authorize Layer 2 observations for narrow declared use case. Safety is preserved because alignment properties are invariant — Layer 1 canonical classes cannot be structurally overridden. Continuity is preserved because chain records what blindness discipline was in effect at every observation event, so future audit of substrate behavior can verify alignment held. The substrate is aligned not just by what it does, but by what — by design — it never sees.
