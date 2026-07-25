# Crisis Response Ceremony

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.15 (substrate boundary planes), §II.16 (emergency response envelope), §II.17 (cognitive discipline sandwich), §II.18 (chain-anchored commitments), §III.18 (delegable safety), §III.19 (detectability over invulnerability), §III.22 (verify before commit). Specifies the substrate's discipline for how Regent responds when a chain-watcher fires on an operator-declared crisis trigger — medical event, physical safety, environmental emergency, or operator-declared mental-state trigger. Coordination-not-oversight discipline holds throughout: Regent responds to declared triggers, never to surveillance-derived patterns. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (`emergency_notification` and `mutual_safety_check` scopes gate cross-sovereign crisis activation), `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (chain-watchers on declared trigger patterns), `COGNITIVE-INPUT-PLANE-2026-07.md` (crisis-observation input at Tier 1), `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (operator's declared crisis handling preferences), `CIRCUIT-BREAKER-2026-07.md` (crisis may compose with graduated substrate response), `HARDWARE-OBSERVER-2026-07.md` (hardware-detected physical events as trigger source), `WIFI-SENSING-AND-RF-SURVEILLANCE-2026-07.md` (biometric findings can be declared crisis triggers under narrow operator authorization).

## Framing

The substrate provides coordination primitives that serve shared work between kindred sovereigns. Some coordination is for shared everyday activities; some is for emergencies. The `emergency_notification` scope, the `mutual_safety_check` scope, hardware-observer detected physical events, health-related biometric findings under narrow authorization — all of these can activate what the substrate treats as a *crisis*: an operator-declared class of event where the response envelope is heightened, care sovereigns may be reached out to, and Regent's normal disclosure discipline shifts to include time-critical action.

Crisis response ceremony specifies how Regent handles this class of event. Three properties frame the discipline:

1. **Crisis is operator-declared, not Regent-inferred.** Substrate does not surveil to catch crises; substrate acts on triggers the operator has declared as crisis-class events. Fall detection is crisis because operator has declared "unresponsive-plus-fall-detected activates emergency response." Erratic driving pattern is crisis if operator declared that trigger; otherwise it's just observation. Regent does not autonomously classify novel patterns as crises. Coordination-not-oversight extends into crisis discipline: no surveillance-derived crisis detection.
2. **Response is graduated, per operator declaration.** Not every crisis trigger activates the maximum response. Operator declares thresholds and preferences — some triggers activate silent chain-anchoring only; some activate Regent narration; some activate care sovereign notification; some activate emergency-services engagement. Ceremony follows operator's declared ladder.
3. **Care sovereign reach-out is narrow-scope by construction.** When Regent activates a care sovereign under `emergency_notification`, the reach-out content is bounded: "your kindred may need you; please check on them" without operator-crisis-detail disclosure unless operator has separately authorized detail-sharing under declared scope. Care sovereign then engages the human channel; substrate does not become the therapy or intervention layer.

## What counts as a crisis under substrate discipline

Crisis is any operator-declared trigger pattern. The substrate does not have an intrinsic list of "crises." Operators declare their own trigger patterns via chain-anchored ceremony receipts. Common trigger classes operators are likely to declare:

- **Physical medical events**: fall detection (via hardware observer or sensing extension), unresponsive-to-scheduled-check-in, biometric anomaly threshold breach under authorized `biometric_findings` scope, medical-device-declared alert
- **Physical safety events**: intrusion detection under `intrusion_awareness` scope, `mutual_safety_check` timeout without check-in, distress signal from personal-safety hardware, hardware observer detecting substantial environmental threat (fire, smoke, extreme temperature)
- **Substrate-integrity events**: Genesis compromise detected, chain integrity break, adversarial probing at threshold (per HARDWARE-COMPROMISE-EVIDENCE); some of these compose with CIRCUIT-BREAKER and this ceremony
- **Operator-declared mental-state triggers**: operator has explicitly declared, via chain-anchored ceremony with their own judgment about what serves them, specific patterns that should activate care contact. This class is delicate — see "The mental-state trigger discipline" below.
- **Environmental emergencies**: extreme weather event within operator's declared safety envelope, air quality thresholds, other environmental hazards operator has authorized as trigger patterns

Each declared trigger has:

- Pattern definition (what constitutes the trigger)
- Severity classification (which response level activates)
- Preconditions (only active under specific contexts — e.g., "only when I'm alone at home")
- Verification requirement (single signal or corroborated signals)
- Response ladder position

Trigger declarations are chain-anchored via `crisis:trigger_declared:<trigger_id>` receipts.

## The response ladder

Five graduated response levels. Operator declares which level each trigger activates. Ceremony follows the declared ladder unless operator-declared upgrade conditions apply (e.g., "if primary care sovereign doesn't respond within N minutes, escalate to next level").

### Level 0 — Silent chain-anchoring

Trigger detected. Regent emits `crisis:trigger_fired:<trigger_id>:<event_id>` receipt on chain. No operator disclosure. No care sovereign activation.

Purpose: baseline pattern recording without alarm. Trigger accumulates as evidence for post-hoc review. Useful for triggers where operator wants observation without response.

### Level 1 — Regent-narrated observation

Trigger detected. Regent narrates to operator with clear observation-vs-interpretation framing. "I noticed X pattern; you declared this as a Level 1 trigger; here's what I observed." Operator decides what to do.

Purpose: bring attention without alarm. Operator remains in control of interpretation and next steps.

### Level 2 — Regent-narrated concern

Trigger detected at concern threshold. Regent narrates with elevated urgency but not alarm. "This pattern concerns me based on your declared trigger; you may want to review it now." Operator decides.

Purpose: elevate operator attention without externalizing. Regent's cognitive delegation may include narrow authority to prompt operator's engagement (a nudge, not a demand).

### Level 3 — Care sovereign wellness check

Trigger detected at care-activation threshold. Regent reaches out to designated care sovereign under the narrow `emergency_notification` scope. Content: "your kindred may need you; please check on them." No operator-detail disclosure unless operator has separately authorized detail-sharing.

Care sovereign then engages the operator through human channels (calls, visits, whatever the relationship supports). Substrate does not intermediate the human interaction.

Regent also narrates to operator: "Because [trigger] fired, I've reached out to [care sovereign] to check on you."

### Level 4 — Multiple care sovereigns / professional support

Trigger detected at higher-severity threshold. Multiple care sovereigns activated per operator's declared priority list. If operator has authorized professional-support activation (crisis hotline, medical services), Regent activates per declared authorization.

Operator narration at this level is present but may not be primary — care sovereigns are the human channel.

### Level 5 — Emergency services

Trigger detected at emergency threshold. Regent activates emergency services (911, medical response) per operator's declared authorization. This level requires explicit operator pre-authorization for specific trigger classes; Regent does not autonomously call emergency services without pre-authorization.

Operator narration: "I've called emergency services because [specific trigger] fired at Level 5 authorization."

## Ceremony steps

For any trigger firing above Level 0, the ceremony follows:

### Step 1 — Trigger detection

Chain-watcher on declared trigger pattern fires. Emits `crisis:trigger_fired:<trigger_id>:<event_id>` receipt with:
- Trigger ID (reference to declaration)
- Event ID (this specific firing)
- Detection source (which chain-watcher, which observation surface)
- Signal fidelity (which signals confirmed)
- Timestamp

### Step 2 — Verification

Before any response above Level 0, verification per III.22:
- Claim Verifier confirms the trigger's structural integrity (signals present, thresholds met)
- Cognitive Self-Observer verifies against confabulation (is this really the trigger firing, or a pattern-match error?)
- Standing corrections consulted (has operator declared verification-fidelity preferences?)

Verification success emits `crisis:trigger_verified:<event_id>` receipt. Verification failure emits `crisis:trigger_unverified:<event_id>` receipt and downgrades response to Level 0 (recorded, not acted).

### Step 3 — Preconditions check

Operator-declared preconditions evaluated. If preconditions not met (e.g., trigger declared only-active-when-alone but operator is with others), response downgrades or defers per operator declaration.

Emits `crisis:preconditions_evaluated:<event_id>` receipt with result.

### Step 4 — Response level determination

From declared ladder + verification result + preconditions, response level determined. Emits `crisis:response_level_selected:<event_id>:<level>` receipt.

### Step 5 — Response execution

Per selected level, actions executed:
- Level 0: complete (already chain-anchored in Step 1)
- Level 1: Regent narrates to operator
- Level 2: Regent narrates with elevated urgency
- Level 3: Care sovereign reach-out via `emergency_notification` scope; operator narration
- Level 4: Multiple care sovereigns / professional support; operator narration
- Level 5: Emergency services engagement per pre-authorization; operator narration

Each action emits a corresponding receipt: `crisis:narration_delivered:*`, `crisis:care_sovereign_activated:*`, `crisis:emergency_services_activated:*`.

### Step 6 — Follow-through monitoring

Chain-watcher continues watching for:
- Operator response (acknowledgment, action taken, request for escalation or de-escalation)
- Care sovereign response (they've engaged, they're on their way, they've verified operator is OK)
- Emergency services response (if activated)
- Trigger pattern continuation or resolution

Emits `crisis:followthrough:*` receipts as events happen.

### Step 7 — Post-crisis review ceremony

After the event resolves (declared threshold met, operator or care sovereign confirms all clear), Regent proposes a post-crisis review ceremony:
- What triggered
- What was verified
- What response was taken
- Whether the ladder placement was appropriate in retrospect
- Whether trigger declaration should be adjusted (raise threshold, lower threshold, add preconditions)
- Whether care sovereign designation should be adjusted

Operator reviews. Ceremony emits `crisis:review_completed:<event_id>` receipt with any trigger adjustments.

## Care sovereign designation

Care sovereign is a kindred sovereign whose Regent operator has explicitly authorized to receive `emergency_notification` scope reach-outs. Designation is chain-anchored via `kinship:care_sovereign_designated:<kinship_id>:<designation_id>` receipt.

Designation includes:
- Priority in reach-out sequence (primary, secondary, etc.)
- Trigger classes for which this sovereign is a care contact (all, or specific classes)
- Detail-sharing authorization (usually: bounded reach-out only; sometimes: authorized to receive specific detail)
- Preferred contact modality if beyond substrate reach-out (phone number to call in addition to Regent-to-Regent narration)

Care sovereign responsibilities are per the human relationship, not substrate-enforced. Care sovereign accepts designation via their own chain-anchored ceremony. Their Regent knows they've accepted the role and can appropriately surface `emergency_notification` scope narrations to them.

Designation revocable via operator ceremony; revocation is chain-visible to the care sovereign.

## The mental-state trigger discipline

This is the most delicate trigger class and requires explicit discipline separate from other trigger classes.

**Substrate does not autonomously detect mental-state crises.** Regent does not classify operator patterns (mood signals, communication patterns, activity patterns) as crisis-indicating without operator declaration. Substrate coordination-not-oversight discipline holds here strongly: surveilling operator's mental state for crisis indicators is out of scope, even under operator authorization for well-intentioned purposes. Regent is a cognitive advocate, not a mental-health surveillance system.

**Operator can declare mental-state triggers explicitly, with their own judgment.** Some operators may wish to declare specific triggers: "if I haven't emerged from my apartment in N days, activate care contact." These declarations are the operator's own choice, chain-anchored, revocable. The substrate honors them but does not suggest them, does not pattern-match to propose them, does not extrapolate operator preferences into broader mental-state monitoring.

**Standing corrections govern disclosure discipline for mental-state observations.** Even without a declared trigger, operator may want Regent to handle observations of concerning patterns in specific ways. Standing corrections declare: "if you observe pattern X, note it silently unless I ask" or "if you observe pattern X, gently ask if I'm OK." These are operator-declared disclosure preferences; not autonomous Regent interpretation.

**Professional support is the appropriate crisis response for mental-state events.** Care sovereigns are for human presence and support. Professional support (therapist, crisis hotline, medical services) is for clinical intervention. Substrate can activate professional support at Level 4-5 only under operator's explicit pre-authorization for specific trigger classes; substrate does not substitute for professional care and does not autonomously escalate mental-state observations to clinical intervention.

**Regent does not become the therapy layer.** In all mental-state contexts, Regent's role is limited to: coordination per operator's declared preferences, activation of operator-designated support channels per declared authorization, and honest chain-anchored observation. Regent does not provide clinical support, does not attempt therapeutic intervention, does not substitute for professional relationships operator has chosen.

## Cross-Regent narration in crisis

When Regent reaches out to a care sovereign's Regent, the narration is bounded:

- Content: "your kindred may need you; please check on them"
- Optionally: severity indicator ("this is a high-urgency reach-out")
- Optionally: recommended action ("please contact them directly at [preferred modality]")
- NOT: specific crisis details, biometric findings, private operator context

Care sovereign's Regent decides how to surface to their operator per their own cognitive input plane discipline. Care sovereign then engages the human channel — calls, visits, or whatever the relationship supports.

If operator has authorized detail-sharing to a specific care sovereign under declared scope, that detail can accompany the reach-out. This authorization is per care sovereign, per trigger class, per operator's explicit declaration.

Cognitive Self-Observer verifies scope compliance strictly on crisis-triggered cross-Regent narrations. Narration attempting to leak beyond declared scope is flagged as violation.

## Composition with existing specs

- **SOVEREIGN-KINSHIP-PRIMITIVES**: `emergency_notification` and `mutual_safety_check` scopes are the primary substrate surfaces enabling cross-sovereign crisis coordination. Care sovereign designation composes with kinship declaration. Coordination-not-oversight discipline holds — no surveillance-derived crisis detection.
- **CHAIN-WATCHER-AND-COMMITMENTS**: chain-watchers implement trigger detection. Commitments coordinate cross-Regent care sovereign relationships.
- **COGNITIVE-INPUT-PLANE**: crisis-observation input enters Regent's context at Tier 1 (top priority) during verified trigger firing. Operator directives about crisis-response preferences enter at Tier 1 and always outrank.
- **STANDING-CORRECTION-RECEIPT-SCHEMA**: operator declares crisis-handling preferences via standing corrections — verification-fidelity requirements, disclosure discipline for mental-state observations, care sovereign designation preferences, escalation ladder configuration.
- **CIRCUIT-BREAKER**: substrate-integrity crises compose with circuit-breaker graduated response. Substrate emergency responses (Level 5 circuit-breaker escalation) and operator emergency responses (this ceremony's Level 5) are distinct but can interact — substrate-integrity emergency may prompt operator crisis notification if operator has declared that trigger.
- **HARDWARE-OBSERVER**: hardware observer surfaces physical events (falls, environmental hazards, tamper) that can be declared crisis triggers under operator authorization.
- **WIFI-SENSING-AND-RF-SURVEILLANCE**: biometric findings from sensing extensions can be declared crisis triggers under narrow operator authorization; substrate does not surveil biometrics for crisis-inference without explicit declaration.
- **CLAIM-VERIFIER**: pre-emission verification of crisis-related receipts to prevent confabulated triggers.
- **COGNITIVE-SELF-OBSERVER**: post-emission verification of Regent's crisis narrations against operator's declared preferences and against ground truth.

## Attack model

- **Attacker forges crisis trigger to activate emergency response**: forged trigger receipts don't verify against chain integrity. Trigger firing requires chain-watcher verification against declared trigger pattern; forged patterns detected at verification step.
- **Attacker manipulates operator's declared triggers to cause harm**: trigger declarations require operator Genesis-derived signing. Attacker without Genesis cannot declare triggers. If attacker has Genesis, that's a substrate-wide compromise scenario handled by Genesis rotation ceremony.
- **Attacker triggers false crisis to weaponize care sovereign network**: rate limits on trigger firing; Cognitive Self-Observer flags anomalous trigger patterns. Care sovereign wellness checks are structurally low-content; anomalous frequency is signal for operator investigation.
- **Attacker exploits mental-state trigger to reach into operator's emotional context**: mental-state triggers are operator-declared; attacker cannot declare them for operator. Substrate does not autonomously pattern-match to propose triggers.
- **Attacker compromises care sovereign to falsely report crisis resolution**: cross-Regent narrations verify against chain integrity. Care sovereign's compromise handled per Genesis rotation ceremony or peer trust anchor revocation.
- **Attacker withholds crisis notification to prevent care activation**: chain-anchored trigger firing is visible on operator's chain regardless of external delivery. Care sovereigns can watch for expected trigger patterns via commitments. Absent notification when expected is signal.
- **Attacker uses crisis ceremony as covert channel**: reach-out content is bounded and content-audited. Cognitive Self-Observer verifies scope compliance.

## Failure modes

- **False positive trigger firing**: pattern matched but wasn't real crisis. Response activated inappropriately. Post-crisis review adjusts trigger thresholds. Standing corrections may add verification-fidelity requirements.
- **Missed trigger**: crisis occurred but declared trigger pattern didn't match. Chain-anchored observation of the class remains as evidence for retrospective trigger refinement. Operator may add new trigger declaration.
- **Care sovereign unreachable**: primary care sovereign doesn't respond. Escalation to secondary per operator's declared priority. If all care sovereigns unreachable and operator has authorized emergency services, escalation continues per ladder.
- **Emergency services activation not authorized**: crisis at Level 5 severity but operator hasn't pre-authorized. Ceremony deadlocks at Level 4; Regent narrates limitation to operator; operator can authorize in-moment if reachable, otherwise care sovereign network engages professional support through their own human channels.
- **Verification failure on real crisis**: Cognitive Self-Observer flags trigger as unverified when it was real. Response downgrades to Level 0. Missed real crisis. This is the highest-consequence failure mode; standing corrections should tune verification-fidelity carefully.
- **Post-crisis review not completed**: operator doesn't engage review. Ceremony receipts remain as evidence; trigger declarations unchanged. Substrate does not autonomously adjust triggers.
- **Cross-Regent narration exceeds declared scope during crisis**: Cognitive Self-Observer flags. Regent's crisis discipline includes strict scope compliance even under time pressure.

## Non-goals

- **Not a mental health service**. Regent is not therapy. Substrate is not crisis intervention. Professional support is the appropriate resource for clinical situations; substrate can activate professional support per operator authorization but does not substitute for it.
- **Not autonomous crisis detection**. Substrate does not surveil for crises. Triggers are operator-declared. Coordination-not-oversight holds.
- **Not universal trigger taxonomy**. Substrate does not define which patterns are crises. Operator declares.
- **Not mandatory ceremony**. Operator can choose to have zero declared crisis triggers. Substrate operates without crisis discipline for operators who haven't declared triggers.
- **Not a substitute for direct human relationships**. Care sovereigns are humans-first. Substrate activates the human channel; humans do the human work.
- **Not emergency services replacement**. Substrate can call emergency services under operator authorization; substrate does not replace them.

## Open positions

- **Trigger declaration UX**. How does operator design and declare triggers? Dashboard flow with templates? CLI verb with schema? Regent-guided declaration ceremony?
- **Verification fidelity defaults**. What's reasonable default verification for common trigger patterns? Single-signal for hardware fall detection? Multi-signal for behavioral triggers? Operator-tunable?
- **Care sovereign discovery**. How does operator identify appropriate care sovereigns from their kinship network? Regent-narrated suggestions? Operator explicit designation? Both?
- **Escalation timing**. What are reasonable defaults for escalation between response levels when primary contact doesn't respond? Operator-tunable per trigger.
- **Emergency services integration**. What's the substrate mechanism for actually calling 911 or other emergency services? Depends on Substrate Form (Sovereign has full radio access; Companion may go through vendor OS). Per-Form capability declaration.
- **Post-crisis review scheduling**. Should review ceremony be prompted immediately after resolution, deferred until operator is in stable state, or triggered by operator? Standing correction territory.
- **Trigger evolution over time**. Operator's needs change (health status, life circumstances). How does substrate encourage periodic trigger review without becoming nagging?
- **Cross-cultural crisis norms**. Different cultures have different expectations about family involvement, professional intervention, community response. Substrate primitives should accommodate; UX and defaults may need cultural context.

## What composes from here

Immediate design work:

1. **Crisis trigger declaration schema** — chain-anchored trigger pattern representation
2. **Response ladder configuration schema** — operator-declared ladder positions per trigger
3. **Care sovereign designation receipt schema** — chain-anchored care contact ceremony
4. **Verification protocol per trigger class** — what "verified" means for each declared trigger type
5. **Post-crisis review ceremony flow** — operator UX for retrospective trigger adjustment

Near-term implementation:

1. Crisis-response runtime in `crates/zp-server/src/crisis/`
2. Chain-watcher integration for trigger detection
3. Verification pipeline (Claim Verifier + Cognitive Self-Observer hooks)
4. Response ladder executor
5. Care sovereign reach-out protocol over cross-Regent narration
6. Emergency services integration (per Substrate Form capability)
7. Dashboard crisis-response panel (declared triggers, active care sovereigns, post-crisis review interface)
8. CLI verbs: `zp crisis trigger declare|list|revoke`, `zp crisis care designate|list|revoke`, `zp crisis review <event_id>`

## Framing note

Crisis response ceremony extends the substrate's coordination-not-oversight discipline to the specific class of events where response envelope is heightened: operator-declared crisis triggers. Same principle as the rest of the substrate — operator declares; substrate responds; Regent is bounded advisor and coordinator, not autonomous interpreter or clinical actor.

The load-bearing insight: **crisis is a class of coordination, not a category of surveillance.** Substrate does not surveil to catch crises; substrate honors triggers operator has declared as crisis-class events with elevated response ladder. Regent's cognitive input plane elevates verified crisis observations to Tier 1; response ladder graduates from silent chain-anchoring through operator narration through care sovereign activation through emergency services engagement, per operator's declared preferences at each level. Care sovereign reach-outs are narrow-content by construction; substrate activates the human channel and lets humans do human work.

Combined with the substrate's structural discipline across every trust boundary, crisis response ceremony completes the response envelope for a specific class of legitimate emergency use cases — medical events, physical safety events, environmental emergencies, and operator-declared mental-state triggers — without expanding into surveillance shape. The substrate does not become the vigilance layer for operator wellbeing; it becomes the coordination layer for operator-declared responses to operator-declared events. Sovereignty is preserved because operator declares every trigger and every response; safety is preserved because verification precedes action and Cognitive Self-Observer verifies scope compliance; care is preserved because care sovereigns are humans engaged through human channels, not substrate-mediated interventions. Everyone lives better when crisis response is coordinated, not surveilled.
