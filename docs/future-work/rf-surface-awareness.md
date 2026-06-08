# RF Surface Awareness — Defensive Posture Against Adversarial WiFi Sensing

*Status: design note, intentionally deferred. Dated 2026-05-26. Pick up after*
*the substrate-readiness arc (task #91) is complete and Compute Surface*
*Awareness (Part VIII of `ARCHITECTURE-2026-04.md`) has a first implementation.*

---

## The threat

An adversary does not need to be on the operator's network to read the
operator's environment. They need to be in RF range and listening. Commodity
WiFi-CSI sensing — channel state information harvested from ambient WiFi
transmissions — now resolves presence, position, count, gait, breathing rate,
and heart rate. The capability has moved from research papers to nine-dollar
ESP32 hardware. RuView, ESPectre, Espressif's esp-csi reference, and the
CMU "DensePose From WiFi" line are the public surface; well-resourced
adversaries have had this for longer.

The defensive gap is that an operator has no legible signal that this is
happening to them. There is no equivalent of `lsof` for the RF environment
around the host. The host's compute surface, in the sense Part VIII names
it, includes the air around the host — and that air is currently opaque to
the substrate.

## Why this is parked

This work depends on substrate primitives that are currently being hardened.
Anomaly receipts depend on the receipt schema being final. Signed alerts
depend on chain integrity (Claim 1) being adversarial-tested, not merely
tamper-evident in the happy path — an RF anomaly alert with a forgeable
chain is worse than no alert, because it manufactures false confidence.
Countersense authorization depends on capability-scope grants being load-bearing
enough to gate physical-world emissions. None of those are true today.

Do not start RF surface work until these are true:

- Receipt schema is final. Anomaly receipts extend the schema; they cannot
  ride on shifting ground.
- Chain integrity (Claim 1) is adversarial-tested. Signed RF alerts inherit
  the chain's authority; if the chain wobbles, the alerts wobble.
- Gate enforcement (Claim 3) is real. Countersense emissions cross a
  capability boundary; they must be gated by chain-anchored grants, not by
  config flags.
- Part VIII (Compute Surface Awareness) has a first implementation. The
  five-stage arc — inventory, attribution, surface, integrity, recommendation —
  is the architectural slot RF awareness extends into. Without that slot,
  this work has nowhere to land.

## The vision in one paragraph

ZeroPoint extends Compute Surface Awareness from the host's process and
credential footprint to the host's electromagnetic neighborhood. A
ZP-resident RF-awareness agent consumes a RuView-class CSI sensor mesh on
the operator's premises, but inverts the application: instead of sensing
the room for the operator's benefit, it watches the RF environment for
*who else is sensing it*, and what their access pattern looks like.
Detections — anomalous CSI access on operator APs, probing transmissions
from unrecognized sources, side-channel emissions an adversarial collector
could harvest — emit signed chain receipts. The chain becomes the operator's
legible, verifiable record of who attempted to sense this space, when, with
what confidence, from what bearing. Optionally, with explicit operator
authorization, the substrate emits countersense patterns that defeat
adversarial inference. The whole arc is observability first, control
second, never autonomous physical-world action.

## Composition pattern

ZP does not reimplement CSI sensing. The capability stack — ESP32 firmware,
CSI extraction, classifier pipelines, sensor-mesh topology — already exists
in RuView and adjacent projects under permissive licenses. ZP's role is the
trust stack that wraps the capability stack: typed wrappers around the
sensor mesh's output, capability-scope grants around the countersense
controls, signed chain receipts around every anomaly and every operator
response.

The shape is the same one named in the "tool is intent, crystallized"
principle (P6) and demonstrated in the Printing Press composition: someone
else builds the typed wrapper around the messy capability; ZP composes one
layer above as the receipt-emitting harness. RuView's sensor output is the
capability surface. ZP's receipts are the trust surface. The two compose
without either reimplementing the other.

## Two postures, with different cost profiles

The design supports two operator postures, sequenced.

**Passive alert mode.** Always-on monitor, low cost, signs anomaly receipts.
The minimum viable posture and the one to ship first. Matches the substrate's
existing observability-versus-control split: visibility is universal, authority
remains scoped. The substrate observes the RF event, attests it via chain
receipt, surfaces it to the operator through the Sage interface and the
chain-anchored alert artifact. The operator decides whether to act. No
physical-world emission, no operator authorization required beyond running
the sensor mesh in the first place.

**Active countersense.** Controlled emission patterns that defeat adversarial
CSI inference when alert mode trips a threshold. Higher cost, higher impact,
operator-authorized per incident rather than always-on. The countermeasure
is a chain-anchored capability invocation: operator signs the authorization,
substrate emits the pattern, chain receipt records both the authorization
and the emission. The countersense receipt cites the anomaly receipt that
triggered it, closing the causal chain.

Active countersense raises questions that passive alert mode does not.
Regulatory: emitting characteristic patterns may cross radio-spectrum rules
in some jurisdictions. Ethical: countersense disrupts not only adversarial
sensing but any sensing in the same band, including legitimate uses by
neighbors. Architectural: the threshold function that decides when to escalate
from alert to countersense is itself a high-stakes policy that should be
chain-anchored and operator-tunable, not vendor-fixed. None of these are
blockers, but they need design work before the active posture ships.

## Architectural placement

This is the cleanest extension of Part VIII (Compute Surface Awareness)
beyond the host. The "lsof test" heuristic — substrate is mature when its
own footprint is legible — generalizes to the host's electromagnetic
neighborhood: substrate is mature when every signal entering the host's RF
environment is either accounted-for as operator-acknowledged or actively
suspect. The same five-stage arc applies: inventory the RF emitters and
receivers in range, attribute them where possible, surface them to the
operator, monitor their integrity over time, and recommend posture changes,
never autonomous action. The compute surface includes the air.

## Principle alignment

P1 (signing is gravity) is the value-add. An RF anomaly alert without
operator-signed provenance is a smart-home notification with no chain of
custody. Signed and chain-anchored, it becomes evidence — citable, replayable,
defensible. This is the inversion that makes the whole architecture worth
building; otherwise this is just another sensor product.

P3 (no center) composes naturally. RuView and adjacent CSI projects are
already edge-only, no cloud. The ZP-resident agent runs on the operator's
substrate, the sensor mesh runs on the operator's premises, the chain lives
on the operator's host. No external authority is involved in the trust
decision.

P5 (store-and-forward is primary) is load-bearing. Adversarial sensing is
exactly the kind of event that may happen during an outage — possibly
*because* of an outage, since the attacker is exploiting the absence of
defenders. The chain has to absorb anomaly receipts during disconnection
and forward them on reconnect; live state cannot be the substrate.

P4 (every bit counts) sets a constraint. The sensor mesh produces a
high-bandwidth stream; the chain cannot absorb every CSI sample. The right
shape is the artifact-library pattern applied here: the substrate proposes
anomaly *candidates* continuously, but only signs and persists anomaly
*receipts* when a classifier threshold trips. Raw CSI is derived; signed
anomaly receipts are canonical.

## Claim impact — open question

This work touches Claim 1 (chain integrity) by extending what the chain
attests to. It may also motivate a fifth claim around environmental
attestation — the question of whether the chain authoritatively records
the operator's *physical-world* context as it does the operator's
computational context. This is unresolved.

The argument for keeping it under Claim 1: chain integrity is already the
claim that says "the chain says what happened, and the chain is not lying."
RF events are events. Extending the chain's domain to physical-world events
is a scope question, not a structural one.

The argument for a new Claim 5: the verifiability conditions for "did this
RF event actually happen as the chain says it did" differ from the
verifiability conditions for "did this computational event actually happen
as the chain says it did." The latter can be re-derived from inputs; the
former requires trust in the sensor mesh's reporting. That difference may
deserve its own claim line.

Resolve when this thread becomes scheduled.

## Sage's role

The operator-facing surface for RF awareness pairs a reference panel
(visible RF environment, current sensor mesh status, alert history, threshold
configuration) with Sage's conversational interface, per the conversational-
interface-plus-reference-surface heuristic. Both surfaces read and write the
same chain state; the panel makes the control space legible, Sage makes
expression natural.

Anomaly-detection alerts are exactly the kind of artifact-library candidate
that should propose (substrate-rendered from raw classifier output) and
require operator signature before promoting to canonical. The substrate sees
a suspicious CSI pattern, renders an alert artifact (what was detected, with
what confidence, what bearing, what reasoning), surfaces it to the operator
as a candidate. Operator reviews, signs to confirm the alert is real,
substrate persists the signed alert as canonical. False-positive alerts get
discarded by not being signed; true-positive alerts become part of the
attested record. The candidate is cheap; the canonical is rare and human-endorsed.
Same lifecycle as every other artifact in the library.

This matters because false positives are the failure mode that destroys
operator trust in any anomaly-detection system. The artifact-library lifecycle
absorbs the false-positive cost structurally: cheap candidates, expensive
canonicals, signed only when the operator confirms.

## Open questions

The sensor mesh sovereignty question is unresolved. The ESP32 firmware
ships with cloud-default vendor relationships in some distributions; ZP
needs to confirm that the sensor mesh's data path is operator-controlled
end-to-end, or assume the worst and design around vendor exfiltration.

The threshold-tuning question is unresolved. Anomaly classifiers have a
false-positive rate that depends on the local RF environment, the time of
day, the season, and the operator's tolerance. Threshold should be operator-
tunable per location, with the threshold itself recorded as a chain-anchored
preference per the conversational-interface pattern. Default thresholds
should be tuned to high-precision/low-recall for the alert posture (better
to miss some attacks than to drown the operator in noise).

The bearing-estimation question is unresolved. Triangulating an adversarial
sensor's bearing requires multiple sensor nodes in known positions; the
sensor mesh topology becomes itself a sovereignty artifact. How that topology
is enrolled, verified, and re-attested when nodes move is design work.

The composition with `zp doctor` is unresolved. RF anomalies should appear
in the doctor's posture report, but the report shape and the doctor's
relationship to the chain are still being designed.

## Sequencing & dependencies

Not immediate. The readiness arc (task #91) has higher-priority threads, and
RF awareness depends on Part VIII landing first. Reasonable sequencing:

1. Substrate-readiness arc completes — Claims 1 and 3 become true.
2. Part VIII (Compute Surface Awareness) ships its first implementation for
   the host's process/credential footprint. The five-stage arc is exercised
   on a domain that is fully under the substrate's control.
3. RF awareness is added as a second domain under the same arc, reusing the
   Part VIII machinery. Passive alert mode ships first.
4. Active countersense is designed and shipped only after passive alert
   mode has produced a meaningful chain of attested anomalies, and the
   regulatory/ethical/threshold questions have been worked.

The total path is on the order of multiple quarters of substrate work, not
weeks. This brief exists so the thread is not lost.

## Adjacent references

- `docs/ARCHITECTURE-2026-04.md`, Part VIII (Compute Surface Awareness) —
  the architectural slot this work extends.
- `docs/ARTIFACT-LIBRARY-2026-05.md` — the substrate-proposes-operator-signs
  lifecycle that anomaly alerts inherit.
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — countersense authorizations
  derive from the operator's sovereign root; no separate credentials.
- `docs/future-work/cognitive-accountability.md` — sibling future-work brief
  with the same parking discipline applied.
- RuView (`ruvnet/RuView`) — the public capability stack ZP wraps.
- Espressif `esp-csi` reference and Wi-ESP CSI Tool — upstream of most of
  the field's CSI extraction.
- CMU "DensePose From WiFi" — the research lineage of through-WiFi pose
  estimation, useful for understanding the upper bound of what's currently
  inferable.

## A note on framing

The arms race this brief enters is older than ZP and not solvable by
better sensors. Better sensors strengthen both sides — the defender's
detection improves and the attacker's inference improves in the same
direction. What changes when ZP is in the loop is not the sensing
arithmetic, it is the *accountability* arithmetic. The operator gains a
signed, portable, defensible record of who attempted to sense their
environment, when, and how. That record is what existing smart-home
products do not produce and what ZP is structurally able to produce. The
defensive value is downstream of the attestation, not upstream of the
sensing.

The same logic applies to the broader anti-detection-browser space
(CloakBrowser and adjacent): those tools exist because the web's identity
layer cannot tell signed agents from unsigned scrapers. ZP's portable
signed-identity thesis is the substrate-level fix to the underlying
problem. RF sensing is the same shape, in a different medium: the air
currently cannot tell signed sensing from unsigned sensing. ZP makes the
distinction structural.
