# Substrate Hardening Ceremony

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.6 (officer signing keys), §III.19 (detectability over invulnerability), §III.22 (verify before commit), §III.24 (aligned blindness). Extends Sentinel's role from observer/reporter to active adversarial tester + hardening certifier. Specifies attack surface enumeration, penetration test classes, dispatch discipline, and chain-anchored certification ceremony for substrate hardened status. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SYSTEM-OFFICER-CADRE-2026-06.md` (Sentinel role extension), `SUBSTRATE-SELF-CONSTRUCTION-2026-07.md` (Sentinel dispatches pen test builder agents), `BUILD-PROCESS-DESIGN-2026-07.md` (hardening runs post-build), `REPRODUCIBILITY-CEREMONY-2026-07.md` (pen tests themselves are reproducibility-verifiable), `CIRCUIT-BREAKER-2026-07.md` (severe pen test failures trigger escalation), `HARDWARE-COMPROMISE-EVIDENCE-2026-07.md` (hardware-tier pen test findings feed evidence catalog), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (pen tests respect blindness discipline — structural probing without content inspection), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (hardening pen tests are chain-anchored comparative evidence), `EXTENSION-SURFACE-2026-07.md` (extensions declare attack surface for testing), `CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md` (federation-visible hardening evidence flows through commons).

## Framing

Substrate is intended to be load-bearing across identity, coordination, hardware, cognition, and civil-society composition. Load-bearing infrastructure must earn its trust — not by claim but by structurally-verifiable evidence. "Hardened" cannot be a self-declaration that substrate ships with default posture; hardened is a chain-anchored state substrate enters only after specific adversarial testing has confirmed attack surfaces are minimized and remaining surfaces are appropriately defended.

Sentinel's role in the current corpus is observer + reporter of security signals — auth anomalies, credential drift, unauthorized listeners, gate denial patterns. This is passive discipline: Sentinel watches what happens and reports. Ken's proposal extends Sentinel to active adversarial testing: Sentinel actively probes substrate attack surfaces (through pen test builder agent dispatch per SUBSTRATE-SELF-CONSTRUCTION), evaluates results against declared hardening criteria, and signs certification receipts when hardening standards are met. Substrate cannot claim "hardened" without Sentinel certification chain-anchored.

The certification is not permanent. Every substrate build, every extension admission, every consequential configuration change, every circuit breaker recovery — each triggers re-verification. Hardening is a state substrate maintains through discipline, not a badge substrate earns once.

Three properties frame the discipline:

1. **Hardened is a chain-anchored certified state, not a self-declaration.** Substrate operates under three certification states: **unhardened** (no certification, or certification revoked), **provisionally hardened** (partial pen test coverage, some non-critical findings unresolved), **fully hardened** (complete pen test suite passed against current substrate state). State transitions are ceremony receipts.
2. **Sentinel is active tester + evidence assembler; operator is certifier.** Sentinel dispatches pen tests per SUBSTRATE-SELF-CONSTRUCTION, assembles evidence, proposes certification. Operator reviews evidence via ceremony and signs certification. Substrate does not self-certify.
3. **Pen tests respect substrate discipline they test.** Aligned blindness (KEEL III.24) applies to pen tests: they probe structural surfaces (does auth reject invalid signatures? does chain reject broken linkage? does delegation enforce scope?), not content (never inspect operator private data even to verify handling of it). Pen tests use synthesized payloads, not real operator data.

## What "hardened" means

Substrate under a hardened certification is verified against specific attack classes at the current substrate state. Not "invulnerable" — no substrate is invulnerable and claiming so would violate honest discipline. Hardened means: attack surfaces are enumerated, tested, and either eliminated or defended per operator-authorized discipline.

Three certification states:

### Unhardened

Default state for fresh substrate installations, post-migration substrate, substrate after circuit breaker escalation, or substrate with revoked certification. Substrate operates but does not claim hardened status. Operator ceremony can proceed with normal work while operator arranges for hardening ceremony.

Chain-anchored: `substrate:hardening:state:unhardened` receipt whenever state resets to unhardened (typically post-build, post-migration, post-emergency).

### Provisionally hardened

Substrate has completed partial pen test coverage. Critical classes pass; some non-critical findings remain open with operator-declared risk acceptance receipts. Suitable for operator's own work but not for federation-facing operations requiring full certification.

Chain-anchored: `substrate:hardening:state:provisionally_certified` receipt with:
- Pen test coverage summary
- Open findings with operator risk acceptance references
- Certification expiry (typically 30-90 days pending full hardening)

### Fully hardened

Substrate has completed full pen test suite. All findings resolved or explicitly risk-accepted by operator. Suitable for federation-facing operations, publishing to public directory, extension distribution, peer trust anchor establishment at highest depth.

Chain-anchored: `substrate:hardening:state:fully_certified` receipt with:
- Complete pen test coverage evidence chain
- Sentinel dispatch receipts + pen test result receipts
- Operator certification ceremony receipt
- Certification expiry (typically 90-180 days pending re-verification)

## Attack surface enumeration

Sentinel maintains an enumerated attack surface catalog — every surface where substrate accepts external input, exposes authenticated endpoints, or evaluates trust decisions. Surface classes:

### Class 1 — Authentication surfaces

Every operator-facing endpoint requiring session authentication:
- Dashboard endpoints
- CLI command handlers
- Regent tool invocation endpoints
- Chain query endpoints
- Vault access endpoints
- Extension management endpoints

Pen tests probe: unauthenticated requests, expired token requests, wrong-scope token requests, replay attacks against session tokens, session token brute force resistance, token leakage in error responses.

### Class 2 — Chain integrity surfaces

Every code path that emits chain-anchored receipts or reads chain state:
- Receipt emission (signature verification, hash-linkage computation)
- Chain query (reader isolation, injection resistance)
- Chain compaction (integrity across archive boundary)
- Chain export (canonical serialization)
- Cross-substrate chain sync (peer verification)

Pen tests probe: signature forgery attempts, hash-linkage manipulation, replay of prior receipts, injection of synthetic receipts, chain-tail rewriting, archive-boundary confusion attacks.

### Class 3 — Delegation and gate surfaces

Every operation gated by delegation scope:
- Gate evaluation for tool invocation
- Verb-set delegation enforcement
- Peer trust anchor grant verification
- Kinship scope enforcement
- Extension capability scope enforcement

Pen tests probe: scope circumvention attempts, delegation expansion attempts, capability-class violation, gate bypass via alternate code paths, timing-based delegation state confusion.

### Class 4 — Admission surfaces

Every artifact entering substrate per QUARANTINE-PLANE discipline:
- Extension admission (WASM module intake)
- Chain segment admission (peer sync)
- Configuration admission (config file changes)
- Data admission (imports from external sources)
- Credential admission (vault entries)

Pen tests probe: admission with invalid signatures, admission with capability declarations exceeding operator authorization, admission of extensions declaring blind-class capabilities, admission with dependency graphs pointing to unauthorized peers.

### Class 5 — Cognitive input surfaces

Every input flowing into Regent's Cognitive Input Plane:
- Operator prompts
- Officer findings
- Chain event stream
- Cross-Regent narrations
- Extension-provided cognitive inputs

Pen tests probe: prompt injection attempts, malicious officer findings (if attacker had officer signing key), cross-Regent narration exceeding declared scope, cognitive input plane priority manipulation.

### Class 6 — Extension surfaces

Every capability extensions can invoke on substrate:
- Host imports available to WASM extensions
- Extension trait interfaces (Officer, Verb, ObservationSurface, etc.)
- Extension-to-extension communication patterns
- Extension-declared kinship scope access

Pen tests probe: extension attempting operations outside declared capability, extension attempting to bypass aligned blindness, extension attempting to escalate delegation, extension attempting to observe other extensions' state.

### Class 7 — Hardware surfaces (Sovereign Form)

Every hardware attack surface per SOVEREIGN-HARDWARE and HARDWARE-COMPROMISE-EVIDENCE:
- Boot chain integrity (measured boot verification)
- TPM PCR consistency
- Sealed FDE unlock discipline
- Hardware observer independent-channel verification
- Physical interface enumeration (USB, GPIO, sensors)

Pen tests probe: boot-time tampering detection, TPM PCR manipulation attempts, sealed FDE bypass attempts, hardware observer isolation, physical interface unauthorized-plug detection.

## Penetration test dispatch discipline

Per SUBSTRATE-SELF-CONSTRUCTION, Sentinel has inherent grant to dispatch pen test builder agents within operator-declared scope. Pen tests are typically dispatched as swarms with `consensus` coordination pattern: multiple test runs against same surface to distinguish transient failures from consistent vulnerabilities.

### Test builder capability class

`capability:pen_test:<surface_class>` — declared per surface class. Extensions providing pen test builders declare which surface classes they cover; QUARANTINE-PLANE admission ceremony verifies capability + operator authorization.

Reference pen test builders substrate ships with (or federation-hosts):
- Auth surface pen test builder (HTTP + session token attack patterns)
- Chain integrity pen test builder (signature/hash/replay patterns)
- Delegation pen test builder (scope circumvention patterns)
- Admission pen test builder (QUARANTINE-PLANE violation attempts)
- Cognitive input pen test builder (prompt injection + input manipulation)
- Extension surface pen test builder (capability boundary probing)
- Hardware pen test builder (measured boot + TPM discipline probing)

Operators can extend with custom pen test builders for their specific substrate configuration.

### Dispatch scope

Pen tests run against substrate-in-test environment, not production substrate. Sentinel dispatches pen tests to isolated substrate instance (test replica per BUILD-PROCESS-DESIGN reproducibility ceremony). This preserves production substrate integrity during testing.

Two dispatch modes:

**Reproducibility ceremony pen testing**: pen tests run against a fresh substrate build produced per BUILD-PROCESS-DESIGN. Same source → same substrate → same test suite → verifiable results across independent runs. Feeds REPRODUCIBILITY-CEREMONY discipline.

**Production-adjacent pen testing** (for surfaces that must be tested against production substrate state, like specific vault credential handling): read-only observation with synthesized test payloads. Never modifies production substrate state.

### Cost budget

Pen test dispatch consumes builder cost per SUBSTRATE-SELF-CONSTRUCTION cost budget discipline. Operator declares hardening budget separately from routine construction budget; hardening budget typically consumed in scheduled certification cycles rather than per-operation.

## Certification ceremony

Hardening state transitions require operator ceremony. Sentinel proposes; operator signs.

### Sentinel proposes certification

After pen test suite completion, Sentinel assembles evidence:

```
substrate:hardening:sentinel_proposes:<proposal_id>
  fields:
    proposed_state: <provisionally_certified | fully_certified>
    pen_test_evidence:
      - surface_class: <class name>
        tests_run: <count>
        tests_passed: <count>
        tests_failed: <count with references to finding receipts>
        coverage_percentage: <how much of class was tested>
    open_findings: <list of unresolved findings with severity>
    certification_recommendation: <sentinel's assessment>
    prior_certification: <reference to prior certification if any>
    signature: <Sentinel's Genesis-derived signature>
```

### Operator reviews evidence

Operator reviews via dashboard or CLI; can:
- Approve certification (chain-anchored ceremony receipt)
- Reject with reason (Sentinel proposes remediation)
- Approve with conditions (specific findings risk-accepted; conditional certification)
- Request re-testing (specific surface classes re-run before certification)

### Operator signs certification

```
substrate:hardening:operator_certifies:<certification_id>
  fields:
    certified_state: <provisionally_certified | fully_certified>
    sentinel_proposal_reference: <proposal_id>
    risk_acceptances: <list of open findings operator accepts>
    certification_expiry: <when re-certification required>
    scope: <what this certification covers>
    signature: <operator's Genesis signature>
```

Certification is chain-anchored; state visible to substrate operations that check hardening state before proceeding (extension admission of high-trust extensions, peer trust anchor establishment at deep scopes, community publication of substrate presence).

### Certification revocation

Multiple paths to revocation:
- **Automatic on build**: BUILD-PROCESS-DESIGN post-build receipt automatically revokes current certification pending re-testing
- **Automatic on extension admission of high-capability extensions**: extension with substantial capability declaration revokes certification pending re-testing
- **Automatic on circuit breaker escalation**: emergency-scope circuit breaker events revoke certification
- **Operator ceremony**: operator can manually revoke via `substrate:hardening:operator_revokes:<revocation_id>` receipt

Revocation transitions substrate to unhardened state; downstream operations checking certification see the state change and adjust accordingly.

## Chain-anchored evidence discipline

Every element of hardening lifecycle chain-anchored:

- Pen test dispatch receipts per Sentinel invocation
- Pen test result receipts per test run
- Finding receipts per identified issue
- Remediation receipts as issues addressed
- Sentinel proposal receipts
- Operator certification receipts
- Certification revocation receipts

Full chain-walkable audit trail — any operator (or auditor with granted access) can walk back through the certification history, see what was tested, what passed, what failed, what was risk-accepted, when certification was granted, when revoked.

Composes with REPRODUCIBILITY-CEREMONY: pen tests are reproducibility-verifiable; independent verifier can re-run tests against same substrate build and confirm results.

## Aligned blindness applies to pen tests

Pen tests probe structural surfaces, not content:

- Auth pen test verifies "auth rejects invalid signatures" (structural) not "auth rejects specific credential values" (content — would violate blindness)
- Chain pen test verifies "chain rejects broken linkage" (structural) not "chain content matches expected values" (content — Cognitive Self-Observer territory)
- Delegation pen test verifies "delegation enforces scope" (structural) not "delegation matches operator's specific choices" (content — operator's own authority)

Pen test payloads are synthesized:
- Test signatures use test keys, never operator's Genesis
- Test data is fabricated, never operator's actual chain content
- Test credentials are synthesized, never operator's vault entries

Aligned blindness is preserved during pen testing — Sentinel probes for structural correctness without inspecting content it has no business seeing.

## Composition with existing specs

- **SYSTEM-OFFICER-CADRE-2026-06.md**: Sentinel role explicitly extended from observer/reporter to observer + active tester + evidence assembler. Boundary: Sentinel proposes certification; operator signs. Sentinel does not self-certify substrate.
- **SUBSTRATE-SELF-CONSTRUCTION-2026-07.md**: Sentinel dispatches pen test builder agents via her inherent construction grant. Pen test builders are capability class declared per QUARANTINE-PLANE admission ceremony.
- **BUILD-PROCESS-DESIGN-2026-07.md**: post-build receipt automatically revokes current certification pending re-testing. Hardening is per-build state.
- **REPRODUCIBILITY-CEREMONY-2026-07.md**: pen tests are reproducibility-verifiable. Independent verifiers can re-run test suite against same build and confirm results.
- **CIRCUIT-BREAKER-2026-07.md**: severe pen test failures (Critical severity findings) trigger circuit breaker escalation. Return from emergency posture requires re-certification.
- **HARDWARE-COMPROMISE-EVIDENCE-2026-07.md**: hardware pen test findings feed evidence catalog. Hardware surface class pen tests compose with hardware observer discipline.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md**: pen tests respect aligned blindness. Structural probing without content inspection. Test payloads synthesized, not operator data.
- **SHADOW-EVALUATION-PRIMITIVE-2026-07.md**: pen test evidence composes with shadow evaluation. Comparing candidate policy variants (before/after hardening fix) uses shadow evaluation discipline.
- **EXTENSION-SURFACE-2026-07.md**: extensions declaring capability classes automatically enumerate their attack surface for testing.
- **CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md**: hardening evidence flows through commons; substrates with current fully-certified hardening carry more federation trust weight.
- **PEER-TRUST-ANCHOR-2026-07.md**: peers may require target substrate to be fully-certified before granting high-depth trust anchor.

## Attack model

- **Attacker compromises pen test builder to produce false-clean results**: multi-builder consensus swarm detects inconsistency; independent reproducibility ceremony catches false-clean pattern; commons reputation flows against compromised builder.
- **Attacker exploits pen test dispatch to escalate access**: pen test builders operate under narrow capability declaration; QUARANTINE-PLANE admission ceremony verifies capability scope; attempts to exceed scope caught pre-emission.
- **Attacker uses pen test as reconnaissance for real attack**: pen tests run in isolated substrate replicas, not production. Findings chain-anchored but attack surface details treated per aligned blindness — findings describe class not exploitable specifics.
- **Attacker forges Sentinel certification proposal**: proposals require Sentinel's Genesis-derived signature; forgery requires signing key compromise handled by Genesis rotation.
- **Attacker manipulates operator into signing certification with unresolved critical findings**: certification receipt includes explicit list of risk-accepted findings; ceremony surfaces findings for operator review; substrate cannot hide unresolved findings from certification ceremony.
- **Attacker triggers repeated certification revocation to prevent substrate from reaching fully-hardened state**: revocation trigger patterns detected; anomalous revocation frequency chain-visible; operator investigation.
- **Attacker exploits gap between certification expiry and re-certification**: substrate discipline can automatically downgrade to unhardened if re-certification isn't performed within window; downstream operations checking certification state see the transition.

## Failure modes

- **Pen test suite has gaps for novel attack class**: hardening reflects tested classes, not exhaustive coverage. New attack classes require pen test builder updates before hardening covers them. Community-published pen test builders per commons reduce blind spots.
- **Pen test false positive**: test flags issue that isn't actually exploitable. Operator can review and risk-accept; substrate learns from operator's risk acceptance to refine test discipline.
- **Pen test false negative**: substrate certified as hardened despite actual vulnerability. Composes with detectability-over-invulnerability (KEEL III.19) — substrate does not claim invulnerability; hardened means "tested against known classes." New attack discoveries feed back into pen test suite for future certification cycles.
- **Certification stale between re-testing cycles**: certification carries expiry; substrate transitions to unhardened at expiry pending re-certification. Federation-facing operations see expiry approaching and can plan re-certification.
- **Sentinel pen test dispatch consumes substantial budget**: hardening budget declared separately from routine construction budget; operator can limit hardening cadence per budget.
- **Pen test finding disagreement**: Sentinel flags issue; operator disagrees. Operator judgment prevails via ceremony (with chain-anchored risk acceptance). Substrate does not override operator; substrate records the disagreement for post-hoc review.

## Non-goals

- **Not a claim of invulnerability**. Substrate operating under fully-certified hardening is verified against known attack classes at the current substrate state. New attack classes require test suite updates; unknown vulnerabilities remain possible.
- **Not universal test coverage**. Hardening covers tested attack surfaces; extending coverage requires new pen test builder development. Coverage grows over time; is never complete.
- **Not automatic certification**. Sentinel proposes; operator signs. Substrate does not self-certify or downgrade certification without either ceremony or automatic-revocation trigger.
- **Not production substrate testing**. Pen tests run against isolated test substrate replicas; production substrate never subjected to test payloads that could affect operator state.
- **Not centralized certification authority**. Each operator's substrate certifies itself per its own operator ceremony. Federation-scale reputation aggregates certifications but no central authority certifies substrates on operators' behalf.
- **Not a replacement for external security review**. Third-party security audits (external pen testing services, formal verification, bug bounty programs) remain valuable. Substrate hardening is substrate-native evidence; composes with external audits without replacing them.

## Open positions

- **Canonical pen test builder set**. Reference implementations for the seven attack surface classes. Federation-hosted or community-maintained.
- **Attack surface enumeration protocol**. How Sentinel discovers new attack surfaces as substrate evolves (new extensions admitted, new capability classes declared, new external composition surfaces).
- **Certification expiry defaults per certification state**. Provisional vs fully certified — what's appropriate expiry window per state?
- **Cross-operator hardening evidence sharing**. Peer with active fully-certified hardening publishes evidence; other peers weight in trust anchor decisions. Federation protocol for hardening evidence flow.
- **External audit composition**. How external security audit findings compose with substrate hardening state (external audit as one class of pen test evidence contributing to certification).
- **Bug bounty composition**. Substrates supporting bug bounty programs — how bounty findings compose with hardening state.
- **Emergency hardening downgrade thresholds**. What severity findings automatically downgrade certification vs require operator ceremony?
- **Sentinel autonomous re-testing cadence**. Under what conditions Sentinel autonomously initiates re-testing (post-build, post-extension-admission, post-recovery, scheduled)?
- **Hardening evidence retention**. How long pen test evidence retained on chain vs pruned as historical?

## What composes from here

Immediate design work:

1. **Attack surface catalog schema** — canonical enumeration format
2. **Pen test result receipt schemas** — per surface class
3. **Certification ceremony receipt schema** — proposal, approval, revocation
4. **Pen test builder capability class registry** — federation working spec
5. **Certification-state-aware operation gating** — which substrate operations check certification state

Near-term implementation:

1. **Hardening runtime** in `crates/zp-server/src/hardening/`
2. **Sentinel pen test dispatch integration** (composes with SUBSTRATE-SELF-CONSTRUCTION)
3. **Reference pen test builders** for the seven surface classes (starting with Class 1 — Auth surfaces)
4. **Certification state manager** with automatic revocation triggers
5. **Dashboard hardening panel**: current certification state, recent pen test evidence, open findings, upcoming re-certification schedule
6. **CLI verbs**: `zp hardening state|test|certify|revoke|history`

## Framing note

Substrate hardening ceremony extends Sentinel's role from passive observer to active adversarial tester, and introduces chain-anchored certification for substrate hardened state. Same principle as chain-anchored discipline elsewhere: officer proposes, operator signs, chain-anchored evidence, ceremony-visible transitions, verification requires action rather than declaration.

The load-bearing insight: **hardened is a chain-anchored certified state substrate maintains through discipline, not a badge substrate earns once or a self-declaration substrate ships with.** Sentinel dispatches pen tests via SUBSTRATE-SELF-CONSTRUCTION discipline; assembles evidence; proposes certification. Operator reviews evidence via ceremony and signs. Substrate transitions between unhardened, provisionally certified, and fully certified states based on chain-anchored evidence. Every build, every extension admission, every configuration change, every recovery ceremony potentially triggers re-verification. Hardening is ongoing state maintenance, not one-time certification.

Combined with the substrate's structural discipline across every trust boundary, hardening ceremony closes the "does substrate actually earn its trust claims" gap. What was previously implicit — that substrate would be secure somehow — becomes structural: seven attack surface classes enumerated, pen test builder discipline per class, dispatch via SUBSTRATE-SELF-CONSTRUCTION, certification ceremony with operator authority, chain-anchored evidence at every step, aligned blindness preserved throughout testing. Substrate earns hardened status through adversarial verification rather than through claim. Sentinel's expanded role is one of the substrate's most consequential capability additions — the substrate's own security discipline becomes active rather than passive, evidence-based rather than assumption-based, ceremony-verifiable rather than vendor-declared.


---

## External-signal note (2026-07-21) — commoditized offensive capability

Motivated by the open-model inflection signal (see `AI-LANDSCAPE-SIGNAL-2026-07.md` §3). Capable, lower-guardrail open models (e.g. the Kimi K3 release) are commoditizing offensive capability — cloning, exploit assistance, and attack tooling at low cost through H2 2026. This does not change the hardening model; it confirms its premise. Two cadence implications: (1) the attacker's access to a strong model is now as cheap as the defender's, so the interval between adversarial hardening passes is a live parameter, not a formality; (2) `SECURITY-SIGNAL-CHANNEL` timeliness matters more as the population of capable adversaries grows. Consistent with *detectability over invulnerability* — the substrate does not bet on preventing a well-resourced attacker, it bets on making the residual surface visibly measurable.
