# ZeroPoint Architecture — April 2026

**Document type:** Canonical Architecture Record. Referenced in `CLAUDE.md` as the north star for all structural decisions. Every session reads the six design principles and four claims from this document as binding constraints.
**Author:** Ken Romero, with synthesis assistance from Claude.
**Date:** 2026-04-06. Last updated: 2026-04-22.
**Status:** Active. This document is revised after every major adversarial test cycle and every architectural commitment. Code that contradicts it is wrong.
**Companion documents:**
- `docs/whitepaper-v2.md` — the public thesis (autoregressive trust, the trajectory model)
- `security/pentest-2026-04-06/PENTEST-REPORT.md` — what the 2026-04-06 black-box pentest found
- `security/pentest-2026-04-06/INVARIANT-CATALOG-v0.md` — the grammar that the substrate is supposed to satisfy
- `security/pentest-2026-04-06/REMEDIATION-NOTES.md` — working notes, decisions, deferred questions
- `docs/design/governed-agent-runtime.md` — the Governed Agent Runtime (GAR) architecture specification (Phase 4)
- `docs/future-work/cognitive-accountability.md` — the cognitive accountability layer (Layer 3 trace vision, parked until foundation hardening completes)
- `docs/design/sentinel-rf-sovereignty-design.md` — WiFi sensing defense network: firmware integrity, 802.11bf detection, active countermeasures, fleet correlation, sovereign hardware selection

This document sits *above* all four. The whitepaper is the thesis; the pentest is the evidence; the catalog is the grammar; the notes are the workshop. This document is the operating spec — the thing that says what ZeroPoint actually is now, what it is supposed to become, and how the work between those two states is sequenced.

---

## Part I — What ZeroPoint Is

### 1. The one-sentence statement

> ZeroPoint is an autorecursive trust substrate: a Rust-implemented protocol layer in which every action is a step in a hash-linked, signed, replayable derivation, and the derivation is well-formed iff it parses against a fixed grammar of constitutional, delegation, and continuity invariants.

That sentence does work. Each clause is load-bearing and is grounded in something concrete:

- **autorecursive** — each step is conditioned on the full prior context (whitepaper §1, Claim 1; the eight delegation invariants; the `pr` field on every receipt). Not Markovian. Not stateless. The chain *is* the state, and the state *is* the history.
- **trust substrate** — not an application, not a guardrail, not a compliance layer. The thing that lives below the application and refuses to be bypassed. Governance as protocol, not as policy (whitepaper §6.1).
- **Rust-implemented** — 22 crates, 700+ tests, the actual code in `~/projects/zeropoint`. This is not a paper system. It runs.
- **every action is a step in a hash-linked, signed, replayable derivation** — receipts (signed), chains (hash-linked, ordered by `pr`), collective audit (replayable). The whitepaper's three properties of a trajectory: evidence, ordering, replayability.
- **well-formed iff it parses against a fixed grammar** — this is the catalog's contribution. The grammar is fixed; what is well-formed and what is ungrammatical is decidable. The verifier is a re-deriver, not a checker.
- **constitutional, delegation, and continuity invariants** — the three layers of the catalog: required (Σ), possible (delegation envelope), actual (the hash chain).

The sentence is not yet true of the running code. It is the target. The pentest revealed that several of its clauses are aspirational. Part II says which ones.

### 2. The four claims that make the substrate load-bearing

The whitepaper makes four testable claims (§1). The catalog formalizes them as productions and invariants. Together they are what makes the substrate worth building rather than just another audit log.

**Claim 1 — Each step is conditioned on all prior context.** Mechanism: `pr` linkage, Blake3 transitivity. Catalog rule: P1 (Chain extension), M3 (hash-chain continuity). Falsifier: any receipt whose `pr` does not point to the previous receipt's `id`. *Status:* AUDIT-01 found four such breaks (concurrent-append race). Fixed: transactional append with BEGIN IMMEDIATE, UNIQUE(prev_hash) index, atomic chain-tip computation. Currently true.

**Claim 2 — Present state compresses full history.** Mechanism: collective audit (AuditChallenge → AuditResponse → PeerAuditAttestation). Catalog rule: this is what the verifier *does* — it walks the full chain to confirm the present state. Falsifier: a peer claiming a state that does not match its full chain. *Status:* the mechanism exists; it has not been load-tested against an adversarial peer.

**Claim 3 — System-wide coherence from local evaluation.** Mechanism: PolicyEngine fixed evaluation order, constitutional rules at positions 1 and 2. Catalog rule: M2 (constitutional persistence), P3 (the gate). Falsifier: any side effect that did not pass through P3. *Status:* EXEC-01..04 originally proved the gate was not enforced for `/ws/exec`. Fixed: gate.evaluate() now called before every spawn. Currently true.

**Claim 4 — Future actions narrowed by trajectory.** Mechanism: the eight delegation invariants. Catalog rule: P2 (Delegation), X1 (Possible ⊆ Required), X2 (Actual ⊆ Possible at time of action). Falsifier: a delegation chain that widens authority anywhere along its length. *Status:* the invariants are implemented in `DelegationChain::verify()` and are believed to hold. The pentest did not exercise delegation paths because it never needed to — it bypassed them via the gate failure. Untested under adversarial pressure.

**Two of the four claims are currently false.** That is the central fact of April 2026, and it is what this document exists to address. The substrate is not yet load-bearing. It is *architecturally capable of being load-bearing*, and that is a different and weaker statement.

### 3. The three layers of the substrate

The catalog introduced these as Required / Possible / Actual. Translated into operating terms:

**Layer 1 — Required (☐, the constitutional layer).** What must be true at every step in every reachable state. Two rules: HarmPrincipleRule and SovereigntyRule. They are non-removable, non-overridable, evaluated first. They are the conservation laws. Their failure mode is *tampering* — someone removes them, reorders them, or finds a code path that doesn't consult them. M2 governs this layer.

**Layer 2 — Possible (◇, the delegation layer).** What is still authorizable from the current state. The capability grants in force, narrowed by the chain of delegations that produced them. Each delegation can only constrain. The envelope shrinks monotonically in scope, time, depth, and trust tier. P2 and X1 govern this layer. Its failure mode is *widening* — a child grant claiming authority its parent did not have.

**Layer 3 — Actual (the chain layer).** What was actually signed, by whom, in what order, against which policy decisions. The hash-linked sequence of receipts. P1, M3, M4, X2 govern this layer. Its failure mode is *forgery, gap, or rewriting* — receipts that don't link, hashes that don't match, signatures that don't verify, timestamps that go backward.

A chain is well-formed iff all three layers agree at every step. This is the modal/temporal-logic substrate Ken landed on as Version C. The whitepaper already speaks it without the modal vocabulary; the catalog made the vocabulary explicit; this document operates against it.

### 4. The trust-as-grammar reframe

The substrate is a *grammar*, not a system. This is not a metaphor. It changes how the work gets sequenced.

A system has a state and you check whether the state is correct. A grammar has productions and you check whether the derivation is well-formed. The difference matters because a grammar is *open* — it accepts new well-formed strings indefinitely, and its correctness is a property of the parse, not of any single moment. A finished grammar is a dead language.

Three consequences flow from this:

**(a) Verification is re-derivation, not checking.** The verifier doesn't ask "is this state valid?" It asks "can I re-derive this state from the productions, starting from Genesis?" If yes, accept. If no, reject. The verifier is a parser. This is why O(n) is not overhead — it is the architecture.

**(b) Failure is meaningful, not just bad.** A chain can break in a *grammatical* way: which rule failed, at which step, against which prior context. The pentest's AUDIT-01 (four broken hash links) is not "the system is broken" — it is "P1 fails at step N because R.pr ≠ id(last(Γ′))." That sentence is precise enough to fix and precise enough to detect automatically.

**(c) The substrate is never finished.** Each new receipt is a production, each new finding is either a new rule or a new test of an existing one, each new version of the catalog is conditioned on what the prior version revealed. ZeroPoint is autoregressive *as a project*, not just as a runtime. The catalog has versions for the same reason a language does.

This reframe is what makes the WASM trust-boundary direction structural rather than tactical. A WASM module with no ambient authority and only host-function access to side effects *is* the grammar enforced by the runtime: the only way to extend the derivation is through productions the host explicitly exposes. Gate coverage stops being something humans have to remember to do and starts being something the type system prevents you from forgetting.

### 4a. The substrate is never finished — and that is the design

One more consequence of the grammar reframe deserves to be stated as a structural commitment, not a contingency: **ZeroPoint does not have a completion state.** A finished grammar is a dead language. The substrate is supposed to keep absorbing what reality reveals about it — through the adversarial loop, through new pentest findings, through new catalog versions, through new deployments hitting edges that earlier deployments did not. The catalog has versions for the same reason a natural language has dialects and drift: because the thing it describes is alive.

This is not "we will be behind schedule indefinitely." It is "the project's success criterion is *the loop closing repeatedly*, not *the loop terminating*." Phase 0 through Phase 3 are not the path to a finished ZeroPoint. They are the path to ZeroPoint becoming the kind of system that *can* keep absorbing what reality reveals, on a cadence that matches reality's pace of revealing it. After Phase 3, there is Phase 4, which is whatever the first three phases made visible. The document that names Phase 4 is `ARCHITECTURE-2026-XX.md`, conditioned on what the first three phases revealed — exactly the same way the catalog's v1 is conditioned on v0.

This is the project's autoregressive structure at the *meta* layer: not just receipts conditioned on prior receipts, but architectural decisions conditioned on prior architectural decisions, conditioned on what running the prior decisions taught you. The substrate is autoregressive. The catalog is autoregressive. So is this document.

---

## Part II — What the Pentest Revealed

### 5. The structural finding, not the tactical one

It is tempting to read the pentest as "we have a shell-injection bug." That reading is true and useless. The structural finding is bigger.

The pentest revealed that **gate coverage was disciplinary, not structural.** The PolicyEngine, the constitutional rules, the delegation chains, the audit chain — all of them exist and all of them work *when they are consulted.* The bug is that they are not consulted on every path. `/ws/exec` had its own independent code path that talked directly to `Command::spawn` without ever passing through the gate. It is not that the gate is weak. It is that the gate is optional.

Translated into the catalog: every P0 finding is an M1 (gate coverage) violation. That is not a coincidence. It is the symptom of the structural fact that "every privileged action must pass through the gate" was a *convention*, not an *invariant*. Conventions get violated. Invariants do not — because the type system or the runtime makes the violation impossible.

The same fact in different vocabulary: the substrate currently has *spawn sites that exist outside the grammar.* A spawn site is a place where the actual world is modified — a process is created, a file is written, a network call is made. If that spawn site is not preceded by the production P3 (intent → policy → exec), then the action *happened in reality but not in the substrate.* By the substrate's own rules, it didn't happen. And yet it did.

This is the failure mode Version C names but the implementation didn't yet enforce: actuality outrunning the grammar. The world changed but the chain didn't notice.

### 6. The four kinds of damage

The 20 findings cluster into four families, each pointing to a different structural commitment that needs to be made:

| Family | Findings | Structural fix | Catalog rule |
|---|---|---|---|
| **Gate-bypass** (privileged actions outside the grammar) | EXEC-01..04, AUTH-VULN-01..07, TOOL-REG-01 | WASM trust boundary; every side effect goes through host functions | M1 |
| **Chain breakage** (the actual layer is corrupted) | AUDIT-01..04 | Crash-safe writes (PRAGMA synchronous=FULL, fsync), incremental verification, rollback to last known-good prefix | M3, M4 |
| **Sovereignty leakage** (internal processes bypass Guard) | PREFLIGHT-01..05 | Background tasks must go through their own gate; no shared mutable state across the await boundary | M6 |
| **Discovery leakage** (amnesia and reciprocity weakened) | PROXY-01, INFO-01 | Audit the relay for any code path that parses, indexes, or persists payload bytes | M9, M10 |

Three of the four families are M1-adjacent: they are all "the grammar is not enforced on this path." Only the AUDIT family is about the chain layer itself being damaged. That asymmetry tells us where the leverage is.

### 7. What the pentest did not test

Honesty about the testing surface, because absence of evidence is not evidence of absence:

- **Delegation chains were not exercised.** Shannon never needed to forge a delegation because it never needed authority — it had a direct path to spawn. The eight invariants are believed to hold but were not adversarially tested in this run. *Implication:* the next pentest cycle must specifically target delegation paths.
- **Constitutional rules were not exercised.** Same reason. The HarmPrincipleRule was never invoked because the actions never went through the engine. *Implication:* a separate test campaign must verify that Σ holds *under load* and *under pressure to bypass*, not just under normal flow.
- **Cross-node introduction was not tested.** This was a single-node black-box. P4 (Introduction) is unverified at the implementation level.
- **Mesh transport was not tested.** HDLC framing, link handshake, replay protection — none of it was in scope.
- **WASM policy modules were not tested.** Sandbox escape, fuel exhaustion, hash verification of module contents — none of it was exercised.
- **Sequence-level constitutional compliance (X3) was not even formulable.** The catalog names X3 as the substrate's hardest open problem. The pentest could not have tested it because the mechanism does not yet exist.

This list is the next test campaign's scope, in addition to re-verifying what the current campaign exposed.

---

## Part III — Where ZeroPoint Is Going

### 8. The three architectural commitments

These are decisions made (some yesterday, some today) that the rest of the work serves. They are not negotiable; they are the shape of the target.

**Commitment A — The WASM trust boundary becomes the structural enforcement of M1.** Every spawn site, every file write, every network call, every state mutation that affects the world outside the participant's own audit chain is reachable only through host functions exposed to a sandboxed module. The host functions are the only productions in the grammar that have side effects. There is no ambient authority. There are no "internal" code paths that skip the gate, because there is no way to express such a path in the type system. This is the fix that makes M1 stop being a convention and start being an invariant.

**Commitment B — The catalog is the spec, the verifier is the parser, and both have versions.** The invariant catalog is not documentation. It is the formal spec for `zp-verify`, a crate whose only job is to walk a chain and report which catalog rules pass and which fail. v0 of `zp-verify` implements P1, M3, and M4 — the three rules that would have caught AUDIT-01 the moment it happened. v1 adds P2, P3, M1, M2, M6. v2 adds the cross-layer rules X1, X2 and the discovery rules P5, M9, M10. The catalog and the verifier evolve together; a catalog rule without a verifier test is an untested claim.

**Commitment C — Adversarial testing is continuous, not episodic.** The Shannon / PentAGI / Caldera / Nuclei stack runs as a matter of course, not as a special event. Every finding is categorized by the catalog rule it exploits. A finding without a catalog mapping is either a new rule the catalog needs or a new test of an existing rule the implementation failed. Either way the loop closes: pentest → catalog → implementation → re-pentest. The substrate hardens by absorbing what reality reveals about it. This is the autoregressive structure of the *project*, not just the runtime.

These three commitments form a triangle: A makes M1 enforceable, B makes failures detectable, C makes failures discoverable. None of them is sufficient alone. All three are necessary.

### 9. The fourth commitment, made explicit

There is a fourth commitment that is implicit in everything above and that needs to be named explicitly because it is the hardest one and the one most likely to drift if not stated:

**Commitment D — X3 is the substrate's central open research problem and is treated as such.** Sequence-level constitutional compliance — the requirement that *sequences* of individually-allowed actions also satisfy Σ — is the property that distinguishes ZeroPoint from "a hash-chained audit log with policy gating." Without X3, ZeroPoint is a strictly better audit system. With X3, ZeroPoint is the first substrate that can detect gradual exfiltration, slow-drift policy violations, and emergent constitutional breaches — failures that no single receipt can reveal but that the trajectory does.

X3 has no implementation in v0. Candidate mechanisms include WASM rules with bounded lookback, reputation accumulators that emit refusals on sequence patterns, and constitutional rules that maintain rolling state. v1 of the catalog must propose at least one concrete mechanism. v2 must implement and test it.

Naming X3 as Commitment D makes it impossible to forget. It is the thing that justifies everything else.

### 9a. The fifth commitment: external truth anchoring

**Commitment E — The receipt chain's state is externally witnessable via distributed ledger anchoring, and this is an enrichment, not a dependency.**

The chain is self-verifying (M3, M12). External truth anchoring extends the guarantee across organizational boundaries by publishing the chain's head hash, sequence number, and operator signature to an independent distributed ledger — creating a timestamped witness that no single party controls. In the deployment scenarios where this matters — cross-organizational transactions, regulated exchanges, multi-party trust — ledger infrastructure is already present as part of the transaction itself. Governance anchoring piggybacks on that existing infrastructure at effectively zero marginal cost. External witnessing is not an exotic add-on; it is the natural consequence of deploying governed agents in contexts where transactions already touch a shared ledger.

**Architecture.** The `zp-anchor` crate defines the `TruthAnchor` trait — three methods (`anchor()`, `verify()`, `query_range()`) that any DLT backend implements. The `AnchorCommitment` carries the chain's cryptographic fingerprint; the `AnchorReceipt` carries the ledger's proof of publication. Both are compact (hundreds of bytes) and carry no governance content — the ledger sees a hash and a signature, not the governed data.

**Event-driven model.** Anchoring is triggered by `AnchorTrigger` — six variants representing actual reasons to anchor:

| Trigger | When |
|---------|------|
| `OperatorRequested` | Explicit operator invocation (CLI, API, UI) |
| `CrossMeshIntroduction` | Two meshes exchanging trust each anchor for the other to verify |
| `ComplianceCheckpoint` | Before audit export or scheduled compliance review |
| `DisputeEvidence` | Governance action contested, external timestamping needed |
| `Opportunistic` | Existing blockchain transaction — embed chain head as metadata at zero marginal cost |
| `GovernanceEvent` | Significant state change (revocation, constitutional update, trust tier change) |

There are no timers. No receipt-count triggers. The chain's internal integrity is self-contained via hash-linking. External witnessing is valuable when something is at stake, not on a schedule.

**Reference backend: Hedera Hashgraph HCS.** Chosen for sub-second deterministic finality, low cost (fraction of a cent per message), public queryability via mirror nodes, and council governance aligned with transparency commitments. The trait architecture ensures Hedera is a choice, not a dependency — Ethereum L2, Bitcoin OpenTimestamps, Ceramic, or any timestamping authority can be substituted.

**Cross-mesh trust.** When two deployments meet, each announces its anchor backend identifier (e.g., HCS topic ID). Each independently queries the other's anchor history. Trust between strangers is established through shared external proof, not mutual assertion. A deployment with months of consistent anchoring provides a verifiable trajectory of external attestations that a newly fabricated chain cannot reproduce.

**What anchoring does not provide.** It does not prove chain content is true — only that the chain was in a specific state at a specific externally-witnessed time. It does not prevent parallel fabrication (maintaining two chains and anchoring only one). It does not replace internal integrity — a corrupt chain remains corrupt regardless of anchoring. It does not create a runtime dependency — if the ledger is unreachable, the chain continues with full internal integrity.

**Current status.** The `zp-anchor` crate (313 lines) defines all types and traits. The `NoOpAnchor` implementation provides the no-backend-configured fallback. The trait is not yet wired into the runtime's receipt emission pipeline. This is tracked as a deferred obligation in the Invariant Catalog v1, §8.

---

## Part IV — The Path

The path is structured as four phases, with a dependency DAG inside each phase. Phases are sequential (Phase N+1 depends on Phase N completing). Inside a phase, the DAG shows what depends on what — items with no inbound arrows are critical path; items with multiple inbound arrows are downstream; the leaves are the deliverables.

Each phase has:
- **Goal** — the one-sentence statement of what the phase exists to accomplish
- **Exit criterion** — the falsifiable condition that says the phase is done
- **Deliverables** — the artifacts that must exist
- **DAG** — the dependency graph of the work inside the phase
- **Catalog rules addressed** — which rules become enforceable as a result

### Phase 0 — Stop the bleeding (1–2 weeks)

**Goal.** Make the four P0 findings non-exploitable. Rotate the leaked token. Restore chain integrity.

**Exit criterion.** A second Shannon run against the patched build produces zero P0 findings, and `cargo run -- audit verify` returns `valid: true, broken_links: 0`.

**DAG.**

```
[token rotation] ──┐
                   ├──► [Shannon re-run, P0 cleared]
[EXEC-01 hotfix] ──┤
   (replace sh -c with structured argv exec, no shell interpretation)
                   │
[EXEC-02..04 hotfix]
   (depends on EXEC-01) ──┘

[AUDIT-01 investigation] ──► [chain repair OR rollback to last good prefix] ──► [audit verify clean]
   (root-cause the 4 broken links: race? crash? deliberate?)

[PREFLIGHT-01 mitigation already in place via ZP_PREFLIGHT_SCAN_PATH]
   ──► [document the escape hatch in REMEDIATION-NOTES.md]
```

**Deliverables.**
- Patched `auth.rs` with `Command::new(...).args(...)` instead of `sh -c`
- Patched `exec_ws.rs` that refuses any command containing shell metacharacters even after structured exec is in place (defense in depth)
- Root-cause writeup for AUDIT-01 in `security/pentest-2026-04-06/AUDIT-01-rca.md`
- Clean `audit verify` output committed as `security/pentest-2026-04-06/audit-verify-clean.txt`
- Second Shannon report committed as `security/pentest-2026-04-06/shannon-rerun-01.json`

**Catalog rules addressed.** Tactical fixes only — does not yet make M1 structural. P1 and M3 are restored to passing state.

**What Phase 0 deliberately does not do.** It does not architect anything. It does not move toward WASM. It does not start the verifier crate. Phase 0 is triage. The only goal is to leave the system in a state where Phase 1 work can proceed safely.

### Phase 1 — Make the grammar enforceable (4–6 weeks)

**Goal.** Move from "the gate exists and is sometimes consulted" to "the gate is the only way to reach side effects, and the type system enforces this."

**Exit criterion.** Every spawn site, file write, and network call in the codebase is reachable only through a host function exposed to a WASM module. A grep for `Command::new`, `std::fs::write`, `tokio::net::TcpStream::connect`, etc. outside the host-function module returns zero results in the production code paths. A test harness fuzzes the public API and asserts every observable side effect produces a corresponding receipt triple (intent + policy + exec).

**DAG.**

```
[zp-verify v0] ────────────────────────┐
   (implements P1, M3, M4)             │
   ↓                                    │
[verifier integrated into CI]           │
   (every PR runs verify against         │
    a known-good test chain)             │
                                         │
[host-function inventory]                │
   (list every existing side-effect call)│
   ↓                                     │
[host-function trait design]             │
   (the grammar's productions, in code)  │
   ↓                                     ▼
[WASM trust boundary v0] ───────► [test harness: every side effect produces a receipt triple]
   (one module, one host function set,        ↓
    one privileged action ported)        [Phase 1 exit]
   ↓
[port remaining privileged actions]
   (incremental, one action at a time,
    each port verified against the catalog)
   ↓
[ambient authority audit]
   (final grep, final lint, final test)
```

**Deliverables.**
- `crates/zp-verify/` — new crate, v0 implementing P1, M3, M4
- `crates/zp-host/` — new crate, host-function trait + canonical implementation
- WASM module template for "a privileged action" with the host functions as its only side-effect surface
- All `auth.rs`, `exec_ws.rs`, `tool_registry.rs`, and `preflight.rs` privileged actions ported to use the host-function interface
- A `#[no_ambient_authority]` lint or convention check enforced in CI
- Updated `INVARIANT-CATALOG-v1.md` reflecting what v0 missed and what Phase 1 made explicit

**Catalog rules addressed.** M1 (gate coverage) becomes structural. P3 (AuthorizedAction) becomes enforced rather than encouraged. M6 (sovereignty preservation) gains a concrete mechanism: the host function for a privileged action must consult the Guard before invoking the side effect.

**The load-bearing decision in Phase 1.** Whether to use WASI Preview 2 / component model or wasmtime with a custom host-function interface. Component model is more standard and forward-compatible; custom is faster to implement and gives more control. The recommendation is WASI Preview 2 because it makes the host-function surface a *typed contract* rather than a hand-written API, which is exactly what the grammar reframe wants. But this is a real decision and should be made deliberately, not by default.

### Phase 2 — Adversarial loop closes (6–8 weeks, overlapping the tail of Phase 1)

**Goal.** Stand up the continuous adversarial testing stack and make it a normal part of development. Every commit gets a full pass; every release gets an extended campaign.

**Exit criterion.** Shannon, PentAGI, Caldera, and Nuclei all run unattended on a CI schedule, all four produce findings categorized by catalog rule, and the time from "Shannon files a finding" to "the catalog or the implementation is updated" is measured in days, not weeks.

**DAG.**

```
[Shannon hosted in zp stable]
   ↓
[PentAGI hosted in zp stable]
   ↓
[Caldera installed and configured for ZP TTPs]
   ↓
[Nuclei templates curated for ZP-relevant CVEs]
   ↓
[unified findings format] ─────► [catalog mapping in every finding]
                                              ↓
                                  [findings dashboard, severity by catalog rule]
                                              ↓
                                  [SLA: P0 findings = 24h triage, P1 = 1 week]

[Phase 1 verifier integration] ──► [verifier becomes a baseline check in every campaign]
   (already exists from Phase 1)        (every campaign starts with `cargo verify`)
```

**Deliverables.**
- `tools/adversarial/` directory with the four agents installed and configured
- A unified findings JSON schema that includes a mandatory `catalog_rule` field
- A simple findings dashboard (HTML, no backend) showing open findings by catalog rule and severity
- A `SECURITY.md` that documents the loop, the SLAs, and the catalog reference
- Scheduled task definitions for the four agents (daily Shannon, weekly PentAGI, weekly Caldera, daily Nuclei)

**Catalog rules addressed.** The catalog stops being a document and starts being a runtime concern. New rules can be added based on what the agents find. Old rules get re-tested continuously.

### Phase 3 — Sequence-level compliance (X3) (open-ended research, starts 8+ weeks in)

**Goal.** Build the first concrete mechanism for sequence-level constitutional compliance. Make X3 implementable.

**Planning posture.** Phase 3 is the only phase whose internal structure cannot be predicted in advance. Per Part V.2, confidence that *some* X3 mechanism is tractable is high (~85%); confidence that the *first* attempt is the right shape is low (~30%). The phase therefore explicitly budgets for **at least two iterations** before the right shape emerges, and treats the first iteration's *failure mode* as its most valuable output. A first attempt that produces clean measurements about *why* a mechanism does not work is more valuable than a first attempt that produces ambiguous success — because the second attempt is conditioned on the first one's failure, and only sharp failures sharpen the second attempt.

**Iteration A — the probe.** Pick the candidate mechanism with the lowest implementation cost (likely bounded-lookback WASM rules, since the WASM runtime already exists from Phase 1). Implement v0 against the simplest realistic adversarial fixture (synthetic gradual exfiltration over a fixed window). Measure: detection rate, false-positive rate, latency added at the rolling-window edge, lookback window length needed, and *what kinds of patterns the mechanism cannot represent at all.* That last measurement is the most important — it tells you what the next mechanism has to do that this one couldn't.

**Iteration B — informed by A's failure mode.** Pick the candidate mechanism whose strengths cover Iteration A's gaps. If A was bounded-lookback WASM and it could not handle interleaved sequences across multiple grants, B is probably reputation accumulators with sequence detectors (which compose across grants naturally). If A could not handle slow-drift patterns longer than the window, B is probably stateful constitutional rules with adaptive windows. The choice of B is *determined* by what A revealed, not pre-selected.

**Exit criterion.** A mechanism (the result of Iteration A, B, or possibly C) exists that catches a defined class of sequence-level constitutional violations with stated false-positive and false-negative rates, runs inside the existing constitutional evaluation budget, and is exercised by adversarial fixtures in `security/x3/`. The exit criterion is *not* "X3 is solved." It is "X3 has a working mechanism with measured properties, the catalog is updated to reflect what the mechanism enforces and what it does not, and Commitment D moves from 'named open problem' to 'implemented with stated bounds'."

**DAG.**

```
[Iteration A — the probe]
   pick lowest-cost candidate (likely bounded-lookback WASM rules)
   ↓
[v0 implementation against synthetic gradual exfiltration fixture]
   ↓
[measure: detection rate, FP rate, latency, lookback window needed,
           AND patterns the mechanism cannot represent at all]
   ↓
[Iteration A failure-mode writeup ─────► informs Iteration B candidate choice]
                                                      ↓
                                  [Iteration B — informed pivot]
                                  candidate selected to cover A's gaps
                                                      ↓
                                  [v0 implementation of B against same fixture
                                    PLUS the patterns A couldn't represent]
                                                      ↓
                                  [measure same dimensions]
                                                      ↓
                                  [if B's gaps are tolerable: ship as v1]
                                  [if not: Iteration C]
                                                      ↓
                                  [INVARIANT-CATALOG-v2.md
                                    with X3 implemented + stated bounds]
```

**Deliverables.**
- A research note in `docs/x3-mechanisms.md` evaluating the three candidates
- A v0 implementation of the chosen mechanism
- An adversarial test fixture in `security/x3/` that produces gradual-exfiltration patterns
- Measurement results
- v2 of the catalog with X3 promoted from "named open problem" to "implemented and tested"

**Catalog rules addressed.** X3. This is the rule that justifies everything else.

**What Phase 3 acknowledges that Phase 0–2 do not.** Phase 3 is research. It might fail. The first mechanism might prove inadequate; the second might too. The phase has an indefinite duration on purpose. The other three phases are engineering with known shapes; Phase 3 is the place where the project earns its claim to be doing something novel.

### Phase 4 — The Governed Agent Runtime (starts when Phase 1 exit lands)

**Goal.** Extend the substrate from governing *tools and delegations* to governing *persistent autonomous agents*. Make ZeroPoint the runtime, not the accessory.

**Why Phase 4 exists.** Section 4a says the substrate is never finished, and that Phase 4 is "whatever the first three phases made visible." What they made visible is this: the grammar, the gate, the five-surface mediation model, and the WASM trust boundary are exactly the machinery needed to run a durable autonomous agent as a *governed tenant* — an entity that persists across sessions, accumulates memory and skills, spawns subprocesses, and reaches the outside world through surfaces that ZeroPoint already knows how to mediate.

The agent ecosystem has converged on a common capability set: persistent memory, learned skills, tool use, browser automation, scheduled execution, and multi-agent orchestration. This creates a new category of software — the durable autonomous actor — and a governance gap that the substrate is architecturally positioned to close. The first concrete tenant is Hermes Agent (Nous Research), chosen because it exhibits all five surfaces that Phases 0-3 taught ZeroPoint to govern.

**Architecture.** The Governed Agent Runtime (GAR) uses a wrapper model, not a plugin model. ZeroPoint is the outer process; the agent is a managed tenant inside controlled Linux namespaces. Every I/O surface the agent touches — model API, filesystem, subprocess, network, IPC — is mediated by the same host-function boundary that Phase 1 established. The grammar is the same; the productions are new.

The full GAR architecture, including containment model, governance surfaces, receipt schema, and phased implementation, is specified in `docs/design/governed-agent-runtime.md`.

**Relationship to existing commitments.**

- **Commitment A (WASM trust boundary)** extends directly: the five mediation surfaces are host functions. The agent's namespace isolation is the kernel-level expression of the same principle — no ambient authority, no side effects outside the grammar.

- **Commitment B (catalog as spec, verifier as parser)** extends: 11 new receipt types (AgentSessionClaim, MemoryWriteClaim, SkillProposalClaim, SkillPromotionClaim, BrowserSessionClaim, BrowserActionClaim, SubprocessClaim, InferenceRequestClaim, WorktreeResultClaim, CapabilityQuarantineClaim, ReasoningTraceClaim) join the existing chain. `zp-verify` gains rules for agent lifecycle events. The catalog's grammar absorbs new productions without changing its shape.

- **Commitment C (continuous adversarial testing)** extends: the GAR's containment model is a new attack surface. Shannon's next campaign must attempt namespace escape, overlay bypass, and proxy circumvention.

- **Commitment D (X3)** is where the GAR produces its deepest contribution. A persistent agent that accumulates memory, learns skills, and spawns subprocesses over days or weeks is *exactly* the workload where sequence-level constitutional compliance matters. Individual actions may be benign; the trajectory may not be. The GAR provides the receipt stream that X3 needs to operate against real agent behavior, not synthetic fixtures.

**The reasoning attestation extension.** The GAR introduces a sixth governance concern beyond the five I/O surfaces: the autoregressive reasoning chain that *produces* the decisions manifesting at those surfaces. If autoregression is understood as a universal computational principle — a fundamental mode of computation alongside recursion, iteration, and reduction — then the reasoning chain is the primary computational substrate, and I/O-surface actions are its side effects. Governing the side effects without governing the computation that produces them is like an operating system that controls file I/O but has no concept of process memory.

The GAR addresses this through two-layer governance: an enforcement layer (five surfaces, kernel-enforced) and an attestation layer (reasoning chain, cryptographically linked to receipts via `reasoning_hash`). Every receipt carries a content-addressed reference to the chain of thought that produced it, creating causal provenance across the autoregressive boundary.

This is the concrete precursor to the cognitive accountability layer designed in `docs/future-work/cognitive-accountability.md`. The GAR's reasoning attestation provides Layer 3's anchor point — the hash-linked bridge between "what happened" (receipts) and "what computation produced what happened" (traces). When the foundation is hardened enough to support LARQL decomposition and MEDS fingerprinting, the GAR's attestation infrastructure is what they plug into.

**Three inference trust tiers.** The GAR distinguishes local models with full trace capture (attested), remote APIs with prompt/response logging (observed), and untraced inference (unattested, not permitted in sovereign mode). The trust tier determines what the attestation layer can prove and what the operator can audit.

**Planning posture.** Phase 4 is engineering, not research. Its shape is known because Phases 0-3 defined the grammar and the surfaces. The implementation phases within the GAR (contained execution → skill/memory governance → multi-agent orchestration → portable governance) are specified in the companion document with concrete deliverables. Phase 4 can begin in parallel with Phase 3's research work, since it depends on Phase 1's WASM trust boundary and Phase 2's adversarial loop, not on X3's resolution.

**Exit criterion.** A Hermes Agent instance runs as a GAR tenant with all five surfaces mediated, memory writes classified and policy-gated, skill proposals quarantined and verified, subprocess spawns receipted, and `zp-verify` validating the full agent-session chain against the extended catalog. A second agent framework (Claude Code, Cursor, or equivalent) runs under the same governance model, proving the wrapper is general.

---

## Part V — Calibrated Uncertainty

A north-star document is most useful when it is honest about *which* of its claims it would defend strongly and which it holds with real uncertainty. The earlier draft of this section read as generic hedging — "everything might be wrong, here are fallbacks." That is not honest, because most of these claims are not held with equal confidence. This revision states the actual confidence levels and identifies what would change them.

The structural commitment that "the project might never finish" has been moved out of this section and into Part I §4a, where it belongs as a positive design statement. The operational risk that "the agent stack might change" has been removed entirely — it is real but it is a tooling concern, not an architectural one, and putting it in the same section as the WASM and X3 questions overstated its importance.

What remains is three claims, ordered by how much uncertainty I actually hold about each.

### V.1 — The WASM trust boundary as the M1 mechanism

**Confidence it's the right answer: ~80%.** This is a recommendation I'd defend strongly, not a placeholder.

The reasoning is structural, not aspirational. ZeroPoint already ships WASM modules in `zp-policy` for sandboxed rules with fuel limiting, so the runtime is already in the codebase, the ergonomics are understood, and the team has shipped against wasmtime before. The case isn't "WASM is trendy" — it is "the only way to make M1 stop being disciplinary is to make ambient authority *unrepresentable*, and a sandboxed module with host-function-only side effects is the cleanest way to express that in Rust today." The grammar reframe wants the host-function surface to be a *typed contract*, and a WASM boundary is the closest production-grade Rust technology that gives you one.

**The 20% I held back is almost entirely about WASI Preview 2 specifically, not WASM in general.** Preview 2 is newer, the component model story is still settling, and if the team hits a sharp edge there it could push toward custom wasmtime with a hand-written host interface. That would be a Phase 1 implementation pivot, not a commitment change. If WASM proved actively painful at the *runtime* level — fuel accounting interferes with latency budgets, memory copies between host and guest dominate, sandbox crossing dominates — then the fallback (Rust-level capability passing with a `#[no_ambient_authority]` lint) becomes the answer. I do not expect that.

**What would change my mind:** the first port of a real privileged action through the boundary. Once `auth.rs::execute_command` is reachable only via a host function and the test harness confirms every spawn produces a receipt triple, this stops being a recommendation and becomes either confirmed or disproven. The decision converts to evidence the moment Phase 1's first deliverable lands.

### V.2 — X3 has a tractable mechanism

**Confidence X3 has *some* tractable form: high (~85%).**
**Confidence the *first* mechanism we try will be the right one: low (~30%).**

These two confidences are the heart of the project's open research. The first is high because the general problem (sequence-level temporal-property checking) has a real literature — runtime verification of LTL/MTL properties, streaming complex event processing, monitoring of metric temporal logic — and the bounded-lookback subset of X3 falls squarely inside what is known to be decidable and implementable. "Detect gradual exfiltration" is engineering-tractable in the sense that you can build something that catches obvious cases and misses subtle ones, and that is still novel and still useful.

The second is low because *which* mechanism wins depends on properties of ZP's actual workload that nobody has measured yet: how long the relevant lookback windows are, how many concurrent sequences need monitoring, what the false-positive tolerance is for refusing a legitimate sequence, and how much latency the constitutional check can absorb at the rolling-window edge. None of those are knowable in advance. They become knowable as soon as v0 of any of the three candidate mechanisms (bounded-lookback WASM rules, reputation accumulators with sequence detectors, stateful constitutional rules with rolling windows) runs against a real adversarial fixture.

**The honest version of the X3 risk is not "X3 might be impossible." It is "Phase 3 will iterate two or three times before the right shape emerges, and the document should plan for that explicitly rather than treating Phase 3 as a single attempt."** Phase 3 is the only phase whose internal structure I cannot fully predict. That is what makes it research instead of engineering — and it is also exactly why it justifies the project. If X3 were obviously solved, ZeroPoint would be a strictly better audit log. Because X3 is not obviously solved, ZeroPoint is doing something the field needs.

**What would change my mind on the high-confidence claim:** running the first candidate mechanism against a synthetic gradual-exfiltration fixture and finding that *no* configuration of bounded lookback catches it without unacceptable false positives. That would push the catalog toward acknowledging X3 as best-effort with measured rates rather than as a property the substrate enforces. It would not invalidate ZeroPoint, but it would change Commitment D from "X3 is implemented" to "X3 is approximated with stated error bounds."

### V.3 — The catalog's grammar formalism

**Confidence the overall shape survives: ~80%.**
**Confidence every individual rule survives unchanged: lower (~50%).**

The grammar formalism is doing real work in v0 — productions for chain extension and delegation, invariants for constitutional persistence and continuity, modal layers (Required / Possible / Actual) that map cleanly onto the whitepaper's existing vocabulary. I'd defend the formalism in outline.

The lower confidence on individual rules reflects that some rules will probably want to be reshaped after `zp-verify` is real. Specifically: M2 (constitutional persistence) might be cleaner expressed as a *type-class constraint* on the PolicyEngine constructor than as a runtime invariant. M4 (trajectory monotonicity) might want to be a *refinement type* on receipts rather than an invariant the verifier checks separately. P5 and M9 (Presence Plane rules) might belong in a separate session-grammar layer rather than the main catalog. None of these are "the grammar is wrong" — they are "this rule fights its expression and wants a different one." The catalog is the spec; the formalism serves the spec; if part of the formalism stops serving, it should be refactored.

**What would change my mind on the high-confidence claim:** implementing `zp-verify` for P1, M3, M4 and finding that even those three core rules fight the grammar shape — that the verifier wants to be a state machine with productions as transitions, or a type checker with rules as judgments, or something else structurally different from a grammar parser. That would prompt a v1 of the catalog with a different formalism. I do not expect it, because the three core rules map to grammar productions cleanly enough that I can describe their pseudocode in my head right now.

### What this section is actually saying

The three remaining claims, ordered by how much I'd bet on them:

1. **WASM as M1's mechanism** — I'd take the bet at 4:1. The fallback exists for completeness, not because I expect to use it.
2. **The grammar formalism survives** — I'd take the bet at 4:1 in outline, even at money on every individual rule surviving unchanged.
3. **X3 has a tractable form** — I'd take the bet at 5:1 that *some* mechanism works. I would *not* bet that the first attempt is the one.

The thing that converts all three claims from confidence to evidence is the same: **start `crates/zp-verify` and run it against the actual chain.** That is why Part VI says start there. It is the smallest first step *and* it is the step that converts the most uncertainty into evidence per line of code written. Every other commitment in the document gets sharper the moment the verifier runs.

---

## Part V½ — Design Philosophy: The Zen of the Trust Layer

**Inspirational debt:** Mark Qvist's *Zen of Reticulum* (early 2026). What Reticulum articulates for the networking layer — uncentralizability, encryption as gravity, portable identity, scarcity as craft, sovereignty through infrastructure — ZeroPoint articulates for the trust layer. The principles below are not decorative. They are load-bearing constraints that shape every architectural decision in the substrate. If code violates one, the code is wrong.

### Principle 1 — Signing is gravity

In Reticulum, encryption is not a feature; it is the force that allows the network to exist. Strip the encryption and the routing breaks.

In ZeroPoint, signing is not a feature; it is the force that allows the trust layer to exist. The Receipt's `content_hash` IS the routing logic of trust. The governance gate validates cryptographic proofs, not permissions. The reconstitution engine replays signed evidence, not log messages. The blast radius model traces compromise through signature chains, not through configuration.

An unsigned Receipt is structurally meaningless. It is an assertion without a witness. The abacus model requires that every bead on every wire carries an Ed25519 signature from the entity that attests to the claim. This is not a security feature bolted onto a logging system; it is the force without which the readiness state cannot be derived, the governance gate cannot validate, and the reconstitution engine cannot replay.

To ask for a version of ZeroPoint without signing is to ask for a version of the ocean without liquid.

### Principle 2 — Identity is a key, not a location

In Reticulum, an address is a hash of an identity, not a coordinate in a grid. You can move from WiFi to LoRa to packet radio and your destination hash never changes.

In ZeroPoint, a tool's identity is its bead zero — the `CanonicalizedClaim` receipt that captures its first-known-state, signed by the genesis key. The tool is not "the process listening on port 8080." It is "the entity whose bead zero was signed by key `<327c...>` and whose subsequent beads form an unbroken chain of attestations." Move the tool to a different machine, change its port, rotate its credentials — the bead chain persists. The identity is the cryptographic lineage, not the deployment coordinates.

The genesis key is the operator's true name. It is not assigned by a service, granted by a registrar, or conditional on the uptime of a server. It is a 32-byte Ed25519 secret that the operator generates locally and carries sovereign. The vault encrypts around it. The audit chain is signed by it. The entire infrastructure can be destroyed and rebuilt, and the operator's identity — the mathematical entity that signed the genesis ceremony — persists.

### Principle 3 — There is no center

In Reticulum, there is no cloud. There is only other people's computers.

In ZeroPoint, there is no trust server. There is only the local audit chain and the cryptographic proofs it contains. The cockpit does not ask a remote authority "is ironclaw ready?" It reads the local audit chain, finds the bead zero, verifies its signature, walks the subsequent beads, and derives the readiness state from mathematical evidence. The answer is in the chain or it is nowhere.

This is uncentralizable by design. There is no DNS to hijack, no certificate authority to compromise, no API endpoint to DDoS. The trust state lives on-device, signed by keys the operator controls, verifiable by anyone with the public key. The audit chain is a sovereign artifact. It belongs to the operator, not to a platform.

### Principle 4 — Every bit counts

In Reticulum, 5 bits per second is a valid speed. The cost of a byte is energy, time, and spectrum. Efficiency is stewardship.

In ZeroPoint, every field on a Receipt exists because removing it would break a verifiable claim. The canonical serialization (Phase 2.5) strips non-deterministic whitespace before signing. The epoch compaction (Merkle roots) reduces verification from O(n) chain walks to O(log n) proofs. The naming coherence pass ensures every term carries exactly one meaning — no byte of cognitive bandwidth wasted on ambiguity.

Phase 6 applied this principle: lifecycle Receipts now carry `ClaimMetadata::Lifecycle` (self-describing event type, tool ID, detail), and the query path reads Receipt metadata first. The redundant detail JSON that was duplicated in `PolicyDecision::Allow` conditions has been stripped — the Receipt is the single source of truth. String events remain as lightweight indexes for wire lookups, but they carry no payload. Every bit in the audit chain earns its place through cryptographic necessity.

### Principle 5 — Store-and-forward is the primary mode

In Reticulum, connectivity is a spectrum, and Store & Forward is not a fallback but a primary mode of existence. You send a message; it arrives when it arrives.

In ZeroPoint, the audit chain IS store-and-forward. You do not ask "is the system healthy right now?" — you ask "what does the chain say?" The readiness state is derived from accumulated evidence, not from a live heartbeat. If the system goes down and comes back, the chain persists. The beads are still signed. The truth survives the outage.

This changes the psychological texture of trust. You are not anxiously polling a health endpoint. You are reading a permanent, hash-linked, signed record of everything that happened, and deriving the current state from first principles. The audit chain is not a log you might read later; it is the ground truth from which all other state is projected.

### Principle 6 — A tool is intent, crystallized

In Reticulum, a tool is never neutral. Architecture is politics.

In ZeroPoint, the governance gate is not a guardrail; it is the protocol. A `CanonicalizedClaim` receipt does not merely record that something happened — it makes a cryptographic claim with specific semantics (`ClaimSemantics::IntegrityAttestation` means "this entity's state has not changed since I last attested to it"). The claim type, the metadata structure, the signature — these are not logging conventions. They are the grammar of trust.

The HarmPrincipleRule and SovereigntyRule are constitutional — non-removable, non-overridable, evaluated first. They are conservation laws, not policy preferences. Their presence in the governance gate is not a feature; it is the substrate's statement about what kind of tool it is. A tool that can be turned against its operator is not a tool but a trap.

By encoding these principles into the protocol's mathematical structure — not into a terms-of-service document, not into a configuration file, but into the cryptographic invariants themselves — we align the software with the interests of the operator. The network is not something that happens to you; it is something you make happen.

### Principle 7 — Contact does not commit

In Reticulum, reaching a destination does not make you authorized to speak through it. Only a key holder can. Contact is not credential.

In ZeroPoint, contact with the world — a tool firing, a memory being proposed, a browser action adapting, a skill being learned from experience — does not automatically update the substrate. The receipt chain is not a log that faithfully records everything that happens; it is the substrate's own account of what it *chose to commit to*. Every update is a decision. Every bead is a signature on "this is what I accept as part of what I am now."

This matters most where mutable agent systems touch the unmutable trust layer. An agent like Hermes learns skills from experience. A browser harness writes helpers mid-task to route around brittle DOM. A memory provider suggests that a new fact should persist. None of these are wrong. But if any of them silently become part of the trusted substrate, the substrate has lost agency over its own evolution — it is just an accumulating record of whatever contact produced. That is not governance; that is transcription.

The distinction the substrate must make is between **adaptive use of existing capabilities** (the agent solves a problem in a new combination of what it already has — signed receipt, no promotion) and **creation of new operational capabilities** (a skill, helper, DOM strategy, or memory fact that would *extend* what the substrate allows next time — unsigned artifact, held in quarantine, signed only after review). The first is a bead on an existing wire. The second is a proposed new wire, and the substrate decides whether to open it.

The integration sentence, in operational form:

> *Hermes may learn from the world. Browser Harness may adapt to the world. ZeroPoint decides what the system is allowed to become because of that contact.*

This principle was discovered during the Phase 4 Hermes integration analysis. It is the reason the Governed Agent Runtime distinguishes between dispatch-time gates (which govern *use*) and artifact-creation gates (which govern *becoming*). Receipts are the substrate's membrane. Events reach it; the substrate decides what passes through.

### The design test

When evaluating any architectural decision, apply the seven principles as a filter:

1. Does this require signing to function, or does it work without? (If it works without, signing is decorative, not gravitational.)
2. Is identity derived from cryptographic lineage, or from deployment coordinates? (If coordinates, it's fragile.)
3. Does this require a central authority, or can it be verified locally? (If central, it's a single point of failure.)
4. Is every field load-bearing, or is there waste? (If waste, strip it.)
5. Does this survive an outage, or does it require live connectivity? (If live, it's brittle.)
6. Are the semantics in the structure, or in the comments? (If comments, the intent isn't crystallized.)
7. Does contact produce a commit, or is the commit a separate, signed decision? (If contact commits, the substrate is transcribing, not governing.)

Code that fails any of these tests should be revised until it passes. The principles are not aspirational; they are operational.

---

## Part VI — The One Thing to Do First

If this document is too long to act on, the one thing to do first is: **start `crates/zp-verify` and implement P1 and M3.** Two rules, one crate, maybe 200 lines of code. The verifier runs against the existing chain and reports what is broken. That is the first concrete artifact that proves the catalog is real and the substrate is parseable. Everything else in Phase 1 depends on it. Everything in Phase 2 reuses it. Phase 3 cannot exist without it.

Start there. The rest follows.

---

## Part VII — Competitive Landscape Adaptations

**Added:** 2026-04-25, following comparative analysis of Microsoft's Agent Governance Toolkit (AGT, released 2026-04-02, MIT license). Full analysis in `docs/design/AGT-COMPARATIVE-ANALYSIS.md`.

**Context.** Microsoft released an open-source, seven-package governance toolkit covering all 10 OWASP Agentic AI risks. Ed25519 signatures, DID-based identity, execution rings, dynamic trust scoring (0–1000), policy engines in YAML/OPA/Cedar, adapters for 20+ frameworks. Multi-language: Python, Rust, TypeScript, Go, .NET. This validates the market ZeroPoint is building in and sets the industry baseline.

**The permanent differentiation.** AGT is governance-as-software. Its policy engine, trust scoring, and compliance grading all require a running process. The governance exists in the toolkit, not in the data. ZeroPoint's governance is governance-as-data — the receipt chain carries its own proof, survives the governed system, and is cold-auditable. This is an architectural commitment, not a feature gap. AGT cannot add chain integrity without redesigning from append-only logs to hash-linked, signed, self-verifying chains.

Additionally: AGT's trust is not portable. Trust scores live in-process and reset on restart. ZP's trust is the chain — it travels with the entity. AGT has no canonicalization (entities are assumed to pre-exist governance). AGT has no formal grammar (no equivalent of "well-formed" or "ungrammatical"). AGT is not autorecursive (the governance toolkit's own decisions are not subject to its own governance).

### Adaptations — what to learn from AGT

Eight capabilities observed in AGT that ZeroPoint should adapt. Ordered by priority. Each is restated in ZeroPoint's vocabulary and architecture.

**F1 — Chain verification CLI (`zp verify`).** AGT ships `agt verify` — a single command that runs OWASP compliance checks and produces a signed attestation. ZeroPoint already has the Falsification Guide (9 tests), the Invariant Catalog (13 invariants, 6 productions, 4 cross-layer rules), and `zp-verify` (the chain-walking crate). What's missing is the single-command UX that ties them together. `zp verify` walks the chain, checks all invariants, and outputs a trajectory attestation: "Chain intact. N receipts. 0 invariant violations. Well-formed since genesis on [date]." This is a CLI wrapper around existing machinery, not new governance logic. **Affected crate:** `zp-verify`, new `zp-cli` subcommand. **Effort:** Low.

**F2 — Uncanonicalized entity discovery.** AGT's `agent-discovery` scans processes, configs, and repos for unregistered agents. In ZP terms, this is a scanner that reports entities executing without a canon — violations of the canonicalization invariant (M11). "These 3 processes are running but have no canonicalization receipt. They do not exist in the governance domain." The invariant says nothing executes without a canon; this tool detects when the invariant is violated in the surrounding environment. **Affected crate:** New `zp-discover` crate or CLI subcommand. **Effort:** Medium.

**F3 — MCP tool content scanner (pre-canonicalization security gate).** AGT's MCP Security Scanner detects tool poisoning, typosquatting, and hidden instructions in MCP tool definitions. ZP's tool canonicalization establishes that a tool exists and who authorized it, but does not inspect the tool's definition for malicious payloads. A pre-canonicalization scanner makes canonicalization a security gate, not just an identity gate. The scan result is a receipt claim (`tool:scanned:clean` or `tool:scanned:flagged`) — chain-linked and auditable. This is a constitutional-rule-level check: the tool must pass content safety verification as a precondition for being constituted. **Affected crates:** `zp-governance` (gate evaluation), new scanner module. **Effort:** Medium.

**F4 — Published performance benchmarks.** AGT publishes specific numbers: 0.012ms p50 for single-rule eval, 35K ops/sec under 50-agent concurrency. ZeroPoint publishes nothing. The governance gate, receipt emission (Ed25519 signing + Blake3 hashing), and chain verification have measurable costs. Benchmark them. Publish the numbers with honest caveats about what's measured. **Affected crates:** Benchmark suite across `zp-governance`, `zp-receipt`, `zp-verify`. **Effort:** Low.

**F5 — Reversibility annotations on tool capabilities.** AGT's Agent Hypervisor verifies execution plan reversibility before actions execute. In ZP terms, reversibility is a property of the tool's canonicalization record — part of its capability envelope. When a tool is canonicalized, its manifest declares `reversible: true|false`. The governance gate applies stricter policy to irreversible actions (higher trust tier required, operator approval, mandatory cooldown). The annotation is a receipt claim: `tool:capability:irreversible`. **Affected crates:** `zp-receipt` (capability metadata), `zp-governance` (gate policy). **Effort:** Low.

**F6 — Health check CLI (`zp doctor`).** AGT ships `agt doctor` for initialization verification. ZP equivalent: `zp doctor` checks genesis sealed, chain intact (quick hash-link walk), all entities canonicalized, vault accessible, signing key available, verifier operational. Reports what's healthy and what needs attention. **Affected crate:** `zp-cli`. **Effort:** Low.

**F7 — Python SDK.** AGT ships SDKs in 5 languages. Most tenant frameworks (Cline, CrewAI, OpenHands, LangGraph) are Python. ZP's MCP interface provides language-agnostic governance, but a native Python SDK (`zeropoint-py`) would lower integration friction for tenant development. Start with receipt creation, chain verification, and governance gate client. **Affected:** New `zeropoint-py` package wrapping MCP or FFI to Rust core. **Effort:** High.

**F8 — Post-quantum algorithm agility.** AGT implements hybrid Ed25519 + ML-DSA-65 (FIPS 204). Not urgent for ZP, but the receipt format should accommodate algorithm agility — a receipt signed with Ed25519 today should be co-signable with a post-quantum algorithm tomorrow without breaking the chain. This is a format design decision, not a cryptography implementation. **Affected crate:** `zp-receipt` (signature algorithm field in receipt format). **Effort:** Low (design), deferred (implementation).

### What NOT to adapt

**Dynamic trust scoring (0–1000).** AGT's trust score erases the trajectory. ZP's trust IS the trajectory. A derived trust score — computed from the chain as a projection (Primitive 4) — may be useful as a UX convenience, but must never replace the chain as the source of trust.

**Execution rings.** ZP's containment levels (1–5) serve the same function. Different metaphor (physical containment vs. CPU privilege), equivalent capability.

**SRE patterns (SLOs, error budgets, circuit breakers).** Operational concerns, not governance concerns. Belong in the deployment infrastructure, not in the governance substrate.

**20+ framework adapters.** Premature. MCP provides framework-agnostic integration. Build native adapters when specific tenant integrations demand them.

---

*ZeroPoint Architecture document — April 2026 — drafted in /docs/ alongside whitepaper-v2.md following the pentest synthesis pass. Phase 4 (Governed Agent Runtime) added April 21, 2026 following the Hermes Agent integration analysis. Part V½ (Design Philosophy) added April 22, 2026 following the Zen of Reticulum alignment pass — inspired by Mark Qvist's articulation of uncentralizable networking principles, mapped to ZeroPoint's trust layer. Elevated to Canonical Architecture Record on April 22, 2026 — wired into CLAUDE.md as binding constraint for all sessions. Part VII (Competitive Landscape Adaptations) added April 25, 2026 following Microsoft AGT comparative analysis. Next revision expected after Phase 1 exit.*
