# ZeroPoint Claim Methodology

**Date:** 2026-04-25
**Purpose:** How ZeroPoint states claims, designs falsifiers, tracks status, and maintains honesty. This is the meta-methodology — the process by which we hold ourselves accountable. It is exportable: any project can adopt this discipline.

---

## 1. Why This Document Exists

Most infrastructure projects make claims. Few projects specify how to test those claims. Fewer still publish the results when the tests fail.

ZeroPoint's governance thesis is built on testable claims — not aspirational statements, not feature descriptions, not compliance checkboxes. Each claim is a falsifiable proposition about the system's behavior. The methodology described here is how we ensure those claims stay honest as the project evolves.

This methodology is itself a claim: *we test our own claims rigorously and publish the results, including failures.* If we stop doing that, this document becomes a lie, and someone should call it out.

---

## 2. Anatomy of a Claim

Every ZeroPoint claim has five components:

### 2.1 The Statement

A precise, unambiguous assertion about the system's behavior. Written in the present tense. No hedging, no "designed to," no "intended to." The claim says what *is* true, not what *should be* true.

**Good:** "Every side effect passes through the GovernanceGate."
**Bad:** "The system is designed to route side effects through governance."

The difference matters. The first is falsifiable. The second is always true (the design intention exists regardless of whether the implementation satisfies it).

### 2.2 The Mechanism

How the system achieves the claim. Specific code paths, data structures, algorithms. The mechanism is what makes the claim an engineering fact rather than a wish.

**Example:** "Mechanism: GovernanceGate.evaluate() called on all five mediation surfaces (Model API, filesystem, subprocess, network, IPC) before side effect execution."

### 2.3 The Catalog Rule

The formal invariant or production in the Invariant Catalog that the claim corresponds to. This links the prose claim to the grammar.

**Example:** "Catalog rules: M1 (Gate Coverage), P3 (Authorized Action)."

### 2.4 The Falsifier

The specific, executable test that would prove the claim false. Not a vague description — a concrete procedure with a concrete expected result.

**Example:** "Falsifier: any side effect observable in the chain (tool:cmd:executed, tool:started) without a corresponding prior gate evaluation receipt."

The falsifier must be:
- **Executable** — someone can actually run it
- **Unambiguous** — the result is true or false, not "it depends"
- **Independent** — it can be run by someone with no project affiliation
- **Specific** — it names the exact condition that constitutes failure

### 2.5 The Status

One of four values:

| Status | Meaning |
|--------|---------|
| **TRUE** | The claim holds. The falsifier has been run and did not produce a falsifying result. |
| **FALSE** | The claim does not hold. The falsifier has been run and produced a falsifying result. The specific result is documented. |
| **UNTESTED** | The claim is believed to hold based on code inspection, but the falsifier has not been run under adversarial conditions. |
| **CONDITIONAL** | The claim holds under specific conditions (e.g., a feature flag being enabled) and those conditions are documented. |

There is no "partially true." A claim either holds or it doesn't. If it holds under some conditions but not others, the status is CONDITIONAL and the conditions are stated.

---

## 3. How Claims Transition

### 3.1 The Status Register

Every claim has a status register — a dated log of status transitions. This is the claim's history, and it is never edited retroactively. A claim that was false and is now true shows both entries.

**Format:**

```
| Date       | Status    | Evidence |
|------------|-----------|----------|
| 2026-04-06 | FALSE     | AUDIT-01: four broken hash links from concurrent-append race |
| 2026-04-07 | TRUE      | Fixed: transactional append, UNIQUE index, schema recanonicalization |
```

### 3.2 Transition Rules

**TRUE → FALSE:** A falsifying result was found. Document the finding with specific evidence (finding ID, code path, reproduction steps). This transition is *always* published, never suppressed.

**FALSE → TRUE:** The root cause was identified and fixed. The fix was verified by re-running the falsifier. Document the fix with specific evidence (commit hash, code change, test results). This transition requires re-running the falsifier, not just inspecting the fix.

**UNTESTED → TRUE:** The falsifier was run under conditions sufficient to have confidence. Document the test conditions.

**UNTESTED → FALSE:** The falsifier was run and failed. Same as any other FALSE transition.

**Any → CONDITIONAL:** The claim was found to depend on a condition not originally specified. Document the condition. This is not a failure — it's a refinement. But the condition must be stated publicly.

### 3.3 What Never Happens

- **Retroactive editing.** A FALSE entry is never removed from the register. The history is append-only, like the receipt chain itself.
- **Silent transitions.** Every transition is dated and evidenced. "It was fixed at some point" is not acceptable.
- **Status without evidence.** "TRUE (we believe)" is not a status. Run the test or mark it UNTESTED.

---

## 4. How Falsifiers Are Designed

### 4.1 The Adversarial Principle

Falsifiers are designed by someone trying to break the claim, not by someone trying to confirm it. Confirmation bias is the enemy. A falsifier designed to pass is not a falsifier — it's a demo.

In practice, this means:

- **Test the boundaries.** If the claim says "every side effect," test the most obscure side effect path, not the main one.
- **Test the assumptions.** If the mechanism assumes single-threaded access, test with concurrent access.
- **Test the negative.** If the claim says "X cannot happen," attempt X through every available path.
- **Test after changes.** A claim that was true yesterday can be false today if a code change introduced a new code path that bypasses the mechanism.

### 4.2 Levels of Falsification

| Level | Description | When Sufficient |
|-------|-------------|-----------------|
| **Code inspection** | Read the source and verify the mechanism exists | Never sufficient alone — bugs hide in code that looks correct |
| **Static analysis** | Grep, lint, or type-check for structural properties | Sufficient for structural claims ("no public API allows X") |
| **Unit test** | Automated test of the specific mechanism | Sufficient for mechanism-level claims |
| **Integration test** | End-to-end test through the real system | Required for system-level claims ("every side effect") |
| **Adversarial test** | Red team, fuzzer, or pentest specifically targeting the claim | Required for security claims |

A claim's confidence level should reflect the highest level of falsification that has been applied. A claim verified only by code inspection is UNTESTED regardless of how careful the inspection was.

### 4.3 The Independence Requirement

The strongest falsification comes from someone who didn't write the code, didn't design the architecture, and has no incentive for the claim to be true. External pentest findings (like the 2026-04-06 run) are the gold standard. Internal testing is necessary but not sufficient for security-critical claims.

---

## 5. How Honesty Is Maintained

### 5.1 The Two-Sentence Test

Before publishing any claim, apply this test: *Can I state the claim in two sentences, and would I be comfortable if those two sentences were quoted by a critic?*

**Good:** "Every side effect passes through the GovernanceGate. This was false until 2026-04-25 when the last ungated path was fixed."

**Bad:** "Our comprehensive governance framework ensures policy compliance across all execution surfaces."

The first is specific, dated, and honest about its history. The second is unfalsifiable and sounds like it was written by someone who has never found a bug in their own system.

### 5.2 The Overclaim Audit

Periodically (at minimum: before every major release, after every pentest, after every architecture change), audit all published claims against the codebase. For each claim:

1. Is the status still accurate?
2. Has a code change introduced a new path that bypasses the mechanism?
3. Has the scope of the claim grown beyond what the mechanism covers?
4. Are we using language that implies more than the mechanism delivers?

The footprint audit (docs/design/FOOTPRINT-AUDIT-2026-04.md) is an example of this process applied to external framework claims. The same discipline applies to internal claims.

### 5.3 Naming Gaps

Gaps are not embarrassments — they are evidence of rigor. A project that claims no gaps has either not looked or is not being honest. ZeroPoint's Invariant Catalog (v1, §8) explicitly lists open obligations with their catalog rules, current status, and path to closure.

The discipline is: *name the gap before someone else finds it.* The canonicalization invariant is documented as "NOT ENFORCED" in every document that references it. The receipt signing is documented as "feature-gated, disabled by default." These are not admissions of failure — they are statements of current engineering reality that will be resolved on a documented timeline.

### 5.4 The Asymmetry Rule

It is always acceptable to:
- Downgrade a claim from TRUE to FALSE
- Add a new gap to the open obligations
- Publish a falsifying result
- Admit that a previous claim was overclaimed

It is never acceptable to:
- Upgrade a claim from FALSE to TRUE without evidence
- Remove a gap from the open obligations without closing it
- Suppress a falsifying result
- Strengthen a claim without strengthening the mechanism

This asymmetry is intentional. It mirrors the scientific principle that falsification is decisive but confirmation is provisional. A single falsifying result disproves a claim; no amount of passing tests proves it.

---

## 6. How This Methodology Is Exportable

Any project can adopt this discipline. The requirements are:

1. **State claims as falsifiable propositions.** Not features, not aspirations, not compliance checkboxes. Propositions with specific falsifying conditions.

2. **Design falsifiers adversarially.** Try to break your own claims before someone else does.

3. **Maintain a status register.** Dated transitions, never retroactively edited.

4. **Publish failures.** When a claim is falsified, document it publicly with the same prominence as the original claim.

5. **Audit periodically.** Claims drift as code changes. Test them regularly.

6. **Name gaps.** Document what you know is incomplete before someone discovers it for you.

The overhead is modest — a few hours per audit cycle. The return is credibility that cannot be manufactured: the credibility of a project that tests its own claims and publishes the results, including the failures.

---

## 7. Relationship to Other Documents

- **Invariant Catalog** — States the formal rules. This document describes the process for maintaining them.
- **Falsification Guide** — The external-facing test procedures. This document describes the internal discipline that produces and maintains them.
- **Formal Primitives** — States what's novel. This document describes how we verify the novelty claims hold in implementation.
- **Vocabulary Lock** — Defines terms. This document ensures the terms mean what we say they mean — not through definition alone, but through testable commitment.

---

*A methodology that isn't followed is worse than no methodology at all — it creates the illusion of rigor without the substance. This document is a commitment. If ZeroPoint stops following it, someone should point at this sentence and ask why.*
