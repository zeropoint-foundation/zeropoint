# ZeroPoint Invariant Catalog v1

**Date:** 2026-04-25
**Lineage:** v0 (2026-04-06, Ken Romero + Claude, post-pentest synthesis) → v1 (2026-04-25, updated with Claims 1/3 fixes, canonicalization stack, GAR formalization, footprint audit findings)
**Status:** Living document. The catalog is autorecursive — each version is conditioned on the full prior version plus what the world has revealed since.

---

## 0. What This Document Is

This is the formal specification of ZeroPoint's correctness. Not a feature list, not a compliance checklist, not a marketing claim. It is a grammar — a set of productions and invariants that together define what it means for a ZeroPoint system to be well-formed.

A system that satisfies the catalog is governed. A system that violates any rule is ungoverned from the point of violation forward, regardless of what it claims about itself. The violations are detectable, the detection is falsifiable, and the falsification procedure is specified for every rule.

**Relationship to other documents:**

- The **whitepaper** states the thesis in prose. The catalog formalizes it.
- The **architecture doc** describes the implementation. The catalog specifies what the implementation must satisfy.
- The **vocabulary lock** defines terms. The catalog uses them.
- The **footprint** maps coverage against external frameworks. The catalog defines what coverage *means*.
- The **GAR spec** describes the runtime. The catalog constrains it.

**How to read this document:** If you disagree with a rule, edit it and open a PR. The catalog is the thing; the code exists to serve it. If the catalog is wrong, fix the catalog first and the code second.

---

## 1. The Three Layers

Borrowed from modal/temporal logic, grounded in the whitepaper's existing vocabulary:

| Layer | Modal sense | What it constrains |
|---|---|---|
| **Required (☐)** | Must hold in every reachable state | Constitutional rules, trajectory invariants, conservation properties |
| **Possible (◇)** | What is still reachable from the current state | Delegation envelope — the space of authorized futures, narrowed by the accumulated chain |
| **Actual (now)** | The state that has actually been derived | The chain itself — what was signed, when, by whom, in what order |

A chain is **well-formed** when all three layers agree at every step. A chain is **ungrammatical** when any layer fails. Ungrammaticality is binary, local-to-detect, and global-in-consequence.

---

## 2. The Alphabet

| Symbol | Meaning |
|---|---|
| `R` | A signed receipt (the atomic unit of the chain) |
| `G` | A capability grant |
| `D` | A delegation chain (ordered sequence of `G`s) |
| `K` | An Ed25519 keypair at some trust tier |
| `C` | A certificate in the key hierarchy (Genesis / Operator / Agent) |
| `Π` | A policy decision (allow / deny / escalate / audit) |
| `Σ` | The constitutional rule set (HarmPrinciple, Sovereignty) |
| `Γ` | The accumulated chain context (everything derived up to now) |
| `τ` | A timestamp |
| `Ω` | The Genesis event |
| `Κ` | A canonicalization receipt (new in v1) |

---

## 3. The Productions

### P1. Chain Extension

```
Chain(Γ) ::= Chain(Γ′) · R
    where R.pr = id(last(Γ′))
      ∧ R.ch = Blake3(content(R))
      ∧ Verify(R.sg, R.ch, K_signer)
      ∧ Σ ⊨ allow(R)
      ∧ τ(R) ≥ τ(last(Γ′))
```

Every receipt must hash-link to its predecessor, content-hash correctly, signature-verify under the signer's key, satisfy constitutional rules, and not precede its predecessor in time.

**Status:** TRUE. AUDIT-01 (four broken hash links from concurrent-append race) fixed 2026-04-07 with BEGIN IMMEDIATE transactions, UNIQUE(prev_hash) index, atomic chain-tip computation. See `zp-audit/src/store.rs`.

### P2. Delegation (Authority Narrowing)

```
Delegation(D, G_child) ::= D · G_child
    where scope(G_child) ⊆ scope(last(D))
      ∧ valid_until(G_child) ≤ valid_until(last(D))
      ∧ trust_tier(G_child) ≥ trust_tier(last(D))
      ∧ depth(G_child) = depth(last(D)) + 1
      ∧ depth(G_child) ≤ max_delegation_depth(root(D))
      ∧ grantor(G_child) = grantee(last(D))
      ∧ grantor(G_child) ≠ grantee(G_child)
      ∧ Verify(G_child.sg, grantor.key)
```

Authority can only narrow. The eight invariants are implemented in `DelegationChain::verify()` with self-issuance prevention (M4-3). Break any invariant and the chain is rejected.

**Status:** Implemented. Not adversarially tested — the pentest bypassed delegation via the gate failure (now fixed). Adversarial delegation testing is a v2 obligation.

### P3. Authorized Action (The Gate)

```
AuthorizedAction(Γ, action a) ::= Π · R_exec
    where Π = GovernanceGate.evaluate(PolicyContext(a), actor)
      ∧ Π.decision ∈ {allow, escalate}
      ∧ R_exec attests the result of executing a
```

No action is well-formed unless it passes through the GovernanceGate and produces an execution receipt.

**Status:** TRUE. As of 2026-04-25, all five mediation surfaces route through `gate.evaluate()`. The last ungated path (`/ws/exec`) was fixed by wiring GovernanceGate into `exec_ws.rs` (lines 209-264). 67/67 tests pass. See Claim 3 in the Status Register below.

### P4. Introduction (Cross-Genesis)

```
Introduction(K_self, K_remote) ::= R_intro · Π · R_attest
    where C_remote walks back to a Genesis key
      ∧ Verify(every C_i.sg, C_i.parent.pubkey)
      ∧ Π = GovernanceGate.evaluate(PolicyContext(PeerIntroduction))
```

Two nodes meeting produce a derivation including chain walk, policy decision, and signed attestation.

**Status:** Implemented in zp-mesh. Not exercised under adversarial conditions.

### P5. Discovery (Presence Plane)

```
Discovery(client) ::= Announce · (Receive)*
    where Announce is signed with valid Ed25519
      ∧ Receive permitted only after Announce
      ∧ relay parses no payload, persists no state
```

Reciprocity and structural amnesia. A client that receives without announcing produces an ungrammatical session.

**Status:** Implemented in zp-mesh. Reciprocity enforcement active.

### P6. Canonicalization (New in v1)

```
Canonicalize(entity E, parent P) ::= Κ
    where Κ.type ∈ {system, agent, tool, provider, skill, memory_tier}
      ∧ Κ.parent_receipt = id(Κ_P)
      ∧ Κ_P exists in Γ (parent is already canonicalized)
      ∧ Verify(Κ.sg, Κ.ch, K_operator)
      ∧ Κ follows the canonicalization chain:
        genesis → system → agent → {tools, providers, skills, memory_tiers}
```

Canonicalization is the constitutive production — it establishes what *exists* in the governance domain. An entity without a canonicalization receipt has no canonical identity, no provenance, no governance relationship. It does not exist.

**The canonicalization chain:** `Ω → system:canonicalized → agent:canonicalized → {tool:canonicalized, provider:canonicalized, skill:canonicalized, memory:canonicalized}`. Order matters: system first (closest to genesis), memory tier last (most derived).

**Status:** PARTIAL. Three of six entity types emit canonicalization receipts at startup (system, provider, tool). Agent, skill, and memory tier canonicalization types are defined in `zp-receipt/src/types.rs` but not yet emitted. The canonicalization invariant (M11, below) is **not enforced** in the gate — this is the single most important gap.

---

## 4. The Invariants

Properties of the *whole* derivation that must hold at every step. The modal layer (☐).

### M1. Gate Coverage

> ☐ Every action that affects state outside the participant's own audit chain passes through P3 (AuthorizedAction).

The meta-invariant. If there are code paths that bypass the gate, the rest of the grammar is meaningless.

**Status:** TRUE. All spawn sites, all five mediation surfaces, now route through `GovernanceGate::evaluate()`. Last gap (exec_ws.rs) closed 2026-04-25.

**How to falsify:** Run an adversarial agent against every public API surface. For every observable side effect, assert a corresponding gate evaluation receipt exists in the chain. Any side effect without a receipt is an M1 violation.

### M2. Constitutional Persistence

> ☐ HarmPrincipleRule and SovereigntyRule evaluate at positions 1 and 2 of the PolicyEngine, are not removable, are not reorderable, and are not overridable.

**Status:** TRUE. `zp-policy/src/rules/` — HarmPrincipleRule is non-removable. No public API allows removal or reordering.

**How to falsify:** Attempt to construct a PolicyEngine without constitutional rules. The constructor must reject.

### M3. Hash-Chain Continuity

> ☐ For every R in Γ where R is not the Genesis receipt, R.pr = id(predecessor(R)) and the predecessor exists in Γ.

**Status:** TRUE. AUDIT-01 (four broken hash links) resolved via schema recanonicalization. Historical forks preserved as forensic evidence. New schema enforces continuity structurally via UNIQUE(prev_hash) index and transactional append.

**How to falsify:** Walk the chain by `pr` linkage. Any missing predecessor or hash mismatch is an M3 violation.

### M4. Trajectory Monotonicity

> ☐ Timestamps in Γ are non-decreasing; delegation depth is strictly monotonic.

**Status:** TRUE. Enforced by AuditStore append logic and DelegationChain::verify().

**How to falsify:** Sort chain by linkage; assert τ is monotone. Walk delegation chains; assert depth is 0, 1, 2, ….

### M5. Identity Continuity

> ☐ For every R in Γ, the signing key K_signer is reachable by walking a certificate chain back to Genesis key Ω.

**Status:** CONDITIONAL. Ed25519 receipt signing is feature-gated (`#[cfg(feature = "signed-receipts")]`). When enabled, M5 holds. When disabled, receipts are hash-linked but unsigned — M5 is structurally unsatisfiable. This is an honest gap: the "signed receipt" claim requires the feature flag.

**How to falsify:** For every distinct signer in the chain, walk the cert chain. A key whose chain doesn't terminate at Genesis is an M5 violation.

### M6. Sovereignty Preservation

> ☐ Every participant's Guard runs locally, before any external input is accepted, and consults only that participant's accumulated Γ.

**Status:** TRUE. GovernanceGate evaluates before all side effects. SovereigntyRule enforces human-as-root.

**How to falsify:** Trace any inbound message. The Guard must execute before state mutation. A message that reaches state before Guard receipt is an M6 violation.

### M7. Refusal Preservation

> ☐ Every participant retains the right to emit a refusal receipt, at any time, for any reason, and that refusal joins the chain.

**Status:** TRUE. Gate result includes `is_blocked()` path with receipt emission (`tool:cmd:gate_blocked`).

**How to falsify:** Attempt to construct a code path where a refusal is swallowed without joining the chain.

### M8. Genesis Singularity

> ☐ Ω is sealed exactly once per deployment and is referenced (transitively) by every certificate and receipt in Γ.

**Status:** TRUE. Genesis v2 ceremony (`P5-4`) enforces single sealing with key escrow.

**How to falsify:** Attempt to run Genesis on a deployment with an existing sealed Genesis. Must be refused.

### M9. Discovery Amnesia

> ☐ The Presence Plane relay never parses, indexes, or persists announce payloads. Memory state resets on restart.

**Status:** TRUE (architecturally). The relay handles opaque blobs. No `serde_json::from_slice` on payload bytes.

**How to falsify:** Diff the relay binary for deserialization calls on payload bytes. Restart test asserting empty state.

### M10. Reciprocity

> ☐ For every active relay connection, `announces_published > 0` within the grace period, or the connection is terminated with a `reciprocity_violation` signal.

**Status:** TRUE. Implemented in zp-mesh connection behavior.

### M11. Canonicalization Invariant (New in v1)

> ☐ Nothing executes in a governed context without a canon. An entity without a canonicalization receipt in Γ does not exist in the governance domain and cannot participate in any production.

This is the constitutive invariant — the one that binds existence to governance. It is structural, not policy: it cannot be overridden by operator preference, policy configuration, or capability grant.

**The invariant cascades:**
- An uncanonicalized agent cannot invoke tools
- An uncanonicalized tool cannot execute
- An uncanonicalized provider cannot serve requests
- An uncanonicalized skill cannot be loaded
- An uncanonicalized memory tier cannot be promoted to

**Status:** NOT ENFORCED. This is the project's most important open gap. The canonicalization infrastructure exists: receipt types defined (`zp-receipt/src/types.rs`), emission sites wired for 3 of 6 entity types (`system:canonicalized`, `provider:canonicalized`, `tool:canonicalized`), vocabulary locked. But the GovernanceGate does not check for the presence of a canonicalization receipt before allowing actions. An uncanonicalized entity can still execute. Closing this gap requires a `CanonInvariantRule` in the gate pipeline.

**How to falsify:** Attempt to execute a tool that has no `tool:canonicalized` receipt in the chain. If it executes, M11 is violated.

### M12. Governance Without Runtime (New in v1)

> ☐ The receipt chain is a self-contained, self-verifying cryptographic artifact. An external party with nothing but the chain file and a verifier binary can confirm: which entities were canonicalized, what policy decisions were made, whether the chain is intact, and whether every action traces back to a legitimate authority. No API, no running server, no credentials, no cooperation.

This is a conservation property — governance state is conserved regardless of whether the system is running. It is what makes the other invariants *unconditional*: they survive shutdown, migration, bankruptcy, acquisition, infrastructure failure, and adversarial compromise.

**Status:** TRUE. The receipt chain is portable and self-verifying. `zp-receipt/src/verify.rs` implements standalone chain verification. The chain carries its own proof.

**How to falsify:** Copy the chain to an isolated machine with no network access. Run the verifier. If verification requires any external call (API, DNS, credential lookup), M12 is violated.

**Relationship to truth anchoring:** M12 says the chain is self-verifiable *without* external infrastructure. Truth anchoring (`zp-anchor`) is an optional enrichment that adds external timestamp proof *on top of* self-verification. The two are complementary, not contradictory: the chain verifies itself (M12); the anchor proves to third parties *when* the chain was in a given state. If the anchor backend goes down, M12 still holds. If the chain is corrupted, the anchor proves the pre-corruption state existed.

### M13. Non-Repudiation (New in v1)

> ☐ Every receipt in Γ identifies its actor. No receipt can be disowned after the fact. The actor field, combined with the signature, constitutes cryptographic proof of who authorized the action.

**Status:** CONDITIONAL (same condition as M5 — requires signed-receipts feature). When signing is enabled, non-repudiation holds. When disabled, actor is recorded but not cryptographically bound.

---

## 5. Cross-Layer Coherence Rules

### X1. Possible ⊆ Permitted by Required

The delegation envelope can never widen past the constitutional envelope. A capability grant that authorizes a HarmPrinciple-blocked action is well-formed in isolation but X1-ungrammatical in context.

**Status:** Enforced by self-issuance prevention (M4-3) and scope subsetting in delegation verification.

### X2. Actual ⊆ Possible at Time of Action

Every executed action must have been within the possible envelope *at the time of execution*. Authority that has since expired does not retroactively invalidate a receipt that was valid when signed.

**Status:** Enforced by capability expiry checks in gate evaluation.

### X3. Required Holds for the Sequence, Not Just Each Receipt

The *sequence* must comply with Σ: individually-allowed actions that together constitute a violation (e.g., gradual exfiltration) are X3-ungrammatical even if every single receipt looks fine.

**Status:** OPEN. This is the substrate's hardest problem. Named as an invariant since v0. Candidate mechanisms: WASM rules with bounded lookback, reputation accumulators with pattern matching, constitutional rules with rolling windows. No implementation yet.

### X4. Canon Precedes Participation (New in v1)

For every entity E that participates in any production (P1-P5), there must exist a canonicalization receipt Κ_E in Γ such that Κ_E precedes E's first participation.

**Status:** NOT ENFORCED. Same gap as M11. The temporal ordering requirement adds specificity: it's not enough that a canon receipt exists *somewhere* — it must precede the entity's first governed action.

---

## 6. The Four Whitepaper Claims — Status Register

The whitepaper makes four testable claims. This register tracks their status with transition history.

### Claim 1 — Each step is conditioned on all prior context

**Mechanism:** `pr` linkage, Blake3 transitivity.
**Catalog rules:** P1, M3.
**Falsifier:** Any receipt whose `pr` does not point to the previous receipt's `id`.

| Date | Status | Evidence |
|------|--------|----------|
| 2026-04-06 | **FALSE** | AUDIT-01: four broken hash links (rowids 8214/8217/8223/8228) from concurrent-append race |
| 2026-04-07 | **TRUE** | Fixed: BEGIN IMMEDIATE transactions, UNIQUE(prev_hash) index, atomic chain-tip computation. Schema recanonicalized. Historical forks preserved as forensic evidence. |

**Current status: TRUE.**

### Claim 2 — Present state compresses full history

**Mechanism:** Collective audit (AuditChallenge → AuditResponse → PeerAuditAttestation).
**Catalog rules:** Verifier obligation.
**Falsifier:** A peer claiming a state that does not match its full chain.

| Date | Status | Evidence |
|------|--------|----------|
| 2026-04-06 | **UNTESTED** | Mechanism exists; not load-tested against adversarial peer |
| 2026-04-25 | **UNTESTED** | No change. Adversarial peer testing remains a v2 obligation. |

**Current status: UNTESTED.** The verifier walks the full chain and confirms present state. The claim is architecturally true but has never been tested against a peer that lies about its state.

### Claim 3 — System-wide coherence from local evaluation

**Mechanism:** GovernanceGate fixed evaluation order, constitutional rules at positions 1 and 2.
**Catalog rules:** M1, M2, P3.
**Falsifier:** Any side effect that did not pass through P3.

| Date | Status | Evidence |
|------|--------|----------|
| 2026-04-06 | **FALSE** | EXEC-01..04: `/ws/exec` bypassed GovernanceGate entirely |
| 2026-04-25 | **TRUE** | gate.evaluate() wired into exec_ws.rs before every spawn. 67/67 tests pass. All five mediation surfaces now gated. |

**Current status: TRUE.**

### Claim 4 — Future actions narrowed by trajectory

**Mechanism:** The eight delegation invariants.
**Catalog rules:** P2, X1, X2.
**Falsifier:** A delegation chain that widens authority anywhere along its length.

| Date | Status | Evidence |
|------|--------|----------|
| 2026-04-06 | **UNTESTED** | Implemented in DelegationChain::verify(). Pentest bypassed delegation via gate failure. |
| 2026-04-25 | **UNTESTED** | No change. Self-issuance prevention added (M4-3). Gate fixed. Adversarial delegation testing is a v2 obligation. |

**Current status: UNTESTED.** The delegation invariants are implemented and believed to hold. They have not been tested under adversarial pressure because the pentest exploited the gate bypass instead.

---

## 7. Falsification Map (Updated)

Every finding maps to at least one catalog rule. This is the bridge from live security work to the grammar.

| Finding | Date | Rule Violated | Resolution | Date Resolved |
|---------|------|--------------|------------|---------------|
| EXEC-01 (shell injection) | 2026-04-06 | M1, P3 | ValidatedCommand: no shell, direct exec | 2026-04-08 |
| EXEC-02 (allowlist bypass) | 2026-04-06 | P3 | shlex tokenization + per-program validators | 2026-04-08 |
| EXEC-03 (no argument quoting) | 2026-04-06 | P3 | ValidatedCommand handles quoting | 2026-04-08 |
| EXEC-04 (env var injection) | 2026-04-06 | M1, M6 | Subprocess env sanitization | 2026-04-08 |
| AUDIT-01 (broken hash links) | 2026-04-06 | M3, P1 | Transactional append, UNIQUE index | 2026-04-07 |
| AUDIT-02..04 | 2026-04-06 | M3, M4 | Same fix as AUDIT-01 | 2026-04-07 |
| EXEC-GATE (no gate on /ws/exec) | 2026-04-25 | M1, P3 | gate.evaluate() in exec_ws.rs | 2026-04-25 |

**Pattern:** Every P0 finding is an M1 or M3 violation. The catalog is predictive — it tells you where to look for the next failure, not just where the last one was.

---

## 8. Open Obligations

Honest accounting of what the catalog requires but the implementation does not yet provide.

### Critical (blocks correctness claims)

| Obligation | Catalog Rule | Gap | Path to Close |
|-----------|-------------|-----|---------------|
| Canonicalization invariant enforcement | M11, X4 | Canon receipts emitted but gate doesn't check | Add CanonInvariantRule to GovernanceGate pipeline |
| Remaining entity canonicalization | P6 | 3 of 6 entity types emit canon receipts | Wire agent, skill, memory tier canonicalization |
| Receipt signing by default | M5, M13 | Signing feature-gated, disabled by default | Evaluate performance impact; enable or document the conditional |

### Important (blocks confidence claims)

| Obligation | Catalog Rule | Gap | Path to Close |
|-----------|-------------|-----|---------------|
| Adversarial delegation testing | P2, Claim 4 | Never tested under attack | Design adversarial delegation test suite |
| Adversarial peer testing | Claim 2 | Never tested with lying peer | Design adversarial collective audit test |
| Sequence-level compliance | X3 | No mechanism for detecting multi-receipt violations | WASM rules with bounded lookback or reputation accumulators |
| Cost guard enforcement | M1 (extended) | Cost tracked but not enforced in gate | Add CostGuardRule or document as monitoring-only |
| Skill quarantine | M11, P6 | Registry exists, no quarantine mechanism | Mirror memory quarantine pattern for skills |

### Deferred (v2 scope)

| Obligation | Catalog Rule | Notes |
|-----------|-------------|-------|
| Truth anchor wiring into runtime | M12 extension | `zp-anchor` crate provides TruthAnchor trait, AnchorCommitment (with AnchorTrigger), AnchorReceipt — event-driven model, no cadence/scheduler. Not yet wired into runtime's receipt emission pipeline. Anchoring triggered by: operator request, cross-mesh introduction, compliance checkpoint, dispute, opportunistic piggyback, or governance lifecycle event. |
| Distributed Genesis (quorum) | M8 extension | Requires extending Ω from singleton to quorum set |
| Cross-deployment trust composition | P4 extension | How do two grammars compose? Cross-mesh anchor verification (`zp-anchor::query_range`) is the mechanism |
| Verifier trait specification | All M-rules | Who runs verification, when, with what obligations? |
| Clock skew / NTP resilience | M4 | Timestamp monotonicity assumes reliable clocks; anchor consensus timestamps provide external clock reference |
| Multi-participant session grammar | P3 extension | Interleaved chains across agent interactions |

---

## 9. What the Catalog Does Not Cover

Some things are explicitly outside this grammar's domain:

- **Model internals:** Training data quality, embedding security, weight protection. The grammar governs what agents *do*, not what they *are*.
- **Network infrastructure:** Firewalls, segmentation, endpoint protection. The grammar operates at the agent runtime layer.
- **Organizational processes:** Workforce training, stakeholder engagement, change management. The grammar is a technical specification, not an organizational one.
- **Prompt-level defenses:** The gate evaluates structured actions (PolicyContext), not raw prompt text. Prompt injection defense requires a different layer.

These boundaries are features, not bugs. A grammar that tries to cover everything covers nothing well.

---

## 10. How the Catalog Gets Used

1. **Correctness verification.** Every invariant has a falsification procedure. Run them. A system that passes all falsification tests satisfies the grammar. A system that fails any test is ungoverned from the failure point forward.

2. **Remediation prioritization.** When a finding maps to a catalog rule, the rule tells you how important it is. M1 violations (gate coverage) are always highest priority because they make the entire grammar optional.

3. **Implementation guidance.** The catalog tells you what a new feature must satisfy before it's correct. Adding a new mediation surface? It must satisfy M1 (gate coverage), P3 (authorized action), and M11 (canon check). If it doesn't, the feature is architecturally incomplete regardless of how well it works.

4. **External audit.** Hand an auditor the chain file, the verifier binary, and this catalog. They can verify every invariant without running the system, without credentials, without cooperation. This is M12 in practice.

5. **Community extension.** If someone discovers an invariant the catalog doesn't cover, or a falsification test that breaks a rule the catalog says holds, that's a contribution. The catalog grows by being tested, not by being admired.

---

## 11. Versioning

| Version | Date | What Changed |
|---------|------|-------------|
| v0 | 2026-04-06 | Initial catalog. Post-pentest synthesis. 5 productions, 10 invariants, 3 cross-layer rules. |
| v1 | 2026-04-25 | Added P6 (canonicalization). Added M11 (canon invariant), M12 (governance without runtime), M13 (non-repudiation), X4 (canon-precedes-participation). Updated M1, M3 status from FALSE to TRUE. Added claim status register with transition history. Updated falsification map. Added open obligations register. |

---

*The substrate is autorecursive. So is the catalog. Each version is conditioned on the full prior version plus what the world has revealed since.*
