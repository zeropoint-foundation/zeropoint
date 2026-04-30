# How to Falsify ZeroPoint's Claims

**Audience:** External auditors, security researchers, skeptics, and anyone who wants to test whether ZeroPoint's governance claims hold up.

**What you need:**
- A ZeroPoint receipt chain file (SQLite database)
- The `zp-verify` binary (standalone, no dependencies beyond the chain)
- Optionally: the ZeroPoint source code (for deeper structural tests)

**What you don't need:**
- A running ZeroPoint server
- API credentials
- Network access
- Cooperation from the system operator

That last point is itself a testable claim (see Test 7).

---

## The Claims

ZeroPoint makes specific, testable governance claims. Each claim below is stated exactly as the project states it, followed by the procedure to falsify it. If any test produces a falsifying result, the claim is false — not "partially true," not "true in spirit." False.

---

### Test 1: Chain Integrity

**Claim:** "Every receipt is hash-linked to its predecessor. The chain is tamper-evident."

**Catalog rule:** M3 (Hash-Chain Continuity), Production P1

**Procedure:**

```
1. Obtain the chain file (audit_entries table in SQLite).
2. Walk the chain from the first entry (genesis) to the last.
3. For each entry e_i (i > 0):
   a. Verify e_i.prev_hash == e_{i-1}.entry_hash
   b. Recompute e_i.entry_hash from e_i's content fields
   c. Verify the recomputed hash matches the stored hash
4. For the genesis entry (i = 0):
   a. Verify e_0.prev_hash matches the known genesis hash constant
```

**Falsifying result:** Any entry where `prev_hash` doesn't match the predecessor's `entry_hash`, or where the recomputed content hash doesn't match the stored `entry_hash`.

**Tool:** `zp-verify --chain path/to/audit.db` performs this walk. You can also write your own — the hash function is Blake3, the schema is public, and the computation is documented in `zp-audit/src/chain.rs`.

**What this tells you:** If this test fails, the chain has been tampered with or suffered a data corruption event. Everything from the first broken link forward is untrustworthy.

---

### Test 2: Gate Coverage

**Claim:** "Every side effect passes through the GovernanceGate."

**Catalog rule:** M1 (Gate Coverage), Production P3

**Procedure:**

```
1. Identify all code paths that produce external side effects:
   - Command execution (exec_ws.rs)
   - Proxy requests (proxy.rs)
   - Tool invocations (lib.rs tool handlers)
   - Network operations (mesh handlers)
   - File system operations (tool launch paths)

2. For each code path, verify that gate.evaluate() is called
   BEFORE the side effect occurs (not after, not optionally).

3. Verify that a gate evaluation receipt is emitted for every
   evaluation, including allows (not just blocks).

4. Cross-reference: for every side effect observable in the chain
   (tool:cmd:executed, tool:started, etc.), verify a corresponding
   gate evaluation entry exists earlier in the chain.
```

**Falsifying result:** Any side effect that occurs without a prior gate evaluation. Any code path that reaches a spawn/write/send without calling `gate.evaluate()`.

**Tools:** Static analysis (grep for `Command::new`, `spawn`, `write`, network calls — verify each has a preceding `gate.evaluate()`). Dynamic analysis: run an agent workload and assert every execution receipt has a matching gate receipt.

**What this tells you:** If a side effect bypasses the gate, the entire governance grammar is optional for that code path. This is the most critical test — a system with ungated paths is not governed, regardless of how robust the gate itself is.

---

### Test 3: Constitutional Persistence

**Claim:** "HarmPrincipleRule and SovereigntyRule are non-removable, non-reorderable, and evaluate at fixed positions in the policy pipeline."

**Catalog rule:** M2 (Constitutional Persistence)

**Procedure:**

```
1. Examine PolicyEngine construction (zp-policy/src/engine.rs).
   Verify that HarmPrincipleRule and SovereigntyRule are inserted
   at positions 0 and 1 in every construction path.

2. Search for any public API that allows:
   a. Removing a rule from the engine
   b. Reordering rules
   c. Inserting a rule before position 2
   d. Replacing the constitutional rules

3. Attempt to construct a PolicyEngine without constitutional rules.
   The constructor must reject — not warn, not log, reject.

4. Attempt to evaluate an action with constitutional rules disabled.
   No such path should exist.
```

**Falsifying result:** Any construction path that produces an engine without constitutional rules at positions 0 and 1. Any API that allows removal or reordering.

**What this tells you:** If constitutional rules can be removed or bypassed, the governance system has no floor — any policy configuration is possible, including no governance at all.

---

### Test 4: Delegation Narrowing

**Claim:** "Authority can only narrow along a delegation chain. The eight invariants ensure scope, time, trust tier, and depth all monotonically constrain."

**Catalog rule:** P2 (Delegation), Claim 4

**Procedure:**

```
1. Extract all delegation chains from the chain.

2. For each delegation chain, verify the eight invariants:
   a. Parent linkage: each grant references its parent
   b. Depth monotonicity: depth increments by 1 at each step
   c. Scope narrowing: child scope ⊆ parent scope
   d. Time narrowing: child expiry ≤ parent expiry
   e. Trust tier monotonicity: child tier ≥ parent tier (higher = less trusted)
   f. Depth limit: no grant exceeds root's max_delegation_depth
   g. Grantor-grantee linkage: each grantor is the previous grantee
   h. No self-issuance: grantor ≠ grantee

3. Attempt to construct a delegation that widens authority:
   a. A child grant with broader scope than its parent
   b. A child grant with later expiry than its parent
   c. A child grant with lower trust tier than its parent
   d. A grant where grantor == grantee
```

**Falsifying result:** Any delegation chain accepted by the system that violates any of the eight invariants. Any self-issued grant that passes validation.

**What this tells you:** If delegation can widen authority, the least-privilege principle is not structurally enforced — it's a convention that can be violated.

---

### Test 5: Canonicalization

**Claim:** "Every governed entity is cryptographically anchored to the operator's genesis identity via a signed receipt chain."

**Catalog rule:** M11 (Canonicalization Invariant), P6 (Canonicalization), X4 (Canon Precedes Participation)

**Procedure:**

```
1. Enumerate all entities that participate in governed actions
   (agents, tools, providers, skills, memory tiers).

2. For each entity, search the chain for a canonicalization receipt:
   - system:canonicalized
   - agent:canonicalized
   - tool:canonicalized
   - provider:canonicalized
   - skill:canonicalized
   - memory:canonicalized

3. Verify the canonicalization receipt:
   a. References a parent canonicalization receipt
   b. Parent receipt exists in the chain
   c. Parent chain walks back to genesis
   d. Canonicalization receipt precedes the entity's first
      governed action in the chain

4. Attempt to execute an action with an uncanonicalized entity.
```

**Falsifying result:** Any entity that participates in governed actions without a canonicalization receipt. Any canonicalization receipt whose parent chain doesn't reach genesis.

**Current honest status:** This test WILL produce falsifying results today. The canonicalization invariant is not yet enforced in the gate. Uncanonicalized entities can execute. Three of six entity types emit canonicalization receipts; three do not. This is documented as the project's most important open gap (see Invariant Catalog v1, §8).

**What this tells you:** If entities can act without canon, the governance system governs entities it hasn't constituted — a weaker guarantee than the architecture claims.

---

### Test 6: Receipt Signatures

**Claim:** "Every receipt is signed. Non-repudiation is cryptographic."

**Catalog rule:** M5 (Identity Continuity), M13 (Non-Repudiation)

**Procedure:**

```
1. For each receipt in the chain:
   a. Check that the signature field is non-empty
   b. Verify the signature against the receipt's content hash
      and the signer's public key
   c. Walk the signer's certificate chain back to Genesis

2. For each distinct signer, verify:
   a. A valid certificate exists
   b. The certificate chain terminates at the deployment's Genesis key
   c. No certificate in the chain is expired at the time of signing
```

**Falsifying result:** Any receipt with an empty or invalid signature. Any signer whose certificate chain doesn't reach Genesis.

**Current honest status:** This test WILL produce falsifying results if the `signed-receipts` feature flag is disabled (which is the default). When disabled, receipts are hash-linked but unsigned. The claim "every receipt is signed" is conditional on the feature flag. This is documented in the Invariant Catalog.

**What this tells you:** Without signatures, non-repudiation is a property of the hash chain (tamper-evident but not attributable to a specific actor with cryptographic certainty). With signatures, non-repudiation is cryptographic.

---

### Test 7: Governance Without Runtime

**Claim:** "The receipt chain can be audited cold — no running server, no API, no credentials, no cooperation."

**Catalog rule:** M12 (Governance Without Runtime)

**Procedure:**

```
1. Copy the chain file to an air-gapped machine (no network).
2. Copy the zp-verify binary to the same machine.
3. Run verification:
   zp-verify --chain path/to/audit.db --full
4. The verification must complete successfully with:
   - Chain integrity confirmed
   - All hash links valid
   - Entity inventory listed
   - Policy decision history readable
   - No external calls made (monitor with strace/dtrace)

5. Verify that zp-verify makes ZERO network calls:
   strace -e trace=network zp-verify --chain audit.db
   Expected: no connect(), no sendto(), no recvfrom()
```

**Falsifying result:** Any network call during verification. Any verification step that requires data not present in the chain file. Any error indicating a missing external dependency.

**What this tells you:** If this test passes, the governance state is truly portable and self-verifying. An auditor who has never seen the system, has no credentials, and has no cooperation from the operator can verify the full governance history. No other agent governance system offers this property.

---

### Test 8: Sovereignty

**Claim:** "The human operator is always root authority. No agent can override, outlast, or outrank the operator."

**Catalog rule:** M6 (Sovereignty Preservation), M2 (Constitutional Persistence — SovereigntyRule)

**Procedure:**

```
1. Verify SovereigntyRule exists at position 1 in PolicyEngine
   (position 0 is HarmPrinciple).

2. Verify the operator holds the Genesis key and that no
   delegation chain can produce a grant with higher authority
   than the operator's root grant.

3. Attempt to:
   a. Create a delegation that exceeds the operator's scope
   b. Remove the SovereigntyRule via any API
   c. Override a sovereignty-blocked action via capability grant
   d. Issue a capability grant not traceable to the operator's key

4. Verify kill switch: the operator can revoke any capability
   and that revocation is immediate and irreversible (within
   the current chain — a new grant requires a new receipt).
```

**Falsifying result:** Any agent action that succeeds after operator revocation. Any delegation chain that grants authority not traceable to the operator's Genesis key. Any path to remove or bypass SovereigntyRule.

---

### Test 9: External Truth Anchoring

**Claim:** "The receipt chain's state can be anchored to an independent distributed ledger. Anchor receipts are stored in the chain and are verifiable both internally (as chain entries) and externally (against the ledger)."

**Catalog rule:** M12 (Governance Without Runtime) extension, deferred obligation

**Procedure:**

```
1. Obtain a chain file that contains anchor receipts
   (entries with anchor commitment data: chain_head_hash,
   chain_sequence, operator_signature, trigger).

2. For each anchor receipt in the chain:
   a. Verify the anchor receipt is a valid chain entry
      (hash-linked, signed, properly sequenced — same as
      any receipt in Test 1)
   b. Extract the commitment's chain_head_hash and
      chain_sequence
   c. Walk the chain to the receipt at that sequence number
   d. Verify that the chain head hash at that sequence
      matches the commitment's chain_head_hash
   e. Verify the operator_signature over the commitment

3. For each anchor receipt with a non-empty ledger_proof:
   a. Query the external ledger using the receipt's
      external_id (e.g., HCS topic + sequence number)
   b. Verify that the ledger entry exists and contains
      the same commitment data
   c. Verify that the ledger's consensus timestamp matches
      the anchor receipt's consensus_timestamp
   d. Verify the ledger-specific proof data (e.g., HCS
      running hash, Ethereum block inclusion)

4. Verify the anchor trigger field is present and is one of
   the six defined variants (operator_requested,
   cross_mesh_introduction, compliance_checkpoint,
   dispute_evidence, opportunistic, governance_event).

5. Verify anchor chain continuity: each anchor receipt's
   prev_anchor_hash references the previous anchor receipt's
   commitment hash. Walk the anchor sub-chain from the latest
   anchor back to the first.

6. Attempt to submit a fabricated commitment (wrong
   chain_head_hash) to the anchor backend. The backend
   should accept it (it has no knowledge of chain validity),
   but verification in step 2d should fail — proving that
   anchor validity depends on chain consistency, not ledger
   acceptance.
```

**Falsifying result:** Any anchor receipt whose commitment's chain_head_hash does not match the actual chain state at that sequence number. Any anchor receipt whose ledger proof is invalid or references a non-existent ledger entry. Any broken link in the anchor sub-chain (prev_anchor_hash mismatch).

**Current honest status:** This test WILL produce falsifying results today. The `zp-anchor` crate defines the `TruthAnchor` trait, `AnchorCommitment`, `AnchorReceipt`, and `AnchorTrigger` types, but the trait is not yet wired into the runtime's receipt emission pipeline. No anchor receipts are currently emitted during normal operation. The `NoOpAnchor` implementation returns `NotAvailable` errors. Steps 2–5 require a chain that contains anchor receipts, which does not yet exist. This is documented as a deferred obligation in the Invariant Catalog v1, §8.

**What this tells you:** If this test passes (once the wiring is complete), the governance chain's external witnessing is cryptographically sound: each anchor accurately reflects the chain state at the time of anchoring, the anchor history is itself a verifiable sub-chain, and the external ledger proof is independently queryable. If step 6's fabricated commitment passes step 2d, the verification logic is broken — the anchor is rubber-stamping rather than verifying.

---

## Meta-Test: Does This Guide Work?

The ultimate test of this guide is whether an external party, with no prior relationship to the project, can follow these procedures and produce meaningful results — including falsifying results for the gaps we've documented. If the guide produces false confidence (passes tests that should fail) or false alarm (fails tests that should pass), the guide is wrong and should be corrected.

We publish this guide knowing it will produce falsifying results for Tests 5, 6, and 9 under current conditions. That is the point. A falsification guide that only produces passing results is not a falsification guide — it's marketing.

---

## Reporting Findings

If you find a falsifying result not documented in our known gaps:

1. Check the Invariant Catalog (docs/foundations/INVARIANT-CATALOG-v1.md) to see if it's already tracked.
2. If not, open an issue or contact the project. Map your finding to the catalog rule it violates.
3. If your finding requires a new catalog rule, propose one. The catalog grows by being tested.

Findings that break claims we say are true are the most valuable contributions anyone can make to this project.
