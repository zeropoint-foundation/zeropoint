# Verifier Tier Contract — What a Chain-Verifier Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the Verifier tier and
the chains it verifies. Names which affordances a chain-verifier
implementation MUST have, which it MAY have, and which it MUST NOT have,
so that affordance gaps are classifiable without re-deriving from structural
first principles each time.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Verifier tier contract — the operational complement to the
grammar reframe in `docs/ARCHITECTURE-2026-04.md` §4 and the verifier
obligations named in `docs/audit-architecture.md` §8 and
`docs/audit-invariant.md`. Where those documents name the invariant the
chain must preserve and the rule-by-rule enforcement the verifier performs
against it, this document names what makes a verifier implementation
conformant: the re-derivation, catalog-rule evaluation, signature-
verification, and verdict-emission semantics a verifier must, may, and
must not have when walking a chain from Genesis.

The architectural spine of this contract is the grammar reframe from §4:
the verifier is a parser, not a checker. It does not ask "is this state
valid?" It asks "can I re-derive this state from the productions, starting
from Genesis?" If yes, accept. If no, reject with a structurally precise
failure — naming which catalog rule failed, at which entry, against which
prior context. This distinction is not stylistic; it is what makes Claim 2
(present state compresses full history) a falsifiable proposition rather
than an asserted property. A checker that says "yes, valid" without actually
re-deriving may be wrong and untestably so; a parser that says "yes, re-
derived" either walked the chain or it didn't, and the verdict is checkable.

The contract is runtime-neutral and language-neutral by construction.
`crates/zp-verify` is the current Rust reference implementation; verifiers
in Python, TypeScript, Go, WASM, or any other language that can compute
BLAKE3 and verify Ed25519 are conformant if the verification semantics hold.

This document is the spoke for Tier 8 in
`docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`. The Verifier tier
composes at the chain-read boundary with the Storage tier
(`docs/STORAGE-TIER-CONTRACT-2026-06.md`): Storage provides the durable
chain; the verifier walks it. The two contracts compose at the chain-read
API; the verifier is a consumer of the chain, not its host.

---

## 2. The category statement

The Verifier tier covers third-party chain verification: an entity that is
not the chain's operator obtains the chain — from local storage, from a
network stream, from a peer-protocol response, from a published export —
and walks it from Genesis, evaluating every entry against the catalog's
grammar to confirm the chain is well-formed. The verifier makes no authority
claims about what the chain attests to in the world; it makes one structural
claim: this chain either parses against the catalog grammar or it does not,
and here is the evidence for the verdict.

Conformance at this tier rests on three structural commitments that flow
directly from the parser-not-checker framing. First, re-derivation: the
verifier must actually walk every entry and recompute every hash; a verdict
that doesn't derive from this walk is not a verification but a belief. Second,
verdict completeness: the verifier must apply every catalog rule that is in
scope — there is no optional rule the verifier may elect to skip — because
the catalog grammar is the formal statement of what "well-formed" means, and
a partial evaluation is not a parse. Third, isolation: the verifier produces
verdicts only; it does not modify the chain, does not produce signed receipts
in the operator's name, and does not make network calls during the verification
pass itself. The chain is the verifier's complete input; everything the
verifier concludes, it concludes from that input alone.

The Verifier tier is what makes Claim 2 (present state compresses full
history) testable. The claim is that an independent party with access to
the chain can re-derive the substrate's present state. The Required
affordances are the structural primitives that anchor that claim in running
code; the Forbidden affordances are the failure modes that would allow a
verifier to emit verdicts not grounded in actual re-derivation, falsifying
Claim 2 from the verification side.

---

## 3. Required affordances

An implementation lacking any of these cannot serve as a conformant chain
verifier. The fallback when a non-conformant verifier is used is not graceful
degradation — it is the checker model the grammar reframe forecloses: a
verifier that emits verdicts not grounded in actual re-derivation provides
no structural assurance that the chain is well-formed, and the substrate's
Claim 2 becomes an assertion rather than a proof by exercise.

**1. Re-derivation walk from Genesis.** The verifier must walk every chain
entry from the genesis entry to the named tip, recomputing hash linkages
along the way. There is no shortcut that skips entries based on unchecked
cached belief — "we verified these last time" is not sufficient unless
that prior verification is itself authenticated (see Optional #3 and #5).
The walk is the proof; the walk is also the mechanism by which Claim 2
is exercised rather than merely claimed. **Claim 2.**

**2. Catalog rule evaluation per entry.** Each entry must be evaluated
against every catalog rule that applies to it: P1 (prev_hash linkage),
P2 (content hash recomputation), P3 (prev_hash uniqueness), P4/M4
(timestamp monotonicity), S1 (signature verification when the entry
carries a signature), and any other rules the verifier's catalog version
names. Rule evaluation is unconditional: it is not skipped for entries
that "look fine," for entries from trusted signers, or for performance
reasons. The catalog rules are the grammar; evaluating all of them is
what makes the verifier a parser rather than a heuristic. **P6, P8.**

**3. Strict P1 linkage check.** For every adjacent pair ordered by
insertion order, `e_{i+1}.prev_hash` must equal `e_i.entry_hash`, and the
genesis entry's `prev_hash` must equal `genesis_hash()`. Any linkage break
must be reported with the specific entry id at which it occurs and the
expected versus observed values. A P1 failure at a given entry means Claim
1 (each step conditioned on full prior context) is false at that position;
the verifier names the exact position so the operator can identify what
happened. **P1, Claim 1.**

**4. Strict P2 content hash check.** For every entry, the verifier must
recompute `entry_hash` from the canonical preimage — using the same
canonical hash function (`zp_audit::chain::compute_entry_hash` in the
current implementation) — and confirm that the recomputed hash equals the
stored `entry_hash`. A mismatch means the entry was either tampered with
after insertion or was not correctly sealed at insertion time; the verifier
reports the specific entry id and the mismatch values. **P1.**

**5. P3 uniqueness check.** For every non-genesis `prev_hash`, exactly one
entry must hold it. Duplicate-parent detection is a verifier obligation even
when the Storage tier's `UNIQUE(prev_hash)` constraint would have blocked a
fork at append time — verifiers operate on exported chains and peer-attested
chains where storage constraints may not have been enforced, and forks can
arrive via this path. The verifier must independently confirm P3 rather than
assuming the source enforced it. **P1, Claim 1.**

**6. P4 / M4 timestamp monotonicity check.** Timestamps must be non-
decreasing along the chain ordered by insertion sequence. Sub-millisecond
ties are resolved by insertion order; a timestamp that goes backward relative
to the prior entry is an M4 violation at that entry. The verifier reports
the entry id, the prior timestamp, and the observed non-monotone timestamp.
**P1.**

**7. Signature verification (S1).** Entries that carry an Ed25519 signature
must be verified against the signer's registered public key. The `VerifiableEntry`
trait's `signature_b64`, `signer_public_key_hex`, and `signed_payload`
accessors (and the algorithm-agile `signature_blocks` vec for F8-path entries)
are what the verifier uses to obtain the signature material. An entry that
opts out of signature carrying (returning `None` from the signature accessor)
is not subject to S1; an entry that carries a signature whose verification
fails is an S1 violation at that entry. **P1.**

**8. Catalog version awareness.** The verifier must know which catalog version
it is running and must explicitly record that version in its verdict output.
Verifying a chain produced under a catalog version the verifier does not know
must produce a clearly named mismatch — not a silent assumption that unknown
rules pass. If the verifier knows catalog v_n and the chain was sealed under
v_{n+1} rules, the verdict must say so; the operator can then decide whether
to obtain a v_{n+1}-aware verifier or accept the partial verdict. **P4.**

**9. Structured verdict output.** The verifier must produce a verdict that
carries: a well-formed/ill-formed status; the catalog version the verifier
applied; which rules were applied; which (if any) rules failed; at which
entry each failure occurred; and the expected versus observed values for each
failure. The verdict is itself canonicalizable — it can be hashed and signed
by the verifier as a verifier-authored attestation (see Optional #10). A
verdict that says only "ill-formed" without naming the failing rule and entry
is not a structured verdict; it is an unactionable assertion. **P4.**

**10. No-side-effect property.** Verification produces verdicts only.
The verifier must not modify the chain it is walking, must not produce
signed receipts in the operator's name, must not make network calls during
a verification pass to fetch external state, and must not invoke any
substrate action based on what it finds. The chain is the complete input;
the verdict is the complete output; nothing else changes. This is the
structural commitment that makes the verifier a safe party to give chain
access to: verification cannot harm the chain regardless of what the verifier
finds. **P1, P3.**

**11. Revocation-aware receipt check.** Before treating any receipt within
the chain as valid evidence, the verifier must check it against the
`RevocationIndex` using `verify_receipt_status()` (per
`crates/zp-verify/src/receipt_status.rs`). A receipt that appears in the
chain but has been revoked must be reported as such in the verdict; the
verifier must not treat revoked receipts as live evidence of authorization.
The revocation check is part of the verification pass, not an optional
annotation. **P1.**

---

## 4. Optional affordances

Each optional affordance improves the verifier's capabilities or operational
utility without changing what "conformant verification" means.

**Specific implementation language and runtime.** `crates/zp-verify` is the
current Rust reference implementation. Verifiers in Python, Go, TypeScript,
WASM, or any other language that can compute BLAKE3 and verify Ed25519 are
conformant if the Required affordance semantics hold. The contract names the
semantics; the implementation language is operator choice.

**Performance optimizations.** Parallel evaluation of independent entries
where the catalog rules permit, incremental verification against a signed
checkpoint, and batch hash recomputation are all optional and orthogonal to
correctness. A parallel verifier that applies every rule to every entry and
produces the same structured verdict is conformant; a sequential verifier
that skips rules for performance is not.

**Verifier-side caching of verified prefixes.** A verifier may cache its
prior verdict against a specific chain tip and catalog version, and on
subsequent verification of the same chain extended beyond that tip, walk
only the new entries rather than re-walking from Genesis. The cached state
must include the tip's `entry_hash` and the catalog version number; either
changing invalidates the cache. Caching a prior verdict from an authenticated
source (a signed prior-verdict or an external anchor reference) is conformant;
re-emitting a fresh verdict from stale in-process memory without re-checking
is Forbidden #9.

**Output format variety.** Verdicts may be emitted as JSON, structured logs,
conversational natural-language explanations, audit-receipt forms, or any
other consumer-appropriate format. The structural verdict content — well-formed
status, catalog version, rule results, failure entries and values — is what
the Required affordances name; the serialization format is up to the verifier
implementation and its consumers.

**Differential verification.** A verifier may verify only the entries since
a prior verified-and-authenticated tip, provided the prior tip is itself
authenticated by a signed prior-verdict or by an external anchor reference.
The authentication requirement is what distinguishes differential verification
(conformant) from cached-belief emission (Forbidden #9).

**Peer audit attestation participation.** A verifier may participate in the
AuditChallenge → AuditResponse → PeerAuditAttestation protocol implemented
in `crates/zp-audit/src/collective_audit.rs`, either as challenger or as
responder. This is the cross-substrate verification mode named in Claim 2's
mechanism: one substrate challenges another's claimed state; the challenged
substrate responds with signed entries; the challenger verifies the response.
This composes with the Cross-substrate peer tier
(`docs/CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md`) for the protocol mechanics.

**Extended catalog rules.** A verifier may know catalog versions beyond the
substrate's current version and apply them when verifying chains produced
under those versions. When verifying a chain produced under an older catalog
version, the verifier must report which rules from the current version were
not in scope at the time the chain was produced, rather than retroactively
applying them as failures.

**Anchor cross-checking.** A verifier may cross-check the verified chain tip
against external anchor publications — composes with the External anchor tier
when that contract lands. Anchor cross-checking extends the verifier's verdict
from "well-formed against the catalog grammar" to "well-formed and externally
anchored at this tip," which is a strictly stronger claim.

**Conversational interface.** A verifier may explain its findings in operator-
readable form via a cockpit-tier integration — surfacing not just "ill-formed"
but "P2 failed at entry `rcpt-8217` because the stored `entry_hash` is
`3a1c...` but recomputing from the canonical body yields `f9e2...`, suggesting
mutation after insertion." This composes with the Console and cockpit tiers;
the conversational explanation is a rendering of the structured verdict, not
an independent determination.

**Verifier-signed verdicts (verifier-authored receipt class).** A verifier
may sign its own verdict with the verifier's own Ed25519 key, producing a
verifier-authored attestation that "I, this verifier, at this time, observed
this verdict against this chain tip under catalog version N." Verifier-signed
verdicts are a separate receipt class from operator-signed canonical chain
receipts — they have their own type, carry the verifier's own public key (not
the operator's), and must be clearly distinguishable from any operator-
authoritative receipt in any consumer's data model. The verifier's signature
attests to what the verifier observed; it does not substitute for operator
authority, does not endorse the chain's content as "true" in any sense beyond
catalog-conformance, and does not authorize any substrate action. A consumer
who trusts a verifier-signed verdict is trusting the verifier's key, not the
operator's.

---

## 5. Forbidden affordances

The Forbidden category at the Verifier tier is calibrated against one
architectural commitment: the grammar reframe. The checker model — "is this
state valid?" answered from cached belief or shallow inspection — is the
failure mode. Every Forbidden entry below names a specific verifier use that
either reverts to the checker model, claims authority the verifier does not
hold, or breaks the no-side-effect commitment that makes the verifier safe
to give chain access to. The substrate uses signature verification, hash
computation, catalog rule evaluation, and network protocols foundationally
across many tiers; the Forbidden entries name what the verifier itself must
not do at this tier.

**1. Side effects from verification.** The verifier must not modify the
chain, must not produce signed receipts in the operator's audit-chain key's
name, and must not make authority claims that would drive substrate behavior.
Verification is observation; the verifier reports what it sees. A verifier
that writes a corrective chain entry "for consistency," that emits an
operator-signed receipt based on what it found, or that triggers a substrate
action in response to a verification result has claimed the operator's
authority — which only the operator's key and the operator's gate-mediated
action can authorize. **P1.**

**2. Network calls during a verification pass.** Once verification begins,
the chain is the verifier's complete input. The verifier must not reach out
to fetch additional state — updated revocation indexes, missing signature
keys, anchor proofs, external trust databases — during the verification pass
itself. Obtaining the chain in the first place (for remote verification via
the peer protocol) is not a network call during verification; it is pre-
verification acquisition. The no-network-during-pass rule is what makes
verification an offline-capable operation and what prevents a verifier from
depending on a remote authority to "complete" its work. **P3, P5.**

**3. Trust claims about non-chain entities.** A verifier verdict of "well-
formed" is a claim about the chain's internal consistency against the catalog
grammar. It is not a claim that the chain accurately reflects reality, that
the operator was honest, that the signed actions were authorized by the right
principals in the world, or that any external assertion in the chain's
receipts is true. A verifier that says "the chain is well-formed and therefore
the operator's claims are trustworthy" has conflated catalog-conformance with
truth — the grammar cannot prove the latter. **P1.**

**4. Silent catalog version mismatch acceptance.** A verifier that encounters
a chain produced under a catalog version it does not know must produce a
mismatch report, not silently assume that the unknown rules would have passed.
The catalog version is part of the grammar; verifying without knowing the full
grammar means the verification was partial, and the verdict must say so.
Unknown-rule-silently-passes is the checker model applied to the grammar
itself: "seems fine, moving on." **P4.**

**5. Conditional rule skipping.** Every catalog rule that applies to an entry
applies unconditionally. The verifier must not skip rules based on entry
content, trust level of the signer, prior verified status of the entry, or
performance pressure. Conditional rule application would allow entries to be
"well-formed by some rules" rather than "well-formed by all rules" — partial
verification produces partial verdicts, and a partial verdict is not a
verified chain. **P8.**

**6. Producing or constructing chain entries.** The verifier consumes a chain.
It does not produce chain entries, does not construct speculative entries for
"what the chain should have said," and does not create retroactive corrections.
A verifier that writes entries into the chain it is verifying has crossed
from observer to participant; its verdict is no longer third-party, and its
chain access was for modification rather than verification. **P1.**

**7. Authority claims.** The verifier emits verdicts, not endorsements and
not authorizations. A verdict that says "I verify this chain and therefore
authorize this delegation" or "I verify this chain and therefore endorse this
operator's identity" has stepped from catalog-conformance verification into
authority claim — a role the architecture does not give the verifier. The
verifier's sole authority is to say whether the chain parses; what the chain
attests to, and whether that attestation carries weight in the world, is the
operator's concern. **P1, P3.**

**8. Mutating the chain source during verification.** The verifier opens the
chain's source read-only. If it reads from a SQLite file, the file is opened
in read-only mode; if it reads from a network stream, it consumes and does
not write back; if it reads from a memory buffer, it does not modify the
buffer. A verifier that patches a hash, repairs a linkage, or otherwise
modifies the chain to make verification pass has produced an artificially
well-formed verdict — the chain it verified is not the chain it received.
**P1.**

**9. Producing verdicts without re-derivation.** A verifier that emits a
"well-formed" verdict without having actually walked the chain from Genesis
and recomputed the hashes has reverted to the checker model. The grammar
reframe is explicit: verification is re-derivation, not checking. Caching a
prior verdict against an authenticated chain tip is conformant (Optional #3);
the cache is a shortcut for the walk from Genesis to the known tip, not a
substitute for the walk. Emitting a fresh verdict from in-process memory
without re-walking is the checker model with extra steps. No principle
citation needed — this entry is the architectural spine of the contract
stated negatively.

**10. Verifier self-attestation of operator authority.** A verifier may sign
its own verdict with its own key — that is conformant (Optional #10). What a
verifier must not do is sign chain entries with the operator's audit-chain
key, present its own signature as equivalent to the operator's signature,
or claim that a verifier-signed verdict authorizes any substrate action. The
verifier's key is not a delegated authority from the operator's Genesis key;
it is a separate identity the verifier holds for its own attestation. Any
confusion between verifier signatures and operator signatures breaks the chain's
authority model at the reader side. **P1, P3.**

---

## 6. Composition with principles

The Verifier tier is the tier where the grammar reframe becomes an operational
commitment. Five principles carry load-bearing weight simultaneously.

**P1 (signing is gravity) is the primary principle for the Forbidden
category.** Forbidden #1, #6, #7, #8, and #10 all protect a single commitment:
the chain's authority flows from the operator's Genesis-derived key; the
verifier's role is to check that authority, not to exercise it. A verifier
that produces signed receipts in the operator's name, constructs chain entries,
makes authority claims, or presents its own signature as operator authority
has collapsed the separation between verifier and operator. P1 names why the
collapse is structurally wrong: signing is the mechanism by which authority
is demonstrated; a verifier that signs canonically has claimed authority it
does not hold.

**P3 (there is no center) is the structural basis for Forbidden #2 and #7.**
Verifiers can run anywhere — in the operator's own infrastructure, in an
independent third party's system, in a peer substrate's verification pass,
in a browser. This decentralized verifiability is what makes Claim 2
meaningful: not "the operator says the chain is well-formed" but "any party
with the chain and the catalog can verify." A verifier that must phone home
for external state during verification (Forbidden #2) introduces a center;
a verifier that claims authority beyond its verdict (Forbidden #7) becomes
a center. P3 is why the verifier's independence — from network state, from
the operator's authority — is structural, not operational preference.

**P5 (store-and-forward is primary) is the basis for Required #1 (re-
derivation walk) and Forbidden #2 (no network calls during verification).**
The chain is a stored, re-derivable artifact; verification should be possible
against that artifact without a live substrate. Offline verification against
an exported chain is as legitimate as online verification against the storage
layer. P5 is why the verifier's no-network-during-pass rule is an architectural
commitment rather than a convenience: it ensures the verifier remains a peer
of any chain holder, not a service that requires infrastructure.

**P6 (a tool is intent, crystallized) is the structural basis for Required
#2 (catalog rule evaluation per entry).** The catalog rules are intent
crystallized as formal grammar. The verifier is the parser of that grammar.
Evaluating all rules is what makes the verifier an implementation of P6
at this tier: the catalog's semantics live in its structure, and the verifier
respects that structure by applying every rule to every entry. Conditional
rule skipping (Forbidden #5) is P6's negation applied to the verifier: it
treats some rules as optional, which means those rules' intent is not being
honored.

**P8 (one canonical path) is the structural basis for Forbidden #5
(conditional rule skipping) and Forbidden #9 (verdicts without re-
derivation).** There is one canonical verification path: walk from Genesis,
apply every catalog rule, produce a structured verdict. Alternative paths —
skip some rules, cache without re-walking, accept from belief — are second
paths for the same concern. P8 is why neither is conformant: each creates a
verification result that may differ from the canonical path, producing two
answers to "is this chain well-formed?" that may disagree.

**Claim 2 (present state compresses full history) is made testable by this
tier.** The Required affordances — re-derivation walk, per-entry catalog rule
evaluation, strict P1/P2/P3/P4 checks, signature verification, structured
verdict output — are collectively the structural primitives that anchor Claim
2 in running code. A conformant verifier exercises the claim: it walks the
full chain, re-derives the present state, and either confirms the derivation
is consistent or names the exact position where it isn't. The Forbidden
affordances are the failure modes that would allow a verifier to emit "well-
formed" without having exercised the claim — falsifying Claim 2 from the
verification side.

---

## 7. Portability sketches

The contract is language-neutral and runtime-neutral. These five sketches
demonstrate that conformance is achievable across substantially different
implementation contexts.

**`crates/zp-verify` (current Rust reference implementation).** The
`VerifiableEntry` trait abstracts over concrete entry types; the `Verifier`
struct applies catalog rules P1 (prev_hash linkage), M3 (hash-chain
continuity), M4 (timestamp monotonicity), and S1 (signature verification)
to each entry in order. `verify_receipt_status()` in `receipt_status.rs`
provides the revocation-aware check (Required #11). `foundation.rs` handles
foundation-receipt-specific verification. Used by `zp-server` for self-
verification and by the `zp verify` CLI subcommand. All eleven Required
affordances are present.

**An independent Python verifier.** A consumer auditing an operator's
published chain export implements the same catalog rules in Python: read the
export in insertion order, compute BLAKE3 over the canonical preimage for
each entry, compare to the stored `entry_hash`, verify any Ed25519 signatures
using a standard cryptography library, check timestamp monotonicity, check
`prev_hash` linkage and uniqueness, check the revocation index. The same
structured verdict shape — well-formed status, catalog version, per-rule
outcomes, per-failure entry ids and values — makes the Python verifier's
output machine-comparable with the Rust reference. No Rust, no `zp-audit`
dependency, no substrate installation required. Conformant if all eleven
Required affordances hold.

**A peer-substrate verifier via AuditChallenge / AuditResponse.** A peer
substrate verifying a counterparty's claimed state participates in the
`collective_audit.rs` protocol: it issues an AuditChallenge naming a chain
tip, the counterparty responds with signed chain entries sufficient to
re-derive up to that tip, and the challenger verifies the response using its
own verifier. Required affordance #5 (P3 uniqueness check) is especially
important here because the verifier is operating on entries it received via
the peer protocol rather than from a storage backend that enforces the
`UNIQUE(prev_hash)` constraint. Required affordance #2 (no network calls
during verification) means the challenge-response acquisition happens before
the verification pass begins; verification runs against the received entries
with no further protocol interaction.

**A specialized adversarial verifier.** A fuzzer, formal-methods checker, or
adversarial-security verifier walks exported chains looking specifically for
catalog-rule violations, grammar edge cases, or linkage anomalies. Conformant
if it applies all catalog rules to all entries and emits structured verdicts
that name violations precisely. The adversarial verifier may implement
Optional #7 (extended catalog rules from future versions) to test chains
against rules they were not produced under, which is a valid adversarial
technique provided the verdict clearly names the catalog version mismatch.

**A browser-resident WASM verifier.** A WASM-compiled verifier running in
the client browser verifies a public-page-served chain export against the
catalog rules — enabling any visitor to confirm chain well-formedness without
trusting the server's assertion. Required affordance #2 (no network calls
during verification) is what makes this practical: once the chain export is
loaded, verification runs in the WASM sandbox without additional requests.
BLAKE3 and Ed25519 verification are both available via standard WASM-ready
libraries. The browser context is the canonical deployment shape for Optional
#7 (anchor cross-checking) once the External anchor tier contract lands.

---

## 8. Autoregressive update triggers

1. **New catalog version with new rules introduced.** Each new rule in the
   catalog is a new Required affordance candidate at the Verifier tier. If a
   new catalog version adds a rule that conformant verifiers must apply, the
   Required affordances should be updated to name it. Required #8 (catalog
   version awareness) and Optional #7 (extended catalog rules) are the existing
   scaffolding; new rules land as additions to Required #2's rule enumeration.

2. **New chain entry type or new signed-payload form added.** If the substrate
   adds a new receipt type with new signature-bearing fields, or if the F8
   algorithm-agile signature path (`signature_blocks()`) adds new supported
   algorithms, Required #7 (S1 signature verification) should be updated to
   name the new form and its verification semantics.

3. **A Required affordance proves hard to implement portably.** If a target
   runtime cannot compute BLAKE3 or verify Ed25519 without significant overhead,
   the question is whether to relax the affordance (accept a conformance note
   indicating which rules are unavailable in this runtime) or accept that the
   runtime is out of scope for full conformance. Either answer belongs in this
   document. Required affordances must not be silently dropped; non-conformance
   must be named.

4. **A Forbidden affordance is proposed for relaxation.** If someone proposes
   "let verifiers cache verdicts without an authenticated prior tip for
   performance," this document is what the proposal must justify against. The
   default answer is no; the grammar reframe is the architectural commitment
   the contract protects, and caching without re-derivation reverts to the
   checker model it forecloses.

5. **A new principle is added to Architecture Part V½.** Each new principle
   may make existing Optional affordances Required, or add new Forbidden entries
   where a verifier-level use would violate the new principle.

6. **A verifier-side bug surfaces a verification failure mode not yet
   captured.** If an implementation exhibits a way to emit "well-formed" that
   isn't covered by the existing Forbidden entries — a new path to the checker
   model, a new form of side effect, a new authority claim — the Forbidden
   category should be updated with the new entry. The Forbidden category is
   calibrated empirically; each new failure mode earns an entry.

---

## 9. Refs

- `docs/handoffs/verifier-tier-affordance-pass-2026-06.md` — the
  architectural-decisions source; the Required / Optional / Forbidden partition
  and the Claim 2 mapping this contract synthesizes
- `docs/ARCHITECTURE-2026-04.md` Part I §2 — the four claims; Claim 2
  (present state compresses full history, mechanism via AuditChallenge →
  AuditResponse → PeerAuditAttestation) is the primary claim this tier makes
  testable
- `docs/ARCHITECTURE-2026-04.md` §4 — the grammar reframe; the parser-not-
  checker commitment that is the architectural spine of this contract
- `docs/audit-architecture.md` §8 — verifier obligations (P1-P4) and their
  strict-enforcement status; the operational complement to this contract at
  the chain-level
- `docs/audit-invariant.md` — the formal chain invariant; the Verifier
  obligations section names the rules the verifier must apply
- `docs/STORAGE-TIER-CONTRACT-2026-06.md` — the durable chain the verifier
  walks; the two contracts compose at the chain-read boundary
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 8 entry ("Verifier tier"); §5 contract template; §6
  Verify-by-re-derivation integration pattern
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the contract template exemplar
- `docs/CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` — the peer-protocol carrier
  for remote verification (Optional #6 composes here via the AuditChallenge /
  AuditResponse protocol)
- `docs/CAPABILITY-VERIFICATION-RECEIPTS.md` — adjacent but distinct concern:
  runtime capability outcome verification, not chain well-formedness; the two
  concerns are related but the Verifier tier contract covers only the latter
- `crates/zp-verify/src/lib.rs` — the `VerifiableEntry` trait abstraction and
  the catalog rules (P1, M3, M4, S1); the reference implementation surface
- `crates/zp-verify/src/receipt_status.rs` — revocation-aware receipt
  verification; `verify_receipt_status()` is the implementation of Required #11
- `crates/zp-verify/src/foundation.rs` — foundation-receipt verification
- `crates/zp-audit/src/verifier.rs`, `catalog_verify.rs` — chain-side verifier
  obligations at the audit chain level
- `crates/zp-audit/src/collective_audit.rs` — the peer audit attestation
  protocol; the implementation carrier for Optional #6
