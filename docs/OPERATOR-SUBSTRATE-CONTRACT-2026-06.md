# Operator Substrate Tier Contract — What the Canonical Rust Core Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the Operator substrate
tier and the adjacent tiers that compose against it. Names which affordances
an operator-substrate implementation MUST have, which it MAY have, and which
it MUST NOT have, partitioned across seven internal sub-layers so that
affordance gaps are classifiable in one lookup rather than by re-derivation
from first principles.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Operator substrate tier contract — the operational complement to
the substrate's distributed Rust crates at the central tier of the SCC tier
taxonomy. Where `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` (tier 2
entry) names the conformance criterion in summary — "all four claims
empirically true, all eight principles enforced by the type system or by
discipline pins with CI enforcement" — this document partitions that criterion
into seven sub-layer affordance tables so that each proposed substrate feature
can be classified without rebuilding the argument from principles.

The central position of this tier is structural, not merely descriptive. The
four substrate claims (Architecture Part I §2) are made testable only by
this tier's conformance: the chain layer makes Claim 1 testable; the chain
and surface layers together make Claim 2 testable; the gate layer makes
Claim 3 testable; the policy layer makes Claim 4 testable. The adjacent
tiers — cockpit (Tier 3), cockpit/Console (Tier 4), agent/tool (Tier 6),
edge (Tier 1), peer (Tier 9), anchor (Tier 10), verifier (Tier 8) — each
compose against the surface this tier exposes. A nonconforming substrate
makes every adjacent tier's conformance guarantee vacuous, because the
guarantees those tiers carry derive from this one. This is the substrate's
heart.

The architectural decisions governing this contract — the seven-sub-layer
decomposition, the affordance partition per sub-layer, the schema-versioning
synchronization across chain/receipt/verb-set, the single-surface commitment,
the Policy/Gate substrate-side-vs-consumer-side distinction — are recorded in
`docs/handoffs/operator-substrate-affordance-pass-2026-06.md`. This contract
synthesizes those decisions into the template form established by
`docs/EDGE-TIER-CONTRACT-2026-06.md` and generalized by
`docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`. The affordance pass is the
source for the partition; this document is the partition in prose form.

Runtime-neutral by construction. The current Rust implementation across
`crates/zp-audit`, `crates/zp-receipt`, `crates/zp-verbs`,
`crates/zp-gate-envelope`, `crates/zp-policy`, `crates/zp-keys`, and
`crates/zp-server` is one conformant expression. Alternative implementations
that satisfy the same Required affordances and respect the same Forbidden
boundaries are conformant regardless of language or backend.

---

## 2. The category statement

The operator substrate is the canonical trust core that holds chain-anchored
state, enforces gate-mediated authority, signs canonical receipts with
Genesis-derived authority, and exposes a programmatic surface for adjacent
tiers to compose against. It is not an application layer, a governance
framework by decree, or a SaaS service. It is the runtime that other things
run on — the seat from which the four claims are made testable and from which
the eight principles become conservation laws rather than aspirations.

The substrate's architecture decomposes into seven behavior surfaces, each
with its own contract role. The Chain layer holds the durable, hash-linked,
append-only record of every signed receipt. The Receipt layer defines the
canonical attestation primitive — the content-addressed, Genesis-signed unit
that the chain chains together and the verifier re-derives. The Verb-set
layer enumerates every governed action the substrate knows how to dispatch,
giving those actions fixed semantic binding. The Gate layer enforces
pre-evaluation of every privileged action, making Claim 3's "system-wide
coherence from local evaluation" a structural property rather than a
convention. The Policy layer holds the constitutional rules that are
conservation laws and the delegation invariants that narrow authority
monotonically. The Identity binding layer derives all signing material from
Genesis via a singular sovereign root, so that the chain's authority over
"who said this happened" traces unambiguously to one operator key. The
Surface layer is the authenticated programmatic boundary through which every
adjacent tier reaches all of the above — one boundary, tier-aware endpoint
partitioning, no side-entry paths.

An implementer reading this contract cold needs to hold one thing above all
others: these seven sub-layers are not independent components to be
cherry-picked. They are behavior surfaces of a single coherent artifact.
An implementation that conforms at six sub-layers but allows side effects
without gate evaluation breaks Claim 3 regardless of how correct the other
six are. The contract's Required affordances name the minimum that makes
each sub-layer genuinely present; the Forbidden affordances name the specific
uses that would undermine it from within.

---

## 3. Required affordances

The sub-layers follow the same order throughout §§3–5.

### Chain

*The hash-linked, append-only record of every signed receipt. Makes Claim 1
testable.*

**1. Hash-linked prev-hash pointer.** Every entry must carry a `prev_hash`
field whose value is the `entry_hash` of the entry with the immediately
preceding rowid. The chain is well-formed if and only if every `prev_hash`
resolves correctly from Genesis forward. An entry whose `prev_hash` does not
point to the prior entry's `entry_hash` breaks Claim 1 at that position, and
the break is detectable by any verifier walking the chain from Genesis.
**P1, Claim 1.**

**2. Atomic append with `BEGIN IMMEDIATE` and `UNIQUE(prev_hash)` constraint.**
Every append operation must read the current chain tip and insert the new
entry within a single serializable transaction that fails rather than
producing a duplicate or missing `prev_hash` link under concurrent writers.
This closes the AUDIT-01 race surfaced in the April 2026 pentest, which
produced four broken hash links under concurrent append. The `UNIQUE(prev_hash)`
constraint is the structural enforcement; `BEGIN IMMEDIATE` is what makes the
tip-read-plus-insert atomic. **Claim 1.**

**3. Content-addressed entry ids derived by BLAKE3 over the canonical body.**
The entry's `entry_hash` (its content-derived id) must be computable by any
party with access to the canonical body, using only the BLAKE3 hash of that
body. This makes entry ids replay-safe, collision-resistant, and independently
verifiable without access to the substrate's internal state. **P1, P4.**

**4. Re-derivability from Genesis.** Any chain segment must be walkable from
Genesis to a named tip without external state — no remote truth server, no
cached chain summaries that substitute for re-derivation. This is the structural
basis for Claim 2: present state compresses full history because the full
history is re-derivable, not because someone asserts the present state is
correct. **P5, Claim 2.**

**5. A single canonical insertion path.** Every receipt that enters the chain
enters through the same atomic-append function. An implementation with multiple
insertion paths — one for "normal" receipts and another for "system" or
"internal" receipts, or separate paths for different crates — multiplies the
surface that must respect the Claim 1 invariants and creates the half-state
failure mode (two paths that may disagree on chain tip). The one canonical
path is the structural expression of P8 at the chain layer. **P8.**

**6. Schema versioning that preserves verifiability of prior entries.** Chain
schema versions must evolve such that an entry signed under schema version
*n* remains verifiable after the substrate moves to version *n+1*. Schema
versioning at the chain layer is synchronized with the receipt and verb-set
layers — one substrate version governs all three simultaneously. **P1.**

### Receipt

*The canonical attestation primitive: content-addressed, Genesis-signed,
intent-policy-exec structured. The unit the chain chains.*

**1. Deterministic canonical body serialization.** The receipt body must
serialize to the same bytes regardless of platform, language runtime, or
field insertion order. The current implementation uses a form of JCS (JSON
Canonicalization Scheme); the contract names the property — determinism —
not the specific format. Any serialization scheme that produces the same
canonical bytes for the same logical content is conformant. **P1, P4.**

**2. Content-derived receipt id.** `receipt_id = blake3(canonical_body)`.
The id is a pure function of the content; two receipts with the same canonical
body have the same id; two receipts with different bodies have different ids.
This makes dedup-by-id structurally safe and makes id fabrication detectable
(a fabricated id cannot match the body's hash). **P1, P4.**

**3. Intent + Policy + Exec triple for every governed action.** A receipt that
represents a governed action — any action that passed through the gate — must
carry all three legs of the triple: the intent (what was requested), the policy
decision (what the gate decided and why), and the execution outcome (what
happened). An incomplete triple breaks the structural evidence that the action
passed through the gate, undermining Claim 3's attestation. **Claim 3, P1.**

**4. Signature over the canonical body with the Genesis-derived audit key.**
The receipt must be signed with the operator's canonical signing key,
derived from Genesis via the identity binding layer. The signature is what
makes the receipt an attestation rather than a log entry. **P1.**

**5. Receipt schema versioning synchronized with chain and verb-set.**
Receipt schema versioning advances in lockstep with the chain layer's schema
versioning and the verb-set layer's versioning. A receipt claiming a verb that
belongs to schema version *n+1* cannot appear in a chain whose chain-layer
schema is still at version *n*. The synchronization is what prevents
incoherent state from entering the chain during a schema transition. **P1.**

### Verb-set

*The canonical enumeration of governed actions, their semantic binding, and
the receipt shapes they produce. The grammar of substrate intent.*

**1. Canonical schema covering every governed action.** The substrate must
maintain a canonical schema that enumerates every verb it can dispatch, with
three components per verb: the claim type the verb emits, the subject the
verb acts on, and the capability that authorizes it. The schema is the
structural expression of Principle 6 ("a tool is intent, crystallized"):
verbs are not ad-hoc string labels but schema-anchored semantic units whose
meaning is in the structure. **P6.**

**2. Schema enforcement at receipt construction time.** Receipt construction
must fail for any receipt body whose claim does not match a verb in the
canonical schema. The `verbs_must_match_schema` discipline pin enforces this
structurally at build time. The Required affordance is the runtime enforcement
that the pin protects: a receipt claiming an undefined verb cannot enter the
chain. **P6, P8.**

**3. Versioned verb addition and explicit deprecation.** New verbs may be
added in a new schema version. Verbs may not be silently removed; removal
requires a deprecation receipt on the chain acknowledging that the substrate
no longer dispatches the verb, so that any historical chain entry referencing
it can be understood as referencing a then-active verb. **P4, P6.**

### Gate

*Pre-evaluation of every privileged action. Constitutional rule enforcement.
The structural basis for Claim 3.*

**1. Pre-evaluation before every side effect.** Every action that produces a
substrate side effect — a receipt written, a subprocess spawned, a network
call made, a filesystem entry changed — must pass through gate evaluation
before the side effect is initiated. The side effect cannot start before the
gate's decision is final and chain-anchored. This is the EXEC-01..04 failure
mode the pentest surfaced: `/ws/exec` had a direct path to `Command::spawn`
that bypassed the gate entirely. Pre-evaluation is the structural closure of
that class of gap. **Claim 3.**

**2. Constitutional rules at evaluation positions 1 and 2, non-removable
and non-overridable.** `HarmPrincipleRule` and `SovereigntyRule` must
occupy the first two positions in the policy engine's evaluation order and
must be executed before any other rule on every gate invocation. No code path
may reorder or remove them. These are conservation laws, not policy preferences.
The M2 catalog invariant (constitutional persistence) is what the chain
verifies when walking for this property. **P3, P6, Claim 3.**

**3. Decision-as-receipt before the side effect.** Every gate decision —
allowed, denied, or evaluation error — must produce a chain receipt before
the corresponding side effect is initiated. The receipt is the structural
commitment that the gate was consulted. An action that happened in the world
but has no gate receipt in the chain is an M1 violation: the gate was not
enforced at this spawn site. **P1, Claim 3.**

**4. Envelope verification before accept.** A gate input whose envelope
signature fails cryptographic verification must produce a denial receipt
(or an error receipt), never a default allow. Signing is gravity: failed
verification means the envelope's claimed provenance is unsubstantiated, and
an unsubstantiated envelope cannot authorize action. **P1.**

**5. Idempotent decision emission.** A gate evaluation presented with the
same canonical input — same envelope, same verb, same subject, same capability
declaration — must produce a receipt with the same id. Idempotency makes
gate decisions safe to re-present after transient failure and makes the chain's
record of gate activity deduplicate correctly. **P1, P4.**

### Policy

*Constitutional rules, delegation invariants, capability scoping. Makes
Claim 4 testable.*

**1. Constitutional rules as fixed-position, non-conditional entries in
the rule engine.** `HarmPrincipleRule` and `SovereigntyRule` must be
implemented as first-class entries in the policy engine's rule registry at
positions 1 and 2, with no conditional activation, no feature-flag bypass,
and no operator-configuration override. The rule-engine implementation may
vary (hand-written Rust, WASM-hosted, Rego-style) provided the fixed-position,
non-conditional, always-first invariant holds. **P3, M2.**

**2. Delegation envelope verification implementing the eight invariants.**
Every delegation envelope that reaches the gate must be verified against all
eight invariants from the whitepaper §1, including X1 (possible ⊆ required)
and X2 (actual ⊆ possible at time of action). A delegation chain that passes
these invariants narrows authority monotonically from Genesis to the current
action; one that fails has widened authority somewhere, and the failure must
produce a denial receipt. **Claim 4.**

**3. Monotonic narrowing at every delegation depth.** An envelope at depth
*n+1* must not exceed the envelope at depth *n* in scope, time, depth,
or trust tier. Widening in any of these four dimensions is a Claim 4
falsifier. The structural enforcement is `DelegationChain::verify()`;
the Required affordance is that this verification is called on every
delegation chain presented to the gate. **Claim 4, P4.**

**4. Capability scoping at every action invocation.** Every action must
carry a capability declaration, and that declaration must be checked against
the active delegation envelope before the action is allowed. A verb whose
required capability is not present in the envelope produces a denial receipt;
the substrate does not infer capability from context. **Claim 3, Claim 4.**

**5. Receipt evidence for every policy decision.** Every constitutional rule
outcome, delegation invariant check, and capability scope check must produce
receipt evidence — not aggregate evidence ("policy passed") but per-rule
evidence that names which rule reached which verdict. The chain attests not
just that policy was consulted but what the rules decided. **P1, Claim 3.**

### Identity binding

*Singular sovereign root, Genesis-derived signing, sovereignty provider
abstraction. Binds chain authority to operator authority.*

**1. Singular sovereign root per process lifetime.** Exactly one operator-
authentication ceremony may occur per process lifetime; all signing material
flows from that ceremony in memory. The `singular_sovereign_root` discipline
pin (`docs/handoffs/discipline-pin-audit-2026-06.md`) enforces this
structurally at build time for the current implementation. The Required
affordance is the runtime behavior the pin protects: no second credential-store
access, no parallel authentication path. The full specification is in
`docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md`. **P2, P8.**

**2. Genesis-derived signing for canonical chain receipts.** The key that
signs chain receipts derives from Genesis via the established derivation
hierarchy in `crates/zp-keys` — `audit_signer.rs` being the specific
derivation for chain receipts. Independent credential-store entries for
signing material break the single-authentication guarantee and weaken chain
authority (each independently-stored key is an independently-authenticatable
root, which is a center). **P1, P2.**

**3. Sovereignty provider abstraction.** The substrate must support multiple
sovereignty-provider implementations — Touch ID, YubiKey, Trezor, file-based,
future M-of-N quorum — behind a single abstraction surface. The contract names
the abstraction, not the set of implementations. The `sovereignty/` module
in `crates/zp-keys/src/` is the current Rust expression of this abstraction.
**P2, P8.**

**4. Identity-binding receipts for signing-key derivations.** The chain must
record which Genesis-derived key signs which class of receipt. This enables
a verifier walking the chain to re-derive the signing key from Genesis and
confirm that the key that signed a given receipt is the expected derivation
for that receipt class. Without these binding receipts, the verifier cannot
independently confirm key-class matching. **P1, P2.**

### Surface

*One authenticated programmatic boundary, partitioned by adjacent tier.
Every other sub-layer is reached through it.*

**1. Authenticated entry at the surface boundary.** Every endpoint must
require inbound authentication before dispatching any substrate operation.
Unauthenticated requests are rejected at the surface, not by individual
sub-layers. The authentication boundary is at the surface — not scattered
through the chain, gate, or policy layers — because P8 demands one canonical
auth path, and the surface is it. **P1, P8.**

**2. Tier-aware endpoint partitioning.** The surface must expose distinct
endpoint groups for each adjacent tier's contract: cockpit/Console (Tier 3/4),
agent/tool (Tier 6), peer (Tier 9), edge (Tier 1), anchor (Tier 10).
Each tier's spoke contract names what it expects at its endpoint group;
the surface enforces the tier-correct entry path. The surface is one surface
— one auth boundary — with endpoint partitioning. It is not a separate surface
per adjacent tier. **P8.**

**3. Receipt-insertion endpoint funneling through the chain-layer canonical
path.** The surface's receipt-insertion endpoint must route all inserts through
the chain layer's single canonical append function. An insert endpoint that
bypasses the chain layer's atomicity or `UNIQUE(prev_hash)` constraint breaks
Claim 1 at the surface boundary. **P8, Claim 1.**

**4. Chain-read endpoint emitting signed receipts for independent re-derivation.**
The surface's chain-read endpoint must return receipts in their original signed
form — the original signer's key material, the canonical body, the
`entry_hash` — so that the consumer can re-derive the receipt's id from the
body and verify the signature against the known signing key. This is the
surface-side enablement of Claim 2: a verifier who can re-derive the chain
from the surface's signed responses can confirm that present state compresses
full history. **Claim 2, P1.**

**5. Gate-mediated verb-dispatch endpoint.** The surface must expose a verb-
dispatch endpoint that routes every invocation request through the gate,
receives the triple receipt (intent + policy + exec), and returns the
triple's outcome to the caller. No verb may be dispatched through the
surface without a gate evaluation. **Claim 3, P1.**

**6. Honest failure with structured error categories.** Surface errors must
distinguish "authentication failure" from "policy denial" from "internal
error" in their response shape, so that callers can take tier-correct action
on each category. The substrate must not fabricate success for any failure
category, and must not collapse distinct failure types into a single
undifferentiated error that conceals the cause. **P1.**

---

## 4. Optional affordances

### Chain

**Storage backend.** SQLite is the current implementation. PostgreSQL, RocksDB,
or any other transactional backend that supports the atomic-append semantics
(serializable transactions, unique-constraint enforcement, rowid ordering) is
conformant. The contract names the semantics, not the engine.

**Compaction strategies.** Epoch snapshots, content-addressed segment archives,
and Merkle root summaries that reduce the cost of chain walks for Claim 2
verification are all optional enrichments. The canonical chain must remain
re-derivable without the compaction artifacts; compaction is optimization, not
replacement.

**Replication and backup beyond chain-walk export.** Streaming replication to
a secondary database, periodic export to content-addressed archives, and other
resilience mechanisms are optional. The chain is its own backup via
re-derivability; operational replication is operational quality-of-life.

**In-process read caches.** Caches of recently-appended entries for read-after-
write optimization are optional provided the cache is consistent with the chain
and does not serve stale entries in place of chain state.

### Receipt

**Compact receipt forms for mesh transit.** `CompactReceipt` and similar
compressed representations for bandwidth-constrained transports (per
`crates/zp-mesh`) coexist with the canonical form as long as the canonical form
is what enters the chain. Compact forms are transport shapes, not chain shapes.

**Field indexing for query convenience.** Extraction and indexing of receipt
fields — claim type, subject, capability used, timestamp — for query
performance is optional. Indexes are read-side conveniences that must not
affect write-side canonical semantics.

### Verb-set

**Verb-specific helper utilities.** Constructors, validators, and schema-aware
builders that wrap the canonical verb schema are optional. Helpers improve
ergonomics at call sites; they do not alter the schema.

**Documentation generation from the schema.** Auto-generated verb catalogs for
cockpit and agent consumption are optional. The canonical schema is the source
of truth; generated documentation is a projection of it.

### Gate

**Performance optimizations within a single dispatch context.** Caching of
recent `allow` decisions across invocations within the same delegation context,
parallel evaluation of non-constitutional rules, and similar optimizations are
optional provided constitutional rules still execute first and the decision-as-
receipt commitment is met.

**Rule-engine implementation.** Rego-style declarative engine, hand-written Rust,
WASM-hosted evaluation — the implementation is optional provided fixed-position
constitutional rules and non-removability hold.

**Operator-deployed constitutional rules at positions 3 and above via signed
deployment manifest.** Operators may extend the constitutional layer with
WASM modules whose hashes are anchored in an operator-signed manifest, per
`docs/handoffs/wasm-rule-evaluation-2026-06.md`. These extended constitutional
rules are evaluated immediately after positions 1 and 2; they are non-removable
within a process lifetime and may only be updated via the operator ceremony
defined in the brief. This is the canonical mechanism for any operator-deployed
rule — there is no weaker category that bypasses the manifest ceremony.

### Policy

**Operator-defined policy rules above constitutional positions.** Additional
rules at positions 3+ in the rule registry are optional. They may be added,
modified, or removed by the operator; the constitutional rules are not in
this category.

**Delegation envelope precomputation.** Precomputing capability-set
intersections across multiple delegation depths for performance is optional.

**Capability-set caching within a delegation context.** Caching the resolved
capability set for the duration of a single operator session is optional,
provided the cache is invalidated when the delegation envelope changes.

### Identity binding

**Sovereignty provider implementations beyond the canonical set.** Additional
hardware wallets, biometric providers, and OS-keyring backends are optional
extensions to the sovereignty provider abstraction.

**M-of-N quorum configurations.** Multi-device quorum sovereignty (per
`docs/design/quorum-sovereignty.md`) is an optional variant of the singular
sovereign root. The Required affordance is the abstraction; quorum is one
implementation of it.

**Idle-timeout re-authentication policies.** Requiring a fresh authentication
ceremony after a period of inactivity is an optional security posture.

### Surface

**Transport choice.** HTTP/2, gRPC, Unix domain socket, in-process function
call — the wire format is optional. The contract names the endpoint semantics
and the authentication requirement, not the framing protocol.

**Content-blind telemetry.** Logging request rates, latency, error counts,
and other metrics that do not inspect receipt contents or operator-derived
material is optional and operationally useful.

**Rate limiting.** DoS mitigation at the surface is optional; it is a
perimeter concern, not a policy primitive. The gate is the policy primitive.

**Connection pooling, compression, multiplexing.** Standard performance
affordances; substrate-orthogonal.

---

## 5. Forbidden affordances

The forbidden category names specific substrate uses that escape canonical
paths, violate constitutional persistence, or break claim-testability.
The substrate uses persistent storage, Ed25519 signing, network primitives,
and WASM trust boundaries foundationally across these sub-layers; none of
those capabilities is forbidden in the abstract. Every entry below names the
specific *use* that is forbidden at this tier.

### Chain

**1. Non-atomic append.** Any append path that can produce a chain with
duplicate or missing `prev_hash` links — because it reads the chain tip and
inserts in separate transactions, because it lacks the `UNIQUE(prev_hash)`
constraint, or because it allows concurrent writers to interleave — breaks
Claim 1 at that position. The AUDIT-01 pentest finding is the empirical
instance. **P1, Claim 1.**

**2. Mutation of existing entries.** An entry appended to the chain is
permanent. Any code path that modifies an existing entry's body, id, signature,
or prev-hash link breaks Claim 1 for every subsequent entry that chains through
it. The chain is append-only by structural commitment, not by convention;
mutation paths are not conformant even when the mutation would "fix" an error.
**P1, Claim 1.**

**3. Inserting entries whose body fails to canonicalize against the declared
schema.** An entry that enters the chain with a body shape inconsistent with
its claimed schema version produces a chain entry that a conformant verifier
will reject when it attempts to re-derive the entry's id from the canonical
body. The chain entry has been made unfalsifiable in the wrong direction: it
exists in the chain but cannot be verified. **P4, P1.**

**4. Multiple insertion paths within the same substrate process.** Two
insertion paths for chain entries — even if both are "correct" in isolation —
are the half-state failure mode for the chain layer. They can diverge on tip
computation, transaction scope, or schema version, and the substrate breaks
differently every restart. **P8.**

**5. Storage backends without serializable atomic-append semantics.** Flat-file
append without locking, eventually-consistent distributed stores, and any
backend that cannot enforce the `UNIQUE(prev_hash)` invariant under concurrent
writers are not conformant chain-layer backends. Using such a backend at the
chain layer makes Claim 1 untestable under concurrency. **Claim 1.**

### Receipt

**1. Receipt bodies that cannot be canonicalized.** Bodies containing
non-deterministic fields (floating-point values without fixed serialization,
ordering-sensitive maps without canonical ordering rules, implementation-
specific timestamp formats) produce ids that differ across implementations,
breaking the dedup-by-id guarantee and the independent-verifiability
commitment. **P1, P4.**

**2. Receipt ids derived from anything other than the canonical body hash.**
A receipt whose id is a UUID, a sequence number, a timestamp, or any other
non-content-derived value can have two receipts with the same id and different
bodies — defeating dedup, defeating content-addressing, and defeating
independent re-derivation. **P1, P4.**

**3. Signatures over anything other than the canonical body.** A signature over
a partial body, a formatted display representation, or a wire-transport form
of the receipt cannot be verified by a consumer who holds only the canonical
body. The signature's verifiability must be a property of the canonical form
alone. **P1.**

**4. Receipts claiming verbs not present in the canonical verb-set schema.**
A receipt whose claim references an undefined verb is intent without
crystallization — the receipt asserts something happened but the schema has
no structural account of what that something means. **P6.**

**5. Receipts that omit the Policy or Exec leg of the triple for a governed
action.** A receipt that carries only the intent leg, or only the intent and
policy legs, is incomplete evidence of gate passage. It may record that
something was requested, or that the gate was consulted, but not that the
action completed with chain-anchored authority. Incomplete triples break Claim
3's attestation at the receipt level. **Claim 3, P1.**

### Verb-set

**1. Dispatching verbs not present in the canonical schema.** An action
dispatched under a verb name not in the canonical schema produces a receipt
that the `verbs_must_match_schema` pin would catch at build time — but
production dispatch must also refuse. Schema enforcement at construction
time and at dispatch time are both required; dispatch-time enforcement is
the last line. **P6, P8.**

**2. Implicit verb-to-claim binding that varies by call site.** If the
mapping from verb name to receipt claim type is computed at the call site
rather than derived from the canonical schema, two call sites can produce
different claim types for the same verb. The verb's semantics have become
call-site-derived, which means they are not crystallized into structure but
scattered through code. **P6.**

**3. Removing verbs from the schema without deprecation receipt evidence.**
Silently removing a verb from the schema makes every historical chain entry
that referenced it appear to claim an undefined action — the historical record
breaks in a way no verifier can distinguish from tampering. Verb removal
requires a deprecation receipt that chain-anchors the substrate's acknowledgment
that the verb is no longer dispatched. **P4, P8.**

### Gate

**1. Side effects without prior gate evaluation.** The substrate must not
initiate any side effect before the gate has produced a chain-anchored
decision for the corresponding intent. This includes writing receipts,
spawning processes, making network calls, and mutating filesystem state.
The EXEC-01..04 finding is the canonical empirical instance; the gate
coverage failure it surfaced was structural (a spawn site outside the grammar),
not incidental. **Claim 3, P1.**

**2. Reordering constitutional rules at runtime.** Any code path that can
place a non-constitutional rule before `HarmPrincipleRule` or `SovereigntyRule`
in the evaluation order breaks M2 (constitutional persistence). The rules must
be at positions 1 and 2 by structural commitment, not by initialization-time
convention that can be overridden. **P3.**

**3. Removal of constitutional rules by any code path.** No runtime, operator-
configuration, or dynamic-evaluation path may remove `HarmPrincipleRule` or
`SovereigntyRule` from the active rule set. These rules are conservation laws;
a substrate that allows their removal does not have constitutional enforcement,
it has constitutional suggestion. **P3.**

**4. Silent allow on envelope verification failure.** A gate input whose
envelope signature fails must produce a denial or error receipt; it must not
proceed to rule evaluation as if the signature had passed. Signing is gravity:
a gate that defaults to allow on verification failure has inverted the
attestation — the absence of a valid signature produces the same outcome as
a valid one. **P1.**

**5. Multiple gate-evaluation paths within the same substrate process.** Two
code paths that both claim to perform gate evaluation — the gate and a "fast
path" that skips some rules for performance, a secondary gate for "internal"
actions — produce the half-state failure mode for the gate layer. They can
diverge on constitutional rule application, and Claim 3 becomes untestable
across their combined action space. **P8, Claim 3.**

**6. Asynchronous gate evaluation that allows the side effect to start before
the decision is final.** Any execution model that starts the side effect
concurrently with gate evaluation — on the assumption that the gate will
likely allow — is a Claim 3 violation when the gate denies. The denial receipt
would post-date the side effect; the chain would record the action as denied
after it already happened. **Claim 3.**

### Policy

**1. Constitutional rules that can be conditionally disabled.** A feature
flag, operator-configuration key, or environment variable that disables
`HarmPrincipleRule` or `SovereigntyRule` makes them optional features rather
than conservation laws. A substrate that ships with conditional constitutional
rules does not conform, regardless of what the conditions are. **P3, M2.**

**2. Delegation envelopes that widen authority at any depth.** The claim-4
falsifier is precise: a delegation chain that increases scope, time, depth,
or trust tier anywhere along its length breaks the "future actions narrowed
by trajectory" commitment. The policy layer must reject widening envelopes
and chain-anchor the rejection. **Claim 4.**

**3. Capability grants self-issued by the substrate without an upstream
delegation chain rooted at Genesis.** A capability that the substrate
grants itself — without a delegation chain from the operator's Genesis key
authorizing it — is a capability without a key behind it. The grant asserts
authority the chain has no record of issuing. **P2, P1.**

**4. Policy decisions without receipt evidence.** A policy decision that
produced no chain receipt did not happen as far as the chain is concerned.
An undocumented allow or deny is invisible to any verifier; Claim 3 requires
that every governed action's policy decision be chain-anchored. **Claim 3, P1.**

### Identity binding

**1. Multiple credential-store entries for sovereign material in a single
process.** Two credential-store entries for Genesis material mean two
authentication ceremonies must occur (or one ceremony must be trusted to
unlock both, which simply moves the second entry into the first). Either
multiplies the authentication burden or weakens the chain's authority over
"who said this happened" by introducing material that wasn't covered by the
ceremony. The `singular_sovereign_root` discipline pin catches this
structurally. **P2, P8.**

**2. Signing key material persisted outside the sovereignty provider's
storage.** The sovereignty provider controls access to the operator's keys;
persisting key material in a separate file, environment variable, or
in-process cache outside the provider's control creates a second credential-
store entry that is not gated by the operator's authentication ceremony.
**P1, P2, P3.**

**3. Derivation of new sovereign roots without operator ceremony.** A new
Genesis key derived without an explicit operator authentication act is a root
with no authenticated provenance — a chain anchored to a key whose creation
was not witnessed by the operator. **P2.**

**4. Bypassing the sovereignty provider for "performance" reasons.** The
sovereignty provider IS the authentication; the operator's biometric or
hardware key approval is not overhead to be cached away. A code path that
uses a previously-derived signing key without consulting the sovereignty
provider on the grounds that "the operator authenticated earlier" has
removed the gate between operator intent and substrate action for that
signing class. **P1.**

### Surface

**1. Unauthenticated endpoints that allow any substrate operation.** Even
read-only chain-read endpoints must authenticate when they expose operator-
derived chain state. An unauthenticated chain-read endpoint makes the
operator's full chain visible to any requester with network access, which is
not a read-performance decision but an operator-consent decision. **P1, P3.**

**2. Surface-resident state that persists across requests with operator-derived
contents.** The surface is stateless or request-scoped; persistent state lives
in the chain. A surface cache that holds operator-derived material — receipts,
delegation grants, session tokens with embedded chain state — across request
boundaries creates a persistent copy of chain truth at the surface, where it
may drift and where it is not chain-anchored. **P3.**

**3. Endpoints that bypass the chain-layer canonical insertion path.** A
surface endpoint that writes directly to the `audit_entries` table, bypassing
`AuditStore::append`, breaks the single-insertion-path Required affordance at
the chain layer by creating a second path reachable through the surface. **P8.**

**4. Endpoints that mediate chain reads with surface-claimed authority.** The
surface forwards signed chain entries; it does not augment, filter, or
re-sign them with surface-level authority. A surface that returns "the chain
says X, and I (the surface) confirm X" has interposed a second authority
claim between the chain and the consumer. The consumer should verify against
the chain's original signed entries, not against the surface's endorsement
of them. **P1, P3.**

**5. Endpoints that allow caller-specified signing keys.** The operator's
Genesis-derived key is the canonical signing authority for chain receipts.
A surface endpoint that accepts a signing key from the caller — for "testing
convenience," for "multi-operator routing," or for any other reason — allows
the caller to sign receipts with keys the chain has no record of authorizing.
**P1, P2.**

---

## 6. Composition with principles

All eight principles contribute to this tier's contract because this is the
tier they are conservation laws *for*. The structure below names which
principle carries load-bearing weight for which sub-layer, and makes explicit
the Policy/Gate substrate-side-vs-consumer-side boundary.

**P1 (signing is gravity) is the primary principle for the Receipt, Gate, and
Identity binding sub-layers.** The receipt's signature is what makes it an
attestation; the gate's decision-as-receipt is what makes the gate's authority
chain-anchored; the identity binding layer's Genesis-derived key is what makes
the chain's "who said this" traceable to the operator. Across all five Forbidden
categories that cite P1, the structural claim is the same: an action without
a signed chain entry is an action the substrate cannot vouch for.

**P3 (there is no center) is the primary principle for the Policy and Surface
sub-layers.** Constitutional rules cannot be conditionally disabled because that
would make constitutional compliance a matter of configuration rather than
structure — the operator's own configuration could remove the conservation laws,
which is a center forming inside the substrate. The surface must not mediate
chain reads with its own authority claims, because that would make the surface
an authority center interposed between the chain and its consumers.

**P8 (one canonical path) justifies the single-insertion-path Required
affordance at the chain layer, the schema-enforcement Required affordance at
the verb-set layer, the single-gate-evaluation-path Required affordance at
the gate layer, the singular-sovereign-root Required affordance at the identity
binding layer, and the surface-as-single-auth-boundary Required affordance
at the surface layer.** Every sub-layer has exactly one canonical path for its
primary concern; the Forbidden entries at each sub-layer that name a "second
path" are P8 violations.

**P2 (identity is a key, not a location) justifies the identity binding
Required affordances and carries into the Surface sub-layer's Forbidden #5.**
The operator's Genesis key is the identity; signing material that is not
derived from Genesis is material from a location, not from a key.

**P4 (every bit counts) is the structural basis for the chain layer's content-
addressed ids, the receipt layer's canonical serialization requirement, and the
verb-set layer's prohibition on silent verb removal.** Every field earns its
place by cryptographic necessity; a receipt id that doesn't derive from its body
is a field without cryptographic purpose.

**P5 (store-and-forward is primary) is the structural basis for the chain
layer's re-derivability Required affordance.** The chain must be walkable
from Genesis without external state because the chain is the primary mode —
not a query against a live substrate state that might be unavailable.

**P6 (a tool is intent, crystallized) is the structural basis for the verb-set
layer's entire contract** — the schema-as-canonical-enumeration and the
prohibition on implicit or undefined verb binding are both expressions of the
same principle: semantics live in structure, not in comments.

**P7 (contact does not commit) carries into the Policy layer's Required
affordance #5** (receipt evidence for every policy decision). A policy
evaluation that produces no receipt record has the substrate making a
governance decision in response to contact without committing to it in
the chain — exactly the failure mode P7 exists to prevent.

**Policy/Gate substrate-side vs consumer-side.** The Gate sub-layer contract
above and the Agent/tool tier contract (`docs/AGENT-TOOL-CONTRACT-2026-06.md`)
both reference the gate primitive, but from different ends of the boundary.
The Gate sub-layer here is the substrate-side concern: rule evaluation,
constitutional persistence, decision-as-receipt emission. The Agent/tool
tier's gate-mediated invocation pattern is the consumer-side concern: the
agent requests the gate, the gate evaluates, the agent receives the decision.
Both reference the same gate enforcement point; the boundary is the surface
layer's gate-dispatch endpoint. This distinction must not be blurred: the
substrate does not "request" its own gate; the gate is the substrate's
enforcement mechanism, not a service the substrate consumes.

---

## 7. Portability sketches

The contract is runtime-neutral. The affordances at each sub-layer name
semantics, not implementations.

**Current Rust implementation across seven primary crates.** The reference
implementation: `crates/zp-audit` (chain layer, `AuditStore::append` as the
single insertion path); `crates/zp-receipt` (receipt layer, canonical body
serialization, content-derived ids, I+P+E triple); `crates/zp-verbs` (verb-set
layer, canonical schema with `verbs_must_match_schema` discipline pin);
`crates/zp-gate-envelope` (gate layer, ZP-Sig v1 envelope signing and
verification); `crates/zp-policy` (policy layer, constitutional rules at fixed
positions, `DelegationChain::verify()` for the eight invariants);
`crates/zp-keys` (identity binding layer, `load_sovereign_root()` as the
single credential-load path, `audit_signer.rs` for chain receipt signing,
`sovereignty/` module for provider abstraction); `crates/zp-server` (surface
layer, authenticated HTTP endpoints partitioned by tier). All Required
affordances are present across these seven crates; discipline pins in
`crates/zp-discipline` enforce several of the Forbidden boundaries at
build time.

**Alternative storage backend at the chain layer.** A deployment that replaces
SQLite with PostgreSQL at the chain layer, preserving `BEGIN IMMEDIATE`-
equivalent serializable transaction semantics and a `UNIQUE(prev_hash)`
constraint, is conformant at the chain layer. Receipt, verb-set, gate, policy,
identity binding, and surface sub-layers are unaffected by the storage
backend change. The portability of the contract across storage backends is
what makes the Optional affordance ("specific storage backend") genuinely
optional.

**Partial implementation in a different language against the same canonical
receipt schemas.** An operator substrate implemented in Go or TypeScript that:
(a) uses the same canonical receipt body serialization (same deterministic
form, same BLAKE3 id derivation), (b) verifies the same eight delegation
invariants, (c) enforces gate pre-evaluation before every side effect, and
(d) derives signing keys from the same Genesis key derivation hierarchy —
is conformant at the receipt, policy, gate, and identity binding sub-layers
regardless of implementation language. The contract is what binds
implementations together; the Rust crate boundaries are one expression of it.

**Same-machine development deployment.** A substrate where all seven sub-layers
run in a single process on the developer's machine, with the chain layer
writing to a local SQLite file and the surface layer bound to localhost, is
conformant. The deployment shape does not affect conformance; the sub-layer
semantics are the contract. This deployment shape is appropriate for the
empirical loop (testing gate coverage, verifying claim-testability, walking
the chain) before production deployment.

---

## 8. Autoregressive update triggers

1. **New sub-layer added.** If a future SCC revision splits an existing sub-
   layer — for example, separating the surface layer into a public read surface
   and an authenticated write surface, or extracting a dedicated compaction sub-
   layer from the chain layer — this contract should be updated to name the new
   sub-layer's affordance partition and its interaction with adjacent sub-layers.

2. **Schema-version axis bump across chain, receipt, and verb-set.** Schema
   versioning is synchronized across these three sub-layers in lockstep — one
   substrate version governs all three simultaneously. If a schema change is
   proposed that requires independent versioning (chain moves to schema v3
   while receipt stays at v2), this contract is what the proposal must justify
   against. The default is synchronization; the justification must show that
   independent versioning does not produce incoherent state at the chain
   boundary.

3. **New sovereignty provider category adopted as default.** If M-of-N quorum
   sovereignty (per `docs/design/quorum-sovereignty.md`) transitions from
   Optional to the canonical single-key shape, the identity binding Required
   affordances should be updated to name quorum as a first-class variant rather
   than an optional extension.

4. **A Required affordance proves hard to implement portably.** If "atomic
   append with `BEGIN IMMEDIATE` semantics" turns out to exclude a storage
   backend worth supporting — perhaps a backend where serializable transactions
   are prohibitively expensive — the question is whether to relax the chain-
   layer Required affordance or accept that the backend is out of scope for
   conformant chain-layer implementations.

5. **A Forbidden affordance is proposed for relaxation.** If someone proposes
   "allow gate evaluation to proceed asynchronously for non-state-modifying
   actions," this doc is what the proposal must justify against. The default
   answer is no; justification must advance at least one claim without
   weakening any other.

6. **New constitutional rule added or existing rule's interpretation changes.**
   Constitutional rules at positions 1 and 2 are named by the Policy Required
   affordances. Adding a third constitutional rule, or clarifying what
   "HarmPrincipleRule" covers, changes the policy sub-layer's Required
   affordances and the gate sub-layer's enforcement commitment.

7. **A new principle is added to Architecture Part V½.** Each new principle
   may reclassify Optional affordances as Forbidden, make implicit Required
   affordances explicit, or add new Forbidden entries where a sub-layer's
   current behavior would violate the new principle.

---

## 9. Refs

- `docs/handoffs/operator-substrate-affordance-pass-2026-06.md` — the
  architectural-decisions source; the sub-layer decomposition, per-sub-layer
  affordance partition, four-claims mapping, cross-layer composition rules,
  and crate-to-sub-layer map that this contract synthesizes
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 2 entry ("Operator substrate tier"); §5 contract template;
  §6 integration patterns; §5.c tier-scoping discipline
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the template exemplar; the
  Required / Optional / Forbidden partition structure and composition-with-
  principles section this doc follows
- `docs/AGENT-TOOL-CONTRACT-2026-06.md` — the template exemplar with multi-
  side partitioning; the parallel pattern for the seven-sub-layer partition
  used here
- `docs/ARCHITECTURE-2026-04.md` Part I §§1–4 — the one-sentence substrate
  statement, the four claims, the three modal layers, the grammar reframe,
  and the cockpit-OS framing that contextualizes what the operator substrate is
- `docs/ARCHITECTURE-2026-04.md` Part V½ — the eight design principles from
  which every per-tier contract derives its affordance partition
- `docs/ARCHITECTURE-2026-04.md` Part II §§5–6 — the pentest structural
  finding ("gate coverage was disciplinary, not structural") that motivated
  the Gate sub-layer's Forbidden entries for side effects without prior
  evaluation and for multiple gate-evaluation paths
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — the complete Tier 5 spoke;
  the identity binding sub-layer Required affordance #1 defers to this
  document for the full singular-sovereign-root specification
- `docs/audit-architecture.md` — the chain sub-layer reference; the single-
  ownership diagram and the lifecycle of a single audit entry
- `docs/audit-invariant.md` — the chain sub-layer invariant statement;
  the formal claim that there is exactly one chain, one writer, and one
  hash function
- `docs/handoffs/discipline-pin-audit-2026-06.md` — the structural
  enforcement inventory; the pins that enforce several Forbidden entries
  at build time (`verbs_must_match_schema`, `singular_sovereign_root`,
  `no_raw_keychain_service_strings`, and the P8 family)
- `crates/zp-audit` — chain sub-layer primary crate; `AuditStore::append`
  as the canonical insertion path
- `crates/zp-receipt` — receipt sub-layer primary crate; canonical
  serialization and id derivation
- `crates/zp-verbs` — verb-set sub-layer primary crate; canonical schema
- `crates/zp-gate-envelope` — gate sub-layer primary crate; ZP-Sig v1
  envelope verification
- `crates/zp-policy` — policy and gate sub-layer crate; `engine.rs`,
  `rules.rs`, `gate.rs`, `downgrade.rs`
- `crates/zp-keys` — identity binding sub-layer primary crate; `audit_signer.rs`,
  `genesis_v2.rs`, `hierarchy.rs`, `sovereignty/` module
- `crates/zp-server` — surface sub-layer primary crate; tier-partitioned
  authenticated endpoints
