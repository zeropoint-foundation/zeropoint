# Non-Delegable Authority

**Date:** 2026-08-13
**Status:** **Proposed. Not adopted.** Not in `CANONICAL-CORPUS-INDEX-2026-07.md`.
Part I proposes a **Layer A invariant** and therefore requires a new substrate
binary through the release chain per KEEL §III.6 — not a ceremony. Part II is
Layer B and lands by operator ceremony.
**Origin:** operator direction, 2026-08-13 — *"Some things must not ever be
delegate-able."* Prompted by the CAC's 仅限用户本人决策 tier; see
`docs/handoffs/cac-authority-tiers-steering-2026-08.md`.
**Model tier:** Opus — Layer A proposal touching the delegation core.

---

## 1. The gap

The substrate assumes some authority is non-delegable. It has never said so.

Concretely, ZeroPoint can currently express three things, none of which is *"this
capability may never appear in any grant, to any grantee, at any tier, at any
depth."*

| Existing mechanism | Scoped by | What it actually says | Where |
|---|---|---|---|
| `DelegationError::CeremonyTierNotDelegable` | **Trust tier** | No running process may issue or re-delegate Tier 5 authority. T5 is exercised only at a genesis ceremony with the operator key physically present. | `capability_grant.rs:648-652`; `policy.rs:46-50` |
| `RedelegationPolicy::Forbidden` | **Grant instance** | *This particular grant* may not be re-delegated. | `capability_grant.rs:665-676` |
| `is_internal_only_capability` | **Issuance origin** | `ConfigChange` and `CredentialAccess` may not be granted via `ExternalRequest`. Closes the M4-3 SSRF self-grant vector. | `capability_grant.rs:449-454` |

Each is real and each is doing useful work. But:

- **Tier 5 is the closest thing we have to a non-delegable class, and it is a
  proxy.** It protects ceremony authority by making a *tier* undelegable, which
  works only for as long as everything that must never be delegated happens to
  be tier-5. That is a convention, not a statement, and it is invisible to anyone
  reading the capability rather than the tier.
- **`RedelegationPolicy::Forbidden` has a compatibility hole.** It is enforced
  only when `provenance` is `Standing`, because pre-P4 grants defaulted to
  `Forbidden` and would otherwise have broken. So the enum's most restrictive
  variant is, for most grants, a no-op. Worth its own task regardless of this
  spec.
- **Nothing is scoped by capability.** `GrantedCapability` has ten variants
  (`Read`, `Write`, `Execute`, `CredentialAccess`, `ApiCall`, `ConfigChange`,
  `MeshSend`, `Custom`, `ToolCall`, …). None carries any statement about whether
  it is delegable at all.

The operator's observation is that the substrate has been relying on the *absence*
of a grant to mean *"this is not delegated"*, when for some authority it needs to
mean *"this cannot be delegated."* Those are different claims, and only the second
survives an adversary who can get a grant issued.

---

## 2. The distinction this spec turns on

Three states, currently collapsed into two:

1. **Prohibited** — constitutional rules (Harm Principle, Sovereignty Rule).
   Nobody may do it, *including the operator*. Evaluates ahead of everything.
   Already exists; not touched by this spec.
2. **Reserved** — legitimate, and only the sovereign human may exercise it. Not
   delegable to the Regent, an officer, an extension, a peer, or a future
   self-hosted process. **This is the missing state.**
3. **Ungranted** — delegable in principle, not currently delegated. Already
   exists, as the absence of a grant.

Reserved is not a weaker prohibition. It is a *different axis*: prohibition is
about the act, reservation is about **who may perform it**.

### 2.1 Reconciling with III.18 (delegable safety)

KEEL III.18 says every structural restriction the substrate imposes must have a
chain-anchored delegation path by which the operator can deliberately grant
admission — because rigid safety mechanisms without delegation paths get
bypassed. A non-delegable class looks like a direct violation.

It is not, and the reason is worth stating precisely because it is the load-bearing
argument for Part I:

> III.18 protects **operator authority against the substrate**. Part I of this
> spec is not the substrate restricting the operator; it is the substrate
> declining to help the operator **stop being the operator**.

You cannot delegate being the sovereign root, for the same reason you cannot sign
a contract transferring your own legal personhood. There is no sovereignty
*gained* by permitting it, because the thing on the other side of the transaction
is the dissolution of the sovereign. Every other structural restriction in the
substrate — quarantine admission, observation scope, circuit-breaker reset —
takes something *from* the operator that a delegation ceremony can give back.
Part I takes nothing; it defines what the operator is.

Part II is the inverse and III.18 applies to it normally: the operator restricting
their own delegates is an *exercise* of sovereignty, and it is revocable by the
same ceremony that created it.

---

## Part I — Structural non-delegability (Layer A)

**Claim:** a set of capabilities exists that no conformant substrate will place
in a grant, regardless of who signs, at what tier, or at what depth. Delegating
any member collapses a Layer A invariant the substrate already holds.

### 3. Proposed membership, with the invariant each protects

| # | Capability | Collapses | Argument |
|---|---|---|---|
| **N1** | Genesis signature | II.5 (Genesis-as-single-root), *singular sovereign root* | If Genesis signing is delegable, every signature traceable "to the operator" is traceable only to whoever last held the delegation. Chain authority over *who* evaporates. Currently protected by T5 convention. |
| **N2** | Amendment of the N-set itself | This spec | Self-defeating otherwise: delegate the power to shorten the list, then shorten it. Any non-delegable class must include its own amendment authority or it is decorative. |
| **N3** | Root revocation authority — revoking or rotating the operator's own Genesis | II.5, XI | The recovery path *is* the sovereignty. If it is delegable, the M-of-N quorum design has a bypass with one signature. |
| **N4** | Form graduation signature | KEEL XIV | Graduation changes the trust-chain reach of the whole substrate. A delegate could move the operator to Companion Form — surrendering the trust root to a vendor — without the operator present. |
| **N5** | Constitutional-rule modification | II.3, Sovereignty Rule | Already unbypassable by grants; N5 makes it unbypassable by *delegation of the modification authority*, which is the adjacent door. |
| **N6** | Issuance of a grant naming any N-member | — | Closure rule. Without it, N1–N5 are one indirection away from defeat. |

**N6 is the one to argue about.** It is what makes the set closed under
composition, and it is also the one most likely to have unforeseen interactions
with legitimate machinery — the `delegate()` path, quorum ceremonies, peer
introduction. It should be implemented last and tested hardest.

### 4. Enforcement points

Four, and per *one canonical path per substrate concern* the check lives in one
function that all four call:

```
fn reserved_class(cap: &GrantedCapability) -> Option<ReservedReason>
```

| Point | Site | Behaviour on hit |
|---|---|---|
| Grant construction | `CapabilityGrant::validate_issuance` | `Err(IssuanceError::NonDelegableCapability)`. Extends the existing M4-3 enforcement point rather than adding a second one. |
| Delegation | `CapabilityGrant::delegate` | `Err(DelegationError::NonDelegableCapability)`, sibling to the existing `CeremonyTierNotDelegable`. |
| Gate evaluation | policy engine, ahead of operational rules, behind constitutional rules | Deny unless the acting identity *is* the Genesis holder for this substrate. |
| Chain validation | `substrate_validate.rs` | A chain containing a grant receipt naming an N-member is malformed. Catches a substrate that shipped without the check. |

### 5. Chain expression

Refusals emit. Per III.19 (*detectability over invulnerability*), a refused
delegation that leaves no trace is the failure mode, not the success:

```
type: authority:reserved:refused
rt:   authority_reserved_refused
st:   denied
ex: {
  capability:      <GrantedCapability name>,
  reserved_member: N1..N6,
  requested_by:    <actor id>,
  requested_for:   <intended grantee>,
  at_depth:        <u8>,
  enforcement:     issuance | delegation | gate | chain_validation,
}
```

No corresponding `authority:reserved:granted` exists, by construction. The
absence of that receipt type in the schema is itself the statement.

### 6. Amendment cost — stated plainly

Part I is a Layer A invariant. Per KEEL III.6, amending Layer A requires a new
substrate binary through the release chain, not a ceremony. Adding a member to
the N-set later is a release. **Removing** one is a release that every peer can
detect via the Peer-Verification Contract, which is the point: a substrate whose
N-set is shorter than canonical is visibly non-conformant.

This is expensive on purpose. If the N-set is easy to change, it is not an
invariant.

---

## Part II — Operator-declared reservation (Layer B)

**Claim:** beyond the structural set, the operator can declare that specific
capabilities are exercised by them alone — legitimate, delegable in principle,
withheld by choice.

This is the direct analogue of the CAC's 仅限用户本人决策 for everything that is
not architecturally load-bearing: contract formation, financial commitment above
a threshold, communication to named counterparties, publication under the
operator's identity, deletion of anything.

### 7. Receipt

Enumeration, not patterns (Q3). One receipt per reserved capability; no glob, no
matcher.

```
type: authority:reserved:declared
rt:   authority_reserved_declared
ex: {
  capability:  <explicit GrantedCapability name — no wildcards>,
  scope:       <optional constraint — threshold, destination set, path list>,
  rationale:   <operator's stated reason, free text>,
  supersedes:  <receipt_id | null>,
}
sg: <Genesis signature>
```

A capability added to `GrantedCapability` after a declaration is written is **not**
covered by it. That is deliberate: silent inheritance by a reservation authored
before the capability existed is worse than an explicit gap, because the gap is
visible to the operator and the inheritance is not.

Withdrawal is `authority:reserved:withdrawn` citing the declaration. Both are
ordinary chain events; the reserved set at any moment is the fold over
declarations minus withdrawals, exactly like delegation state. Per III.18 this
is fully reversible — it is the operator's own instrument.

### 8. Interaction with precedent (III.16)

**A Part II reservation is a ceiling on precedent.** Phase 7's three-part test
gains a limb, or more precisely limb 1 gains a clause:

> **Limb 1 (authority).** Does the action fall within active delegation scope
> **and outside the reserved set?** A reserved capability fails limb 1
> regardless of accumulated precedent. Precedent cannot promote a reserved
> action into autonomous scope, because reservation is a statement about *who*,
> and precedent is a statement about *what*.

This is the answer to the open question in the CAC brief §5 about precedent
silently promoting irreversible actions — and it is a better answer than the
reversibility ceiling I proposed there, because it does not require a consequence
taxonomy the substrate does not have. The operator names what they keep; they do
not have to classify everything else.

### 9. The Regent's declination gets a citation

`EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 7 warns that *"declaring an absence
is a floor, not a terminal state"* — a bare "I have no mechanism for that"
converts the Regent into a notification engine.

Reservation fixes the shape of that response. Instead of an absence, the Regent
has a signed statement to cite:

> "That is reserved to you under `authority:reserved:declared` #4471 — you
> declared contract signature operator-only on 2026-06-02. I've prepared the
> action; here it is for your signature."

Absence becomes citation, and the terminal state becomes a proposal. That is
what the Phase 7 amendment asks for, arriving from a different direction.

---

## 10. Mapping to the CAC shape

The instrument that prompted this (item 6 of the CAC *Implementation Opinions*)
delineates three modes. The correspondence after this spec:

| CAC mode | ZeroPoint |
|---|---|
| 仅限用户本人决策 — decisions limited to the user alone | **Part I (structural) ∪ Part II (declared).** Currently: nothing, plus a T5 convention. |
| 需由用户授权决策 — decisions requiring user authorisation | `regent:proposal:*` → operator signature. Exists. |
| 智能体自主决策 — autonomous decisions within authorised scope | Delegation scope + precedent. Exists. |

Note what the substrate has that the instrument does not ask for and cannot
provide: **Part I is not available to a regulated developer at all.** A developer
filing a decision-tier classification is describing choices they made and could
unmake. Part I is a property of the binary, verifiable by peers, that the
developer cannot unmake without shipping a detectably non-conformant substrate.
That is the declaration-versus-enforcement distinction with a concrete referent,
which it did not have before.

---

## 11. Questions — resolved 2026-08-13 by operator direction

**Q1. Is N4 (Form graduation) Layer A or Part II? → Layer A.** N4 stays in the
structural set as specified. The fleet case that made me uneasy — a quorum member
graduating a device — is handled by the quorum path, not by delegation, per Q2
below; graduation under quorum is K holders performing a ceremony, not one
delegate acting on the operator's behalf. The uneasiness was misplaced because it
assumed quorum ran through the grant machinery. It does not.

**Q3. Patterns or enumeration for Part II? → Enumeration.** `capability_pattern`
in §7 becomes `capability` — an explicit `GrantedCapability` name plus optional
scope constraint, one receipt per reserved capability. No glob, no matcher, no
policy language. Consequences worth naming: reserving "all outbound
communication" becomes several receipts rather than one, and a capability added
to `GrantedCapability` later is *not* automatically reserved by an existing
declaration. The second is the real cost, and it is the right cost — a new
capability silently inheriting a reservation written before it existed is the
failure mode patterns would have introduced. Auditable beats expressive here.

**Q5. Does the reserved set feed the CAC brief's §6 declaration artifact? → Yes.**
Recorded as a hard dependency in both documents. The artifact's T1 partition is
exactly Part I ∪ Part II at the moment of rendering.

**Q4. `RedelegationPolicy::Forbidden` carve-out → separate work, and it needs
addressing.** Written up as
`docs/handoffs/redelegation-forbidden-carveout-2026-08.md`. Not carried by this
spec.

### 11.1 Q2 — the closure rule and quorum. Answer: no interaction today, and a contradiction found on the way

**Direct answer: N6 does not touch quorum, because a quorum share is not a grant
and never passes through the delegation path.**

Verified this session:

- `ShamirShare` is `{ index: u8, data: Vec<u8> }` — raw secret material split
  over GF(256). No grantee, no capability, no signature, no chain reference. It
  shares nothing structurally with `CapabilityGrant`.
  (`crates/zp-keys/src/genesis_v2.rs:95-101`)
- A share confers **zero** authority alone. Below threshold, reconstruction does
  not fail — it produces the *wrong* secret, which the module's own test asserts
  (`genesis_v2.rs:414`). There is no partial authority to close over.
- `split_secret` and `reconstruct_secret` have **no callers outside their own
  module**. Quorum Genesis is built and tested but unwired — the same shape as
  F5. KEEL:1033 says the quorum-sovereignty design is "in progress," which is
  consistent.
- No threshold-signature scheme exists anywhere in the tree — grep for
  `frost|FROST|MuSig|partial_sig|threshold_sign` returns nothing.

So under the quorum design as currently specified and coded, authority does not
exist until the secret is reconstructed, and what is reconstructed *is* Genesis —
the singular root, not a delegate of it. N1 and N6 are silent because no grant is
ever issued.

**The contradiction.** Tracing this surfaced a conflict inside KEEL that is
independent of this spec and probably more important than it:

> **KEEL:1031** — "The substrate never holds raw Genesis material."
> **KEEL:768** — "Signing requires K shares to reconstruct."

Both cannot be true. Under single-root Hardware Genesis the commitment holds:
the token signs, the key never leaves it. Under M-of-N as written at 768, K
shares are brought together and the seed is reassembled — and the place it is
reassembled is the substrate. Quorum sovereignty as specified therefore
*weakens* the property that hardware Genesis exists to provide, and does so at
precisely the moment of highest consequence.

**The resolution is threshold signatures, and it changes the Q2 answer.** Under a
FROST-style scheme each hardware root emits a partial signature and the private
key never exists in one place at any time. That satisfies KEEL:1031 under quorum,
which Shamir reconstruction cannot.

But under threshold signing, a share stops being inert material and becomes a
**standing capability to contribute to Genesis-authority signatures**, held by a
party who is not the operator. That is much closer to a delegation, and N6 then
needs a real answer — is holding a FROST share a grant naming N1?

My reading, for discussion rather than as a proposal: it still should not be a
`CapabilityGrant`. A share holder cannot produce a signature; they can only
contribute to one that K-1 others also contribute to. Authority remains
threshold-collective and never resides in any holder, so there is nothing for a
grant to describe. The right construct is probably a distinct `quorum:share:*`
receipt family with its own lifecycle — issuance, rotation, revocation, loss —
that N6 explicitly exempts by naming, rather than by silence.

**What this means for sequencing:** N6 is a no-op against today's code and can
land whenever. The question it raises becomes live only if quorum moves to
threshold signatures — which it probably should, for the KEEL:1031 reason, which
has nothing to do with this spec. **Recommend splitting that off as its own
design question rather than letting it block N6.** It is a Genesis-ceremony
problem that this spec merely walked past.

## 12. Sequencing

1. ~~`reserved_class()` + `IssuanceError`/`DelegationError` variants + refusal
   receipt. No members yet.~~ **Core half written 2026-08-13 — see §13.
   Compile-unverified. Receipt half not started.**
2. N1, N3, N5 — the three with no plausible legitimate delegation. *Sonnet.*
3. Part II receipts, fold, and the Phase 7 limb-1 clause. *Opus for the limb
   change, Sonnet for the receipts.*
4. N2 and N4. Both settled — N4 is Layer A per Q1, N2 was never in doubt.
   *Sonnet, following step 2's pattern.*
5. N6, with a named exemption for the quorum-share receipt family. Per §11.1 it
   is a no-op against current code, so the adversarial tests I originally wanted
   here have nothing to bite on until quorum is wired. *Sonnet.*

Steps 1–3 are independently useful and do not require Layer A amendment if the
N-set ships empty in step 1 — the machinery can land as Layer B, with the
invariant claim made only when members are added. That is the cheap path and
probably the right one.

**Split off, not blocking:** the KEEL:768 / KEEL:1031 contradiction found in
§11.1 — quorum-by-reconstruction versus "the substrate never holds raw Genesis
material." That is a Genesis-ceremony design question, it is more consequential
than anything in this spec, and it should not ride along here. It also gates
whether N6's quorum exemption ever needs to become something more than a
one-line carve-out.

---

## 13. Step 1 — landed and verified 2026-08-13

`cargo check -p zp-core` clean; `cargo test -p zp-core` **66 passed, 0 failed**,
including the five new tests. Run on APOLLO by the operator — the Cowork sandbox
has no `cargo`, so the code was written there and verified here, same posture as
git in this repo.

### 13.1 What landed

`crates/zp-core/src/capability_grant.rs`:

- `ReservedReason` — six variants, N1–N6, each carrying the spec's rationale in
  its doc comment. `member_id()` returns `"N1"`…`"N6"`; `Display` gives prose
  plus the id.
- `RESERVED_CAPABILITY_NAMES` — the membership table, **empty**.
- `reserved_class(&GrantedCapability) -> Option<ReservedReason>` — the canonical
  helper, per Principle 8.
- `lookup_reserved(name, table)` — table lookup split out so it is testable
  against a non-empty synthetic table while the real one is empty. Without the
  split, step 1 would ship an enforcement path with no executable test behind it.
- `IssuanceError::ReservedCapability` and `DelegationError::ReservedCapability`,
  with `Display` arms.
- Enforcement in `validate_issuance()` (before the provenance check —
  reservation does not depend on who is asking) and at the top of `delegate()`
  (before tier/depth/scope, so the refusal names the real reason).
- Five tests: custom-name matching, exact-match-not-substring, the empty-table
  invariant, an ordinary-delegation regression guard, and member-id stability.

`crates/zp-core/src/lib.rs`: `reserved_class` and `ReservedReason` added to the
`capability_grant` re-export. Also keeps `dead_code` quiet on variants that are
only constructed in tests, since the enum is public API.

### 13.2 Design note — why a name table and not a match on variants

None of N1–N5 is expressible as an existing `GrantedCapability` variant. There is
no `GenesisSign`, no `FormGraduation`. **The only way any of them could enter a
grant today is through `Custom { name }`** — which is exactly why the protection
has been accidental rather than structural, and exactly the path the lookup must
cover. `GrantedCapability::name()` returns the custom name for `Custom` and the
static name otherwise, so one lookup handles both shapes.

This has a consequence worth flagging for step 2: adding a member is not enough.
Whatever code path actually performs Genesis signing or Form graduation must be
made to *route through* the capability check, or the table row protects a name
nobody uses. Step 2 is not "add six strings."

### 13.3 Safety property of this commit

`RESERVED_CAPABILITY_NAMES` is empty, so `reserved_class` returns `None` for
every input and both new call sites are no-ops. **This commit cannot change the
behaviour of any existing grant.** The `reserved_set_is_empty_in_step_1` test
asserts that and is expected to be deleted in step 2 — if it still passes after
members are added, the members are not wired to the live table.

### 13.4 Not done

- **The refusal receipt (§5).** `authority:reserved:refused` is specified but not
  emitted anywhere. It belongs where grants are issued, in `zp-server`, not in
  `zp-core` — the core returns the error, the server emits the receipt. Left for
  the same commit that wires the first real member, since a refusal receipt for a
  refusal that cannot happen is untestable.
- **The gate and chain-validation enforcement points** (§4 rows 3 and 4). Only
  issuance and delegation are wired.
- **Part II entirely.** No `authority:reserved:declared` receipt, no fold, no
  Phase 7 limb-1 clause.

### 13.5 Risks flagged before compiling — all three resolved

- `ReservedReason::member_id(self)` takes `self` by value, called on `&self`
  inside `Display`. **Resolved** — auto-deref through `Copy` compiles.
- `const TEST_TABLE` inside test fn bodies. **Resolved** — legal and accepted.
- The regression test's dependence on `CapabilityGrant::new()` yielding
  `GrantProvenance::OperatorIssued`. **Resolved, and it confirms the carve-out
  reading:** `reserved_check_does_not_disturb_ordinary_delegation` passes, which
  means a default-constructed grant carrying `RedelegationPolicy::Forbidden` does
  in fact re-delegate. That is a passing test documenting a defect — see
  `docs/handoffs/redelegation-forbidden-carveout-2026-08.md`.

**The coupling stands and is now load-bearing.** Fixing the carve-out will break
this test, correctly. When that fix lands, update the test to set an explicit
`RedelegationPolicy::Allowed { max_subtree_depth }` rather than relying on
`Forbidden` failing to enforce.

### 13.7 The liveness probe, and why step 2 is bigger than it looks

**Scoping question asked 2026-08-13: what would it take to get a first real
member the system responds to? Traced, and the answer is: more than adding a
row.**

| Member | Code path today | Does it touch the capability system? |
|---|---|---|
| **N1** Genesis signature | `load_genesis_secret_composed()` in `zp-cli/src/commands.rs:71`, called from ~10 CLI sites | **No.** `crates/zp-keys/` contains zero references to `CapabilityGrant` — signing never sees a grant. |
| **N3** Root revocation | `zp-keys/src/revocation.rs` — `revoke_agent_key` / `revoke_operator_key` exist only as **test functions** | No |
| **N4** Form graduation | **Not implemented.** Repo-wide grep for `SubstrateForm` / `form.*graduat` returns nothing outside docs | No — nothing to bind |
| **N5** Constitutional modification | Referenced across `zp-cli` (`policy_commands.rs`, `secure.rs`, `init.rs`) | No |
| **N2** Reserved-set amendment | The table is a `const` in the binary | **Already structural** — amending it is a recompile, which is exactly the KEEL III.6 cost. Arguably enforced by construction, with no runtime capability to name. |

So none of N1–N5 flows through `GrantedCapability` at all. A table row for
`genesis_sign` today would protect a name nothing constructs — real, latent, and
misleading, because the test suite would go green while nothing was actually
guarded. **Binding a real member means introducing a capability check where none
exists**, in `zp-cli`/`zp-keys`, which is a materially larger job than this spec
scoped and should be its own design pass.

**What landed instead: a liveness probe.** `ReservedReason::Probe`, member id
`N0`, one table row for the capability name `zp:reserved:probe`
(`RESERVED_PROBE_CAPABILITY`). It carries no Layer A claim, is namespaced so it
cannot collide with any real capability, and is removable in one line. Its job is
to keep the enforcement path executing rather than sitting inert until step 2.

**The probe is not reachable from any live path. Correcting a claim made
earlier in this document.**

An earlier revision of this section said a request to
`POST /api/v1/capabilities/grant` naming `zp:reserved:probe` would be refused
with `IssuanceError::ReservedCapability`. **That is false**, and it would have
produced a misleading walk — the request returns `400 Unknown capability type`,
a refusal for entirely the wrong reason that looks like success from the outside.

What the trace actually shows:

- `grant_handler` (`lib.rs:2928-2946`) and `delegate_handler`
  (`lib.rs:3080-3094`) both map `body.capability` through a **fixed match** —
  `read | write | execute | api | config | tool_call` — and return
  `400 Bad Request` on anything else. **Neither can construct
  `GrantedCapability::Custom`.** Since N1–N5 and the probe can only be expressed
  as `Custom { name }`, no HTTP request can reach `reserved_class` at all.
- `zp delegate` (CLI) *does* construct `Custom`, via `parse_capabilities`
  (`zp-cli/src/main.rs:8762-8795`, reached from `:8879`). But that path calls
  `CapabilityGrant::new(...).as_standing("genesis")` and goes straight to
  `emit_delegation_receipt` — **it never calls `validate_issuance()` and never
  calls `.delegate()`**. So it does not reach either enforcement point either.

**So the probe is exercised by unit tests only.** The machinery is correct and
tested; it is not currently reachable by an operator action. Recording that
plainly rather than leaving the stronger claim standing.

**And the reason is a finding in its own right.** `zp delegate` creates a
capability grant, marks it standing, and writes it to the chain **without
issuance validation of any kind**. That means M4-3's SSRF self-grant protection
does not cover this path either — `validate_issuance` is where that check lives.
This is the fourth instance of the pattern catalogued in
`redelegation-forbidden-carveout-2026-08.md` §3.1, and the most consequential:
not an invariant enforced at the wrong layer, but a grant-creation path with no
validation layer at all. Filed there; it is not this spec's to fix.

**What this does to step 2.** Adding a real member does not become useful until
some path both constructs the capability *and* passes it through a check. That
is the same conclusion §13.7's table reaches from the other direction, and it
means the first genuinely useful piece of work here may be *routing existing
grant-creation paths through `validate_issuance`* rather than adding table rows.

**Verified 2026-08-13:** `cargo test -p zp-core` — **159 passed, 0 failed**,
including all nine reserved-authority tests. `test_validate_issuance_missing_provenance`
still passes, correctly: it uses a non-reserved capability, so the new
precedence does not disturb it.

Four tests cover it end to end: refusal at issuance, refusal at delegation
*ahead of* the Tier 5 check (a T5 parent would otherwise mask the reason with
`CeremonyTierNotDelegable`), refusal ahead of `MissingProvenance`, and an
assertion that the shipped table contains **no spec member** — so the Layer A
claim cannot be made by accident.

**Worth noticing while tracing this:** `Gate::validate_grant`'s own doc comment
says "every grant MUST pass through `validate_issuance()` before being stored,"
and it has two callers, both HTTP handlers. This is the third instance of the
pattern in `redelegation-forbidden-carveout-2026-08.md` §3.1 — an invariant
enforced at call sites rather than in the primitive. Any code path that
constructs and stores a grant without going through those two handlers skips
issuance validation entirely, M4-3 included. Not this spec's problem, but it is
the same defect family and belongs in that brief's investigation.

### 13.6 One ordering consequence to carry into step 2

`test_validate_issuance_missing_provenance` still passes because the reserved
check — which now runs *ahead* of the provenance check — is inert against an
empty table. Once members exist, a grant that is both reserved and missing
provenance will return `ReservedCapability` rather than `MissingProvenance`.
That is the intended precedence (§4: the refusal should name the real reason),
but it is a behaviour change that only becomes observable in step 2, and it
should be asserted there rather than discovered.

---

## Appendix — verification

| Claim | Evidence |
|---|---|
| `CeremonyTierNotDelegable` exists; T5 rejected in `delegate()` | `crates/zp-core/src/capability_grant.rs:648-652`, read directly |
| T5 documented as "no running node can hold or issue" | `crates/zp-core/src/policy.rs:46-50` |
| `RedelegationPolicy::Forbidden` enforced only for `Standing` provenance | `capability_grant.rs:665-676`, read directly — comment states the pre-P4 compatibility reason |
| `is_internal_only_capability` covers `ConfigChange`/`CredentialAccess`, keyed on issuance origin, closes M4-3 | `capability_grant.rs:420-454`, read directly |
| `GrantedCapability` has no delegability field | `capability_grant.rs:988-1026`, read directly |
| `delegate()` checks tier, depth, redelegation policy, scope subset, expiry — nothing capability-intrinsic | `capability_grant.rs:641-745`, read directly |
| Layer A amendment requires a release, not a ceremony | `docs/KEEL-2026-07.md` III.6 |
| III.18 delegable safety text | `docs/KEEL-2026-07.md` III.18 (line 268) |
| Phase 7 "declaring an absence is a floor" | `docs/EXECUTION-AUTHORITY-MODEL-2026-07.md:325` |

**Not verified:** whether quorum shares are modelled as `CapabilityGrant`s
anywhere (Q2 depends on this); whether any existing grant in a live chain would
be invalidated by N1–N5 as specified; whether `substrate_validate.rs` is the
right chain-validation enforcement point or merely the most obvious one.
