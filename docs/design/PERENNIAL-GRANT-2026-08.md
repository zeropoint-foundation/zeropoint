# The Perennial Grant — a wildcard delegation that cannot expire, and the three consequences that follow

**Document type:** Design note / decision memo. Elaborates no KEEL section; it examines one construction in `zp-server` against a primitive the corpus adopted on 2026-08-15, and asks for a ruling.

**Status:** Proposed 2026-08-16. **Ruled 2026-08-17: C unconditionally, and B.** The finding was recorded before being patched, because the construction is defended in its own doc comments and reversing a deliberate position is an authority decision, not a lint fix. §7 carries the ruling; §10 records what was built and what it costs.

**Date:** 2026-08-16.

**Composes with:** `AI-LANDSCAPE-SIGNAL-2026-07` (E13 — the four converged authorization primitives, and the amendment that named mandatory expiry as failing), `THREAT-MODEL-2026-08.md` (§6 — where the invariant fails today), `HOST-BROKER-2026-08.md` (§4 — grants replacing the self-asserted tier), `ARCHITECTURE.md` §13.3 (the default-deny reconciliation, still open).

**Attribution:** Drafted by Claude against the tree at `eccc2a6`. Every mechanism below was read, not inferred; the reachability claim in §3 is derived from the source and is stated as derived rather than as observed at runtime. The ruling in §7 is Ken's.

---

## 1. The finding in one paragraph

`zp-server` issues a `CapabilityGrant` carrying `ToolCall { tools: ["*"] }` at two production sites. Both take `CapabilityGrant::new`'s default of `expires_at: None` and attach no `lease_policy`. Because `is_past_grace()` falls through to `is_expired()` when no lease policy is present, and `is_expired()` returns `false` when `expires_at` is `None`, **these grants are permanently alive by construction**. This is not drift: both sites carry doc comments defending it, and the argument they make is a real one. What follows is what the position costs, stated precisely enough to be ruled on.

## 2. Where it is, and what is actually written there

Three sites construct a wildcard `ToolCall`. Only two are production.

| Site | Function | Trigger |
|---|---|---|
| `crates/zp-server/src/lib.rs` | `tool_launch_handler` | every cockpit launch of a tool |
| `crates/zp-server/src/lib.rs` | `register_agent_handler` | every tool startup that calls `register-agent` |
| `crates/zp-server/src/lib.rs` | `p4_phase2_tests::standing_grant` | test fixture |

The production sites state their reasoning:

> Re-issue delegation grant on every cockpit launch. This makes cockpit launch the renewal ceremony — expiry can never surface as an operator concern for tools that call register-agent at startup. `CapabilityGrant::new` defaults to `expires_at: None` (no hard expiry), so the standing grant is perennial; the chain entry is the durable record that the ceremony occurred.

And:

> The grant uses `ToolCall { tools: ["*"] }` with no expiry, making the chain entry the durable record rather than a TTL clock.

**This is a coherent position and deserves to be read as one.** It says: a TTL is a clock that fails at the worst moment, an operator who must renew grants will eventually be interrupted by a renewal at 3 a.m., and a chain entry recording that a ceremony occurred is better evidence than a countdown nobody watched. The substrate re-grants on every launch, so the record is continuously refreshed. Nothing here is careless.

**The test fixture is the interesting one.** It constructs the same wildcard capability and then adds what production omits:

```rust
.with_lease_policy(LeasePolicy::standard_8h())
.with_renewal_authorities(vec![AuthorityRef::genesis("lease_renewal")])
.with_revocable_by(vec![AuthorityRef::genesis("revocation_authority")])
.as_standing("genesis-key")
```

So the lease machinery exists, is wired, and is exercised. The gap is not capability. It is that the production path takes the constructor's default and the test path does not — which means **the tested configuration and the shipped configuration are different objects**, and the tests do not cover the thing that runs.

## 3. Consequence one — a denial path that cannot fire

`lease_prereq_for_agent` is the gate's delegation check. It walks the chain, reconstructs each grant, filters to those neither revoked nor `is_past_grace()`, and returns one of four verdicts:

- `None` — proceed
- `capability_scope_exceeded`
- `no_valid_delegation`
- `delegation_revoked`
- `delegation_expired`

The last is reached only when grants exist, none are revoked, and none survived the liveness filter. For a grant with `lease_policy: None` and `expires_at: None`, `is_past_grace()` returns `false` unconditionally. **No production grant can ever fail that filter**, so `delegation_expired` is unreachable on the production path.

A denial reason that cannot be returned is the same shape of defect this corpus has been closing all month: `ARCHITECTURE.md`'s *"you can't bypass it because it's structural"* one `use` away from false, `CatastrophicActionRule`'s credential message standing in for an injector, `zp-anchor` declaring a default backend the server never constructed. The check is present, the code reads as governed, and the branch is dead.

`zp revoke --reason lease-expired` accepts a reason naming a lifecycle these grants cannot enter.

## 4. Consequence two — revocation is proportional to launch count

Every construction calls `CapabilityGrant::new`, which mints `grant-{uuid_v7}`. Every cockpit launch therefore produces a **new grant id**, appended to the chain and pushed to the in-memory `grants` vector. Nothing supersedes or replaces the prior grant; `lease_prereq_for_agent` keys its map by grant id, so all of them accumulate as independently live.

Revocation targets a grant id: `zp revoke --grant-id grant-…`. The `--cascade` policies (`grant-only`, `subtree-halt`, `subtree-reroot`) act on the *delegation subtree* — children of that grant — not on sibling grants held by the same grantee.

**So revoking an agent requires revoking every grant it has ever been issued.** After N cockpit launches that is N revocations, and missing one leaves the agent fully authorized. There is no revoke-by-grantee verb. The operator surface most likely to be reached for under time pressure — *"cut this tool off"* — has no single action behind it, and the number of actions required grows with how long the tool has been in service.

This is the consequence I would weight highest. The expiry question is philosophical; this one is operational, and it degrades with use.

## 5. Consequence three — Claim 4 narrowing passes vacuously

The scope check added for Claim 4 asks whether some live grant covers the requested tool:

```rust
let tool_action = CoreActionType::ToolCall { name: tool_name.to_string() };
let scope_ok = live.iter().any(|g| g.matches_action(&tool_action));
```

With `tools: ["*"]` this is true for every tool name that will ever exist, including tools not yet written. The check runs, costs a chain walk, and cannot fail. `capability_scope_exceeded` is reachable in principle — a narrower grant would trip it — but no production code path issues a narrower grant, so in the shipped configuration it is dead alongside `delegation_expired`.

`AI-LANDSCAPE-SIGNAL-2026-07` E13 records that the substrate *"passes deny-precedence and attenuation-only on their face."* Attenuation-only is the rule that a delegated grant may only narrow, never widen. It passes here in the sense that nothing widens — but only because the root grant is already maximal. A rule that cannot be violated because the starting point is the top of the lattice is satisfied the way an empty set satisfies a universal quantifier.

## 6. What the corpus already says

E13, applied 2026-08-15, adopted four primitives on the strength of independent convergence between IETF/OAuth and NIST SP 800-162 / RFC 9396: **default-deny, deny-precedence, attenuation-only delegation, mandatory expiry.** It states:

> **Mandatory expiry fails at the constructor**: `CapabilityGrant::new()` defaults `expires_at` to `None`, so non-expiring is what a caller gets by omission rather than by decision.

That is accurate and it is one layer short. The constructor default is how it happens; **the two production sites are where it happens**, and they are not omissions — they are documented choices. The corpus records the mechanism and not yet the instance. This memo is the instance.

Note the asymmetry E13 also names: the capability layer is default-deny, the policy engine is default-allow per `ARCHITECTURE.md` §13.3, and the two have never been reconciled in one statement. The perennial grant sits exactly on that seam. If the capability layer is the thing that makes default-allow tolerable, then a maximal non-expiring capability is the seam's weakest point.

## 7. The options, with what each costs — and the ruling

**Ruled 2026-08-17 (Ken): take C unconditionally, and take B.** A and D were not taken. The options are left below as written on 2026-08-16, unamended, so the ruling can be read against what it was ruling on rather than against a summary of it.

**A — Leave it, and record it.** *(not taken)* The position is defended, the substrate is single-operator today, and the argument that a chain entry beats a TTL clock is not wrong. Cost: `delegation_expired` and `capability_scope_exceeded` stay dead, revocation stays O(launches), and the corpus continues to claim a primitive the code does not implement. If chosen, the honest move is to amend E13 from *"fails at the constructor"* to *"declined at the call sites, for these reasons"* — a stated limitation rather than an open gap, the same treatment `THREAT-MODEL` §5 gave anchor suppression.

**B — Attach the lease policy production already tests.** *(taken)* Add `.with_lease_policy(LeasePolicy::standard_8h())` and renewal authorities to both sites, matching the fixture. Cost: cockpit launch remains the renewal ceremony, so the operator-interruption argument is preserved — a tool relaunched inside 8 hours never notices. A tool running longer than 8h without relaunch enters grace, then dies. That is a real behaviour change and the doc comments were written to prevent exactly it. Benefit: both dead branches come alive, and the tested object becomes the shipped object.

**C — Fix revocation independent of expiry.** *(taken)* Add a revoke-by-grantee verb that emits revocations for every live grant id held by an agent. Cost: small, additive, no behaviour change to the grant lifecycle. Benefit: removes the consequence that degrades with use. **This is separable from the expiry question and I would take it regardless of how A/B is ruled.**

**D — Narrow the scope.** *(not taken; still open)* Replace `["*"]` with the tool's actual capability set. Cost: requires knowing what each tool needs, which is a per-tool discovery problem the substrate does not currently solve; likely blocks on manifest work. Not recommended now, listed for completeness.

## 8. What I would do, and what I would not

I would take **C unconditionally** — it is cheap, it is additive, and it fixes the failure mode an operator meets under pressure rather than the one that reads worst in a design document.

Between **A** and **B** I lean **B**, because the fixture already proves the machinery and the 8-hour lease with launch-as-renewal preserves the operator experience the comments are protecting. But I hold that lightly: the comments were written by someone who had the tool-lifecycle context I am reconstructing from source, and *"a tool that runs longer than 8h without relaunch"* may describe something normal here that I cannot see.

I would **not** silently patch this. Two doc comments state the position deliberately; changing it without a ruling would be the same category of act as exempting fourteen tools from a scope pin because a formatter made them look ungoverned.

## 9. What would falsify the memo

- **Consequence one is derived, not observed.** I read `is_past_grace()` and traced the `None`/`None` path; I did not run a gate check against an aged grant and watch `delegation_expired` fail to appear. A test that ages a production-shaped grant past any plausible expiry and asserts the gate still permits would confirm it — and belongs in the tree either way.
- **Consequence two assumes launches are frequent.** If cockpit launch is rare in practice, N stays small and the revocation cost is theoretical. I have no telemetry on launch frequency.
- **If a revoke-by-grantee path exists somewhere I did not find**, §4 is wrong. I searched the CLI and server surfaces; the only revocation entry points take a grant id.

---

## 10. What was built, 2026-08-17

**C — revoke by grantee.** `crates/zp-cli/src/main.rs`. `zp revoke` now takes `--grant-id` *or* `--grantee`, exclusive and one-required, enforced by clap rather than by a runtime check. `--grantee` resolves through the same `reconstruct_grants` chain-walk the gate uses, selects every live grant held by that grantee, and emits a revocation for each. Already-revoked grants are skipped rather than re-revoked, so the verb is idempotent. If some revocations succeed and one fails, the failure is reported alongside what did land rather than swallowed — a partial revocation an operator does not know about is worse than a failed one. JSON output always carries a `revocations` array; the previous flat fields are retained so existing readers do not break.

This closes §4. Revocation is no longer proportional to launch count, and the action an operator reaches for under pressure — *cut this tool off* — now exists as one command.

**B — the lease attaches at both production sites.** `crates/zp-server/src/lib.rs`. Both wildcard grants now carry `.with_lease_policy(LeasePolicy::standard_8h())`, renewal authorities, revocable-by, `.with_subject_public_key(agent_key)`, and `.as_standing(...)` — the fixture's configuration, so the tested object and the shipped object are the same object. Both doc comments that defended the perennial position were rewritten to record the reversal and cite this memo; the original text is preserved in §2 above rather than only in git history.

**The consequence, stated plainly, because it is a real behaviour change.** Tools do not heartbeat. The heartbeat path is delegate-nodes-only and gated on `~/ZeroPoint/lease.toml`. So a tool that runs longer than **8h30m** (8h lease + 30m grace) without a cockpit relaunch will begin to be denied at the gate with `delegation_expired` — the branch §3 identified as dead, now live. That is the intended effect and also the risk: §8 held B lightly precisely because *"a tool that runs longer than 8h without relaunch"* may describe something normal here.

Binding the subject key is what keeps this from being a dead end. With `subject_public_key` set, the renewal endpoint can authenticate a renewal signed by the agent, so the renewal path exists rather than being unreachable by construction. If long-running tools turn out to be normal, the cheap adjustments are, in order: raise `lease_duration` on a policy of its own rather than editing `standard_8h`; or wire tools into the existing heartbeat. Neither requires revisiting the ruling.

**Still open after this.** D — narrowing `["*"]` to a per-tool capability set — is untouched and still blocks on manifest work. The constructor default (`expires_at: None`) is also untouched: B fixes the two call sites that mattered, not the default that produced them, and E13's proportionate remedy at `validate_issuance` remains unimplemented. And §9's first bullet is now the outstanding test: a production-shaped grant aged past grace, asserted to be denied. It was written to falsify the dead-branch claim; it is now the regression test that the branch stays alive.
