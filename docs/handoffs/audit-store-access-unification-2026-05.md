# Handoff — Audit Store Access Path Unification (#151)

*2026-05-13. Target: terminal Claude working in `~/projects/zeropoint`
on `main`. Surfaced during PoC #147 — `zp configure exec` cannot
launch governed tools because it can't open the audit chain that
other commands open just fine.*

## Goal

Unify the audit-store access paths across `zp` commands so all
readers and writers see the same chain. Today, three commands view
the same on-disk audit store three different ways. The store itself
is healthy; the openers are inconsistent.

When this lands, any governed-tool launch (IronClaw, future tools)
can emit a launch receipt via `zp configure exec` cleanly, unblocking
#147's PoC and any future agent-rendered surfaces that depend on the
bridge.

## Evidence (from 2026-05-13 production walkthrough)

The audit chain is healthy:

- File: `/Users/kenrom/ZeroPoint/data/audit.db` (86016 bytes, mode 644)
- Contents: 21 entries, integrity verified, 17/17 signatures pass,
  hash-link intact, genesis sealed

But three commands disagree about it:

1. **`zp doctor`** reads it correctly:
   ```
   ✓ Audit chain: 21 entries, integrity verified
   ✓ Chain integrity: 21 entries, 17/17 signatures pass,
     hash-link intact, genesis sealed
   ```

2. **`zp status`** reports it as missing:
   ```
   Audit chain: not yet initialized (start server to create)
   ```

3. **`zp configure exec --name <tool> -- ...`** can't open it:
   ```
   Launch blocked: could not emit receipt.
   Failed to open audit store for launch receipt
   ZP-governed tools must be auditable. Fix the audit chain and retry.
   ```

Same file. Three different openers. Two of them are wrong.

## Likely investigation surface

The audit chain has accumulated multiple readers over the verb-set
migration and the v2→v3 schema work (#68 still pending). Candidates
to audit and consolidate:

- `zp-cli/src/commands.rs` and adjacent — likely the doctor / status
  paths
- `zp-configure` crate — the exec wrapper's audit emission path
- `zp-audit` crate — the canonical opener; should be the *only*
  consumer touching the SQLite file directly
- `zp-server` paths if any helper commands route through it

Per Architecture II.0 (contracts singular, implementations plural),
there should be ONE canonical opener — likely
`AuditStore::open_signed` from `zp-audit` (see #14 / Tier-1 work) —
and every CLI command should go through it. Today, at least two of
the three callers are doing something else.

The v2-backup file in `~/ZeroPoint/data/` suggests a migration ran on
2026-05-09 but #68 is still marked pending. That implies either the
migration was partial, or the v3 readers haven't all been updated.
Worth checking as part of this pass.

## Acceptance criteria

After this lands:

1. `zp doctor`, `zp status`, and `zp configure exec` all use the
   same audit-store opener (canonical: probably
   `zp_audit::AuditStore::open_signed` or equivalent)
2. `zp status` reports the chain accurately — same count and health
   indicators as `zp doctor`
3. `zp configure exec --name ironclaw -- ~/projects/ironclaw/target/release/ironclaw`
   succeeds, emits a `tool:launched:ironclaw` receipt to the chain,
   and execs the binary with vault-resolved env
4. The new launch receipt is visible in `zp doctor` and `zp status`
   after the launch (chain grew by exactly one entry)
5. No regression in `zp doctor`'s existing checks
6. Existing audit-store tests pass; new test covers the unified
   opener invariant (all three CLI surfaces yield the same view)

If #68 (v2→v3 migration) turns out to be the same root cause —
multiple readers expecting different schema versions — close both
in one commit.

## Out of scope

- Per-operation auth re-prompts (#149, #150) — different bug class;
  same passkey-state-not-cached pattern but separate fix surfaces
- Receipt signing on the foundation worker (#143) — orthogonal
- PoC #147's evaluation — picks back up once this lands

## Refs

- `docs/handoffs/agentic-poc-chain-render-2026-05.md` — the PoC this
  unblocks
- Task #151 — this task
- Task #68 — sibling: audit DB v2→v3 migration
- Task #90 — completed: canonical audit path resolution (correct path
  but multiple readers diverge after that)
- Task #86 — operating principle the exec wrapper correctly enforces
- CLAUDE.md → Architecture Direction → "contracts singular,
  implementations plural" (II.0) — the rule this work brings into
  alignment for audit-store access
