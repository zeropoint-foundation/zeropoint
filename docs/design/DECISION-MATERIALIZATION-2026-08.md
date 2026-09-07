# Materializing `Decision` — the population, measured first

**Status:** proposed 2026-08-10 · no code written
**Decides:** what becomes a `Decision` object, and in what order the work runs
**Type:** Tier 2 elaboration. Every figure is regenerable — `tools/ontology_surface.py`
for the surface, the queries named inline for the population. Regenerate before quoting.
**Follows:** SEAM-011 (the ontology has 2,202 nouns and no verbs), and the
classification recorded there.

## Why `Decision` and not one of the other three

Measured, not preferred. Materializing exactly one more object type unblocks:

| type | relationship kinds it makes reachable |
|---|---|
| **Decision** | **4** — `BelongsTo`, `SupersededBy`, `InfluencedBy`, `AuthorizedBy` |
| Artifact | 2 — `ContributesTo`, `DependsOn` |
| Friction | 2 — `BelongsTo`, `BlockedBy` |
| Insight | 1 — `BelongsTo` |

Ten of eleven relationship kinds are currently unreachable because they need a
non-`Trajectory` object at an endpoint. `Decision` clears the most of them, and
one of the four it clears — `AuthorizedBy`, gate-decision → delegation-decision
— is the provenance edge SEAM-006 said we had machinery for and no decisions to
trace.

## The population is 441, not 25,758

The instinct is to treat `regent:intent:*` as the decision stream. That is
25,758 entries. It is the wrong set, and taking it would be the mistake this
substrate keeps making.

Whole-chain counts, 296,135 entries:

```
regent:intent:observe            25559     <-- not decisions; see below
regent:intent:respond               97
regent:intent:execute               81
regent:intent:request_approval      20
regent:intent:remember               1
delegation:granted:regent           99
AuditAction::PolicyInteraction      81     <-- gate decisions
regent:proposal:action              18
regent:approval:denied              12
cognitive:correction:standing        9
cognitive:correction:violated        7
regent:precedent:cited               6
regent:approval:granted              3
regent:approval:enacted              2
regent:proposal:duplicate            2
improvement:proposed                 2
regent:precedent:revoked             1
```

**441 candidates. 0.15% of the chain.**

Materializing all 25,758 intents would produce 25,559 rows meaning *nothing
happened* against 199 meaning something did — a 128:1 noise ratio, and an
ontology that reads as full while being empty. That is PIN-002 in a new
register, and it is avoidable by knowing the population before writing the
materializer.

## Why `observe` is excluded, and the caveat that matters

Under SEAM-006, most `regent:intent:observe` entries are the *short-circuit*
path: `reason()` returned before any inference ran. That is not a decision to
stand down. It is the absence of deliberation, recorded.

But some observes are genuine — a cycle that deliberated and chose to act on
nothing. Those are decisions, and they should materialize.

The two are distinguishable only by the `gate=short_circuit` marker, which
exists **from 2026-08-09 onward**. Before that date the two are recorded
identically. So:

- observe **with** `gate=short_circuit` → not a Decision.
- observe **without** it, after 2026-08-09 → a Decision.
- observe before 2026-08-09 → **unclassifiable**, and must not be silently
  bucketed either way. PIN-004 already says this about wake measurement; it
  applies with more force here, because a materializer writes its guess down
  permanently.

The honest handling is a `provenance` marker on any Decision derived from a
pre-marker observe, or excluding them and recording the exclusion. Not a
coin-flip encoded as a row.

## Every `Decision` needs a `Trajectory`, and 314 do not have one yet

`Decision.trajectory_id` is `ObjectId`, not `Option<ObjectId>`. A Decision that
belongs to no trajectory cannot be constructed.

Measured against `object_receipts`:

```
candidate Decision receipts        441
  already linked to a trajectory   127   (28.8%)
  not yet linked                   314
```

The 314 are not a modelling problem. They are behind the Cartographer's cursor,
which sits at `last_processed_sequence = 225690`, last advanced 2026-08-05, with
70,445 entries unprocessed. Catching it up assigns them.

This is good news twice over. The trajectory assignment is not new work — the
Cartographer already decides, per receipt, which trajectory it belongs to, and
already links it as `evidence` (7,895 such links today). Materializing a
Decision is an **additional branch in a loop that already holds the trajectory
in hand**, not a new subsystem.

And the cursor is resumable: 225,690 is inside the archive (rowids 1–286,101),
reachable only because `export_entries_after_rowid` was fixed on 2026-08-09 to
UNION live and archive. Before that it silently skipped 25,713 entries.

## Order of work

1. **Catch the Cartographer up.** 70,445 entries. Produces no new object types —
   it is a prerequisite and a verification of the resume path, not progress.
   Expected outcome: the 314 unlinked candidates gain trajectories, and
   `object_receipts` grows proportionally. If it does not, stop — the resume
   path is still wrong and everything below is built on sand.
2. **Materialize `Decision` from the 441**, in the same per-receipt loop.
3. **Then `AuthorizedBy`** — 81 gate decisions and 99 delegation grants are both
   already on the chain, so both endpoints exist the moment step 2 lands. This
   is the first real edge in the ontology and the one worth having first.
4. `BelongsTo` follows trivially (every Decision has a trajectory by
   construction). `SupersededBy` and `InfluencedBy` need a supersession signal
   that has not been identified yet — see Open.

## Field mapping, per source

`Decision { id, trajectory_id, title, description, status, superseded_by, created_at, receipt_refs }`

- `id` — `derive_object_id(ObjectType::Decision, receipt, discriminator)`, already
  implemented and tested in `zp-ontology/src/id.rs`. Deterministic, so a rebuild
  from the same chain produces identical ids. Nothing to design.
- `trajectory_id` — the trajectory the receipt was assigned to. Already computed.
- `created_at`, `receipt_refs` — from the entry.
- `status` — `Active` for all 441 at first materialization. `Superseded` and
  `Reverted` require signals discussed under Open.
- `title` / `description` — the only genuinely new work, and it differs per
  source. `delegation:granted:regent` now carries a real receipt with
  `zp.capability.*` extensions (wired 2026-08-09), so its title can be
  structured rather than parsed. `PolicyInteraction` carries `decision_type` and
  `user_response` as typed fields. `regent:intent:execute` carries `tool=`. The
  pipe-delimited tails on `regent:proposal:action` and `regent:precedent:cited`
  are the drift already flagged in CHANNEL-BOUNDARY-2026-08 item 5 — **do not
  build a parser for them here.** That would ratify an unspecified wire format
  by depending on it. Either those sources get structured extensions first, or
  they materialize with a title and no description.

## Open

1. **`SupersededBy` and `InfluencedBy` have no identified signal.** Nothing on
   the chain currently says "this decision replaces that one". `regent:precedent:revoked`
   and `regent:approval:denied` are adjacent but not the same relation. Until a
   signal exists these two kinds stay reserved even after `Decision` lands —
   which means materializing `Decision` unblocks 4 kinds *in principle* and 2 in
   practice. That distinction should not be lost in the reporting.
2. **Pre-marker observes.** Exclude, or materialize with a provenance flag.
   Excluding is safer and loses a bounded, dateable amount.
3. **Should officer findings become Decisions?** They are 85,000+ entries and
   they are observations, not decisions — `Friction` and `Insight` are the
   better fits, which is an argument for materializing those next rather than
   stretching `Decision` to cover them.
4. **Cost of catch-up is unmeasured.** 70,445 entries through the boundary
   decision path. If the Cartographer is enabled and it is slow, it competes
   with the Regent's 60s loop for the audit store lock. Measure on a copy of
   the chain before enabling against the live one.
