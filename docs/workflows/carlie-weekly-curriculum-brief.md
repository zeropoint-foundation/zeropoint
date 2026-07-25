# Weekly Curriculum Brief — Carlie's Workflow

*2026-05-12. The first sketch of a post-onboarding workflow. Anchored
in AGENT-AS-UX-ARCHITECTURE-2026-05.md (the Regent's voice + Propose-
Decide-Act pattern) and STEWARD-WIZARD-SCRIPT-2026-05.md (script shape).
Informs #131 (workflow registry) design.*

## Purpose

A weekly synthesis of changes to Foundation course materials, presented
to Carlie for her judgment. Replaces what would otherwise be a manual
scan-everything-since-last-check ritual. Gives her substrate-derived
intelligence about what's moving in the curriculum — what's changed,
who changed it, what's worth her attention — surfaced through
the Regent's framing patterns. Her role is judgment: which observations
matter, what (if anything) to do about them.

This is the *first* post-onboarding workflow — the one that
demonstrates whether the agent-as-UX framing holds against recurring
real work, not just ceremony. If it works for Carlie, it generalizes
to similar shapes for other directors (Lorrie's weekly correspondence
digest, Katie's treasury reconciliation, Louise's strategic brief).

## Workflow header

| Field | Value |
|---|---|
| `workflow_id` | `carlie/weekly-curriculum-brief` |
| `owner` | `carlie` (operator-id) |
| `version` | `1` |
| `pattern` | Propose-Decide-Act |
| `trigger` | Scheduled (Monday 9:00 AM Carlie's local time) + manual ("give me this week's brief") |
| `capabilities_required` | `docs:read`, `receipts:read`, `tasks:write` (optional) |
| `visibility_default` | Member-private |
| `expected_duration` | ~5 minutes (the Regent gathers in advance; Carlie's interaction is the decision moments) |

## Standing pattern

Per AGENT-AS-UX-ARCHITECTURE-2026-05.md surface #1: **Propose-Decide-Act.**

1. **Gather and summarize** — the Regent queries the substrate for course-doc
   changes since the last brief, organizes them, prepares the brief
   *before* Carlie's involvement.
2. **Surface the brief** — the Regent presents what was found, with their
   read on what matters.
3. **Ask for the call** — Carlie decides what (if anything) to act on.
4. **Act on the decision** — the Regent executes whatever Carlie chose.
5. **Confirm the outcome** — the Regent summarizes what was done and
   logged.

Steps 1-2 happen before Carlie engages (asynchronously). Steps 3-5 are
the interactive portion.

## Phases

### Phase 1 — Gather (async, before Carlie engages)

**When:** Monday 9:00 AM, kicked off by the scheduler.

**What the Regent does (no human interaction):**

1. Query the audit chain for `docs:write` receipts under course-tagged
   documents since the last `workflow:weekly-brief:complete` receipt
   for `carlie` (or the past 7 days if this is the first run).
2. For each changed document: fetch the doc, compute a diff summary
   (or fetch the change-event metadata if the substrate provides it),
   note who changed it and when.
3. Categorize changes by signal strength:
   - **Substantive:** the document's structure, scope, or argument
     changed (not just a typo or formatting tweak)
   - **Routine:** small edits, formatting, link updates
   - **New:** new documents added under course tags
4. Compose a brief: 3-7 bullet points covering the substantive +
   new items, with the routine items aggregated as "N small edits
   across M docs." the Regent includes a recommendation per
   substantive item: *"My read: X is worth flagging because Y."*

**Receipt emitted (workflow start):**
```
claim:    workflow:weekly-brief:start
subject:  carlie
metadata: { workflow_id: "carlie/weekly-curriculum-brief", run: <n>,
             trigger: "scheduled" | "manual",
             window_start: <ts>, window_end: <ts>, started_at: <ts> }
```

**Receipt emitted (gather complete):**
```
claim:    workflow:weekly-brief:gathered
subject:  carlie
metadata: { run: <n>, items_substantive: <count>,
             items_routine: <count>, items_new: <count>,
             gathered_at: <ts> }
```

### Phase 2 — Surface (the Regent presents the brief)

**When:** Triggered by Carlie's next session in IronClaw, *or* by an
optional notification ping if she's enabled them.

**the Regent says:**

> Carlie — your weekly curriculum brief is ready.
>
> Three substantive changes this week, eight routine edits across
> twelve documents, and one new draft. The full list is below; my
> read on each substantive item is in italics.
>
> **Substantive:**
>
> 1. *Track 2, Module 4* — restructured the second half. Lorrie
>    rewrote sections 4.3 through 4.6 over two sessions on Wednesday
>    and Thursday. *My read: this is a real structural shift in how
>    the module presents the audit-chain concept. Worth your read
>    before the next curriculum review — would be cheap to flag
>    early if you'd want to revise it.*
>
> 2. *SDK Onboarding Quickstart* — added a new "First Receipt"
>    section. Ken added it Friday evening. *My read: probably aligns
>    with the recent onboarding work; consistent with how members
>    actually encounter their first receipts now. Likely fine, worth
>    a glance.*
>
> 3. *Track 3, Module 1* — the introduction was rewritten. Author
>    unclear (the receipt is attributed to a session with the
>    `pedagogy-helper` capability that I haven't seen used before).
>    *My read: this is unusual. Worth your direct review — both the
>    content and the provenance.*
>
> **New:**
>
> 4. *Curriculum Review Notes — May* — new document, mostly empty.
>    Looks like a placeholder for next week's review meeting.
>
> **Routine:** 8 small edits across 12 documents — typo fixes, link
> updates, minor formatting. Aggregated; no action expected.
>
> Your call: anything worth flagging, drafting a response for, or
> adding to the curriculum-committee agenda?

**Director sees:** A structured brief in IronClaw's chat surface,
following the structural conventions from AGENT-AS-UX surface #3
(headers, italics for the Regent's read, bulleted items). Each item is
clickable to expand into the underlying diff/document, if she wants
to look deeper.

**Receipt emitted (proposal):**
```
claim:    workflow:weekly-brief:proposal
subject:  carlie
metadata: { run: <n>, brief_summary: <text>,
             items: [ <list of items with sage's read> ],
             recommendation_count: 3, presented_at: <ts> }
```

### Phase 3 — Decide

**Director decides:** Carlie reads the brief, optionally clicks into
items for detail, then takes one or more actions:

- **Flag for curriculum committee** — adds the item to the committee
  agenda (next meeting)
- **Draft a response** — the Regent composes a draft note about the
  change for review (e.g., "Lorrie, the Module 4 restructure looks
  good but I have a question about section 4.5...")
- **Dismiss** — acknowledge the item, no action needed
- **Defer** — kick the decision to next week

For each substantive item, Carlie picks one action. She can also leave
a brief rationale in plain text — the Regent captures it.

**the Regent says (between items, if Carlie pauses):**

> Take your time. I'll log whatever you decide.

**the Regent says (if Carlie skips the rationale):**

> No rationale captured — that's fine. The decision itself is
> logged.

**Receipt emitted (one per substantive item):**
```
claim:    workflow:weekly-brief:decision
subject:  carlie
metadata: { run: <n>, item_id: <doc_id>,
             decision: "flag_committee" | "draft_response" |
                       "dismiss" | "defer",
             rationale: <string or null>,
             decided_at: <ts> }
```

### Phase 4 — Act

**What the Regent does:** Executes each decision.

- **Flag for committee** → creates a task in the next committee meeting's
  agenda doc, tagged with the originating item. *Receipt:* `task:created`.
- **Draft a response** → drafts the response in the Regent's chat surface,
  presents it to Carlie for review-and-send. *Receipt:* `proposal:draft`,
  followed by `decision:send` and `mail:sent:carlie` when she sends.
  (This becomes a small sub-workflow inside the larger one.)
- **Dismiss** → no substrate action; the decision receipt itself is the
  record.
- **Defer** → schedules the item to surface in next week's brief with
  a "deferred from prior week" annotation.

**the Regent says (after acting on each):**

> Done. [Specific outcome: "Flagged for next committee meeting." /
> "Draft ready for your review." / "Logged as dismissed." /
> "Deferred to next week."]

**Receipts emitted:** various, per action above.

### Phase 5 — Confirm

**the Regent says:**

> Brief complete. Three substantive items handled: one flagged, one
> dismissed, one drafted (your draft is ready for review when you're
> ready). The routine items and new draft are logged for the record.
>
> Next brief is scheduled for Monday, May 19. Want me to also flag
> the unusual provenance on Track 3, Module 1 to Ken? It was outside
> the usual authoring pattern.

**Director decides:** Optionally takes the Regent up on the
proactive-context offer (flag to Ken).

**Receipt emitted (workflow complete):**
```
claim:    workflow:weekly-brief:complete
subject:  carlie
metadata: { run: <n>, total_substantive: 3, total_routine: 8,
             total_new: 1, decisions_made: 3, actions_executed: 3,
             completed_at: <ts>,
             next_run_scheduled: "2026-05-19T16:00:00Z" }
```

## Edge cases

**No changes this week.** the Regent says: *"No substantive curriculum
changes this week — eight routine edits, no new drafts. Nothing for
your attention. Next brief is scheduled for Monday."* Receipt:
`workflow:weekly-brief:no-changes`.

**Unusual provenance detected.** Surface as a "heads up" item in the
brief (as in the Track 3 example above) — the Regent names it explicitly
rather than burying it in routine.

**Carlie ignores the brief for multiple weeks.** the Regent doesn't badger
or escalate. The brief accumulates; receipts pile up; Carlie's next
engagement surfaces the backlog with a one-line summary. *"Three
weeks of briefs accumulated. Want a consolidated view, or pick up
fresh this week?"*

**A change requires capability Carlie doesn't have** (e.g., something
in Track 1 which is outside her scope). the Regent notes it in the brief
but doesn't open the underlying doc. *"Track 1 had changes I can see
in the chain but can't open under your role. If you need to see them,
talk to Ken."*

**the Regent's read seems wrong to Carlie.** She can override with her own
rationale. The decision receipt captures both the Regent's recommendation
and Carlie's chosen action — including when they diverge. Over time,
the pattern of Carlie-disagrees-with-the Regent becomes a signal the Regent
can learn from.

## Personalization over time

This workflow can refine based on Carlie's patterns:

- If she consistently dismisses routine items without looking, the Regent
  can collapse the routine summary further.
- If she consistently flags Lorrie's edits for committee, the Regent can
  surface those with the recommendation "you'll probably want to
  flag this" pre-attached.
- If she prefers a specific format (e.g., grouping by Track instead of
  by signal strength), the brief layout can tune.

None of this requires re-authoring the workflow — the registry's
manifest carries the tuning as named preferences attached to
Carlie's instance.

## What this workflow demonstrates

This is the first instance of the agent-as-UX framing applied to
recurring real work:

- **Standing pattern (#1).** Propose-Decide-Act, every week.
- **Verbal palette (#2).** *"Your call." / "Done." / "Logged." /
  "Heads up —"* — all in use.
- **Structural conventions (#3).** Bullets for items, italics for
  the Regent's read, headers for categories.
- **Thresholds (#4).** the Regent does the gathering work asynchronously
  before asking; only surfaces when there's something for Carlie to
  judge.
- **Human-role frame (#5).** Carlie's job is judgment; the Regent's job
  is everything before and after the judgment moment.
- **Proposal/decision receipt split.** the Regent's recommendations are
  proposal receipts; Carlie's chosen actions are decision receipts.
  The chain captures both as separable artifacts.

If this works for Carlie — if she finds it useful, if the brief shape
is right, if the framing patterns feel natural — it generalizes. The
workflow registry (#131) absorbs this as the first authored
workflow; subsequent workflows for other directors follow the same
manifest shape.

## Implementation notes

Worker-side:
- Scheduler service to invoke the workflow weekly (cron-like, or
  Cloudflare Workers Cron Triggers)
- Endpoint(s) to support phase 4 actions (task creation, draft
  composition, etc.) — these mostly exist as existing capabilities,
  the workflow composes them
- Receipt schema extensions for `workflow:*` claims

IronClaw-side:
- Workflow invocation surface in the chat (the Regent presents the
  brief as a structured message with interactive decision elements)
- Per-workflow preference storage for the personalization layer

Workflow manifest (the format that will populate #131's registry):
```yaml
workflow_id: carlie/weekly-curriculum-brief
owner: carlie
version: 1
pattern: propose-decide-act
trigger:
  scheduled:
    cron: "0 9 * * 1"   # Monday 9 AM
    timezone: <carlie's local TZ>
  manual: true
capabilities_required:
  - docs:read
  - receipts:read
  - tasks:write
visibility_default: member-private
phases:
  - gather (async)
  - surface (presents proposal)
  - decide (per substantive item)
  - act (executes decisions)
  - confirm (summarizes)
```

## References

- `docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md` — voice, framing, surfaces
- `docs/STEWARD-WIZARD-SCRIPT-2026-05.md` — onboarding precedes daily
  workflows
- `docs/IDENTITY-2026-05.md` — Carlie's identity model
- Task #131 — workflow registry (this is the first registry candidate)
- Task #130 — verb-set proposal/decision split (this workflow
  exercises it)
