# Foundation Artifact Vocabulary

*Drafted 2026-05-11. Candidate for folding into ARCHITECTURE-2026-05.md as
section II.17. Companion to AGENTIC-SURFACE-2026-05.md (II.14),
MULTI-TENANT-2026-05.md (II.16).*

## The question this answers

II.14 established that the substrate doesn't host UI; agentic clients
(IronClaw, future MCP-aware tools) render based on what's needed in the
moment. But that leaves an unanswered question: **how do agentic clients
actually render?** Three plausible positions:

| Position | Shape |
|----------|-------|
| Pure generation | LLM generates every UI artifact from scratch each turn |
| Curated vocabulary | Library of pre-built UI primitives; agentic client composes from the library |
| Hybrid | Vocabulary for common patterns, generation as overflow for novel cases |

ZP Foundation chooses **hybrid**: a small curated vocabulary covers the
patterns members actually use; novel requests are met with generative
extension that grows the vocabulary organically over time.

## Why hybrid

Pure generation is theoretically maximal but practically problematic:
- High latency (every turn pays the LLM-generation cost)
- Inconsistent UX (different sessions produce visually different
  versions of "the audit chain")
- Hard to debug (no persistent source of truth for any artifact)
- Token-expensive (UI generation occupies context that could be used
  for actual reasoning)
- No version control or audit (an LLM regenerating "the calendar" each
  session means the calendar has no canonical form)

Curated vocabulary alone is the conventional approach but too rigid:
- Vocabulary becomes a development bottleneck
- Novel needs require dev work before members can use them
- Scales poorly as Foundation work diversifies

The hybrid resolves both:
- **Common patterns are curated.** Consistent UX, fast response, free
  to invoke, version-controlled. Members learn the vocabulary and rely
  on it.
- **Novel needs are generated.** No vocabulary work blocks a member
  who needs something unique.
- **Vocabulary grows organically.** Generated artifacts that prove
  repeatedly useful get formalized into the vocabulary in follow-up
  curation work.

This is the same shape that has worked for React + design systems:
base components (Button, Card, Table) are curated; composition is
fluid; new components are added when patterns repeat.

## The v1 starting vocabulary

| Artifact | Purpose | Surface area |
|----------|---------|--------------|
| `Chat` (default IronClaw surface) | Conversation; default when no artifact is needed | Already exists in IronClaw |
| `SharedCalendar` | Foundation-bound events (meetings, signing deadlines, governance milestones, member ceremonies) | Curated component; iCal feed for sync-out to members' personal calendars |
| `FoundationTimeline` | Curated view of significant chain events (member joinings, document signings, governance decisions, manually-flagged milestones) | Curated component; filtered audit chain view |

Plus implicit: members ask IronClaw conversationally for anything the
vocabulary doesn't cover. IronClaw answers from substrate state without
needing a dedicated visualization.

## Calendar specifically

Foundation members almost certainly use Google Calendar / Apple
Calendar / Outlook for personal scheduling. The Foundation calendar
can't replace those — too much friction. So the design is:

**Foundation calendar = Foundation-bound events only.** Personal
scheduling stays in personal tools. The Foundation calendar holds
events that matter to the Foundation as an entity: team meetings,
board meetings, partner calls when the Foundation is the host, signing
deadlines, governance ratification windows.

**Sync-out via iCal feed.** Each member gets a per-member iCal URL
with an auth token. Their personal calendar app subscribes to the URL.
Foundation events appear naturally in their existing calendar
alongside their personal events. Sync is one-way: Foundation publishes,
member consumes.

This costs ~half-day of implementation on top of the calendar artifact:
generate an iCal feed at `/api/v1/members/<member>/calendar.ics` with
auth-token-gated access. Members add the URL to their calendar app as
a subscription.

**Out of scope for v1** (capture as future work): bidirectional sync
(member personal events into Foundation calendar) — privacy and scope
concerns; defer.

**Data model:** Foundation calendar events are chain-bound. Each event
is a receipt of kind `RECEIPT_KIND_CALENDAR_EVENT` containing the event
metadata. Updates are new receipts citing the original; the latest
receipt in the cite chain is the current state. Deletes are explicit
`RECEIPT_KIND_CALENDAR_EVENT_CANCELLATION` receipts. The audit chain
becomes the event log; the calendar is a curated view of the current
state of those events.

Privacy tiering: events are Foundation-team-visible by default. Events
marked `leadership-only` are hidden from non-leadership members in
both the calendar UI and the iCal feed.

## Foundation timeline specifically

Filter for "significant" — the default v1 set:

- `RECEIPT_KIND_MEMBER_INVITATION`, `MEMBER_ENROLLED`, `MEMBER_REVOCATION` —
  membership events
- `RECEIPT_KIND_DOCUMENT_SIGNATURE`, `SIGNING_COMPLETION` — signed
  documents (when II.15 ships)
- `RECEIPT_KIND_DELEGATION` — Foundation-level grants (not every routine
  member-level grant; tiered visibility)
- `RECEIPT_KIND_POLICY_VOTE`, `POLICY_AGREEMENT` — governance decisions
- `RECEIPT_KIND_CALENDAR_EVENT` — significant meetings (filtered: only
  those marked "milestone" or "board-level" appear on timeline; routine
  meetings are calendar-only)
- Manually-flagged milestone receipts via a `timeline=true` tag on any
  receipt

That filter produces a substantive feed (orientation-worthy, not noise).
Veterans can drill into the raw chain via the underlying ChainTable
artifact (when curated; ad-hoc via IronClaw conversation otherwise) when
they need full detail.

**Data shape:** Foundation timeline is a derived view, not stored
separately. The component queries the audit chain with the filter set,
groups by date, renders cards per event with brief metadata. No new
receipt kinds needed beyond the ones the filtered events already have.

## How an artifact gets used

Member-facing flow:

1. Member says (chat): "What's coming up this week?"
2. IronClaw decides this is a calendar question; invokes `SharedCalendar`
   artifact with filter `week ahead`
3. SharedCalendar component renders inline in the IronClaw chat surface
4. Member sees their week; can click events for detail, click "RSVP" buttons, etc.

Same shape for timeline, signing flows when II.15 ships, etc.

Each artifact is invoked via standard MCP-style tool call. IronClaw's
LLM decides when each artifact is appropriate based on the
conversation. Members can also invoke artifacts directly via explicit
URLs (`foundation.zeropoint.global/calendar`,
`foundation.zeropoint.global/timeline`) if they prefer.

## Privacy controls in the chat surface

The default IronClaw chat surface is where members most often interact
with the substrate, and it's where privacy controls have to feel
natural. The substrate provides the model (visibility field on every
receipt, see II.16); the chat surface provides the practical controls
that make it usable.

### Session modes

Every chat session has a privacy tier, shown prominently:

| Session mode | Default visibility | Visual indicator | Typical use |
|--------------|-------------------|------------------|-------------|
| **Working** (default) | Member-private (visible to member + Operator) | Lock icon, dimmed background | Personal exploration, drafting, search, thinking-out-loud |
| **Team** | Foundation team (all authenticated members) | Foundation badge, normal background | Collaborative work, decisions, document review |
| **1:1** | Member + named other member(s) | Lock + named-members icon | Private discussions between specific people |
| **Leadership** | Leadership tier only | Crown icon, distinct background | Strategic discussions, sensitive negotiations |

The mode chosen when starting a session is preserved throughout. All
actions taken in the session (chain receipts emitted, artifacts
invoked, documents touched) inherit the session's visibility tier
unless the member explicitly overrides for a single action (rare).

### Inline controls

In any chat session, the member sees:

- **Privacy tier indicator** at the top, always visible: shows the
  current tier, who can read, and how many receipts in this session
  so far.
- **Change privacy button** opens a small dialog with tier options
  + plain-language explanation: "Promote to team — all messages and
  actions in this conversation become visible to all Foundation
  members. This is permanent for past messages; cannot be undone."
- **Add member** (for 1:1 sessions): invite another member; requires
  their consent receipt before they join.
- **Take this offline**: start a new private session, optionally
  carrying selected context forward. Useful when a member realizes
  mid-conversation that they need to switch tiers without affecting
  the existing session's record.

### Natural-language shortcuts

For members who prefer chat over clicking:

| Member says | IronClaw does |
|-------------|---------------|
| "make this private" | Switch session to Working mode (warn if there are existing team-visible receipts: those can't be un-shared) |
| "share this with the team" | Initiate promotion to Team tier; show confirmation dialog before emitting the promotion receipt |
| "loop in Alice" | Propose adding Alice to the session; Alice gets a consent prompt |
| "move to leadership" | Escalate session to Leadership tier (member must have leadership scope; otherwise IronClaw declines with the reason) |
| "what can people see here?" | Show the privacy tier, list of readers, count of receipts at this tier |

### Visibility minimums shown clearly

When a member tries to do something that triggers a visibility minimum
(e.g., trying to sign a document in a Working-mode session), IronClaw
surfaces this explicitly: "Signing a document produces a Foundation-
team-visible receipt regardless of session tier. The document body
can remain private per its ACL, but the signing event will be visible
to the team. Proceed?"

Members never silently accidentally publish something private; they
also never silently fail to record something the substrate requires to
be visible. Both directions are confirmed.

### Visual indicator carries through artifacts

When an artifact is invoked inside a session, the artifact UI shows
the session's privacy tier in a corner badge. This ensures members
understand "I'm looking at this calendar event in a Working-mode
chat — anything I do here is private" vs "I'm in the Team chat,
RSVPing to this meeting publishes my RSVP to the team chain."

### Audit chain perspective on session modes

Every session-mode change is itself a chain receipt
(`VISIBILITY_PROMOTION` or `VISIBILITY_DEMOTION` per II.16). The chain
records when sessions changed tiers, who initiated, who consented
(for promotions of multi-party sessions). Auditing "what privacy
transitions happened this month" is a chain query.

## How an artifact gets defined

Each artifact has:

| Component | What | Where |
|-----------|------|-------|
| Component source | React or HTML component implementing the artifact | `foundation-stack/components/<artifact>/` |
| MCP tool definition | Defines when IronClaw should invoke this artifact, what parameters it accepts | `foundation-stack/components/<artifact>/mcp.json` |
| Data access spec | Which ZP gRPC verbs the artifact calls + with what scopes | `foundation-stack/components/<artifact>/data.md` |
| Documentation | How members use it; what they see; what they can do | `foundation-stack/components/<artifact>/README.md` |
| Versioning | Semver per artifact; changes are deliberate, not surprise UX shifts | `foundation-stack/components/<artifact>/version.toml` |
| Citation in receipts | For trust-critical operations (signing especially), receipt records which artifact version was used | Built into receipts via the launch / action wrapper |

The vocabulary repository pattern mirrors the public/private separation
(docs/PUBLIC-PRIVATE-SEPARATION-2026-05.md): the *vocabulary code* is
public (foundation-stack), the *Foundation's actual calendar events*
are private operational state.

## How the vocabulary evolves

Process:
1. Member asks for something not in the vocabulary
2. IronClaw generates an artifact on the fly to answer
3. If the generated artifact is good, the member can save the request
   pattern as a "saved view"
4. When the same pattern recurs across multiple members, a curation
   task gets opened to formalize it into a named vocabulary entry
5. The curated entry replaces the generative version; future
   invocations get the consistent, faster, version-controlled rendering

This puts vocabulary growth on a demand-driven path: the Foundation
doesn't pre-build dozens of artifacts speculatively; it builds the
ones members actually need based on real usage signal.

## Implementation phasing

For Foundation pilot next week:

| Phase | Components | Effort |
|-------|------------|--------|
| **Pilot week 1** | Chat (default IronClaw); no curated artifacts yet | Already done |
| **Pilot week 1-2** | `FoundationTimeline` v1 (filtered chain view, basic styling) | ~3-5 days |
| **Pilot week 2-3** | `SharedCalendar` v1 + iCal sync-out | ~1-2 weeks |
| **Subsequent weeks** | Vocabulary grows from real usage patterns | Demand-driven |

Pilot week 1 ships with chat alone. Members onboard with IronClaw as
their only interface; they ask conversational questions and IronClaw
either answers from substrate state directly or generates artifacts on
the fly. The two curated artifacts land within 2-3 weeks of pilot
start, both because they're useful and because they're the first
proofs of concept for the vocabulary pattern.

After pilot validates the architecture, vocabulary grows based on the
patterns the Foundation actually exhibits. We don't predict — we
observe and curate.

## What this is not

- **Not a Foundation dashboard with fixed widgets.** The Foundation's
  primary interface is conversational (IronClaw chat). Artifacts are
  invoked in conversation; they're rendered objects, not screens.
- **Not a webapp framework competing with React/Vue/etc.** Components
  internally are standard web tech (React or HTML, Tailwind for
  styling). The vocabulary is about which components exist, not about
  inventing UI primitives.
- **Not a substrate-level concern.** The substrate exposes gRPC verbs.
  Artifacts are how agentic clients render the data those verbs return.
  Substrate-side, nothing changes per artifact added or removed.
- **Not a commercial product.** This is Foundation tooling that
  external adopters can fork. Each adopter's vocabulary will look
  somewhat different based on their workflows. The reference
  implementation is starting-point, not prescription.

## Open questions

- **Component framework**: React + Tailwind is conventional. Should
  Foundation use something more aligned with substrate principles
  (htmx + server-side rendering? a Rust-based UI framework?)? For v1,
  React is pragmatic; revisit if it proves friction.
- **Artifact authentication**: each artifact call goes through the
  member's auth session. Need to confirm IronClaw's tool-call surface
  threads the auth context correctly so artifacts can enforce member
  scope at the data layer.
- **Mobile vs desktop**: iCal feed handles calendar on mobile cleanly.
  But the Foundation timeline + chat surface need to work well on
  phones. IronClaw's existing mobile UX is the starting point;
  artifacts inherit that.
- **Versioning + receipt citation**: when a member signs a document via
  `SignaturePanel` v1.2, the receipt records the artifact version.
  When v1.3 launches, old signings remain attributable to v1.2.
  Need to design the citation mechanism.

## Status

Vocabulary starting set chosen by Ken (chat + SharedCalendar +
FoundationTimeline) reflects the actual Foundation needs at pilot
start. Implementation tasks captured. Vocabulary growth pattern
established (demand-driven, member usage signals curation). The
hybrid model (curated + generative extension) is the architectural
commitment that makes this scale without either pre-building
everything or generating everything from scratch.
