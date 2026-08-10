# Channel boundary — receipt vs event string

**Status:** decided 2026-08-09 · revised same day after three producers were wired
**Decides:** which channel carries structured payload
**Type:** Tier 2 elaboration. Records a decision and the evidence for it. The
classification table at the end is derived — regenerate with `tools/kind_catalog.py`
rather than editing it.

## The decision

The substrate has **two** channels on the chain and both are legitimate:

- **`AuditAction::SystemEvent { event }`** — a colon-delimited string. Internal
  operational telemetry. Cheap, high-volume, human-greppable, read by officers.
- **`AuditEntry.receipt`** — a typed `Receipt` with `claim_metadata` and
  `extensions`. Structured claims that must survive a restart, leave the machine,
  or be independently verified.

The boundary is: **if state must be reconstituted after a crash, or verified by
someone who does not have this process's memory, it goes on the receipt channel.
Everything else is telemetry and belongs in the event string.**

This was previously undeclared, which is the whole problem. Producers chose the
string channel by default because it is easier; consumers that need structure read
the receipt channel because that is where structure lives. Nothing was wrong on
either side, and the join was never made.

## Why not one channel

Collapsing to receipts would put a typed, signed object behind 285,000 heartbeat
and cycle entries for no gain — those are read by grep and by officer sweeps, never
reconstituted. Collapsing to strings would mean serialising structured state into
an unvalidated string format, which the corpus is already drifting toward:
`regent:precedent:cited | tool=browser_use context=… granted_request=…` is a
pipe-delimited record pretending to be a log line. Left alone that becomes a wire
format nobody specified.

## The evidence, which decided this rather than preference

Measured 2026-08-08/09 against the live chain (285,071 entries):

**The string channel cannot carry reconstitution state.** The capability grant
event is emitted 94 times as the literal string `delegation:granted:regent` — no
grant id, no scope, no expiry, no grantor. `system:keychain:accessed`, 90 times,
carries no key id and no role. The data is not truncated or encoded; it was never
put there.

**So `recovery.rs` is reading the correct channel.** An earlier draft of this
decision proposed teaching recovery to parse event strings. That was wrong, and the
measurement above is what corrected it: there is nothing in those strings to parse.
Recovery reads `entry.receipt_extensions` for seventeen `zp.*` keys; zero of
285,071 entries carry a receipt at all, so the fault is entirely on the producing
side.

**And the producers already hold the data.** At the Regent startup delegation site
(`crates/zp-server/src/regent.rs`), a full `CapabilityGrant` — id, grantor, grantee,
capability, expiry — is constructed and bound to `_grant`, the underscore
discarding it. The adjacent comment reads *"Emit delegation receipt on the chain."*
The entry is built with `receipt: None`. Every field recovery needs exists in scope
at the moment of emission and is dropped.

## Four kinds of mismatch, not two

The original draft named two: consumer-without-producer (always a defect) and
producer-without-consumer (usually fine on a chain). Wiring three producers
surfaced two more, and they need different responses.

**1. Consumer with no producer.** An alarm that cannot fire. `zp.policy.version`
is read by `reconstitute`, which raises `PolicyDowngradeDetected` on it; nothing
writes it, so that alarm has never been able to sound. Fix: wire a producer, or
record it as reserved.

**2. Producer with no consumer.** Fine on the chain — an audit trail is
deliberately write-mostly, and the reader may be a future auditor. In *code* it
is dead weight: `AuditStore::live_entry_count` was correct, documented, and had
zero callers while the caller next to it used the wrong sibling.

**3. Producer with no data.** New. `reconstitute` reads
`zp.memory.source_agent`; `zp-memory`'s promotion path emits the receipt and has
no such field — the nearest thing is `source_observation_id`, an observation
rather than an agent. This is not a missing producer and not a missing wire; the
value does not exist at the point of emission. Fix: change the data model, or
delete the read. **Do not invent a plausible value** — that converts a visible
gap into an invisible wrong answer.

**4. Agreed key, disagreed vocabulary.** New, and the most dangerous of the four
because both ends look wired. `reconstitute` matches the *value* of
`zp.certificate.role` against `"operator"` / `"agent"`; `zp_keys::KeyRole`
derives `Serialize` with no `rename_all` and emits `"Operator"` / `"Agent"`.
Writing the serialised enum would have produced a valid receipt that the
consumer reads, matches nothing on, and discards without error. Fix: value
vocabularies get constants too, and producers map their enums explicitly through
an exhaustive `match` rather than serialising.

## Consequences

**Recovery is not redesigned.** It is correct and currently starved. It now warns
when it replays entries and finds no extensions on any of them, rather than
reporting `success: true` over an empty read (`RecoveryEngine::finish`).

**A small number of producers must attach receipts.** Not "many emit sites" — only
those whose state must survive a restart. On current evidence that is: capability
grants and revocations, key certificates and rotations, tool invocation/completion
pairs, and observations. Everything else stays on the string channel unchanged.

**Tests may not supply what production does not produce.** The recovery tests pass
today because their fixtures construct the extensions map directly
(`make_entry("1", Some(json!({"zp.capability.grant_id": …})))`). They validate the
parser against a shape no emitter emits. The missing test category is
**round-trip**: run the real producer, read it back through the real consumer,
assert the state arrives. Every existing test in that file is the middle third with
both ends stubbed.

**Receipt types that carry no reconstitution duty are telemetry.** Several of the
40 declared types describe operational events (`port_allocated`, `port_released`,
`pricing_refresh_claim`). Under this boundary they are candidates for the string
channel, and their declarations should be classified as reserved or retired rather
than left looking built.

## Classification rule

Every declared receipt type carries one of:

- **live** — has a producer, appears on the chain. Falsifiable: a claim of `live`
  with zero chain instances fails.
- **wired** — has a producer that has never fired. An unexercised path, not
  unbuilt work. Needs a round-trip test, not a registry entry.
- **reserved** — deliberately declared, no producer yet. Requires `because` and
  `review_after`. Without an expiry, reserved becomes a graveyard.
- **telemetry** — belongs on the string channel; the type declaration is retired.

**Unclassified is the defect**, not any particular status. This is
`zero unclassified, not zero defects` (QUESTION-002) applied to declared surfaces.

## Corrections to this document

Recorded rather than edited away, because each was a confident claim from an
instrument nobody had checked — the failure this ADR exists to prevent.

- **"The string channel cannot carry reconstitution state" — stands.** Verified:
  `delegation:granted:regent` is 94 identical strings with no fields.
- **"Recovery reads the wrong channel" — withdrawn.** Recovery reads the correct
  channel and was starved. An earlier draft proposed teaching it to parse event
  strings; there is nothing in those strings to parse.
- **"Of six memory keys, exactly one has a writer" — false.** Three are written.
  The survey grepped `.extension("key"` on one line; `zp-memory` puts the key on
  its own line, so every multi-line call was invisible.
- **"`zp.quarantine.memory_id` / `_ids` is a singular-plural typo" — false.**
  Two deliberate keys: one memory, one bulk set. The narrative was built on the
  same broken grep.
- **`KNOWN_ORPHAN_READS` rotted within an hour of being written** — three keys
  were wired the same afternoon and left listed as unwired. It is now
  cross-checked by `tools/false_assurance.py`, which fails on disagreement.
- **That cross-check's first verdict was also wrong.** Centralising the keys made
  the literal-matching survey blind, so it measured zero orphans and declared all
  six declared ones stale. Acting on it would have deleted the record of six live
  defects. Three consecutive diagnoses were wrong before printing the actual
  classified sites gave the answer.

The operating rule that came out of it: **print the sites, not the summary** —
including summaries this document contains.

## Current state, measured

Regenerate before quoting. Receipt-surface figures from `tools/kind_catalog.py`,
pairing figures from `tools/false_assurance.py`.

| | count |
|---|---|
| receipt types declared | 40 |
| live (emitted) | 3 |
| wired (producer exists, never fired) | 11 |
| inert (no producer) | 26 |
| `claim_metadata` variants never constructed, but validated | 18 |
| event kinds on the chain | 298 |
| …matching any declared receipt type | 0 |
| families declared in governed prose | 674 |
| …also emitted | 23 |
| extension keys: paired | 11 |
| extension keys: read, never written | 11 |
| extension keys: written, never read | 40 |
| extension keys: unclassified by the survey | 30 |

**Producers wired under this decision:** capability grants
(`zp_core::capability_grant_receipt`, called from the Regent startup
delegation), key rotation and revocation
(`zp_core::certificate_rotation_receipts`, called from `zp-keys`), and memory
promotion stage. Each has a round-trip test that runs the real producer through
`ReconstitutionEntry::from_audit_entry` into the real consumer — no fixture in
the path.

Regenerate with `python3 tools/kind_catalog.py`. Consumer-side gaps —
read-but-never-written extension keys, unreachable validation branches — come from
`python3 tools/false_assurance.py`.

## Open

1. **Eight orphan reads remain**, in coherent clusters: tool lifecycle
   (`zp.tool.name`, `zp.tool.conversation_id`,
   `zp.tool.completed_invocation_id`), conversation (`zp.conversation.id`,
   `.ended`), observation/reflection (`zp.observation.id`,
   `zp.reflection.consumed_ids`), and capability revocation
   (`zp.capability.revoked_grant_id`). Tool lifecycle is the best next tranche —
   `tool_chain.rs` already emits lifecycle receipts, so it is a wiring job rather
   than a new subsystem.
2. **`zp.memory.source_agent` needs a decision, not a wire** — category 3 above.
   Either `MemoryEntry` gains the field or `reconstitute` stops reading it.
3. **`zp.policy.version` has no producer and gates a real alarm.** The
   `DowngradeGuard` exists in process memory only and never reaches the chain.
4. Classify the 11 wired and 26 inert receipt types against the rule above.
5. Decide whether the pipe-delimited tail on `regent:precedent:cited` and similar
   is a deliberate mini-format or drift toward one. If deliberate, it needs a
   grammar; `zp-memory` writing `zp.merge.*` and `zp.quarantine.count` that
   nothing reads suggests the same question applies to extensions.
6. **30 keys are unclassified by the survey** — its ±2-line window cannot tell a
   read from a write. Unknown risk, not zero risk.
7. **The CLI is a 46-verb operator surface with three attributable verbs.**
   `AuditAction` declares 12 variants; two have ever been written. Ten have
   consumers — `narration.rs` dispatches on all 12 — and eight have no
   producer outside tests. This is the same consumer-without-producer
   disjunction one layer above extension keys, and it is why the tool-lifecycle
   orphan reads in item 1 have no producer: the *action* has none either.
   Measured by `tools/cli_surface.py`; recorded as SEAM-007.
