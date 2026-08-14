# Deliberation log — 2026-08

**Document type:** working log, not canonical. Nothing here is a Layer A or Layer B
claim. Entries are dated observations and open questions; when one resolves into a
canonical statement it moves to a governed document and the entry records where.

**Participants and what each can actually reach.** The asymmetry matters more than
the roles.

| | Ken | Claude | Maria |
|---|---|---|---|
| repository | full, local | read via device bridge | `corpus_search` (line hits in `docs/` and `crates/`) |
| chain | full, `zp` verbs | read `audit.db` directly | `chain_tail` (newest 100, read-only) |
| envelope | grants and revokes | read | `precedent_list` |
| writes anything | yes | proposes edits | no |

Maria cannot read a file end to end. `corpus_search` returns matching *lines*.
This file is therefore written to be grepped, not read: every line of an entry
repeats its ID so that a search for `SEAM-004` returns the whole entry rather than
one orphaned sentence. Keep that discipline when adding entries or she will see
fragments and reason from them.

**Grep keys:** `SEAM-` open seams · `DECIDED-` settled questions · `QUESTION-`
open questions with no owner · `PIN-` things asserted that must stay true.

---

## What we are doing

Building ZeroPoint out solid. Concretely, in priority order:

1. **Find the seams.** A seam is a place where two components each assume the other
   handles something. That gap is where this system's real defects live — not in
   wrong code, which is comparatively easy, but in correct code either side of an
   unowned boundary.
2. **Iron them out or design them out.** Ironing out is fixing the gap. Designing
   out is changing the shape so the gap cannot exist. The second is better and
   usually costs more; say which one you are proposing.
3. **Shape the heuristics.** The substrate makes judgement calls — what counts as a
   finding, when to escalate, what narrows an envelope. Those heuristics are
   currently mostly implicit. Making one explicit is real work.
4. **Harden.** Turn a discovered defect into a pin that prevents its whole class.

**A seam is not a bug list item.** "This function panics on a multibyte boundary"
is a bug. "Eleven call sites slice strings by byte and none of them owns the
question of what a boundary is" is a seam. Prefer the second framing; it is the one
that produces a design change rather than a patch.

---

## Standing rules for entries

- **Name the layer you looked at.** Reasoning from architecture and reasoning from
  observed behaviour are different claims. Say which you did.
- **Evidence or it is a hypothesis.** A file and line, a chain event, a command and
  its output. "This feels risky" is a prompt for investigation, not an entry.
- **A document is not the substrate.** Where a governed document and the running
  system disagree, record both and say which you checked. The document may be the
  thing that is wrong — see SEAM-002.
- **Carried-forward claims are marked.** An entry sourced from an earlier session's
  notes rather than from a check performed now says so and stays unverified until
  someone checks it.

---

## Open seams

### SEAM-001 — three dead databases named `audit.db` sit where a tool would look · RESOLVED

SEAM-001 STATUS: resolved 2026-08-12 · found 2026-08-07 · verified by direct read
SEAM-001 EVIDENCE: `audit.db` at repo root holds 28 rows dated 18–19 February, all `model_call_failed` for a missing OpenAI key. `zeropoint-server/audit.db` holds zero rows.
SEAM-001 EVIDENCE: `data/zeropoint/audit.db` has no `audit_log` table at all. The live chain is `~/ZeroPoint/data/audit.db`, 226 MB, table `audit_entries`.
SEAM-001 CLAIM: nothing owns the question of what a file named `audit.db` is. Any reader that finds one and trusts it gets a confident answer from a dead instrument.
SEAM-001 COST: already paid once. A tool built this session picked the 28-row February copy and would have reported on it as though it were the chain.
SEAM-001 DESIGN-OUT: a chain file could carry a marker identifying it as live, or dead copies could be named so they cannot be mistaken.
SEAM-001 DESIGN-OUT: Ironing out means every reader replicating `zp_core::paths::home()`, which is the second mechanism that P8 warns about.
SEAM-001 CORRECTION: 2026-08-12. "`data/zeropoint/audit.db` has no `audit_log` table at all" is true and reads as reassuring, which it should not. It has **`audit_entries`** — the *current* schema — with zero rows. That makes it the most dangerous of the three, not the most inert: code written today opens it, finds exactly the table it expects, and receives a well-formed answer that the chain is empty. The other two carry the pre-migration `audit_log` and fail loudly against current readers, which is plausibly why the February copy was caught on 08-07 and this one was not. The original entry classified by what was *missing* rather than by what a current reader would *find*.
SEAM-001 EVIDENCE: 2026-08-12 re-read. repo-root `audit_log` 28 rows, 2026-02-18T19:10 → 02-19T16:01. `data/zeropoint` `audit_entries` 0 rows. `zeropoint-server` `audit_log` 0 rows. Live chain `~/ZeroPoint/data/audit.db` 285,835,264 bytes with a 38 MB `-wal` and an active `-shm`, mtime same day — the substrate was writing to it throughout.
SEAM-001 EVIDENCE: each dead copy's `-shm` sidecar carried an August mtime. Something opened all three months after their last write. Which reader, and whether it acted on what it found, is not established.
SEAM-001 RESOLUTION: all nine files — three `audit.db` plus each one's `-shm` and `-wal` — moved to `_to_delete/dead-audit-db/`, grouped by origin, with a README recording schema and row counts. All were untracked and matched `.gitignore`'s `*.db`; nothing outside this log referenced them. Staged rather than destroyed only because the remote tooling cannot delete.
SEAM-001 DESIGN-OUT-TAKEN: neither of the two proposed above. Both put the check on the reader at the moment they are least able to perform it — they are looking for the chain, they have found something called the chain, and the marker is one more thing to remember. **Absence needs no checking.** `zp_core::paths::audit_db_path()` resolves to `$ZP_HOME/data/audit.db`, outside the source tree, so any `audit.db` under the workspace is a stray by construction. `crates/zp-discipline/tests/no_audit_db_in_workspace.rs` asserts none exists. This also avoids the P8 duplication the second design-out named, since no reader learns a path.
SEAM-001 PIN-002: an absence assertion looks identical whether it is clean or blind, so the pin carries two positive controls — the matcher must find a planted `audit.db` in a synthetic tree (and must *not* find the decoy inside a skipped `target/`), and the real walk must visit more than fifty directories. Without those, a broken skip list or a mis-resolved root passes forever.
SEAM-001 LESSON: **classify a dead instrument by what a current reader would find in it, not by what it is missing.** The copy that is obviously broken is the safe one.
SEAM-001 UNBLOCKS: DECIDED-003's falsify-first now has an addressable chain — `~/ZeroPoint/data/audit.db`. It was never missing, only unlocated, and the search kept landing on the dead copies.

### SEAM-002 — the corpus says the chain is unsigned; it is signed

SEAM-002 STATUS: open · found 2026-08-07 · verified by direct read
SEAM-002 EVIDENCE: every row sampled in `audit_entries` carries a populated `signatures` column with an ed25519 `key_id` and signature.
SEAM-002 EVIDENCE: The signer is derived at pipeline construction via `derive_audit_signer_seed(&genesis_secret)` → `AuditSigner::from_seed`.
SEAM-002 CLAIM: governed documents state that zero of roughly ten thousand entries carry a signature. That was true once and is now false. The count is also wrong: 20,000-plus live entries and 251,000-plus archived.
SEAM-002 NUANCE: a software key derived from the Genesis secret is not a hardware operator signature per entry. "Operator-attributed rather than operator-signed" may still be the honest framing. "Unsigned" is not.
SEAM-002 COST: this is the substrate's most load-bearing property, and the stale claim is in the documents an outside reader would trust first.
SEAM-002 OPEN: which documents carry the stale claim, and does the corpus have a mechanism for a Tier 3 frozen document whose factual premise has since changed.
SEAM-002 UPDATE 2026-08-09: ground truth re-measured — **0 unsigned of 294,915 entries, 100% signed across live and archive**. The stale claim is not in the repository: four search patterns over every markdown file return nothing. It is most likely in Maria's Tavus Knowledge Base, which is uploaded separately and is not under version control.
SEAM-002 RECLASSIFIED: per the operator, 2026-08-09 — whatever Maria is hooked into is **scaffolding, like Claude, not part of ZeroPoint**. A stale claim living only in scaffolding is not a substrate seam. The substrate half of this seam (governed documents in `docs/`) is clean.
SEAM-002 RESIDUAL: the underlying question survives the reclassification and is not scaffolding-specific — a Tier 3 frozen document whose factual premise has since changed still has no mechanism. See also SEAM-005, where five governed documents cited a pin that exists in no Rust file.

### SEAM-003 — chain narration cannot be read without a hardware ceremony

SEAM-003 STATUS: open · found 2026-08-07 · verified by reading the dispatch
SEAM-003 EVIDENCE: `is_session_token_only` at `crates/zp-cli/src/main.rs:7897` lists Precedent, Approval, Correction, Substrate::Validate, Officer::Sweep and the Vault verbs.
SEAM-003 EVIDENCE: Chain and Audit are absent, so `zp chain story` and `zp audit log` fall through to `load_genesis_secret_composed()`.
SEAM-003 CLAIM: reading the chain's narration costs a Trezor touch, while reading the autonomous envelope does not. Nothing states the principle that separates them.
SEAM-003 COST: casual chain reads are expensive enough that tools route around them — this session's `chain_tail` reads `audit.db` directly rather than shell out, which creates a second path to chain data and a P8 problem.
SEAM-003 QUESTION: is the ceremony there because reads are privileged, or because narration shares a construction path with things that are? If the second, this is incidental rather than designed.

### SEAM-004 — two chain schemas share one filename with no discriminator

SEAM-004 STATUS: open · found 2026-08-07 · verified by direct read
SEAM-004 EVIDENCE: legacy files carry `audit_log` (`seq`, `event_type`, `details`). The live chain carries `audit_entries` (`actor`, `action`, `policy_decision`, `signatures`, append-only triggers, no `seq`).
SEAM-004 CLAIM: a reader written against either schema silently rejects the other. Nothing declares which is current or that a migration occurred.
SEAM-004 RELATED: compounds SEAM-001. The wrong-file problem and the wrong-schema problem hid each other.

### SEAM-005 — the tool surface has three declarations · RESOLVED

SEAM-005 STATUS: **resolved 2026-08-09 by design-out** · was open, carried forward unverified from a prior session
SEAM-005 EVIDENCE: all three sites confirmed live before the fix — `REGENT_TOOLS` in `zp-server/src/regent.rs:51` (the copy conferring capability), plus two `const TOOLS: &[&str]` in `zp-regent/src/regent.rs`, inside `recover_execute_intent` and `sanitize_tool_name`.
SEAM-005 EVIDENCE: the three sets were equal (14 tools) at the time of the fix, so no live discrepancy — but they had already diverged twice, and the second time bit: `report_assemble` was granted 2026-08-02, missing from both `zp-regent` copies, and dispatched as "unknown tool" while the tool existed and was reachable. Two days between the grant and the drift biting.
SEAM-005 CORRECTION: the claim that `granted_tools_must_be_reachable.rs` pinned one of them was **false**. That name appears in five governed documents and in `tools/connection-map/connections.json`, and in no Rust file anywhere. The safeguard on capability grants was a citation.
SEAM-005 CORRECTION: the in-code premise was also false. `sanitize_tool_name`'s docstring read "neither crate depends on the other in the direction that would let them share a const, so the duplication is structural". `zp-server` depends on `zp-regent` (`Cargo.toml:43`); the dependency always ran the direction needed. Checking it took one grep, and the unchecked claim is what kept the seam alive across two drift incidents — it converted a fixable problem into an accepted cost.
SEAM-005 DESIGN-OUT: one declaration in `crates/zp-regent/src/tools.rs` as `RegentTool { name, scope }`; `zp-regent` iterates `tools::tool_names()` at both sites, `zp-server` imports `zp_regent::tools::REGENT_TOOLS`. Three copies to one; net −85/+46 lines.
SEAM-005 PIN: `tool_names_are_prefix_free` replaces the pin that never existed. `sanitize_tool_name` matches with `starts_with`, so a name becoming a prefix of another would let the shorter shadow the longer by iteration order — and the misdispatch would read as a model formatting error, not a list problem. No collisions today; the test means there never silently will be. Plus `tool_names_are_unique` (names and non-empty scopes).
SEAM-005 CARRIED: `browser_use` advertises scope `web:allowed_domains`, which nothing reads — `ALLOWED_DOMAINS` is hardcoded in the dispatch arm. The grant is narrower than the delegation claims. Documented on the struct where an editor will see it; not fixed.
SEAM-005 CORRECTION-TO-THE-CORRECTION: 2026-08-09. The line above reading *"the claim that `granted_tools_must_be_reachable.rs` pinned one of them was **false** … it appears in no Rust file anywhere"* is itself false. The file exists at `crates/zp-discipline/tests/granted_tools_must_be_reachable.rs`, tracked, committed `ff332f7` on 2026-07-25 in *"regent: single-source granted tools; surface them in both prompts"* — two weeks before the survey that declared it absent. The survey searched `crates/*/src/`; discipline pins live in `crates/*/tests/`. Same class of miss as the `--include=*.rs` scope that hid the pidfile writer and the single-line `.extension("key"` grep that produced the false memory-key narrative: a correct search over the wrong set, reported as an absence.
SEAM-005 CORRECTION-TO-THE-CORRECTION: the lesson recorded below — *"an unverified claim about why a seam cannot be fixed is more durable than the seam"* — was then demonstrated by the correction that recorded it. Both stand. The safeguard was real, and the claim that it was a citation was the unverified assertion.
SEAM-005 CONSEQUENCE: the design-out **broke the pin it did not know existed.** Collapsing the three lists moved `REGENT_TOOLS` from `zp-server/src/regent.rs` to `zp-regent/src/tools.rs` and changed its shape from `("name", "scope")` tuples to `RegentTool { name, scope }` structs. The pin parses that declaration, so from the moment of the fix it panicked: *"`const REGENT_TOOLS` not found … if it was renamed or moved, update this parser — do not delete the pin."*
SEAM-005 CONSEQUENCE: it failed that way for roughly two days and nobody read it, because `cargo test -p zp-discipline` was not run after the change. It surfaced only when the operator ran the suite for an unrelated reason. **A pin that fails into an unread log is not materially better than the pin that never existed** — which is what SEAM-005 was originally about. The gap was never the safeguard; it was that nothing forced anyone to look at it.
SEAM-005 REPAIRED: 2026-08-09. The pin now reads two files — `TOOLS_SOURCE` (`zp-regent/src/tools.rs`) for the declaration, `DISPATCH_SOURCE` (`zp-server/src/regent.rs`) for dispatch arms, the grant, and the delegation projection — and parses `name:` by key rather than by position, so reordering the struct fields cannot silently change what it sees. The grant/delegation windows now look backwards as well as forwards: the projection binds to a local several lines *above* `GrantedCapability::ToolCall`, and a forward-only window reported a correctly-projected grant as a literal list.
SEAM-005 REPAIRED: a second test, `every_tool_declares_a_scope`, asserts no entry arrives with an empty scope — a capability with no scope reads as governed and is not. It does not assert the scope is *honoured*; `browser_use` still advertises `web:allowed_domains` against a hardcoded `ALLOWED_DOMAINS`, which remains CARRIED above.
SEAM-005 VERIFIED: compiled and run against the real sources, with four negative controls — a granted tool with no dispatch arm, an empty scope, the grant restated as a literal list, and the declaration renamed again. Each fails the intended assertion and no other. A green pin nobody has watched fail is a pin of unknown polarity.
SEAM-005 OPEN: nothing runs `cargo test -p zp-discipline` automatically. Every discipline pin in the crate shares this failure mode, and this is the second time in the sequence that the instrument, not the defect, was the thing that had gone quiet. That is the actual finding here, and it is not fixed.
SEAM-005 CORRECTION-3: 2026-08-09. The line above reading *"nothing runs `cargo test -p zp-discipline` automatically"* is **false**, and was written within the hour, unverified, immediately after a correction about writing unverified claims. `.github/workflows/ci.yml:51` runs `cargo test --workspace --no-fail-fast` on push and pull_request to `main`, twice — once minimal-kernel, once full-features — plus `clippy -D warnings` and `fmt --check`. Every discipline pin is inside `--workspace`. The safety net exists and is correctly configured. See SEAM-010 for why it has not fired.
SEAM-005 LESSON: an unverified claim about *why* a seam cannot be fixed is more durable than the seam. Both blockers here were assertions nobody had tested.

---

### SEAM-006 — the Regent's wake gate is an economy measure that became a policy

SEAM-006 STATUS: open · found 2026-08-09 · verified by chain measurement after a rebuild
SEAM-006 EVIDENCE: `reason()` (`crates/zp-regent/src/regent.rs:865`) returns `Intent::Observe` before any inference when four conditions hold: no `pending_input`, no `has_urgent`, empty `tool_results`, no `work_arc`.
SEAM-006 EVIDENCE: `has_urgent` requires a finding of severity `Error` or `Critical` (`regent.rs:851`). Officers can emit both (`steward.rs`, `aegis.rs`), so the path is reachable; it has not been reached.
SEAM-006 EVIDENCE: historical chain — 25,335 `regent:intent:observe` against 76 `execute`, 88 `respond`, 20 `request_approval`, 1 `remember`. 0.3% action rate.
SEAM-006 EVIDENCE: post-rebuild measurement, 44 consecutive cycles, cycles 1..44 contiguous: **44 of 44 short-circuit, zero inference**. Seven officer findings present in context on every one.
SEAM-006 CLAIM: the guard exists to avoid spending inference on empty cycles — a reasonable optimisation. Nobody decided "the Regent acts only on Error/Critical findings or direct address". That is now the system's entire autonomous behaviour, and it arrived as a side effect of a cost guard rather than as a declared policy.
SEAM-006 CLAIM: the seven findings recur every cycle, so they are standing conditions rather than events. Lowering the threshold would fire continuously on the same seven; the missing predicate is closer to novelty than to severity.
SEAM-006 COST: every provenance mechanism downstream — typed intent receipts, Cartographer `Decision` materialisation, `AuthorizedBy` edges — is machinery for tracing reasoning that does not occur. A decision log with no decisions in it.
SEAM-006 COST: the substrate spends 98.6% of chain volume on self-observation (289,654 of 293,911 entries; actor `Operator` appears 25 times).
SEAM-006 DESIGN-OUT: make the wake condition a declared policy with its own record, not a conjunction of four early-return guards. Whatever it becomes, it should be as legible as the threshold now is.
SEAM-006 RELATED: measurable only since 2026-08-09. `begin_cycle()` gave cycles real numbers (they were all `cycle 0`, because `loop_runner::run_cycle` calls `reason()` directly and never went through `Regent::cycle()`), and `gate=short_circuit reason_ms=0 urgent_threshold=Error|Critical` distinguishes a cycle that never thought from one that thought and stood down. Both emitted the same event before.
SEAM-006 REFINED: 2026-08-09 — see SEAM-009. "The path is reachable; it has not been reached" was right about `has_urgent` and wrong about why. The findings carrying Error severity are emitted in `spawn_sensor_forge_task`, which has no `send_findings` call, so they never enter `context.officer_findings`. Not a threshold that never trips — a channel that was never wired.
SEAM-006 SUPERSEDED-IN-PART: the "44 of 44 short-circuit, zero inference" figure is not wrong but is not what it appeared to be. It counts `regent:intent:observe` entries, and a cycle that deliberates does not emit one — see PIN-007. The correct post-fix figure is 76 short-circuits and 9 deliberations across cycles 4–86.

---

### SEAM-007 — the operator surface leaves no trace

SEAM-007 STATUS: open · found 2026-08-09 · measured by `tools/cli_surface.py`
SEAM-007 PROVENANCE: opened as "the CLI commands seem adrift" after `zp restart --all` appeared to do nothing. The investigation found the CLI is not adrift from its own declarations. It is adrift from the chain.
SEAM-007 EVIDENCE: the clap surface is internally consistent and compiler-enforced. 46 top-level verbs, 120 including subcommands, 232 flags. Verbs declared with no pattern site: **0**. Flags declared and never destructured: **0**. The trailing match in `main()` has no catch-all `_ =>`, so a verb without an arm is a compile error rather than a silent gap. Every measure that would show declaration drift comes back clean.
SEAM-007 EVIDENCE: `AuditAction` declares 12 variants (`crates/zp-core/src/audit.rs:74`). Two have ever been written: `SystemEvent` (295,481) and `PolicyInteraction` (79). The other ten are zero across 295,560 entries.
SEAM-007 EVIDENCE: of those ten, eight have **no construction site outside tests** — `MessageReceived`, `ToolInvoked`, `ToolCompleted`, `CredentialInjected`, `OutputSanitized`, `SkillActivated`, `SkillProposed`, `SkillApproved`. The only `ToolInvoked` constructions in the tree are two test fixtures (`collective_audit.rs:337`, `narration.rs:769`). Two do have production producers that have never fired: `ResponseGenerated` (`zp-pipeline/src/pipeline.rs:671`) and `ApiCallProxied` (`zp-server/src/proxy.rs:820`).
SEAM-007 EVIDENCE: all ten have consumers. `zp-officers/src/narration.rs` — the engine behind `zp chain story` — dispatches on all 12 variants; ten of its arms cannot fire. `zp-server/src/lib.rs:3187` categorises five variants, all dead. `zp-audit/src/scrub.rs` redacts variants that are never written. This is `false_assurance.py`'s consumer-with-no-producer, one layer above receipt extensions, and it explains the orphan reads already recorded there: `zp.tool.name`, `zp.tool.conversation_id`, `zp.tool.completed_invocation_id` have no producer because the *action* has no producer.
SEAM-007 EVIDENCE: `crates/zp-regent/src/context.rs:1651–1657` — the Regent's own context builder — matches `ToolInvoked`, `ToolCompleted`, `PolicyInteraction`. Two of the three have never appeared on the chain. The Regent reads for a tool history that was never written.
SEAM-007 EVIDENCE: 16 distinct actors on the chain, 15 of them `System`. Actor `Operator` appears **25 times in 295,560 entries (0.0085%)**, and every one is one of three verbs: `zp correction issue` (9), `zp approval grant|deny` (15), `zp precedent revoke` (1). Of 46 top-level verbs, **three** have ever produced an operator-attributed entry — exactly the three routed through `is_session_token_only`.
SEAM-007 CLAIM: this is P9 inverted. "The system acts, the operator signs" is implemented as the system writing 295,481 self-observations while the operator's acts go unrecorded. `zp restart --self` kills the substrate's process by PID and spawns a replacement, and writes nothing anywhere. `zp keys`, `zp gate`, `zp secure`, `zp configure`, `zp operator`, `zp delegate`, `zp revoke` are all in the same position.
SEAM-007 SYMPTOM: the reported one. `zp restart --all` and `zp port list` read `{data_dir}/tool-ports.json`; that file does not exist, no `port:` event has ever been written, and no `port_registry` actor appears on the chain. The registry has never held a binding. Both verbs are correct code over data that was never produced — so `--all` prints "No tools registered in port registry." and exits 0, which is indistinguishable from a broken flag. PIN-002.
SEAM-007 NOT-A-DEFECT: `zp restart --self` is reachable and works; `--name` and `--all` are compiled in (both `default` and `full` carry `embedded-server`, and the binary carries the feature-on strings). The flag parsing is fine. Nothing is missing from clap.
SEAM-007 ADJACENT: `main()` dispatches 35 verbs in early `if let Some(Commands::X ..) { .. exit() }` blocks and then claims `unreachable!()` for 41. `unreachable!()` is a load-bearing assertion, not an error path: it is true only while every path through the early block exits, and nothing checks the pairing. Six of the 41 have no early block at all and are covered by a third dispatcher, the hand-maintained `is_session_token_only` / `run_session_token_command` pair. That pair matches `Substrate`/`Officer`/`Vault` per-subcommand while the trailing match claims them whole-group — safe only because those enums have one variant each today. Its own doc comment already names siblings (`vault revoke`, `officer list`) that do not exist.
SEAM-007 DESIGN-OUT: not "log every verb". The prior decision applies unchanged — CHANNEL-BOUNDARY-2026-08: if state must survive a restart or be verified by someone without this process's memory, it goes on the receipt channel. An operator restarting the substrate, rotating a key, granting a delegation, or configuring a tool is exactly that. The narrower first tranche is the verbs that change authority or process state: `restart`, `keys`, `delegate`, `revoke`, `gate`, `operator`, `configure`.
SEAM-007 DESIGN-OUT: the third dispatcher wants collapsing into one. `is_session_token_only` was derived by scanning callers of `read_zp_session_token()` rather than by exhaustiveness — the same shape as SEAM-005's three tool lists, and it will drift the same way. One `match` returning a per-verb requirement, checked exhaustively, is the destination its own doc comment already names.
SEAM-007 MEASURE: `python3 tools/cli_surface.py`. Regenerate before quoting any number above.
SEAM-007 LESSON: every declaration-side measure was clean, and that is why this was invisible. The CLI is consistent with itself; it is the join to the chain that was never made. Same disjunction as the receipt channels, one layer up, found only by asking the chain what the CLI had actually done rather than asking the code what it could do.

---

### SEAM-008 — a string compare decides between "known" and "unauthorized"

SEAM-008 STATUS: open · found 2026-08-09 · measured against the live chain
SEAM-008 EVIDENCE: `known_system_category` (`crates/zp-server/src/tool_ports.rs:1773`) matches process names against an exact-name table of ~30 entries before falling back to prefix rules.
SEAM-008 EVIDENCE: the table contains `("python3", "developer runtime")`. The binary on this machine is `/Users/kenrom/anaconda3/bin/python3.13`. The exact match misses.
SEAM-008 EVIDENCE: the miss does not degrade the process to unclassified. It escalates it. A hit yields Sentinel's `unregistered_known_app` (recognised, unvouched); a miss yields `unauthorized_listener` — a *security* finding. Anaconda python has produced 13 of them in the last 20,000 entries.
SEAM-008 EVIDENCE: this has bitten before. `e8bdefe 2026-06-11 "feat: extend known_system_category for lsof-truncated process names"` is the same defect from the other direction — the OS truncating a name rather than the vendor suffixing one.
SEAM-008 CLAIM: the table is not wrong and the classifier is not leaking. `known_system_category` *classifies* rather than suppresses, which is why "known app" and "unauthorized" are distinct finding types — the design is intact. What is wrong is that a version suffix carries the weight of a security escalation.
SEAM-008 CLAIM: the general form is that identity is being asserted by process name, which is neither stable nor unforgeable. `python3.13` is the benign version; the malign version is a process that names itself `ollama`.
SEAM-008 RELATED: under the attestation decision (`RESTART-REDUX-2026-08.md`, second decision) the attestation carries a binary hash. That is the same problem solved properly for the vouched set, and it makes the allowlist's job smaller rather than more accurate — the allowlist stops being the last word for anything an operator has actually looked at.
SEAM-008 DESIGN-OUT: not "add `python3.13` to the table". That fixes one machine until the next minor release. Either match on a normalised stem, or — better — let the allowlist state a confidence and let anything unvouched-and-unrecognised sit in one bucket rather than being sorted into a security finding by a failed string compare.
SEAM-008 CAUTION: whatever replaces it must not silently widen. A stem match on `python` also matches a binary an attacker named `python-helper`, which is precisely the case `unauthorized_listener` exists to catch.

---

### SEAM-009 — the findings that carry Error severity have no channel to the Regent

SEAM-009 STATUS: open · found 2026-08-09 · verified by call-site enumeration and chain measurement
SEAM-009 EVIDENCE: `has_urgent` (`zp-regent/src/regent.rs:976`) reads `context.officer_findings` for `severity == "Error" || "Critical"`. That field is populated only from `latest_findings` (`loop_runner.rs:249, 296`), which is set only by `RegentMessage::OfficerFindings`, which is sent only by `RegentHandle::send_findings`.
SEAM-009 EVIDENCE: `send_findings` has **exactly one call site in the tree** — `zp-server/src/officers.rs:809`, inside `spawn_sweep_task` (the 300s periodic sweep), as its "Step 7: forward findings to the Regent cognitive loop".
SEAM-009 EVIDENCE: every listener assessment lives in the *other* task. `sentinel.assess_unauthorized_listener` (`officers.rs:1126`), `forge.assess_unregistered_listener` (`:1133`) and the `unregistered_known_app` split (`:1147`) are all inside `spawn_sensor_forge_task` (begins `:1035`). That task emits to the chain and never calls `send_findings`.
SEAM-009 EVIDENCE: in the most recent 20,000 entries the officer severity histogram is Info 463, Warning 289, **Error 17** — and all 17 are `officer:sen:security:unauthorized_listener`. Every Error-severity finding on this substrate is produced in the task with no channel.
SEAM-009 EVIDENCE: six of them (`python3.13`, `cloudflared`, `tor`, `node`, `Google Drive`) landed 20:37:10–20:37:37 on 2026-08-09, inside a window in which the Regent ran 85 cycles and deliberated nine times. It deliberated on schedule and on novelty; it never deliberated on urgency, because urgency never arrived.
SEAM-009 CLAIM: this refines SEAM-006 rather than contradicting it. `has_urgent` is reachable *in principle* — steward and aegis can emit Error and run inside the sweep task, so their findings would arrive. What is true is narrower and worse: the only officer actually producing Error severity on this substrate does so in a task with no path to the consumer, so the urgent branch has never had the opportunity to fire.
SEAM-009 CLAIM: fourth instance of one disjunction. Producer writes to the chain; consumer reads a different channel; no join. Previously: receipt extensions vs the event string (CHANNEL-BOUNDARY-2026-08), `AuditAction` variants with consumers and no producers (SEAM-007), the port registry consumed by officers and populated by nobody (DECIDED-003). Here the chain is written correctly and the in-process channel is the one that was never wired.
SEAM-009 ADJACENT: `loop_runner.rs:297` gates the *immediate* cycle on `Severity::Critical` only. Error does not trigger one; it waits for the next 60s tick. Defensible, but the doc comment at `:196` reads "Officer findings (immediate cycle if urgent)", and `Severity::Error`'s own doc reads "requiring operator attention". Three vocabularies for urgency — `Critical`-only in the gate, `Error|Critical` in `has_urgent`, "urgent" in the prose — reconciled nowhere.
SEAM-009 ADJACENT: `regent.rs:2306–2312` builds an "AUTONOMOUS CYCLE: … Officer findings above require your attention" prompt branch on `has_urgent`. For security findings that branch is unreachable — a prompt the Regent has never been shown.
SEAM-009 DESIGN-OUT: not "add a `send_findings` call at `:1140`". That fixes this instance and leaves the shape; a second producer would have the same problem and nothing would notice. Forwarding should be a property of *emitting a finding*, not of the task that happens to emit it. `emit_finding` (`officers.rs:86`) is the one place every finding already passes through.
SEAM-009 CAUTION: forwarding the sensor findings **before** DECIDED-003 would deliver ~394 unclearable findings per window into the Regent's context, at least 17 of them Error, making `has_urgent` true on nearly every cycle — permanent inference on findings nobody can act on. That is SEAM-006's habituation failure in a louder register. Attestation lands first, or this stays open on purpose.
SEAM-009 DEFERRED: 2026-08-09 by DECIDED-004, with a review-after of 2026-09-09. Open on purpose, not by neglect.
SEAM-009 MEASURE: `grep -rn "send_findings" --include=*.rs crates/` — one call site is the defect. The officer severity histogram over the recent chain is the confirmation.
SEAM-009 LESSON: the tension surfaced only because two measurements taken for unrelated reasons disagreed — a severity histogram gathered while sizing the attestation queue, against wake markers gathered to check DECIDED-002. Neither instrument was looking for this. PIN-002: `has_urgent` reads as a working safety net in every file you can open.

---

### SEAM-010 — the safety net watches a branch the work never reaches

SEAM-010 STATUS: open · found 2026-08-09 · measured with `git rev-list --left-right --count origin/main...HEAD`
SEAM-010 EVIDENCE: `main` is **93 commits ahead of `origin/main`**, 0 behind. Last local commit `46077d0`, 2026-08-04. On top of that: 58 modified, 30 untracked, 1 deleted, uncommitted.
SEAM-010 EVIDENCE: CI triggers on `push` and `pull_request` to `main` (`.github/workflows/ci.yml:3–7`). Neither has occurred for 93 commits, so the workflow has not evaluated any of them.
SEAM-010 EVIDENCE: `a11cbb8c` (2026-08-01), which introduced the raw `std::env::var_os("HOME")` that `no_raw_home_lookup` is designed to catch, is inside the unpushed 93. The pin was correct, present, and enabled in CI the whole time. It was red locally for eight days and CI never had the commit to run it against.
SEAM-010 EVIDENCE: the same window explains `granted_tools_must_be_reachable` failing unnoticed after the SEAM-005 design-out — that work is not merely unpushed, it is uncommitted.
SEAM-010 CLAIM: fifth instance of the disjunction this session keeps finding. Producer and consumer both exist and are individually correct; the join is missing. Previously: receipt extensions vs the event string; `AuditAction` variants with consumers and no producers; the port registry consumed by officers and populated by nobody; officer findings emitted to the chain and never sent to the Regent. Here the producer is commits and the consumer is CI.
SEAM-010 CLAIM: this is the *reason* the other four survived as long as they did. A red pin is only information if something reads it. Three pins were failing simultaneously — `granted_tools_must_be_reachable`, `no_raw_home_lookup`, and whatever else the suite has not yet reached — and the substrate's own governance had no way to know, because the only automated reader is downstream of a `git push` that has not happened since before the defects were written.
SEAM-010 NOT-ASSUMED: 93 unpushed commits may be deliberate. This substrate is built around sovereignty, the remote is third-party, and "work stays local" is a defensible posture rather than an oversight. What is not defensible is depending on a safety net positioned on the far side of that choice. **The question is not "why has nobody pushed" — it is "what reads the pins under the posture actually in use."**
SEAM-010 DESIGN-OUT: if the posture is local-first, the pins need a local trigger — a pre-commit or pre-push hook, or `just check` wired into the loop that is actually used. If the posture is push-when-ready, then 93 commits is the drift and CI is fine. Either answer works; the current state is the one that does not, because it looks covered.
SEAM-010 ANSWERED-IN-PART: 2026-08-09 by DECIDED-005 — posture is local-first, pins get `.githooks/pre-commit`. The rest of what CI uniquely covers (clippy -D warnings, fmt, the feature-gate matrix, the workspace suite) still has no local reader. SEAM-010 stays open on that.
SEAM-010 CAUTION: a pre-commit hook that runs the full workspace test suite will be disabled within a week for being slow. `cargo test -p zp-discipline` alone is sub-second on a warm build — the pins are grep over source, not integration tests. Scope the hook to the pins, not the suite.
SEAM-010 MEASURE: `git rev-list --left-right --count origin/main...HEAD` and `cargo test -p zp-discipline`. Both are seconds. Neither had been run.
SEAM-010 LESSON: three corrections deep on one seam, each one a claim made confidently from an instrument nobody had checked — the pin does not exist (it did); nothing runs it automatically (something does); and now, the thing that runs it has not seen the code in 93 commits. The failure was never in any single check. It was assuming that a check I had not run would have told me.

---

### SEAM-011 — the ontology has 2,202 nouns and no verbs

SEAM-011 STATUS: open · classified 2026-08-10 · measured by `tools/ontology_surface.py`
SEAM-011 EVIDENCE: `ontology.db` holds **2,202 objects and 0 relationships**. All 2,202 are `trajectory`. `object_receipts` holds 10,097 rows — 2,202 `origin`, 7,895 `evidence`, with 970 objects carrying more than one evidence receipt. `relationship_receipts`: 0.
SEAM-011 EVIDENCE: `ObjectType` declares 5. One is materialized. `RelationshipKind` declares **11** — `ContributesTo`, `BelongsTo`, `SubTrajectoryOf`, `SupersededBy`, `InfluencedBy`, `AuthorizedBy`, `BlockedBy`, `MitigatedBy`, `RelatedTo`, `ProducedBy`, `DependsOn`. **Zero have a production construction site anywhere in the tree.** The only `RelationshipKind::` mentions outside the declaring module are two `#[cfg(test)]` sites in `zp-ontology/src/store.rs` (`:803`, `:846`).
SEAM-011 EVIDENCE: the substrate already documents the gap. `crates/zp-server/src/cartographer.rs:27–28` reads *"Object CREATE/UPDATE for sub-objects (Decision, Insight, Artifact, Friction) — currently only Trajectory materialization is wired."* This is a stated limitation, not a discovered one — which makes it reserved rather than broken, and is why the classification below reads as it does.

**The classification** (`zero unclassified`, per QUESTION-002, applied to this surface):

| object type | on chain | status |
|---|---|---|
| Trajectory | 2202 | **live** |
| Decision | 0 | **reserved** — no materializer; `review_after` below |
| Insight | 0 | **reserved** |
| Artifact | 0 | **reserved** |
| Friction | 0 | **reserved** |

All 11 relationship kinds are **reserved**. None is retired, and none should be
declared `wired` — there are no producers to be unexercised.

SEAM-011 CLAIM: the important structure is not that the kinds are unwired. It is that **10 of the 11 are unreachable.** Every kind names its endpoint types in its own doc comment, and 10 require a `Decision`, `Insight`, `Artifact` or `Friction` at one end or both. None of those exists. Writing a producer for `BlockedBy` today would emit nothing, because there are no `Friction` objects for it to point at. Only `SubTrajectoryOf` (Trajectory → Trajectory) is reachable with what exists — and it too has no producer.
SEAM-011 CLAIM: that converts a flat zero into a dependency order. Materializing exactly one more object type unblocks: **Decision → 4 kinds** (`BelongsTo`, `SupersededBy`, `InfluencedBy`, `AuthorizedBy`), Artifact → 2, Friction → 2, Insight → 1. Decision is the highest-leverage next step by measurement, not by preference — and it is the one already named as roughly a week of work.
SEAM-011 CLAIM: this is the sixth disjunction of the session and the one underneath the other five. Receipt extensions, `AuditAction` variants, the port registry, officer findings, commits-and-CI — every one was a **relationship** that existed in the world and nowhere in the substrate's model of itself. The ontology exists to materialize exactly those edges, and it has none. The map that would have shown the disjunctions has no edges to show them with.
SEAM-011 CLAIM: and we have been computing those edges by hand all evening. `false_assurance.py` computes producer→key→consumer. `cli_surface.py` computes verb→state and verb→chain. `kind_catalog.py` computes type→emitter→chain. `ontology_surface.py` computes kind→required-type. Four relationship materializations, derived from the chain, correct enough to have found six live defects — living in Python, outside the substrate, recomputed by grep each run, never written down, never queryable, and dependent on someone choosing to run them.
SEAM-011 RESUMABLE: the Cartographer cursor sits at `last_processed_sequence = 225690`, last advanced 2026-08-05T02:40 — five days cold, 70,445 entries behind. It is **inside the archive** (archive rowids 1–286,101; live 286,102–296,135), so it is resumable, and it is resumable *because* of the `export_entries_after_rowid` fix on 2026-08-09 that UNIONs live and archive. Before that the export silently skipped 25,713 entries.
SEAM-011 CAUTION: restarting the Cartographer produces more trajectories, not edges. It materializes `Trajectory` only. Turning it on is a verification of the resume path, not progress on this seam, and should not be mistaken for one.
SEAM-011 REVIEW-AFTER: 2026-11-10. Four reserved object types and eleven reserved relationship kinds, all with `because` recorded above. Without an expiry, reserved becomes a graveyard — the rule from CHANNEL-BOUNDARY-2026-08, applied here to a surface where it would be very easy not to.
SEAM-011 MEASURE: `python3 tools/ontology_surface.py`. Regenerate before quoting anything above.
SEAM-011 CORRECTION: "`RelationshipKind` declares five" — stated confidently earlier the same session, false. There are eleven. The claim came from `grep ... | head -12`, which returned the enum's first five variants and their `as_str` arms, and the truncation was read as the end of the list. Reading the file corrected it. This is the fourth instance of the same error tonight — `| head -10` on the CLI verbs, `--include=*.rs` under `crates/` on the pidfile writer, `crates/*/src` on the discipline test, and now `head -12` here.


### SEAM-012 — a security invariant held by an unused variable · RESOLVED

SEAM-012 STATUS: resolved · found 2026-08-12 · surfaced by `cargo clippy --workspace --all-targets`

SEAM-012 EVIDENCE: six CLI paths bound `open_keyring()` to a variable they never read. `rustc` reported all six as `unused variable: keyring` — `commands.rs:961`, `main.rs:6096`, `:6598`, `:8457`, `:8972`, `:9290`.

SEAM-012 EVIDENCE: `Keyring::open` was not a pure constructor. It created `~/ZeroPoint/keys` and `keys/agents`, then set mode 0700 on both **and on the parent `~/ZeroPoint`** — annotated in place as *"tighten the parent (~/ZeroPoint) so audit.db and sibling state aren't cross-user readable (CROSS-USER-01)."*

SEAM-012 EVIDENCE: five of the six sites open `audit.db` within a few lines of the discarded call. The unused binding was the only thing hardening the directory each of them was about to write into.

SEAM-012 ORIGIN: the composed-loader refactor of 2026-07-18 (`VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07`). `load_genesis_secret_composed()` resolves Genesis through the sovereignty provider and takes no keyring, so the value went dead at every one of these sites. The call and its abort branch stayed. Nothing pointed at the side effect, so nothing noticed it had become load-bearing alone.

SEAM-012 CLAIM: the disjunction inverted. The usual shape is a producer with no consumer — a receipt nobody reads, a finding that reaches no one. Here the *value* had no consumer and the *side effect* had no declared producer. Both halves were invisible, and the compiler could only see the half that did not matter.

SEAM-012 CAUTION: both obvious remedies were wrong, and the safer-looking one was worse. `_keyring` — what `cargo fix` applies, six times — preserves the behaviour and leaves six bindings that read as dead code, converting a live security invariant into something a future cleanup deletes on sight. Deleting the calls removes the `chmod_700` on `~/ZeroPoint` before `audit.db` is created: no test fails, no warning fires, and the only evidence is file permissions on disk, which nothing in the substrate reads.

SEAM-012 DESIGN-OUT: not "silence the warning" and not "delete the call" — **name the side effect**. `zp_keys::harden_key_home(base_dir)` now owns the directory creation and the three `chmod_700` calls; `Keyring::open` delegates to it; `commands::harden_zp_home()` wraps it with the path resolver. The six sites call that. The call site now states the invariant it upholds, which no severity of comment on the old form could do.

SEAM-012 SECOND-DEFECT: `commands.rs:961` (`keys_derive_foundation_edge`) aborted with *"Run `zp init` first to bootstrap your environment"* when the keyring would not open. Under hardware-Genesis sovereignty — Trezor, YubiKey, Ledger — Genesis deliberately does not live in the keyring, so that was a precondition on a resource the composed loader does not use, recommending a remedy that would not have applied. Message now describes what actually failed.

SEAM-012 MEASURE: `cargo clippy --workspace --all-targets -- -D warnings`, then `grep -rn "open_keyring()" crates/zp-cli/src/`. Remaining call sites all bind a keyring they read; none warn.

SEAM-012 NOT-CLOSED: nothing yet asserts that a path creating `audit.db` has hardened its parent first. The invariant is named now, and named is not enforced — the same distinction this entry exists to make. A discipline pin over the `AuditStore::open*` call sites is the obvious candidate and is not written.

SEAM-012 LESSON: **an unused-value warning can be the visible half of a load-bearing side effect.** The compiler reports what the binding does not do; it cannot report what the call does. Before silencing or deleting a warned binding, read the callee — the question is not "is this value used" but "is this call doing something."

SEAM-012 LESSON: found because a toolchain bump made clippy speak after a long silence, and the workspace had accumulated ~60 diagnostics nobody had read. Fifty-eight were style. Two looked like the disjunction class and were test scaffolding. One was this. Reading every warning individually yielded one real finding in sixty — and the bulk-fix path that would have skipped it cost a silent security regression.

SEAM-012 PIN-002: `--fix` would have resolved this correctly by its own lights and left the codebase reporting clean. Machine-applicable is a claim about syntax, not about meaning.

---

### SEAM-013 — the key tests pass only where the substrate is not installed · RESOLVED

SEAM-013 STATUS: resolved · found 2026-08-12 · measured with `cargo test -p zp-keys`

SEAM-013 EVIDENCE: eight tests in `zp-keys` failed on APOLLO — seven in `vault_key`, one in `sovereignty`. Three of them reported the same 32-byte `left` value, which is the operator's live vault key. The suite was resolving real Genesis and asserting it against a fixture's.

SEAM-013 EVIDENCE: the fixtures built a `Keyring` in a `tempfile::tempdir()`, but `resolve_vault_key` consults `zp_core::paths::genesis_record_path()` — `$ZP_HOME/genesis.json`, defaulting to `~/ZeroPoint/genesis.json` — *before* it looks at the keyring it was handed. The fixture controlled the directory; the code read the operator's real home. The isolated half was the wrong half.

SEAM-013 EVIDENCE: `load_sovereign_root_errors_clearly_on_missing_genesis` took no guard at all, so it never installed the mock credential store. Whether it saw the mock depended on whether some *other* test had installed it first — `test_sync::serial_guard` installs it once via `Once`. That is a scheduling-dependent flake, not a stable failure.

SEAM-013 CLAIM: these tests pass on a machine with no provisioned ZeroPoint — CI, a fresh checkout — and fail on an operator's. A check that reports health only in the environment where the thing it checks does not exist is worse than no check, because its green is read as coverage.

SEAM-013 CONNECTS: SEAM-010, third instance. CI has never run these against a provisioned install because it has never had the commits; locally nothing read the red. The failure was almost certainly live from the moment `resolve_vault_key` grew its step-1 sovereignty path.

SEAM-013 DESIGN-OUT: `test_sync::isolated_zp_home()` — a single guard holding the serial lock, the mock credential store, a temp dir, and the prior `ZP_HOME`, restored on drop. Binding them into one value makes "set the env var without holding the lock" unrepresentable rather than merely discouraged. `serial_guard()` stays for tests that only touch the credential store; both doc comments state which to reach for.

SEAM-013 MEASURE: `cargo test -p zp-keys` — 180 passed, 0 failed, on a provisioned operator machine.

SEAM-013 NOT-CLOSED: no pin asserts that a test whose subject resolves through `zp_core::paths` takes `isolated_zp_home()`. The next such test can reintroduce this, and it will pass in CI while doing so.

SEAM-013 LESSON: **a fixture isolates what it constructs, not what the code under test reads.** Ask what paths and process-global state the subject consults, not what the test sets up.

---

## Open questions

QUESTION-001 ASKS: what makes a receipt family real?
QUESTION-001 CONTEXT: several hundred are declared in governed documents with no emitter behind them.
QUESTION-001 FORK: is a declared-but-unemitted family a defect, a plan, or a legitimate reservation?
QUESTION-001 LEAD: the Connection Integrity Program's nine conditions may already answer this, unapplied here.

QUESTION-002 ASKS: does "zero unclassified, not zero defects" extend from connections to receipt families?
QUESTION-002 CONTEXT: the Connection Integrity Program treats a declared tie-off as a legitimate permanent state.
QUESTION-002 FORK: if it does extend, what does declaring a tie-off look like for a receipt family?

QUESTION-003 ASKS: what is the heuristic for when the Regent escalates rather than acts?
QUESTION-003 CONTEXT: it exists in code — `escalate_if_unbacked` has a structural and a language trigger.
QUESTION-003 GAP: it is stated nowhere as a rule someone could disagree with, so nobody can.

---

QUESTION-004 ASKS: what should wake the Regent?
QUESTION-004 CONTEXT: SEAM-006. Four guards decide whether inference runs at all; 44 of 44 cycles skip it with seven findings in hand.
QUESTION-004 FORK: severity threshold (fires constantly on standing conditions), novelty (has anything changed since the last look), accumulation (findings crossing a count or age), or scheduled deliberation (think every Nth cycle regardless).
QUESTION-004 COST: each option trades inference spend against responsiveness, and the current answer spends nothing and responds to nothing.
QUESTION-004 NOTE: this is a policy decision, not a bug fix. Whatever is chosen should be stated where an operator can disagree with it.
QUESTION-004 ANSWERED: 2026-08-09 — see DECIDED-002. Novelty, with a scheduled floor.


## Pins

PIN-001 STATES: adding an entry to the Regent's tool list grants a capability.
PIN-001 THEREFORE: it is an authority decision, never a lint fix.

PIN-002 STATES: the interesting failure presents as health.
PIN-002 EXAMPLES: the task that dies silently; the grant that succeeds and enacts nothing.
PIN-002 EXAMPLES: the receipt reading "completed" for work that never ran.
PIN-002 THEREFORE: when something looks fine, that is exactly when to check the instrument.

PIN-003 STATES: where a document and the substrate disagree, the substrate is the fact.
PIN-003 THEREFORE: record the disagreement rather than quietly preferring one.

---

PIN-004 STATES: absence of `gate=short_circuit` in a `regent:intent:observe` event means inference ran.
PIN-004 THEREFORE: any new early return from `reason()` must carry its own marker, or the chain silently starts reporting un-thought cycles as deliberated.
PIN-004 CAUTION: the marker only exists from 2026-08-09. Entries before that are unclassifiable, not deliberated — a window spanning the change will mis-split unless filtered by rowid.


---

PIN-007 STATES: a marker that rides on one branch cannot measure which branch was taken.
PIN-007 EXAMPLE: `wake=` was added to `regent:intent:observe` to make the wake policy legible. `observe` is emitted only on the short-circuit path, so the field reads `quiet` on every entry that has it, and the two values worth seeing never appear. Measured naively it says the policy never fires; it fires on schedule.
PIN-007 THEREFORE: instrument the *decision*, not one of its outcomes. `cycle` and `wake=` belong on every intent the cycle emits, not only the one that means "nothing happened".
PIN-007 CAUTION: until that is done, the wake policy is measurable only as gaps in the `cycle` series across `regent:intent:observe` — inference from absence, and it will silently break the moment another path stops carrying `cycle`.


---

PIN-008 STATES: a truncated search measures the truncation, not the codebase.
PIN-008 EXAMPLES: `| head -10` reported that no `restart` verb existed; it is one of 46. `--include=*.rs` under `crates/` reported the server pidfile had no writer; it is `lib.rs:1998`. A survey of `crates/*/src` reported `granted_tools_must_be_reachable.rs` did not exist; it had been committed two weeks earlier under `crates/*/tests/`. `head -12` reported five relationship kinds; there are eleven.
PIN-008 THEREFORE: an absence found by a bounded search is not a finding. Either remove the bound and print every site, or report the bound alongside the claim.
PIN-008 CAUTION: each of these was published as a correction to something else, and three were published *inside* a correction warning about unverified claims. The habit does not announce itself; it feels like diligence at the time.

---

PIN-005 STATES: `unreachable!()` is an assertion about control flow, not an error path.
PIN-005 CONTEXT: `zp`'s `main()` claims it for 41 verbs on the strength of early blocks that must always `exit()`. Nothing checks the pairing.
PIN-005 THEREFORE: a cfg that removes a block, or a flag combination with no branch, converts a diagnostic into a panic — and the panic is attributed to the verb, not to the claim.

PIN-006 STATES: a verb that leaves no chain entry is not governed, whatever `--help` says.
PIN-006 CONTEXT: 46 top-level verbs; 3 have ever produced an operator-attributed entry. `zp restart --self` kills the substrate and records nothing.
PIN-006 THEREFORE: "is it implemented" and "is it accountable" are separate questions, and only the first one has a compiler behind it.


## Decided

DECIDED-001 DATE: 2026-08-07
DECIDED-001 DECISION: Maria reaches the substrate through named read-only tools delivered to the browser page.
DECIDED-001 REJECTED: an agent behind the LLM layer, which would need a publicly reachable endpoint.
DECIDED-001 WHY: such an agent answers in tens of seconds, which conversational video cannot absorb.
DECIDED-001 WHY: named tools match the shape the substrate already uses for capability — enumerated, not general.
DECIDED-001 SCOPE: grants no write path. If Maria thinks something should change, she says so and Ken does it.

DECIDED-002 DATE: 2026-08-09
DECIDED-002 DECISION: the Regent wakes on **novelty** — a change in the officer-finding set — with a **scheduled floor** every 20th cycle.
DECIDED-002 REJECTED: lowering the severity threshold to Warning. The seven standing findings recur every cycle, so it would fire continuously on the same seven, burn inference re-deciding the same thing, and habituate exactly as an alarm that always sounds does.
DECIDED-002 REJECTED: accumulation thresholds, for now. Cheap, but the constants would become policy by default — the shape that produced SEAM-006.
DECIDED-002 WHY-FLOOR: novelty alone lets a genuinely static substrate go indefinitely without the Regent forming a view. The schedule is the floor, not the mechanism.
DECIDED-002 IMPLEMENTATION: `Wake { Quiet, Novelty, Scheduled }` decided once per cycle in `Regent::begin_cycle`, reported on the chain as `wake=<reason> deliberate_every=20`. The policy is named in the record rather than implied by a four-clause conjunction.
DECIDED-002 FINGERPRINT: over `(event_key, severity)` sorted. Excludes `timestamp` — including it would make every cycle novel, the gate would never close, and the failure would look like the Regent working. Excludes `summary`/`detail` — findings carrying counts would churn on data unchanged in kind. Includes severity: an escalation is a change worth waking for.
DECIDED-002 SIDE-EFFECT: the first cycle after every restart is novel by definition, so a restart always produces one deliberation. Intended — a restart is when the standing picture should be re-read.
DECIDED-002 OPEN: `DELIBERATE_EVERY_N_CYCLES` is a const in `zp-regent`. A policy number living in code is the shape that produced SEAM-006; it should move to `RegentConfig`.
DECIDED-002 MEASURE: the ratio of `wake=novelty` to `wake=scheduled` over a few hundred cycles says whether this substrate is genuinely static or whether the finding set churns more than 44-of-44 suggested.
DECIDED-002 MEASURED: 2026-08-09, first window carrying the markers — cycles 4 through 86, of which 76 short-circuited and **9 deliberated**. The missing cycle numbers are 9, 20, 40, 60, 61, 62, 80, 81, 82. **20, 40, 60 and 80 are exactly the multiples of `DELIBERATE_EVERY_N_CYCLES`.** The scheduled floor fires. 61–62 and 81–82 are arc continuations following the scheduled deliberations, which is the guard's `work_arc` clause behaving as intended.
DECIDED-002 MEASURED: no `wake=novelty` was observed, consistent with a genuinely static sweep finding-set — cycle 86 reports 7 findings, the same 7 SEAM-006 recorded. Novelty cannot be ruled out for cycle 9, which deliberated for a reason the chain does not record.
DECIDED-002 INSTRUMENT-DEFECT: `wake=` was added to make this policy measurable and can only ever report the null case. It rides on the `regent:intent:observe` string, which is emitted **only when the cycle short-circuits** — so `wake=novelty` and `wake=scheduled` are unreachable on the very entries that carry the field, and all 76 read `wake=quiet` by construction. The deliberating intents (`execute`, `respond`) carry neither `cycle` nor `wake=`. The policy is currently measurable only by *gaps in the cycle-number series*, which is inference from absence. See PIN-007.


DECIDED-003 DATE: 2026-08-09
DECIDED-003 DECISION: the port registry becomes an **attestation surface** — the processes the operator has vouched for — rather than the fleet ZeroPoint launches and owns. The launching path retires; the attribution path stays and gets fed.
DECIDED-003 DECISION: attestations live on the **receipt channel**. `tool-ports.json` becomes a materialisation of chain state, not the source of truth.
DECIDED-003 WHY: the boundary in `CHANNEL-BOUNDARY-2026-08.md` decides it clause for clause. An operator vouching for a process is a signed claim that must survive a restart and be checkable by someone without this process's memory. A JSON file in `data/` satisfies none of that.
DECIDED-003 REJECTED: retiring the registry with the fleet verbs. It is not inert — the officer cadre consumes it (`officers.rs:706`, `:904`, `:1233`), and its emptiness is what makes every listener on the machine unattributed.
DECIDED-003 EVIDENCE: over the most recent 20,000 entries — `unregistered_listener` 268 findings / 21 distinct binaries; `unregistered_known_app` 195 / 12; `unauthorized_listener` 73 / 9. 12 + 9 = 21. The officers already triage; the queue is 21 decisions, not 200.
DECIDED-003 EVIDENCE: the largest single entry is `llama-server` at 118 findings — the inference backend the Regent reasons through on :11434. The substrate flags the process it thinks with as unattributed, every sweep, with no way to say otherwise.
DECIDED-003 CONNECTS: at least three of SEAM-006's standing findings now have a named cause. Empty registry → every listener unattributed → three findings that fire every sweep and can never clear → the finding set never changes → the novelty gate never opens.
DECIDED-003 CONSTRAINT: an attestation carries the **binary hash** at attestation time, not path and port. Otherwise replacing the binary at that path inherits the vouch and the attestation certifies a filename. A hash change raises a finding — and that finding is novel under the DECIDED-002 fingerprint, so it reaches the Regent through the gate already built.
DECIDED-003 FALSIFY-FIRST: attest `llama-server` and watch `unregistered_known_app` fall from 12 distinct binaries to 11. If it does not, the causal chain is wrong and the decision needs revisiting before anything is built on it. No implementation before this passes.
DECIDED-003 CORRECTION: the first instinct was "the allowlist is leaking, fix it first." False — `known_system_category` classifies rather than suppresses, and the 12 + 9 = 21 arithmetic shows the split working as designed. The separate allowlist defect is real but smaller and differently shaped; see SEAM-008.
DECIDED-003 ELABORATION: `docs/design/RESTART-REDUX-2026-08.md`, second decision.
DECIDED-003 BASELINE: 2026-08-12, re-measured against `~/ZeroPoint/data/audit.db` over the most recent 20,000 entries (2026-08-11T14:06 → 2026-08-12T21:51), UNIONing `audit_entries` and `audit_entries_archive` — the live table holds only 14,630 rows, so a window this size spans both. `unregistered_listener` 401 findings / **26** distinct binaries; `unregistered_known_app` 341 / **15**; `unauthorized_listener` 60 / **11**.
DECIDED-003 BASELINE-HOLDS: the arithmetic survived. 12 + 9 = 21 on 08-09; **15 + 11 = 26** on 08-12. Every absolute count moved — volume drifted ~24% and each distinct-binary figure rose — and the partition held exactly. That is materially stronger evidence than the original single observation, which could not distinguish a structural relationship from a coincidence. Three days and a volume shift cannot.
DECIDED-003 BASELINE-UNRECORDED: the partition spans **two officers in two domains** — `unregistered_listener` is emitted by **Forge** (`officer:forge:operations:`), while `unregistered_known_app` and `unauthorized_listener` are **Sentinel** (`officer:sen:security:`). The original entry reads as one officer's internal triage split. It is not, and that is what makes "the queue is 21 decisions, not 200" a real claim rather than an accounting identity: two independent observers of the same host partition the same set.
DECIDED-003 FALSIFY-FIRST-RESTATED: the prediction as written — "attest `llama-server` and watch `unregistered_known_app` fall from 12 distinct binaries to 11" — is stale in two ways. The figure is now 15, and **three** Ollama binaries are present, each appearing under both the parent and the child: `/Applications/Ollama.app/Contents/MacOS/Ollama`, `/Applications/Ollama.app/Contents/Resources/ollama`, `/Applications/Ollama.app/Contents/Resources/llama-server`. Attesting `llama-server` alone predicts `unregistered_known_app` 15 → 14 and `unregistered_listener` 26 → 25, with the arithmetic holding at 14 + 11 = 25. Attesting the whole family predicts 15 → 12 and 26 → 23. If neither moves, the causal chain is wrong and the decision needs revisiting before anything is built on it — the original gate, unchanged.
DECIDED-003 FALSIFY-FIRST-CONSTRAINT-BITE: DECIDED-003 CONSTRAINT requires an attestation to carry the **binary hash**, not path and port. Three distinct binaries is three hashes and therefore three attestations. The entry's singular "attest `llama-server`" implies one, and the queue it sizes is correspondingly larger than 21 decisions if other applications are also multi-binary. Not yet measured.
DECIDED-003 STILL-BLOCKED: `tool-ports.json` does not exist anywhere on disk — the registry is not sparse, it was never created. The cheap falsification is to write a minimal entry at `~/ZeroPoint/data/tool-ports.json` and watch the next sweep, which tests the causal chain without building the receipt-channel attestation surface. That mutates live substrate state while the substrate is running, and is not done.
DECIDED-003 FALSIFY-FIRST-RESULT: 2026-08-12/13. **The test cannot be constructed, and the causal chain is wrong.** Not blocked on implementation — the premise does not hold. `scan_and_diff` (`zp-sensors/src/discovery.rs:159–230`) matches a listener against the registry by **pid**, or failing that by whether its ports overlap a registered port. It never inspects the binary. So an attestation carrying a binary hash — DECIDED-003's own CONSTRAINT — has no path to the matcher, and an attestation carrying pid or port cannot survive contact with the subject.
DECIDED-003 FALSIFY-FIRST-EVIDENCE: over the last 600 `llama-server` findings (2026-08-11T08:51 → 2026-08-13T01:12) there are **299 distinct pids and 299 distinct ports**, spanning 49304–65526 — the macOS ephemeral range. Ollama spawns a fresh `llama-server` per generation with `--port <ephemeral>`; the one sampled had been alive 69 seconds when it was flagged. Under the matcher's identity key, `llama-server` is never the same process twice.
DECIDED-003 FALSIFY-FIRST-VERDICT: the gate reads *"If it does not, the causal chain is wrong and the decision needs revisiting before anything is built on it. No implementation before this passes."* It does not, and it cannot. DECIDED-003 is **re-opened**. The gate worked exactly as intended and cost one afternoon of measurement instead of an implementation built on a false premise.
DECIDED-003 IDENTITY-MISMATCH: three identity models, none of them agreeing. The registry and matcher key on `(pid, port)`. The attestation is specified on binary hash. The largest contributor has a stable value for none of them, and is not even one binary — the Ollama family is three (`Ollama`, `ollama`, `llama-server`), each flagged under both the Forge parent and the Sentinel child.
DECIDED-003 REFRAME: the entry reads *"the substrate flags the process it thinks with as unattributed, every sweep, with no way to say otherwise"* and diagnoses a missing attestation. The attestation is not missing — the process is **unattestable under the current identity key**. That is a different defect with a different fix, and the original phrasing would have sent implementation at the registry rather than at the matcher.
DECIDED-003 SEAM-006-DEEPER: CONNECTS claims empty registry → every listener unattributed → findings that can never clear → the finding set never changes → the novelty gate never opens. The first three links hold; the fourth is wrong in a way that matters. These findings are not stale-and-unclearable — they are **genuinely novel**, roughly 300 times a day, because each carries a pid and port never seen before. A fully populated registry would not quiet them. The novelty gate is not jammed shut on stale input; it is being fed real novelty by a process that reinvents its own identity every few minutes.
DECIDED-003 DESIGN-OUT-CANDIDATE: `parent_pid` **59652** is constant across all 600 findings and the full ~40-hour window; `parent_name` is `ollama` in 600 of 600. The sensor already gathers both into `context` and the matcher already ignores both. Attesting the long-lived parent once and exempting its children would silence ~300 spawns/day with a single operator decision, where the hash approach silences none. Cost, stated plainly: anything spawned by an attested parent inherits the vouch. That is the same inheritance problem CONSTRAINT raises for paths, scoped to a process tree — and it is strictly narrower than what the matcher does *today*, where any process listening on a registered port is exempted regardless of what it is.
DECIDED-003 NOT-DONE: `~/ZeroPoint/data/tool-ports.json` was not written. A hand-populated registry would have produced a green result for the wrong reason — a port entry silences by overlap, without the binary ever being identified — and a green falsification obtained by exercising the mechanism the design is trying to replace is worse than no measurement.
DECIDED-003 MEASURE-CORRECTION: 2026-08-12. The first pass at this baseline filtered on `officer:sen:` and reported `unregistered_listener` at **zero**, which would have read as "the parent finding class has stopped firing." It fires ~270 times a day; it is a Forge finding, and the filter excluded it. Caught only because a follow-up daily-count query was run out of curiosity about the zero. PIN-008, fourth instance — a narrowed search reporting an absence that was present. The lesson keeps recurring because the narrowing always looks like precision at the moment it is applied.

DECIDED-004 DATE: 2026-08-09
DECIDED-004 DECISION: SEAM-009 stays open **deliberately**. The sensor-finding channel is not wired until DECIDED-003 (attestation) lands.
DECIDED-004 WHY: wiring it now delivers ~394 findings per window into the Regent's context, at least 17 of them `Error`, none of them clearable — because clearing one means vouching for the process, and that mechanism does not exist yet. `has_urgent` would be true on nearly every cycle: permanent inference on findings nobody can act on. That is SEAM-006's habituation failure in a louder register, installed on purpose.
DECIDED-004 REJECTED: novelty-gated forwarding now — forward everything as context, but let `has_urgent` require `(Error|Critical) AND novel`, reusing the fingerprint DECIDED-002 already computes. Attractive because it invents no new threshold and closes the gap sooner. Rejected because it requires deciding, under mild security pressure, whether "still unauthorized an hour later" is news. A filter chosen for economy and then inherited as policy is exactly the shape that produced SEAM-006. If it is taken later it gets its own record, not a clause appended to a conjunction.
DECIDED-004 REJECTED: unfiltered forwarding now. Honest about the state of things and unusable.
DECIDED-004 COST-ACCEPTED: named rather than absorbed. `tor`, `cloudflared`, `Google Drive` and an unrecognised `python3.13` are listening, network-exposed, and flagged `Error` by Sentinel, and the cognitive layer cannot hear about any of it. This is now a **dated, recorded blind spot** rather than an unknown one — which is the only difference this decision makes to it, and the difference is the point.
DECIDED-004 REVIEW-AFTER: 2026-09-09. The ADR's own rule for `reserved` — a `because` and a `review_after`, or it becomes a graveyard — applies to our own deferrals. If attestation has not landed by then this is re-decided, not inherited.
DECIDED-004 MEANWHILE: three items carry no dependency on attestation and close most of the *invisibility*, which is what actually bit.
DECIDED-004 MEANWHILE-1: PIN-007's instrument. `cycle` and `wake=` must ride every intent, not only `regent:intent:observe`. Implementation note: `emit_receipt` (`zp-server/src/regent.rs:411`) is the single funnel every `regent:intent:*` string passes through, which is the right seam — but it lives in `zp-server` and does not hold the Regent's `cycle_count` or `wake`, both of which are private to `zp-regent::Regent`. The markers are currently formatted into the observation text by `reason()`, upstream. So this is a threading question, not a one-line append, and it should not be guessed at.
DECIDED-004 MEANWHILE-2: a discipline test that fails when a finding class has no channel to the Regent. `crates/zp-discipline/tests/` is the established home — `adapters_must_be_documented.rs`, `verbs_must_match_schema.rs`, `no_build_time_paths_at_runtime.rs` are the same kind of source-level assertion. The invariant: every officer capable of emitting `Severity::Error` has its findings reachable by the Regent. Today that is false for `spawn_sensor_forge_task`, so the test needs a dated known-exception listing it against SEAM-009 — the `KNOWN_ORPHAN_READS` pattern, including its known failure mode: such lists rot within hours and need their own cross-check.
DECIDED-004 MEANWHILE-3: declare which severity governs. `loop_runner.rs:297` gates the immediate cycle on `Critical` only; `has_urgent` uses `Error|Critical`; the doc comment at `:196` says "urgent"; `Severity::Error`'s own doc says "requiring operator attention". Four statements, reconciled nowhere. Writing down which one governs costs nothing and stops the next reader adopting whichever they meet first.
DECIDED-004 ORDER: MEANWHILE-2 before MEANWHILE-1. The test is pure addition and makes the class of defect visible; the instrument fix touches a live event format and PIN-004 already warns what a format change does to a measurement window.
DECIDED-004 MEANWHILE-2-DONE: 2026-08-09. `crates/zp-discipline/tests/finding_producers_must_reach_the_regent.rs`, with `spawn_sensor_forge_task` listed in `KNOWN_UNFORWARDED` against SEAM-009 and a review-after of 2026-09-09, cross-checked in both directions per the `KNOWN_ORPHAN_READS` rot pattern.
DECIDED-004 MEANWHILE-3-DONE: 2026-08-12. The five statements were not inconsistent — they were a **pair with no names**, and a reader adopted whichever they met first. Both floors now live on `Severity`, which already derived `Ord`: `ATTENTION_FLOOR` (`Error`) is *worth thinking about* — an in-flight cycle reasons rather than observes, and the remediation prompt fires; `INTERRUPT_FLOOR` (`Critical`) is *worth interrupting for* — preempts the timer, and survives compression while the operator is speaking. `Error` means consider it next tick; `Critical` means do not wait for one.
DECIDED-004 MEANWHILE-3-SITES: `loop_runner.rs:306` and `regent.rs:2145` → `interrupts()`. `regent.rs:989` and `:2323` → `demands_attention()`. The `start_loop` doc comment now names its floor and states that findings below it are retained and reasoned about next cycle — continuing there drops the cycle, not the finding.
DECIDED-004 MEANWHILE-3-HAZARD: the count was five, not four. `regent.rs:2140` was a third string comparison, filtering conversation-mode findings on `"Critical"`. More seriously, `FindingSummary::severity` is a `String` produced for the life of the chain by `format!("{:?}")` — the capitalised spelling — while `Severity` derives `Serialize` with `rename_all = "snake_case"`, so the *declared wire form* is `"error"`. Swapping the formatter for serde, which looks like a tidy-up, would have made every urgency check permanently false with no compiler complaint and no failing test. `Severity::as_context_str` is now a pinned function with `context_str_matches_debug_spelling` asserting byte-identity to `Debug`, and `severity_thresholds_have_one_source` stops new open-coded comparisons appearing. PIN-002.
DECIDED-004 MEANWHILE-3-ASYMMETRY: the two predicates fail in opposite directions on an unparseable severity. `demands_attention()` returns true — §III.19, an unreadable severity is a defect and the cheapest failure is the one that wakes someone. `interrupts()` returns false — interrupting is costlier, and the attention path already guarantees the finding is not silently dropped. Deliberate, documented, and worth disagreeing with rather than inheriting.
DECIDED-004 MEANWHILE-1-OPEN: `cycle` and `wake=` still ride only `regent:intent:observe`. Unchanged.

DECIDED-005 DATE: 2026-08-09
DECIDED-005 DECISION: the posture is **local-first** — work stays on this machine and is not pushed. Therefore the discipline pins get a **local reader**: `.githooks/pre-commit` runs `cargo test -p zp-discipline --no-fail-fast` on every commit.
DECIDED-005 WHY: SEAM-010. The pins were correct, present, and wired into CI the whole time; CI triggers on push to `main`, and `main` is 93 commits ahead of `origin/main`. A safety net positioned on the far side of a `git push` that will never happen is not a safety net, and it reads as coverage.
DECIDED-005 SCOPE: pins only, never `--workspace`. The pins are grep over source and run sub-second warm. The workspace suite takes minutes and, on the day this was decided, did not compile at all. A pre-commit hook that is slow, or that blocks every commit on an unrelated break, is disabled within a week — and a disabled hook is worse than none, because the repo still contains one and everyone assumes it runs.
DECIDED-005 SCOPE: `--no-fail-fast` is load-bearing, not tidiness. cargo aborts remaining test *targets* after the first failure, and each pin is its own target, so one red pin hides every pin behind it alphabetically. That happened twice on 2026-08-09 — the run stopped at `granted_tools_must_be_reachable`, and `no_raw_home_lookup` only appeared on the next run.
DECIDED-005 ACCEPTED-LIMIT: the pins read the working tree, not the staged snapshot. Under a partial `git add -p` a pin can pass while the committed content violates it. Deliberate: a pristine index costs a temp worktree and several seconds per commit, and partial staging is not the failure this exists to prevent.
DECIDED-005 ALSO: `.githooks/pre-push` now runs `cargo check --workspace --all-targets`. Without `--all-targets` it compiles only lib and bin targets, so a test fixture that no longer compiles is invisible — which is exactly how `zp-configure::test_manifest` lost a `ToolManifest` field and left `cargo build --workspace` green while `cargo test --workspace` could not build. The hook is inert under local-first, but it should be correct for whenever the posture changes.
DECIDED-005 CORRECTED: `pre-push`'s own doc comment claimed "test failures are caught by the existing discipline pins (cargo test on demand) and CI". Both clauses were false in practice — "on demand" was a developer-memory rule, and CI had not seen a commit in 93. The comment is now the record of that, rather than the claim.
DECIDED-005 OPEN: `.github/workflows/ci.yml` is now configuration that cannot fire. It is well-built and covers more than the pins do — two feature profiles, clippy with `-D warnings`, `fmt --check`, and a six-way feature-gate matrix. Under local-first none of it runs, and a workflow file in the tree reads as coverage to anyone who finds it. Either it is annotated as dormant-by-choice, or the checks it uniquely provides need a local home. Not decided.
DECIDED-005 NOT-CLAIMED: this does not make the substrate's governance self-checking. It makes one class of check unavoidable at one moment. `clippy -D warnings`, `fmt --check`, the feature-gate matrix and the workspace test suite still have no automatic reader under this posture.
