# Commit plan — 105 paths, 2026-08-10

Working tree at `46077d0` + 105 uncommitted paths (71 M · 57 untracked files · 1 D).
Twelve commits, dependency-ordered. Every figure below verified by direct read of the
diff on 2026-08-10, not inferred from filenames.

**Before anything:** two exclusions and one eyeball.

```sh
# 1. docs/_to_delete/ — 9 fragments, NOT gitignored, would be swept by `git add -A`
printf 'docs/_to_delete/\n' >> .gitignore

# 2. eyeball once, then it is permanent history
sed -n '62p' crates/zp-server/tests/vault_end_to_end.rs
#   const SECRET: &[u8] = b"sk-abacus-TESTONLY-4f3a91c2e8b7d60514a2";
#   labelled TESTONLY and it is a test constant — but sk-abacus- matches a
#   provider you actually use. Confirm it was never live.

# 3. decide on substrate-maturity.html (repo root, new this session).
#    Own commit at the end, or leave untracked. It is internal-only either way.
```

---

## Four files carry hunks for more than one commit

These cannot be staged whole. Counts are occurrences in **added** lines.

| File | Concerns present | Goes to |
|---|---|---|
| `crates/zp-server/src/lib.rs` | vault 106 · cartographer/ontology 19 · bedrock 11 | **C4** + **C7** |
| `crates/zp-cli/src/main.rs` | vault 70 · correction 26 · port 11 · approval 11 · precedent 9 | **C7** + **C8** + **C10** |
| `crates/zp-regent/src/regent.rs` | wake/novelty/scheduled 38 · tool 11 · standing corrections 4 | **C2** + **C5** |
| `crates/zp-audit/src/store.rs` | archive/rowid/union 25 · cartographer 4 | **C4** (mostly) |

Use `git add -p` on these four. Everything else stages whole.

---

## A note on ordering, stated honestly

This tree is entangled: a new module and its consumers were written together.
Ordering below minimises the problem but cannot eliminate it — some intermediate
HEADs may not compile.

That is a **bisect hazard, not a clone hazard.** The failure `pre-push` exists to
catch (93b2fe7) is about the *pushed tip* being unbuildable. Only the final HEAD
determines that. So:

- Run `cargo check -p <crate>` after each commit where it is cheap.
- Run `just check` once at the end, before push. That is the real gate.
- If a mid-sequence HEAD genuinely will not build and untangling costs more than
  it is worth, squash the entangled pair and say so in the message. Do not
  silently leave a broken commit — that is what makes a bisect lie later.

---

## C1 — hooks and local-first posture

Lands first: it installs the reader that gates every commit after it.

```sh
git add .githooks/pre-commit .githooks/pre-push .githooks/install.sh Justfile
git commit -m "hooks: pre-commit is the reader the pins never had

The pins were correct, wired into ci.yml, and unread for eight days — CI
triggers on push to main, and main was 93 commits ahead with no push in
sight. no_raw_home_lookup red since 2026-08-01, granted_tools_must_be_reachable
red since a refactor moved the declaration it parses. Both failed loudly into
a log nobody ran.

pre-commit runs the pins only, not --workspace: sub-second on a warm build,
and a hook that takes minutes gets disabled within a week. --no-fail-fast is
load-bearing — cargo aborts remaining targets after the first failure, and
each pin is its own target, so one red pin hides every pin behind it
alphabetically. That happened twice on 2026-08-09.

just pins / just check are the local stand-in for what CI would have provided.
SEAM-010, DECIDED-005."
```

## C2 — discipline pins

Four new readers plus the SEAM-005 repair. `zp-regent/src/tools.rs` must land
here: `granted_tools_must_be_reachable` parses `REGENT_TOOLS` from it, so the pin
is red at any HEAD where the pin exists and the file does not.

```sh
git add crates/zp-discipline/tests/chain_events_carry_a_prefix.rs \
        crates/zp-discipline/tests/finding_producers_must_reach_the_regent.rs \
        crates/zp-discipline/tests/prompt_placeholders_are_substituted.rs \
        crates/zp-discipline/tests/singular_sovereign_root.rs \
        crates/zp-discipline/tests/granted_tools_must_be_reachable.rs \
        crates/zp-discipline/tests/no_raw_tcp_bind_outside_zp_net.rs \
        crates/zp-regent/src/tools.rs crates/zp-regent/src/lib.rs
git add -p crates/zp-regent/src/regent.rs      # tool-dispatch hunks ONLY, not wake
```

```
pins: four new readers — chain prefixes, finding channel, placeholders, sovereign root

chain_events_carry_a_prefix: a chain event string starts with a receipt-type
prefix. The leading token is the receipt's identity — what substrate_validate
partitions by and what the inventory counts. A payload field named receipt_type
is documentation.

finding_producers_must_reach_the_regent: SEAM-009 made structural. send_findings
had exactly one call site; every listener assessment lived in a task that wrote
findings to the chain and forwarded nothing. All 17 Error-severity findings were
on the far side of a missing wire, and has_urgent read as a working safety net in
every file you could open. This is DECIDED-004's MEANWHILE-2, and it passes.

granted_tools_must_be_reachable: repaired rather than deleted. The SEAM-005
design-out moved and reshaped REGENT_TOOLS; the pin now reads two files, parses
by key, and windows look backwards as well as forwards. Verified against four
negative controls. The distinction between fixing a pin's parser and deleting
the pin is recorded in the log under SEAM-005.
```

Verify: `just pins` → expect 23 green targets.

## C3 — receipt extensions and the channel boundary

```sh
git add crates/zp-core/src/receipt_extensions.rs crates/zp-core/src/lib.rs \
        crates/zp-core/src/receipt_emission.rs \
        crates/zp-audit/src/reconstitute.rs crates/zp-audit/src/recovery.rs \
        crates/zp-memory/src/promotion.rs crates/zp-keys/src/rotation.rs \
        crates/zp-receipt/tests/schema_conformance.rs spec/receipt.schema.json \
        crates/zp-hardening-tests/tests/receipt_lifecycle.rs \
        crates/zp-hardening-tests/src/harness.rs \
        docs/design/CHANNEL-BOUNDARY-2026-08.md
```

```
channel-boundary: three producers wired, real producer through real consumer

If state must be reconstituted after a crash, or verified by someone without
this process's memory, it goes on the receipt channel. Everything else is
telemetry and belongs in the event string.

Wired: capability grants, key rotation and revocation, memory promotion stage.
Each carries a round-trip test running the real producer through
ReconstitutionEntry::from_audit_entry into the real consumer — no fixture in
the path. RecoveryEngine::finish now warns on an empty extension read.

Four kinds of mismatch, not two. Consumer-with-no-producer is always a defect
and does not present as missing — it presents as a safety net. Producer-with-no-
data is worse: do not invent a plausible value, that converts a visible gap into
an invisible wrong answer. And agreed-key-disagreed-vocabulary is the most
dangerous of the four, because both ends look wired.

Still open: zp.policy.version has no producer and gates PolicyDowngradeDetected,
so that alarm has never been able to sound.
```

## C4 — ontology and the Cartographer  ⚠ ATOMIC

**The one boundary where getting it wrong is invisible until someone clones.**
`zp-server` imports `zp_ontology` in `Cargo.toml:44`, `cartographer.rs:40,45`
and `lib.rs:1895`. Splitting any of these leaves HEAD importing types from files
that exist only in a working tree.

```sh
git add Cargo.toml Cargo.lock crates/zp-ontology/ \
        crates/zp-server/Cargo.toml crates/zp-server/src/cartographer.rs \
        docs/design/CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md
git add -p crates/zp-server/src/lib.rs         # cartographer/ontology hunks ONLY
git add -p crates/zp-audit/src/store.rs        # archive/rowid/UNION + cartographer
```

```
ontology: zp-ontology + Cartographer materializer — Trajectory only, and that is the finding

The Cartographer was the highest-leverage absence in the substrate: the only one
breaking two edges of the loop, and the one manufacturing a fragility the corpus
denies. E3 (chain to ontology) had no crate, no node or edge type, no schema —
the only occurrence of "Cartographer" in crates/ was a string in a
model-evaluation fixture.

It materializes Trajectory and nothing else. That is not an omission to fix
later, it is the shape of the dependency: every relationship kind requires
particular object types at its endpoints, so ten of eleven kinds are not merely
unwired, they are unreachable. Wiring a producer for them would produce nothing.
Materializing Decision unblocks four; Artifact and Friction two each; Insight
one. 0 relationships is a dependency order, not a flat number.

store.rs: export_entries_after_rowid now UNIONs live and archive. Before this
the export silently skipped 25,713 entries, which is what made the cursor
resumable at all.

E4 is contained, not fixed — officers still read the chain, now through one
helper. Nothing here makes an officer read the ontology.
```

Verify: `cargo check -p zp-ontology && cargo check -p zp-server`

## C5 — Regent wake on novelty

```sh
git add crates/zp-regent/src/loop_runner.rs crates/zp-regent/src/context.rs \
        crates/zp-regent/src/evaluation.rs crates/zp-server/src/regent.rs \
        crates/zp-regent/prompts/compose.md crates/zp-regent/prompts/propose.md \
        crates/zp-regent/prompts/unified_system.md
git add -p crates/zp-regent/src/regent.rs      # wake/novelty/scheduled hunks
```

```
regent: wake on novelty, with a scheduled floor every twentieth cycle

Wake { Quiet, Novelty, Scheduled } in Regent::begin_cycle. Novelty is a change
in the officer-finding set. DECIDED-002, answering QUESTION-004.

Two things this does not fix, recorded rather than papered over.
DELIBERATE_EVERY_N_CYCLES is a const in zp-regent, and a policy number living
in code is the shape that produced SEAM-006 — it belongs in RegentConfig.
And the instrument is defective: wake= rides regent:intent:observe, which is
emitted only on short-circuit, so wake=novelty and wake=scheduled are
unreachable on the very entries that carry the field. That is PIN-007 — a
marker that rides on one branch cannot measure which branch was taken. The
fix is a threading question, not a one-line append, and should not be guessed at.

The 44-of-44 figure this supersedes was itself an instrument artifact: a
deliberating cycle emits no observe entry, so the measurement could not see the
deliberations. Actual is 76 short-circuits and 9 deliberations across cycles 4-86.
```

## C6 — reconciliation invariants

```sh
git add crates/zp-server/src/substrate_validate.rs \
        crates/zp-regent/src/cognitive_observer.rs \
        docs/design/METACOGNITIVE-FIDELITY-HARNESS-2026-08.md
```

```
substrate_validate: reconciliation invariants — and one that shipped and was removed the same day

check_invariants, reported under checks.reconciliation_invariants. The surviving
set is five: three strict, two window-sensitive. A sixth
(signatures_present == entries_examined) shipped and came out the same day —
Sentinel had precedent reporting 12,893 unsigned entries at Critical, so the
invariant was asserting something the substrate already knew was false.

Window-sensitivity is a property of the measure, not a defect in it:
observer_verified <= input_composed read 62 vs 58 during development and 61 vs
61 an hour later across a restart.

The substrate named metacognitive fidelity and gated on it while having no
mechanism that measured it. Five defects motivated this, and every one surfaced
by asking something to describe the substrate out loud and finding the
description did not reconcile. None would have come from reading code: a
prefixless receipt appends, signs and verifies correctly and is merely invisible.

This measures self-consistency, not truth. A substrate can be perfectly
reconciled and wrong about the world. It does not replace the empirical program.

Not yet emitted: substrate:invariant:violated:*. The check reports; it does not
chain-anchor.
```

## C7 — vault custody and bedrock

```sh
git add crates/zp-server/src/bedrock.rs crates/zp-server/tests/vault_end_to_end.rs \
        crates/zp-trust/src/vault.rs \
        crates/zp-config/src/resolve.rs crates/zp-config/src/schema.rs \
        tools/migrate-envs-to-vault.sh \
        docs/design/INFORMATION-CUSTODY-TIERS-2026-08.md
git add -p crates/zp-server/src/lib.rs         # remaining vault + bedrock hunks
git add -p crates/zp-cli/src/main.rs           # VaultCmd hunks
```

```
vault: bedrock custody checks, and the end-to-end test the seam needed

Six .env.zp files alongside an empty vault was an observable contradiction for
four months. The April 2026 vault establishment silently evaporated with nothing
re-checking it — which is PIN-002, the interesting failure presents as health.

vault_end_to_end asserts the four properties an operator actually cares about:
the derivation path is stable, ciphertext differs across nonces, the plaintext
is absent from the file on disk, and the secret survives a process boundary
loaded fresh from disk. It also asserts list() does not leak secret material
into a key-name listing.

Still open and not addressed here: resolve_vault_key() calls
load_genesis_secret() directly with no sovereignty-provider path, so
hardware-Genesis operators see vault operations silently disabled.
```

## C8 — officers, sensors, ports

```sh
git add crates/zp-officers/src/forge.rs crates/zp-officers/src/narration.rs \
        crates/zp-officers/src/sentinel.rs crates/zp-officers/src/steward.rs \
        crates/zp-officers/src/governance_posture.rs \
        crates/zp-officers/src/proposal.rs crates/zp-officers/src/request.rs \
        crates/zp-server/src/officers.rs crates/zp-server/src/tool_ports.rs \
        crates/zp-sensors/src/discovery.rs crates/zp-sensors/src/process.rs
git add -p crates/zp-cli/src/main.rs           # port hunks
```

```
officers: findings reach the Regent, and the port registry stops pretending

The registry never held a binding. tool-ports.json is absent, no chain event
begins port:, tool:, configure: or update:, and no port_registry actor exists
among the 16 on the chain. PortRegistry skips persisting when empty, so an
unused registry leaves no file — the absence is self-concealing.

Sentinel flags llama-server as an unattributed listener on every sweep, 118
findings in the most recent window, with no mechanism to say otherwise. The
substrate flags the process it thinks with.

DECIDED-003 makes the registry an attestation surface with source of truth on
the receipt channel. Nothing here implements that: it is gated on FALSIFY-FIRST
— attest llama-server, watch unregistered_known_app fall from 12 distinct
binaries to 11. If it does not, the causal chain is wrong.
```

## C9 — proxy loopback

Small and separate on purpose: it is a pin catching a defect inside the same
session that wrote it.

```sh
git add crates/zp-server/src/proxy.rs crates/zp-llm/src/providers/proxy.rs
```

```
proxy: ollama base url through zp_net::peer_url — S3 said 127.0.0.1, the code said localhost

no_raw_peer_url_outside_zp_net caught a hardcoded http://localhost:11434 in the
Ollama default. Not a style violation: peer_url's own doc test asserts
peer_url("localhost", 17010) == "http://127.0.0.1:17010" precisely because of
the IPv6-first resolver trap. localhost can resolve ::1 first; Ollama binds
127.0.0.1 and does not listen on ::1, so the local-inference default could fail
to connect on resolver order alone.

SUBSTRATE-READINESS-CONTRACT Surface 3 already names the functional default as
"Ollama 127.0.0.1:11434" — the IPv4 literal, specifically. The corpus held the
canonical form and the substrate did not. Same shape as SEAM-011: a relationship
that existed in the world and nowhere in the substrate's model of itself.

proxy.rs is deliberately not added to the pin's allowlist. lib.rs is
whole-file allowlisted for CSP/CORS/launch URLs; this is not that.
```

## C10 — measurement tools

```sh
git add tools/kind_catalog.py tools/false_assurance.py tools/cli_surface.py \
        tools/ontology_surface.py tools/connection-map/connection_map.py \
        tools/connection-map/connections.json tools/gate-ping/src/main.rs \
        scripts/bench-local-models.py tools/local-model-bench/
git add -p crates/zp-cli/src/main.rs           # correction / approval / precedent hunks
```

```
measure: declared / built / deployed across receipts, extensions, verbs and ontology

Four tools, one discipline: three columns with three different kinds of evidence
and three different confidence levels, stated plainly rather than blended into
one score. DECLARED is exact, parsed from enums and schema. BUILT is grep and
says so. DEPLOYED is exact, SQLite over the live chain.

connection-map: maturity is 689 of 1207 = 57.1% at this commit, up from 331 of
987 = 33.5% at b548fb8. 386 of 518 defects are one shape — a governed document
names a receipt family and no emitter exists.

Two cautions the tools carry about themselves. Maturity must never become a
target: optimising it rewards not writing things down, and coverage fell
33.6% to 33.5% on a day five good documents were written. And a new measure's
first reading is evidence about the measure, not about the system — the
dead-end reachability scan reported 35 of 72 families unreachable and was
wrong about nearly all of them.
```

## C11 — corpus

```sh
git add docs/DELIBERATION-LOG-2026-08.md docs/maria-working-brief.md \
        docs/design/DECISION-MATERIALIZATION-2026-08.md \
        docs/design/RESTART-REDUX-2026-08.md \
        docs/design/AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL-2026-07.md \
        docs/design/SUBSTRATE-COMPUTE-BASELINE-2026-07.md \
        docs/design/SUBSTRATE-TABULAR-CLASSIFIER-2026-07.md \
        docs/design/REGENT-ORCHESTRATION-ARTIFACTS-2026-08.md \
        docs/CANONICAL-CORPUS-INDEX-2026-07.md CLAUDE.md
```

```
corpus: DELIBERATION-LOG-2026-08, five sketches, and two heuristics about stopping too early

The log is a working log, not canonical — written to be grepped rather than
read, so every line repeats its ID. Eleven seams, five decisions, four
questions, eight reasoning pins.

The finding underneath the other five, from SEAM-011: every one was a
relationship that existed in the world and nowhere in the substrate's model of
itself. Receipt extensions versus the event string. AuditAction variants with
consumers and no producers. A port registry consumed by officers and populated
by nobody. Officer findings emitted to the chain and never sent to the Regent.
Commits and CI.

CLAUDE.md gains two heuristics, both instances rather than inventions: reading
to the confirming sentence, and reasoning from a leaf instead of tracing from
the entry point.
```

## C12 — scaffolding, not substrate

Kept separate because none of it is the substrate, and mixing it into a
substrate commit makes a later reader think it is.

```sh
git rm scripts/smoke-test-auth.sh
git add nixos/ tools/swarm-attribution/ maria-tools.json zp-tools-server.py \
        zp-dev.sh scripts/test-governance-lifecycle.sh \
        crates/zp-bench/benches/governance_gate.rs \
        crates/zp-cli/src/init.rs crates/zp-cli/src/run.rs \
        crates/zp-configure/src/lib.rs crates/zp-engine/src/tool_scan_security.rs \
        crates/zp-server/src/anchor_pipeline.rs crates/zp-server/src/lib.rs \
        crates/zp-server/assets/ecosystem.js crates/zp-pipeline/src/pipeline.rs
```

```
scaffolding: pi5-sentinel nixos flake, swarm attribution, maria tool surface

None of this is the substrate. The pi5-sentinel flake is Phase 4 testbed
groundwork; swarm-attribution and the maria tool surface are scaffolding, the
same category as Claude — they reach the substrate through named read-only
tools and hold no write path (DECIDED-001).

smoke-test-auth.sh retired: 246 lines testing a path that moved.
```

Note: `crates/zp-server/src/lib.rs` appears here to catch whatever hunks remain
after C4 and C7 — `git diff --stat crates/zp-server/src/lib.rs` should be empty
before you commit this one. If it is not, the remainder belongs to a group above.

---

## Optional C13 — the ledger

```sh
git add substrate-maturity.html
git commit -m "dashboard: substrate maturity ledger, three lenses and a drift page

Internal. Replaces nothing — zeropoint.global/dashboard.html is still live,
still public, and still tracking a v3 build plan through Phase 8 at 98%
shipped against phase counts. Its framing predates KEEL. Deciding what
happens to that file is separate work.

Claims / Coherence / Frontier, plus Drift. Every figure carries provenance
(derived, quoted, observed, inferred), an as-of date, and its regeneration
command. No progress bars against a plan: the previous dashboard measured
completion of a document, not maturity of a substrate."
```

---

## After the last commit

```sh
just check          # pins + build + clippy + fmt — the real gate
git log --oneline -13
git diff --stat     # expect empty
git status --porcelain
```

Then decide on push separately. `pre-push` will materialise HEAD into a temp
worktree and run `cargo check --workspace --all-targets` — that is the check
that matters, and it will be the first time it has run in 93 commits.

---

## Two things worth a log entry while they are fresh

**SEAM-012 candidate — nothing automatic answers "does this build?"**
`pre-commit` runs pins only, which are grep over source and never compile the
affected crate. `pre-push` does materialise HEAD and check it, but under
local-first posture it never fires. `just check` exists and is correct — the gap
is that nothing invokes it on a cadence. Found because a 0.32s pin run could not
possibly have compiled `zp-server`, which is PIN-002's shape: the interesting
failure presents as health, and a green pin suite reads as a green tree.

**The localhost/127.0.0.1 divergence** — C9's message carries it, but it is
also the ninth instance of SEAM-011's underlying pattern and belongs in the
count.
