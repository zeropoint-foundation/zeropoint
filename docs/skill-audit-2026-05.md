# Skill Audit — 2026-05-17

*Three-lens audit (visibility / determinism / composability) applied across
all skill collections accessible from APOLLO. Output: changelog of applied
rewrites + findings + methodology for ongoing application.*

## Methodology

Three lenses, each catching a distinct failure mode:

### 1. Visibility — frontmatter signals to keep auto-fire honest

| Frontmatter field | When to set | Why |
|-------------------|-------------|-----|
| `disable-model-invocation: true` | Skills whose use has real-world side effects (deploy, commit, send messages, transfer money, modify external systems) | Forces explicit user invocation; Claude can't auto-fire on tangential context match |
| `user-invocable: false` | Skills that are pure background knowledge / methodology / style guides — never something a user would type `/run` for | Hides from `/menu`, declutters surface, reduces confusion |
| Neither set (default) | Most operational skills — user invokes, Claude can also auto-fire when context matches | Status quo for benign productive work |

The frontmatter is the cheapest defense layer. A skill that quietly mutates
external systems shouldn't be a candidate for auto-fire on "anything that
sounds vaguely related." Setting `disable-model-invocation` doesn't break the
skill — it just requires the user to explicitly ask for it.

### 2. Determinism vs judgment — separate the parts

Inside every skill, classify each step:

- **Deterministic** — same inputs always produce same outputs. File renames,
  manifest updates, bash commands with no AI judgment, schema validation,
  hash computation. **These belong in scripts.** Saves tokens, eliminates
  variance, runs faster, can be tested.
- **Judgment** — requires reading context, weighing tradeoffs, naming
  things, interpreting feedback. **These stay as AI prompts** in SKILL.md.

The discipline: every place where SKILL.md says "do X" where X is a
deterministic operation should be a script call, not an instruction. The
common pattern that fails this test is "compose a string from a template
filled with values from a JSON file" — that's `jq` or a 10-line Python
helper, not LLM tokens.

### 3. Composability — share what's shared

When two skills do the same setup work (Python interpreter detection,
config-file location, credential loading), that work belongs in a shared
helper. Skills become thinner and the shared logic gets exercised more,
which surfaces bugs faster.

Anti-pattern: each skill independently implementing path resolution,
environment detection, or output formatting. Compose into utilities.

## Scope and reality

Inventory across APOLLO:

```
ZP project          : 1 (audio-pipeline + mirror)        Durable, owned by Ken
User personal       : 2 (skill-creator, graphify)        Third-party, clobbered on upgrade
User marketplace    : ~28                                Third-party, clobbered on plugin update
Cowork plugin cache : ~100+                              Third-party, clobbered on plugin update
                                                         (data:*, productivity:*, cowork-plugin-management:*,
                                                          bio-research, customer-support, design,
                                                          engineering, enterprise-search, finance,
                                                          human-resources, legal, marketing, operations,
                                                          partner-built/apollo)
```

The durable subset (rewrites stick) is small. The third-party subset is
large but transient — direct edits get clobbered on the next plugin
upgrade. For third-party skills, the right output is *findings* that
become either upstream PRs or fork decisions, not direct edits.

## Applied rewrites — durably editable

### audio-pipeline (ZP project) — no functional changes

Frontmatter audit:

- No deploy/commit/send side effects (file generation only, into ZP
  workspace under explicit operator control). `disable-model-invocation`
  not needed.
- Users will explicitly invoke this when working with narration assets.
  `user-invocable: false` not needed.
- **No frontmatter changes.**

Determinism audit:

- Workflows 1–3 (generate / update manifest / validate) are already
  thin wrappers around bash scripts (`generate-narration-onboard.py`,
  `tools/audio/update-manifest.py`, `tools/audio/audio-check.sh`). Good.
- Workflow 4 (add narration text) is an operator edit + re-run, no AI
  judgment required mid-flow. Good.
- Workflow 5 (add a new domain) involves creating a new generator
  script. The instruction "Write a generator script following the
  pattern" leaves authoring judgment to AI, which is appropriate — the
  pattern varies enough that templating it would lose more than it
  saves.
- **No script-extraction opportunities.**

Composability audit:

- Standalone skill, no duplication with other ZP-owned skills.
- **No composition opportunities.**

**Verdict:** This skill is already well-structured for the three lenses.
The structure that emerged organically (scripts in `tools/audio/`,
generators at repo root, SKILL.md as thin orchestrator) is exactly the
pattern this audit recommends. No changes applied.

## Findings — third-party skills (PR-shape recommendations)

These are not applied. Direct edits at the user-level paths get clobbered
on the next plugin/binary upgrade. Treat them as PR drafts to file
upstream or fold into local forks.

### skill-creator

Frontmatter:

- No deploy/commit/send. Generates test artifacts in a workspace
  directory the user controls. **No `disable-model-invocation` needed.**
- Explicit user invocation expected (the whole point is creating
  skills). **No `user-invocable: false`.**

Determinism:

- The heavy work is already extracted to scripts: `aggregate_benchmark`,
  `run_loop`, `package_skill`, `generate_review`. AI is reserved for
  drafting skills, choosing test cases, interpreting feedback, and
  guiding optimization — all genuine judgment surfaces. **Good.**
- One opportunity: the Cowork-specific instructions (lines ~445–456)
  are pure environment-detection logic that could be a `cowork_detect`
  helper invoked at startup, with the SKILL.md branching off its output
  instead of repeating the same environmental caveats every time.
  Marginal benefit, would simplify future skills that also need to
  adapt to Cowork vs Claude Code vs Claude.ai.

Composability:

- The Python-interpreter resolution pattern (which Python to invoke
  across uv/pipx/venv/system installs) appears in both this skill and
  graphify, with different implementations. **Recommended:** factor into
  a `scripts/detect_python.sh` helper shared by both skills (or extracted
  to a small standalone utility), so future skills that need the same
  resolution get it for free.

### graphify

Frontmatter:

- The skill includes several subcommands with real-world side effects:
  `--neo4j-push` (writes to an external database), `--mcp` (starts a
  long-lived server), `--add` (fetches arbitrary URLs and writes them
  into the corpus), `--watch` (long-lived background watcher).
- These are operator-deliberate actions, not "Claude should auto-fire
  because someone mentioned graphs." **Recommended:** set
  `disable-model-invocation: true` at the skill level.
- The trade-off: model invocation also covers the safe subcommands
  (`/graphify query`, `/graphify explain`). Setting
  `disable-model-invocation: true` means Claude can only help when the
  user explicitly types `/graphify`. Given the side-effect surface, that
  posture is correct. The `trigger: /graphify` already implies user
  invocation; making it explicit closes the loop.
- **No `user-invocable: false`** (this skill is explicitly user-typed).

Determinism:

- Step 2.5 (Transcribe video / audio) asks Claude to compose a Whisper
  initial prompt from the top god-node labels. This is template
  substitution dressed up as AI judgment. The "compose a one-sentence
  domain hint" step could be a deterministic helper:

  ```
  graphify whisper-prompt < .graphify_detect.json
  ```

  Returns: `"Discussion about <top1>, <top2>, and <top3>. Use proper
  punctuation and paragraph breaks."`

  Saves tokens on every video corpus. Removes a place the model could
  fail.

- Step 5 (Label communities) IS judgment — naming a community from its
  member nodes requires semantic interpretation. Keep AI.

- Steps 4 and 5 both contain ~50-line Python heredocs that build the
  graph, score cohesion, generate reports. These should be a single
  `graphify build-and-report` subcommand. Reduces SKILL.md size and
  removes the risk of the heredocs drifting from each other.

Composability:

- The Python-interpreter resolution at the top (see skill-creator
  finding) is duplicated in spirit. Should share a helper.

### marketplace + Cowork plugin skills — sampled patterns

Random sampling across the ~130 third-party skills surfaces these
patterns (illustrative, not exhaustive):

**Pattern A: Missing visibility guards on side-effect skills.** Several
plugin skills wrap external API calls (Stripe, Apollo) or write to
shared corporate systems without setting `disable-model-invocation`. A
mention of "send", "publish", or "post" in user context could auto-fire
the skill. **Recommendation:** when forking or PRing, add the guard
selectively.

**Pattern B: Methodology skills as operational skills.** The
`accessibility-review`, `design-critique`, `tech-debt`, `system-design`
skills look more like style guides / methodology guides — pure
background knowledge — than `/run`-able operations. **Recommendation:**
candidates for `user-invocable: false` so they don't clutter the
operator's `/menu`.

**Pattern C: Repeated environment detection.** Multiple skills
re-implement "is this Cowork? is this Claude Code? is this Claude.ai?"
branching. **Recommendation:** a shared `claude-env-detect` helper,
either as its own micro-skill or as a script bundled with `skill-creator`.

**Pattern D: SKILL.md as code dump.** A few skills (notably some in
`finance/` and `engineering/`) embed long Python blocks inline that
should be in `scripts/`. Tokens-per-invocation rises linearly with
SKILL.md length; pushing code to scripts is a strict win.

**Pattern E: Hardcoded paths.** Some skills assume `/Users/<name>/...`
absolute paths. Should use environment variables or relative paths from
known anchors.

## Changelog

| File | Change | Why |
|------|--------|-----|
| (none) | No durable rewrites needed in this session | ZP project skill (`audio-pipeline`) is already well-structured against the three lenses. Third-party skills are clobbered on upgrade — findings stay as PR drafts in this doc rather than being applied to copies that won't survive. |

## Methodology to apply going forward

When creating new ZP skills:

1. **Frontmatter first.** Before writing the body, decide:
   `disable-model-invocation`? `user-invocable`? Default both unset is
   fine for benign operational work; set them deliberately when the
   skill has side effects or is pure-knowledge.
2. **Scripts before prose.** Every deterministic step gets a script in
   `scripts/`. SKILL.md is the orchestrator, not the implementation.
3. **Shared helpers cross skill-boundaries.** Before duplicating
   path-resolution or env-detection logic, check if another skill
   already does it. If you copy, factor.

When forking or PRing third-party skills:

- Apply the framework above.
- Send the resulting patch upstream before forking locally — Ken's local
  fork creates maintenance burden; upstream lands once and benefits
  everyone using that plugin.

When importing a new plugin:

- Spot-check 2–3 of its skills against the framework before depending
  on them. A skill with `disable-model-invocation` missing on a
  send-message tool is a footgun; better to find it before relying on
  it.

## Specific PR candidates (worth filing)

1. **graphify → safishamsi** — add `disable-model-invocation: true` to
   the SKILL.md frontmatter. Justify via the side-effect subcommand
   list (`--neo4j-push`, `--mcp`, `--add`, `--watch`).
2. **graphify → safishamsi** — extract Whisper-prompt composition to
   a deterministic helper (`graphify whisper-prompt`), wired into
   Step 2.5.
3. **graphify → safishamsi** — extract the Step 4 / Step 5 Python
   heredocs into a `graphify build-and-report` subcommand.
4. **knowledge-work-plugins → Anthropic / plugin authors** —
   set `user-invocable: false` on methodology-style skills:
   `accessibility-review`, `design-critique`, `tech-debt`,
   `system-design`, `brand-voice`, `competitive-analysis`,
   `compensation-benchmarking`, `risk-assessment`. These are reference
   skills, not operational ones.
5. **knowledge-work-plugins → various** — audit each plugin's
   side-effect skills (e.g., `apollo/sequence-load`, `stripe-best-practices`,
   anything that mutates external systems) for `disable-model-invocation`.

## Refs

- `~/projects/zeropoint/.claude/skills/audio-pipeline/SKILL.md` — the durable ZP skill, audit-clean
- `~/.claude/skills/skill-creator/SKILL.md` — third-party, PR candidate
- `~/.claude/skills/graphify/SKILL.md` — third-party, PR candidates above
- This document — methodology to compose forward
