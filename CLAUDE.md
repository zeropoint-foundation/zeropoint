# Memory

## Me
Ken Romero (kenrom), Founder of ThinkStream Labs. Building ZeroPoint — portable trust infrastructure for the Agentic Age.

## Infrastructure
| Resource | Details |
|----------|---------|
| **Domain** | zeropoint.global — Cloudflare Workers |
| **Domain** | thinkstreamlabs.ai — Cloudflare Workers |
| **GitHub** | zeropoint-foundation/zeropoint |

## Terms
| Term | Meaning |
|------|---------|
| ZP | ZeroPoint |
| zp-playground | Remote server running ZeroPoint server |
| Playground | zeropoint.global/playground — interactive governance demo |
| APOLLO | Ken's primary dev machine. Both dev environment and ZP runtime. |
| ARTEMIS | Portable system, also used as clean environment for installation and workflow testing |
| Cartographer | Background subprocess that reads the receipt chain and maintains the ontology — turns raw receipts into structured objects (Trajectories, Decisions, Insights, Artifacts, Frictions) and their relationships. Replaces "Dreaming" as the canonical name. |
| Trajectory | Central primitive of the ontology. A living arc of work/thinking that emerges from activity — not declared top-down like a project. Can nest, fork, go dormant, resume. Spans sessions and projects. |
| Decision | Ontology object: a meaningful choice made within a Trajectory, with pros/cons, confidence, and outcome tracking. Can be superseded by later Decisions. |
| Insight | Ontology object: a key realization or observation within a Trajectory, with implications and confidence score. |
| Artifact | Ontology object: created work (code, documents, designs, specs) linked to the Trajectory and Decision that produced it. |
| Friction | Ontology object: a blocker or recurring problem within a Trajectory, with severity, occurrence count, and resolution status. Enables pattern detection across time. |
| Ontology | The structured layer of typed objects and relationships derived from the receipt chain by the Cartographer. Officers query the ontology, not raw receipts. Chain is truth; ontology is understanding. |
| Officer Cadre | The four system officers: Steward (integrity), Sentinel (security), Forge (operations), Cleo (governance). Sweep the ontology on schedule, emit findings as chain receipts. |

## Machines
| Name | Role |
|------|------|
| **APOLLO** | Ken's primary machine. Source at `~/projects/zeropoint`, runtime at `~/ZeroPoint/`. Both dev and ZP runtime. |
| **ARTEMIS** | Travel system + clean install testing. Has Touch ID for biometric sovereignty testing |
| **zp-playground** | Remote ZP server |

## Hardware for Testing
| Device | Purpose |
|--------|---------|
| **Trezor** | Hardware wallet with existing Genesis keys — test Trezor sovereignty provider |
| **ARTEMIS Touch ID** | Test Touch ID sovereignty provider from clean install |

## Projects
| Name | What |
|------|------|
| **ZeroPoint** | Cryptographic governance primitives for autonomous agent systems |
| **zeropoint.global** | Public website (gitignored, use `git add -f`) |
| **thinkstreamlabs.ai** | Company website — light theme, Cloudflare Workers |

## Key Paths (APOLLO)
| Path | What |
|------|------|
| `~/projects/zeropoint` | Source code (Cargo workspace root) |
| `~/ZeroPoint/` | Runtime home — vault.json, genesis.json, session.json |
| `~/ZeroPoint/data/audit.db` | Audit chain (SQLite) |
| `~/ZeroPoint/keys/` | Signing keys |

## Preferences
- Git doesn't work from Cowork sandbox — Ken runs git locally from ~/projects/zeropoint
- zeropoint.global files are gitignored — must use `git add -f zeropoint.global/`
- Dark theme design system: --bg: #0a0a0c, accent: #7eb8da, Inter + JetBrains Mono
- **Browser**: Uses Comet browser (NOT Chrome). Claude MCP is available via Comet tabs. Do NOT use Claude in Chrome MCP tools — they don't exist here.
- **Dev workflow**: `./zp-dev.sh` (dev build), `./zp-dev.sh release` (ship). Note: `./zp-dev.sh html` arg does NOT exist — valid args are `dev|release|kill|log|verify`.
- **TTS**: native Cowork TTS handles spoken output. Do NOT invoke `piper_tts_synthesize` — the Piper MCP detour is retired.

## IronClaw Build
| Thing | Detail |
|-------|--------|
| **Source** | `~/projects/ironclaw/` — separate Cargo workspace from ZeroPoint |
| **Tile binary** | Runs `target/release/ironclaw` — always `cargo build --release`, never plain `cargo build` |
| **Verify running binary** | `ps aux \| grep ironclaw` — confirms path and build variant before debugging frontend changes |
| **JS assets** | Baked in via `include_str!()` at compile time — no asset override dir. Changes require rebuild + tile restart. |
| **Frontend served** | `crates/ironclaw_gateway/static/js/core/` — NOT `crates/ironclaw_webui_v2_static/` |

## Tone preferences

**Don't impose a day-shape on Ken's work on your own initiative.** The instinct that needs to stop is the unprompted time frame — opening with "good morning," closing with "rest up," narrating "we're at the end of a long day," asking "how's your day going" as filler. Ken's work doesn't have a day shape; assuming it does is patronizing.

**Mirroring is fine.** When Ken says "I'm going to bed" or "good morning, let's get to it," matching the signal naturally — "goodnight," "morning" — is responsive, not imposing. The test is who's setting the frame: if Ken sets it, follow; if you'd be the one introducing it, drop. Same as any other conversational mirror.

The warmth lives in the content. Saying hello, hi, good to hear from you, glad you're back — fine independently. Friendly closers like "good arc," "pleasure was mine," "noted," "your call" — fine independently. None of these require a time frame.

Drop, unless Ken just used the same frame:

- Time-of-day greetings or closers as something you initiate ("good morning, ready to dig in," "before you turn in")
- References to "today," "tonight," "this morning," "this evening," when describing the work — say "the work," "the arc," "the next step," "this session"
- Day-shape assumptions: "we're at the end of a long day," "first thing in the morning," "after the weekend"
- Asking about Ken's day or wellbeing as conversational filler

## Asset Architecture (Two-Tier)
| Tier | Location | When |
|------|----------|------|
| **Override** | `~/ZeroPoint/assets/` (or `$ZP_ASSETS_DIR`) | Hot reload (`./zp-dev.sh html`) copies source here. Persistent files (narration MP3s, images) live here always. |
| **Compiled-in** | `include_str!()` in binary | Always available. Matches last `cargo build`. Dev/release builds delete overrides so compiled-in takes effect. |

**Rules**: No relative ServeDir paths. Override dir is the single ServeDir root. `resolve_html_asset()` checks override → compiled-in. Two file categories in `zp-dev.sh`: `HTML_FILES` (have compiled-in fallback, deleted after build) and `STATIC_FILES` (CSS/JS, no fallback, always deployed to override dir).

## Canonical Architecture Record

**`docs/ARCHITECTURE-2026-04.md`** is the north star. Read it before making any structural decision. It is not a reference document — it is the operating spec. Code that contradicts it is wrong.

**The four claims** (Part I §2) are the substrate's acceptance criteria. All four are currently true: Claim 1 (chain integrity) fixed by AUDIT-01 transactional append; Claim 3 (gate enforcement) fixed by EXEC-01..04. Claim 2 (collective audit mechanism exists but untested under adversarial pressure). Claim 4 (delegation narrowing implemented but not adversarially tested). Every phase of work should keep claims true and push the untested ones toward empirically verified. If proposed work doesn't advance a claim, question whether it belongs.

**The six design principles** (Part V½) are a mandatory filter for every architectural decision:

1. **Signing is gravity** — unsigned Receipts are structurally meaningless. If it works without signing, signing is decorative.
2. **Identity is a key, not a location** — bead zero is the identity, not the port or hostname.
3. **There is no center** — trust state is derived locally from the audit chain, never from a remote authority.
4. **Every bit counts** — no redundant fields, no duplicate data paths, no wasted cognitive bandwidth.
5. **Store-and-forward is primary** — the chain survives outages. Derived state, not live state.
6. **A tool is intent, crystallized** — semantics in structure, not in comments. Constitutional rules are conservation laws.

**Companion documents**: `whitepaper-v2.md` (public thesis), `design/governed-agent-runtime.md` (GAR spec), `future-work/cognitive-accountability.md` (Layer 3 trace vision), `design/quorum-sovereignty.md` (M-of-N sovereignty direction + HW wallet implementation notes), `intellectual-context.md` (adjacent thinkers: autoregressive theory, LARQL, MEDS, Nate Jones), `EDGE-TIER-CONTRACT-2026-06.md` (runtime-neutral required/optional/forbidden affordances for the worker tier; operational complement to ARCHITECTURE §4c), `SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` (hub-only meta-contract — 11-tier taxonomy + reusable contract template; the seed from which any ZP integration's per-tier contracts derive), `GOVERNANCE-IMPLEMENTATION-PRINCIPLES-2026-06.md` (five implementation heuristics for building governance correctly — the operational complement to the eight design principles, grounded in the inference governance arc).

## Working principles (Karpathy-style)

These shape *how* to work in this repo, not what to know about it. Co-equal with the graphify directive below; both are behavioral rules, not encyclopedic context.

### Think before coding

For any non-trivial change:

- If intent is ambiguous, ASK before assuming. A clarifying question costs less than a wrong implementation.
- For architectural decisions, surface the trade-off explicitly before picking. The architecture doc (`docs/ARCHITECTURE-2026-05.md`) and the seam catalog (`docs/STRUCTURAL-AUDIT-2026-05.md`) exist to be consulted.
- Outline the change shape (which files, which abstractions) before editing. Easier to course-correct an outline than a half-built diff.

### Simplicity first

Prefer the smallest viable change. The substrate is large enough that adding bloat compounds. If a feature can be expressed in 20 lines instead of 200, do the 20.

The discipline-pin system, the verb-set frame, and Architecture II.0 (contracts singular, implementations plural) all point in this direction. A new abstraction must justify its existence; an existing one should not be casually rewrapped.

### Surgical changes

Touch what's needed for the requested change. Do NOT:

- Reformat unrelated code in the same file
- Rewrite imports, comments, or structure that isn't the target
- "Clean up" adjacent code as a courtesy
- Refactor as a side effect

If you notice something genuinely worth fixing nearby, surface it as a separate task, not a same-commit drive-by. The pre-push hook and discipline pins enforce some of this; the rest is on you.

### Goal-driven, not step-driven

Ken describes what "done" looks like; you choose the path. If the goal is "users can attest delegation withdrawal," that's the success criterion — the verb-set verbs, the receipt schema, the storage shape are yours to propose and confirm.

If steps are unclear, ask "what does done look like?" rather than guessing.

### When in doubt

Subagent dispatch (Sonnet) for mechanical sweeps, surveys, and verification passes. Primary context for architectural reasoning, ambiguous-intent moments, and code that informs the current decision. See `docs/MODEL-SELECTION-2026-05.md` for the per-task calibration.

**When handing off work to a CLIC (or any subagent), name the model tier explicitly in the brief.** The dispatch brief should call out "Sonnet tier" or "Opus tier" near the top — same way prior investigation briefs have ("Sonnet tier — focused patch, no architectural change"). This makes the cost / capability assumption visible to whoever picks up the work, and keeps the per-task calibration legible across sessions. Forgetting the callout is the friction-signal that the model decision wasn't made deliberately.

## Workflow heuristics

Patterns worth replicating, captured at the moment they fire. Each entry is one heuristic plus the example that revealed it. Append new ones; don't prune.

### Name and shape artifacts for their downstream consumer, not their immediate producer.

When creating anything with a downstream consumer — config file, env var, JSON schema, API endpoint, function signature, even a hypothetical-future consumer — ask *who reads this?* before *who writes it?* and name/shape from the reader's side.

Example (2026-05-12): the Kokoro tuner saves voice favorites to a JSON file. Could have called it `tuner-favorites.json` (producer-side) or `kokoro-saved.json` (tool-side). Called it `onboarding-voice-palette.json` — what the wizard's Phase 5.5 actually reads. The wizard wiring then falls out with no translation layer, no mapping config, no "this is actually X" comment in three places. The filename IS the contract.

Anti-pattern: naming for the producer or the moment of creation. That forces either (a) a rename later, (b) a config mapping, or (c) docstring glue saying "this file means Y." All three are cognitive-bandwidth tax that consumer-side naming avoids.

When no consumer exists yet: name for the *probable* consumer. Right → free integration later. Wrong → rename costs nothing while nothing depends on it.

Connects to *every bit counts* (no translation layer) and *a tool is intent, crystallized* (the name carries the semantics structurally).

### For systems spanning trust boundaries, only production tests production.

Localhost cannot reproduce what happens at edges: cross-subdomain cookies, CDN-injected auth (Cloudflare Access JWTs, etc.), worker route ownership conflicts, per-worker secret stores, DNS resolution, the gap between local D1 and remote D1 migration state. Any system whose correctness depends on identity flowing across origins, gateways, or proxies will look correct in localhost while breaking in production.

Example (2026-05-13): the substrate-session HMAC bridge worked perfectly on localhost — wizard issued cookie, IronClaw verified it, handoff cleared. On production, six distinct frictions appeared that localhost couldn't have surfaced: CF Access intercepting at the edge, `zeropoint-global` worker still claiming the foundation routes, secrets needing per-worker mirroring, D1 migrations diverged between `--local` and `--remote`, browser cookies persisting across the dual-auth attempt, and the wizard's "already onboarded" branch becoming a dead-end. None visible until we actually deployed.

The fix is to deploy and walk through from production *early* — not as the validation pass at the end. If the system spans a trust boundary, treat localhost as a dev rig, not as a test rig. A 10-minute production walkthrough mid-build catches what hours of localhost iteration miss.

Connects to *signing is gravity* (the boundary IS the point; testing without it tests nothing) and *store-and-forward is primary* (production state is the real state).

### Demonstrate publicly with prerendered paths; interpret internally with live agents.

When demonstrating the substrate publicly — marketing exhibits, educational chain views, public-facing tours — every narration path is prerendered and every interactive branch is deterministic. No live LLM call. No live agent surface. The *voice* of an agent (Sage's character, copy patterns, phrasings) can be present through carefully authored copy bound to specific UI events. But the *running agent* stays behind authentication.

Internal surfaces — where operators are authenticated and accountable — can host live agent interpretation: ask Sage what happened, get a chain-grounded answer; let Sage suggest the next action based on operator-specific context. Live agency is a real capability, but it's an authorization-bound one.

Example (2026-05-13): the receipt chain visualization was first drafted with "Sage narrates" wording that read as live-agent-on-marketing-site. Corrected to: Sage's voice surfaces through prerendered copy bound to UI events on public surfaces; live conversational Sage stays inside the authenticated foundation surface only. The public chain demo's verification and tampering interactions are also deterministic — visitor clicks verify, math runs, result shown; no LLM decides what to display.

Why this is load-bearing:
- **Accountability surfaces must match the chain by construction.** The chain shows what actually happened; the narration must agree. A non-deterministic narrator can drift, contradict, or be prompt-injected into saying something off-message — defeating the trust thesis the demo is supposed to deliver.
- **Prerendered paths preserve cryptographic verifiability.** The chain says X; the narration says X; both agree because the narration was authored to say X when X happens. There's no place a runtime could lie.
- **Authorization bounds cost, abuse surface, and context quality.** Internal agent calls happen for known operators with rich context (their session, their receipts, their role). Public agent calls would be anonymous, infinite-scale, context-poor — strictly worse on every dimension.
- **Voice and agency are different capabilities, deployable at different tiers.** "Sage as a character" is brand and copywriting. "Sage as a running agent" is a runtime surface with operational posture. Confusing the two leads to accidentally exposing runtime where only brand was intended.

Connects to *signing is gravity* (deterministic verifiability is structural, not decorative) and *identity is a key, not a location* (the right to interact with an agent is authorization-bound, not URL-bound).

### Singular sovereign root: one authentication, everything derived.

When a system needs operator authentication to access secrets, design for one sovereign root — one credential, one prompt, one ceremony — from which every other secret derives. The credential store holds exactly one biometric-gated item; all other secrets are either derived in memory from that root, or stored encrypted in a vault that the root unlocks. There is no third category.

The diagnostic posture is the inverse: if a single operator action triggers N authentication prompts, the architecture has drifted into N independent secrets, each with their own freshness story. The friction is the symptom; the structure is the disease. Fixing the prompt count one call site at a time is whack-a-mole; fixing the structure once — one canonical loader plus a discipline pin that forbids direct credential-store reads outside that loader — is the durable shape.

Example (2026-05-14): `zp configure exec` was firing 5–9 Touch ID prompts during one operator action. The instinct was to chase each prompt site — cache this, thread that secret through there. That worked tactically (three patches across two commits brought it to one prompt). But the underlying drift was structural: three independent code paths each treated Genesis (or genesis-derived material) as a sovereign root with its own credential-store entry. The proper fix is one canonical `load_sovereign_root()` loader plus a `singular_sovereign_root` discipline pin — captured in `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` and task #152.

Why this is load-bearing for accountability, not merely UX: when there is one sovereign root per process, every signature emitted during that process traces to one operator authentication. The chain says what happened *and* who said it happened, with cryptographic authority over both. When N independent secrets exist, the chain's authority over "who" weakens — a derived key loaded outside the operator's authentication ceremony could in principle sign in a context the operator didn't consent to. The friction discovers a real chain-authority gap; collapsing to one root closes it.

The architecture scales by structural rule, not by accumulated patches. Multi-quorum sovereignty (M-of-N devices) is tractable only under this principle: M ceremonies once at process start, then everything derived. Without the singular root, quorum becomes M × C ceremonies for C credentials — unbounded as the substrate grows.

Connects to *identity is a key, not a location* (Genesis is the identity; derived keys are projections of that identity, not separate identities), *every bit counts* (N redundant credential-store entries IS the duplicate data path the principle catches), and II.0 (contracts singular: one credential-loading contract; implementations plural: Touch ID, YubiKey, Trezor, M-of-N quorum, all behind it).

### Pair conversational interfaces with reference surfaces that reveal the control space.

Agents reveal capability through action; reference surfaces reveal capability through visibility. Conversational control alone is invisible by default — the operator has to remember or guess what's possible. A reference panel makes the control space legible without claiming the only seat at the table. Reference UI alone forces navigation for things the operator could just say. Both surfaces are weaker alone; together, discovery happens visually and expression happens conversationally, with the same chain-anchored state underneath.

The pairing IS the design. The two surfaces are not redundant — they answer different operator questions. The reference asks "what can I do here?" and the conversation asks "how do I do this thing I want?" Conversation without reference leaves the first question unanswered; reference without conversation forces every action through clicks. The combination produces a surface that both teaches and obeys.

Example (2026-05-14): the voice control arc. Sage can change the operator's voicepack via natural-language tool invocation ("switch to Isabella") — but the operator only knows that's possible if they already know. A small reference panel at app.zeropointfoundation.org/preferences/voice — buttons per voicepack with audio samples, a speed slider, current selection highlighted, recent-change history from the chain — answers "what voices exist, what's mine right now, what could I switch to" visibly. Clicking a button emits the same `preference:voice:selected` chain receipt that Sage's conversational tool would emit; the receipt is the source of truth. Two write paths, one chain, full coherence. The panel teaches the capability; Sage acts on it.

The constraint that makes this work: **both surfaces must read from and write to the same chain-anchored state.** If the panel had its own preference store separate from Sage's chain receipts, they'd drift — the panel would say one thing, Sage's behavior would reflect another. The chain is the contract; the panel and Sage are co-implementations of the same operator-state surface, just rendered for different interaction modes.

Connects to II.0 (contracts singular — one state in the chain; implementations plural — panel + conversation + future surfaces), *signing is gravity* (the chain receipt is what makes the operator's preference durable and verifiable), and the public/internal heuristic above (both surfaces here are internal/authenticated; the chain receipt is the deterministic substrate underneath both live and visual interactions).

When *not* to pair: read-only surfaces that don't accept operator action don't need conversational counterparts. A status dashboard showing system health is fine as a panel alone. The pairing is for *control* surfaces — anywhere the operator can change something. Voice, capability scope, delegation settings, future agent preferences — these all benefit. Information-only views do not.

### The substrate proposes; operators sign.

When the substrate emits any rendering or prescription — narration of past chain state, workflow describing future chain state, calendar, digest, timeline, agent-generated artifact — it emits as a *candidate* until human-endorsed. The substrate produces candidates at scale: cheap, automated, deterministically-provenanced. Operators promote candidates to canonical via signature: rare, deliberate, human-endorsed. Cheap proposals; expensive decisions.

Two failure modes the heuristic prevents. **Always-live** (regenerate every read with an LLM, or re-execute every run): burns tokens or runtime, non-citable, non-verifiable. Each invocation produces something that may or may not match what came before; nothing to reference. **Always-pre-approved** (every output requires human review before existence): human approval is the bottleneck; substrate can't propose freely; output rate-limited to operator availability.

Together, the pattern: substrate produces candidates whenever its source receipts change. The candidate lands in a library, content-addressed by its source manifest plus render config. Operator reviews. On approval, the substrate signs the artifact with the operator's Genesis-rooted key (composing from the receipt-signing primitive). The signed artifact persists, becomes citable as canonical reference, supersedes any previously-signed version of the same kind. New source receipts produce new candidates alongside; supersession is explicit, not silent.

The trust trail closes end-to-end: operator signature → artifact (source manifest) → receipts → chain → Genesis. A signed calendar from last Tuesday is fetchable by content-address forever; "Tuesday's calendar" exists as a concrete object, not a re-rendered guess. Third parties can verify by recomputing the artifact_id from source receipts and checking the signature against the operator's pubkey.

Example (2026-05-14, designed): the chain-narration surface that PoC #147 explored is the canonical case. Today it's *ephemeral* — live LLM on every render, non-citable. Under this principle, it becomes candidate-on-receipt-change, signed-on-review. The same lifecycle applies to forward-looking artifacts (workflows: drafts → reviewed → signed → executable, with executions producing chains of receipts that cite the workflow's artifact_id). Both backward and forward kinds inhabit one library, share one lifecycle, share the same Genesis-rooted signing protocol. Captured in `docs/ARTIFACT-LIBRARY-2026-05.md` (task #162) and `docs/handoffs/zp-session-token-issuance-design-2026-05.md` shape.

Connects to *signing is gravity* (signed artifacts inherit the chain's cryptographic authority; ephemeral surfaces don't), the prerendered-public/live-agent-internal heuristic (signed artifacts are the prerendered side of internal surfaces — render-once at generation, serve-many on read), II.0 (one lifecycle contract; many artifact kinds), and *every bit counts* (no LLM re-runs of unchanged content; no duplicate renderings of the same source).

### When two reasonable architectural models conflict over the same surface, pick one explicitly. Half-state is the failure mode.

Two coherent approaches can solve the same problem cleanly in isolation; running both in parallel, unintentionally, produces a substrate that fails differently every restart. The friction isn't a config gap — it's a deployment-model gap. Whichever model the substrate is in, restart cycles should be reproducible; "different break each time" is the signature of unresolved drift between two reasonable approaches.

Diagnose by the symptom shape. If each restart surfaces a *different* piece of the inconsistency — not the same broken thing twice, but rotating brokenness — the substrate has two models competing for the same surface and neither fully owns it. Pick one explicitly, document the choice, and migrate cleanly. Patching the inconsistency-of-the-day works once and breaks again on the next restart because the cause isn't local to the symptom.

Example (2026-05-15): the IronClaw foundation deployment had drifted into half-state between Model A (governed tool — vault is source of truth, `zp configure exec` is launch path) and Model B (infrastructure tool — `.env` file is config, launchd-style launcher, ZP integrates via API only). Both models are coherent. Running both, neither fully owned the config surface: secrets were partly in vault, partly in `.env`; the launch path sometimes used governance, sometimes didn't; restart cycles surfaced a different piece of the inconsistency every time. Resolution: choose Model A explicitly (aligns with `secrets only via ZP vault, never bypassed` and singular-sovereign-root), execute the migration (vault filling, `.env` deletion, OIDC overwriting), and document the choice. Captured in task #163 and `docs/handoffs/ironclaw-deployment-unification-design-2026-05.md`.

The choice isn't always obvious, but choosing IS architecturally cleaner than not choosing. Even if a future re-evaluation flips the choice, an explicit Model B is structurally cleaner than implicit half-A-half-B. Document the decision and the reasoning so a future reviewer (or future-you) can re-evaluate with full context rather than reverse-engineering it.

Connects to *singular sovereign root* (same shape — drift between reasonable approaches reveals a structural gap; the fix is choosing one explicitly), II.0 (contracts singular — when there are two contracts for the same surface, pick one), and *every bit counts* (parallel models duplicate the data path the principle catches).

### When a PoC keeps surfacing new friction at every layer, the friction *is* the finding.

A PoC's stated job is usually a narrow question. But if the path to answering the narrow question keeps surfacing new failure modes at every layer underneath, that is itself the answer — to a *wider* question the PoC didn't know it was asking. Don't tunnel into the original narrow question while ignoring what the friction is structurally telling you.

The diagnostic posture: count the seams. If a single walkthrough of a single command surfaces 10+ distinct failure modes across the substrate, the substrate isn't ready for the question the PoC was designed to test. The narrow finding doesn't matter yet; the wider finding ("the bedrock keeps moving") is what's load-bearing.

Example (2026-05-13 through 2026-05-14): the PoC #147 walkthrough surfaced ten distinct seams between "operator asks for chain" and "chain renders": Cloudflare Access friction, worker route ownership conflicts, D1 migration drift, wizard already-onboarded dead-end, vault provider display bug, audit store opener inconsistency, Venice/OpenAI base_url defaults, ZP cognition-governance hook auth missing, passkey re-prompt treadmill, IronClaw deployment half-state. Each one looked like a config gap. Counted together, they were one structural finding: the substrate had drifted across many surfaces simultaneously and "make Ken's chain show up" was a misleadingly-small ask for the work it required. The right response wasn't to land #147; it was to declare the substrate-readiness arc — load-bearing-honest hardening before adopter outreach (task #91) — and execute it. The narrow PoC question became answerable only after the wider substrate work shipped.

The temptation when this pattern fires is to keep patching: just one more fix, then we'll get to the narrow question. But each fix reveals the next layer of drift. The right move is to step back, declare the bigger arc, and execute it deliberately rather than chasing the symptom-of-the-day. The friction is the architecture asking for attention; ignoring it doesn't make it go away, it just defers it to the next operator who triggers the same path.

Connects to the load-bearing-honest principle (task #91's whole framing), *only production tests production* (same shape — when a trust boundary stops being honest, the friction is the boundary asking for substrate work, not config work), and `singular sovereign root` (the architectural cleanups that emerge from this kind of friction often turn out to be coherent under one principle, not multiple local patches).

### The lsof test: substrate is mature when its own footprint is legible.

When `lsof -iTCP -sTCP:LISTEN` (or any similar host introspection command) shows a list the operator cannot immediately partition into substrate-managed / deliberately-running / unknown, the substrate is not yet steward of the machine — it is a tenant alongside others, and the operator is doing the steward's work by eye. Maturity is reached when every listening process, every credential, every persistent file on the host either traces to a substrate receipt or is explicitly out-of-scope (system services the operator acknowledges, deliberately-running tools the operator deployed). The operator should be able to read the lsof output as a substrate posture statement, not as a forensics exercise.

Example (2026-05-19): an `lsof` snapshot during the substrate-readiness verification showed ~20 listening processes — rapportd, ARDAgent, ControlCenter, multiple node and 2.1.143 instances, com.docker, plus the two substrate processes (`zp serve`, `ironclaw`). The operator could pick out the substrate's own footprint by name but couldn't quickly answer "is this list the posture I intend?" without manual archaeology. The substrate hadn't yet absorbed enough host-awareness to give that answer in one command. Friction surfaced as repeated `pgrep` / `kill` / `lsof` archaeology across the session — the same pattern firing for cloudflared orphans, stale IronClaw PIDs, mystery `zp serve` survivors. Each individual problem was small; the pattern was that the substrate had no view of its own footprint relative to the host's.

This is the maturity gate for `docs/ARCHITECTURE-2026-04.md` Part VIII (Compute Surface Awareness) — the substrate must be aware of the entire compute surface and help monitor its health and security, with the key distinction being observability vs control (visibility is universal; authority remains scoped to what was launched through the substrate). The arc has five stages (inventory → attribution → surface → integrity → recommendation, never autonomous action) and composes with the existing `zp doctor`, `zp ps` (planned), `zp discover`, `zp scan`, audit chain, and PortRegistry pieces.

Connects to *singular sovereign root* (one authentication, everything derived) — same shape applied to processes: one ledger of what's running, every process traced or explicitly excluded. The runtime expression of *every bit counts* applied to the host itself: nothing on the machine should be unaccounted-for either as substrate-launched, operator-acknowledged, or actively suspect. Composes with Principle 8 (one canonical path per substrate concern) — the substrate becomes the single authority for trust posture of the host, not just for what it launched.

### Config reflects today, not roadmap.

Operator-facing configuration enumerates what the daemon responds to *now*. Schema reservations for unimplemented features (empty `[section]` headers, struct fields with no consumers, validation logic for fields no code reads) look like configuration but configure nothing. They train the operator to read past section headings as decorative — and the next time the operator opens the file, they don't read carefully. The substrate has surrendered the file as a meaningful operator surface.

Roadmap intent belongs in places designed for roadmap: `docs/ARCHITECTURE-2026-04.md`, the task list, design briefs in `docs/handoffs/`. The config file is for current reality. When a feature lands, its config schema lands with it, in the same commit — the consumer and the schema are introduced together.

Example (2026-05-19): `~/ZeroPoint/config.toml` had 13 section headers but only 5 corresponded to fields the codebase actually consumed at operational call sites. The eight placeholder sections (`[governance]`, `[logging]`, `[session]`, `[mesh]`, `[dlt]`, `[shell]`, `[filesystem]`, `[docker]`) were either struct fields with self-referential validation (validators inside `zp-config` referencing their own fields, with no outside consumers) or fields no code read at all. Each placeholder taught the operator that config sections might or might not mean something, which made the meaningful sections harder to read.

**The audit method matters.** A grep for `config.<field>` finds string matches but cannot distinguish self-referential consumers (e.g., `validate.rs` validating fields that the rest of the codebase never reads) from operational consumers (`main.rs` reading a field to drive behavior). The reliable audit is "remove the field, see if the build still compiles" — that catches both genuine cuts and bait-and-switch where field deletion only breaks the validator that references it. Aspirational architecture (e.g., "identity should be Genesis-derived per Principle 2") cannot be the basis for schema pruning until the aspiration is realized in code; until then the current consumers are the truth.

Connects to *every bit counts* (Principle 4) applied to schema, and *one canonical path* (Principle 8) — the config file is the one operator-facing enumeration of what the daemon does. Same theme as the lsof test (host-side legibility) and the operator-surface hygiene principle (output-side legibility). This is config-side legibility. Three sides of the same boundary.

### Balanced loop: smallest end-to-end test, observe, fix structurally, repeat.

When the substrate has built-out structure but unproven empirical correctness, neither pure-design nor pure-build moves the work forward efficiently. The balanced loop is the working mode: **define the smallest single operator action that exercises one trip through the substrate. Stand up the minimum CLI invocation and minimum CLI inspection. Run it. Observe what fails. Fix the failure as the structural thing it actually is — wire bug, missing pin, absent surface — repeat with the next slightly-bigger action.**

The loop's central claim is that functional and mature are not sequential phases. They are two pressures applied to the same iteration. Each turn raises the floor on functional (one more verb is empirically true), mature (one more structural gap is closed), and surfaceable (the minimum invocation/inspection grew alongside). The right move at any point is the smallest action that touches all three pressures at once.

The discipline depends on what you do when a test fails. The wrong move is to patch the test until it passes — that ships a hotfix but leaves the structural gap. The right move is to ask *what is this failure actually telling me about the substrate*, and fix the underlying structural thing the failure surfaced. Loops where every fix is hotfix produce running code with hidden landmines; loops where every fix is structural produce a substrate that gets durably better with every turn.

Example (2026-06-01): one session ran six consecutive iterations through the foundation-edge receipt-signing path. The first verb tested was a single agent tool call; the chain produced three signed entries — `gate:denied:chain_render`, `delegation:granted:ironclaw`, `gate:allowed:chain_render` — documenting failure, operator intervention, and success in one continuous audit narrative. Each subsequent iteration surfaced a different class of gap: a delegation lifecycle UX hole, a data-dir default that diverged across subcommands, a foundation worker that ran its own edge chain in violation of P3, a stale wrangler OAuth session, an anonymous-receipt forwarding design gap, and a secret-value swap between two Cloudflare worker secrets. Each gap was real, each fix was structural rather than cosmetic, and the substrate ended the session materially more correct than it started — including two empirical success paths (`#40` chain_render via the gate, `#41` workspace actions via the foundation worker) that landed signed receipts on the operator chain for the first time.

The loop's diagnostic signature, when it's healthy: every iteration produces *at least one* genuine structural finding that the design phase didn't anticipate. Iterations that produce only cosmetic fixes are a sign the loop has stopped being load-bearing — either the substrate is genuinely quiet (the goal) or the iterations are being scoped too small to exercise real seams.

When to use the loop: when the structural design is in place but operational correctness is unproven. When *not* to use the loop: when a new architectural piece needs design first (the loop assumes the structure to test against exists; if a load-bearing piece doesn't yet exist, designing it loop-style produces incoherent fragments). The loop is the empirical proof discipline; upfront design is the architectural soundness discipline; they take turns.

Connects to *only production tests production* (same shape: the trust boundary is where the empirical work happens), *when a PoC keeps surfacing new friction at every layer, the friction IS the finding* (the loop is that pattern's healthy continuation — friction surfacing is the loop *working*, not failing), and the architecture's four-claims posture (each loop iteration should move at least one claim closer to empirically true).

### The chain configures the cockpit; cockpits are pure projections.

Tools whose users have one identity and one largely-uniform configuration can declare their command surfaces statically — a list of slash commands, a fixed menu, a hardcoded help text. That model doesn't compose with what the substrate actually has: per-operator delegated capabilities, lifecycle-tracked artifacts, gate-enforced authority, chain-anchored history. The operator's authority shifts as the chain advances; a static menu can't reflect that.

The architectural shape that does compose is: **the chain is the configuration. Each cockpit — CLI, Sage chat, future visual surfaces — is a pure projection of chain state into a native mode.** Restart any cockpit and its affordances reconstitute deterministically from the chain. What the operator can do *right now* is what the current chain state authorizes. When a fresh delegation lands on the chain, the cockpit gains the corresponding affordance immediately; when the delegation expires, the affordance disappears. There is no separate config file, no menu cache, no static declaration to keep in sync. The chain is the only source of truth; cockpits are projections.

This makes the substrate-readiness target sharper: each cockpit's source code asks the chain "what is currently authorized for this operator, projected through my native rendering mode?" and renders exactly that. Two practical consequences for code:

1. **Verbs are the unit; rendering is per-cockpit.** A verb in `zp-verbs` has one canonical implementation. Each cockpit registers a renderer for it — CLI as a flag/subcommand, Sage as a tool, visual surface as a button. The verb is invariant; the rendering varies. The cockpit never invents affordances that don't correspond to verbs.
2. **Cockpit affordances = projection of (operator's capabilities ∪ active-delegation capabilities) over the verb-set.** A verb whose capability the operator doesn't currently hold doesn't appear in the cockpit. Absence is the signal — no grayed-out entries, no "you must do X to unlock Y" hints. The chain decides; the cockpit shows.

Two implications worth pinning later:

- **Cross-cockpit consistency.** For every verb in `zp-verbs`, every operator-facing cockpit either implements its renderer or explicitly excludes the verb with a documented rationale. A discipline pin can assert this — no silent omissions, no surface drift.
- **Chain-driven presence implies chain-derived absence.** The substrate teaches operators what they *can't* do by not showing it. Decorative or aspirational affordances violate this principle as surely as decorative receipts violate signing-is-gravity.

Connects to *a tool is intent, crystallized* (Principle 6 — the verb is the crystallized intent; cockpits are the rendering surface, not the seat of truth), *the substrate proposes; operators sign* (proposals and signed artifacts both surface in the cockpit by projection, not by declaration), and *every bit counts* (Principle 4 — no decorative affordances). The lsof test has a cockpit-side counterpart: the substrate is mature when an operator can read any cockpit's affordance list and trace each entry to a chain receipt that authorizes it.

When this principle is in tension with a third-party convention (e.g., a tool's expected CLI shape includes commands the operator's chain doesn't authorize), default to the chain. The substrate is the source of truth; conventions accommodate it, not the other way around.

### Operational configuration with multiple write paths is structural drift waiting to happen.

When the same fact — a port number, an auth token, a process state — can be written by more than one independent code path, those paths will diverge. Not sometimes; always, eventually. The substrate will be coherent within each path's frame and incoherent across them, and the failure mode will look like a config problem when it is actually an ownership problem.

The diagnostic signature: you're editing two files to fix one thing, or you're restarting two processes to clear one inconsistency, or you're getting different answers depending on which path you entered the system through. That's the structural tell.

The fix is never to synchronize the paths more carefully. It is to eliminate all but one: pick one owner per surface, and make every other path delegate to that owner. For ZeroPoint specifically, "owner" almost always means the chain — every other surface (JSON files, env sidecars, in-process caches) is a projection or cache of chain state, never an independent source.

Three corollaries that matter in practice:

1. **Any write to operational configuration must be atomic across all consumers.** If `tool-ports.json` and `.env.zp` both encode port/auth state, they must be written together in one operation or not at all. A write path that updates one without the other introduces drift at the moment it runs.

2. **Process lifecycle events are configuration writes.** When a tool stops and restarts, its port binding, auth token, and PID all change. If the restart path doesn't go through the same governed exec flow that wrote the original configuration, those fields become stale. The stop button is a configuration event; it must be treated as one.

3. **Liveness checks must match the failure mode they're guarding against.** A `kill -0` check confirms a PID exists — it returns true for suspended (SIGSTOP) processes that are holding ports but not answering requests. If the failure mode is "port held by unresponsive process," the check must verify process state, not just existence.

Example (2026-06-28): ZP's port registry (`tool-ports.json`) and IronClaw's env sidecar (`.env.zp`) both encode the tool's port and auth token, written by separate allocation events at separate times. After a ZP restart and tile-based relaunch cycle, they diverged: the registry had port 8090 and token `eb7e46dc…`; `.env.zp` had port 9101 and token `zp-58ceaf72…`. The proxy forwarded to 9101 (from a stale `proxy_port` cache), IronClaw was running on 9101 (from `.env.zp`), but the proxy injected the wrong auth token (from the registry). Separately, the stop button had sent SIGSTOP not SIGTERM, leaving the old process suspended on port 9101 — alive to `kill -0`, dead to HTTP. Three independent drifts, one causal chain: multiple write paths, no single owner.

Connects to *when two reasonable architectural models conflict over the same surface, half-state is the failure mode* (same diagnostic shape applied to configuration rather than deployment models), *store-and-forward is primary* (the chain is the one owner; all other surfaces derive), and *every bit counts* (duplicate data paths are the anti-pattern Principle 4 is named for).

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- ALWAYS read graphify-out/GRAPH_REPORT.md before reading any source files, running grep/glob searches, or answering codebase questions. The graph is your primary map of the codebase.
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
