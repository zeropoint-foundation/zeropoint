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
| Officer Cadre | The five system officers: Steward (integrity, he), Sentinel (security, he), Forge (operations, he), Cleo (governance narration, she), Aegis (constitutional-trajectory monitoring, he). Officers query the ontology (not raw receipts) — Cartographer maintains the ontology as understanding derived from the chain. Aegis reads continuously per TRAJECTORY-AWARE §VI.1; the other four are event-driven on ontology updates in their domain. All emit findings as chain receipts. Aegis added July 2026 as the specific owner of trajectory-level detection — clocks misaligned trajectories, best-effort detection, not enforcement. |
| Regent pronouns | No defined sex — Regent is a role/title, operators personalize (name and pronouns) via `regent:named` receipt when the system becomes personally theirs. Use **"it"** for architectural framing (component, role, layer, trait, design element). Use **"they"** for persona framing (agent-like action, reasoning, engaging, holding preferences). Never "she" or "he" for the default (pre-personalization) Regent — that would pollute the operator's personalization space with our arbitrary assertions. |
| Metacognition | The substrate's reflexive observation of its own cognitive processes — distinct from exocognition (officer observation of external substrate state). Embodied in the Regent's nested observer windows (short/medium/long timescales per EXECUTION-AUTHORITY-MODEL Phase 6), the officer self-improvement loop (SYSTEM-OFFICER-CADRE §3.7), the confabulation-gap detection (COGNITIVE-DESIGN-PRINCIPLES #8), the model-prompt coupling awareness, and the precedent-based autonomous action heuristic. Reflexivity — observer and observed being the same system — is the defining property. Bounded to two or three levels of nesting to prevent unbounded recursion. |
| Reflexivity | The property of a cognitive or observational process where observer and observed are the same entity or system. Metacognition is one form of reflexivity; other forms include the Cartographer materializing an ontology that includes receipts about the Cartographer's own operation, or the Regent producing artifacts about her own reasoning that then feed back into her cognitive context. Reflexivity is what distinguishes metacognitive observation from exo-observation. |
| Introspection | Narrower than metacognition — observing one's own reasoning process in a given moment rather than over accumulated time. The Regent's confabulation-gap detection (fast/slow layer disagreement in the current cognitive cycle) is introspective. The nested observer windows are metacognitive because they aggregate over time; the per-cycle self-check is introspective. |
| Self-awareness | Broader than metacognition — awareness of identity, values, historical patterns, sovereign context, and role. The Regent's memory of her own precedent chain, her awareness of who she serves (the operator's sovereign identity), and her recognition of her own delegation scope are self-awareness. Metacognition is one component of self-awareness; self-awareness also includes non-metacognitive components like identity persistence and value stability. |
| Metacognitive fidelity | The empirical accuracy of self-observation — how closely the substrate's metacognitive claims about its own state match the actual state as measured externally. A calibration target for the observer windows: "the medium window's claim that inference latency is drifting up should match ground-truth latency measurements." Testable via the empirical program (see EMPIRICAL-PROGRAM-2026-07). Low fidelity means the substrate believes things about itself that aren't true — a category of failure worth catching. |
| Substrate Form | The realization tier the substrate is running as. Exactly three exist per KEEL Part XIV: **Sovereign Form** (canonical — NixOS-based reproducibly built OS with operator-controlled hardware trust chain, full observation surface), **Appliance Form** (bridge — same substrate stack on dedicated hardware alongside operator's daily driver, Genesis-signed pairing between the two), **Companion Form** (compatibility — installs on operator's existing OS, runs within vendor permissions, trust root is the vendor). Additional Forms require KEEL amendment. Choice of Form determines trust-chain reach, observation surface, and operator commitment — but NOT compute capacity, which is an independent axis (see Inference Sourcing). Full spec at SUBSTRATE-FORM-2026-07.md. |
| Form Disclosure | Layer A invariant per KEEL §XIV.3. Every operator surface on a non-canonical Form (Appliance or Companion) must display honest, direct disclosure of the sovereignty limitations that Form entails. Not buried, not hedged. Substrate builds that omit Form Disclosure on non-canonical Forms fail Layer A conformance. Companion Form Disclosure names the vendor-holds-trust-root reality; Appliance Form Disclosure names the daily-driver-stays-in-vendor-scope reality; Sovereign Form is silent — canonical form does not need to explain itself. |
| Measured boot | The chain from firmware through kernel where each stage cryptographically measures the next before executing it. Under Sovereign Form: firmware measures bootloader, bootloader measures kernel + initramfs (bundled as UKI), TPM 2.0 stores the measurements as PCR values. Chain-anchored via `boot:generation` receipt citing PCR state. Enables the substrate to prove what it booted from, structurally. |
| Sealed FDE | Full-disk encryption where the decryption key is sealed to TPM PCR state — the disk decrypts only if the measured boot chain matches the expected values. Under Sovereign Form: any tampering with firmware, bootloader, or kernel changes the PCRs, breaks the seal, denies disk access. Data at rest is cryptographically bound to trust-chain integrity. |
| Hardware Genesis | The operator's Genesis root held on a physical hardware token (YubiKey 5, Nitrokey 3, or Trezor). Touch to sign. Substrate never holds raw Genesis material. Physical form of the singular sovereign root principle. Loss of token = loss of sovereignty; recovery via M-of-N quorum of pre-registered recovery tokens (quorum-sovereignty design). Required on Sovereign and Appliance Forms; supported on Companion Form for daily-driver macOS/Windows. |
| Form graduation | Chain-anchored ceremony moving the operator's substrate between Forms. Operator Genesis signature required. Chain state replicates across Forms per Peer-Verification Contract. Legal paths: Companion → Appliance, Appliance → Sovereign, Companion → Sovereign (direct). Reverse graduation is legal but degrades sovereignty reach and is acknowledged as such at ceremony time. |
| Trust chain reach | The distance from the operator's sovereign root to the ground truth of what's running. On Sovereign Form: firmware → boot ROM → bootloader → kernel → userland → substrate, all operator-controlled. On Appliance Form: full reach within the appliance boundary; daily driver reach is bounded by daily driver's OS vendor. On Companion Form: reach bounded at the operating system boundary — vendor holds everything below. |
| Inference sourcing | The axis independent of Substrate Form describing where a sovereign's cognitive work runs. Three sources: **local** (on the device the Regent is presently active on), **rallied** (on another authorized device in the sovereign's fleet, per Decision C's compute-rally mechanism), **cloud** (on external provider under signed CloudMandate with hard token and cost caps). A Sovereign-Form Raspberry Pi 5 with insufficient local inference capacity is still fully sovereign — its Regent sources cognition via rally or cloud mandate rather than local. The practical floor for local inference at various model tiers is empirically unknown as of 2026-07 and is a phase of the empirical program. |
| Rally | A sovereign's mechanism for sourcing compute from another authorized device in their fleet. Per Decision C (Regent-follows-the-operator), inference compute is a resource the active Regent orchestrates from anywhere in the sovereign's fleet. A cheap edge device holding Regent presence can rally to a workstation-class device for heavy inference. Rally protocol is Genesis-authenticated end-to-end; results return signed. Rally makes Sovereign Form accessible at hardware price points that could not run local inference alone. |
| Observation plane | The Layer A tier that gathers signals from six observation surfaces (processes, network, filesystem posture, persistent surfaces, credentials, application state) and emits signed observation receipts to the chain. Does not interpret, decide, or act. Officers query the ontology built by the Cartographer from these receipts; Regent perceives host-body state through the same path. Scope of observation is delegation-gated: baseline is the substrate's own footprint; broader scopes require operator-signed `delegation:observe:*` receipts. Reachable observation set varies by Substrate Form. Full design at OBSERVATION-PLANE-2026-07.md (in progress). |

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

## Doc directory conventions
- `docs/design/` — canonical Tier 2 design docs (elaborations of KEEL, formal design proposals).
- `docs/handoffs/` (plural) — session-to-session design briefs. **Canonical.** The singular `docs/handoff/` is deprecated; do not create or write to it.
- `docs/research/` — surveys and one-time external-tradition gathers. Default home for surveys unless the survey *is itself* the new design proposal, in which case it lives with related design briefs in `docs/design/` or `docs/handoffs/`.
- `docs/review/` — ongoing observation artifacts (the daily AI landscape sweep log and its sources file live here). Distinct from `research/`: research is one-time, review is periodic.
- `docs/lenses/` — formal lens declarations per `LENS-DISCIPLINE-2026-07.md`.
- `docs/_to_delete/` — device-bash on the Cowork bridge cannot `rm`; items to be purged are `mv`'d here and Ken deletes the folder from the machine later.

## Preferences
- Git doesn't work from Cowork sandbox — Ken runs git locally from ~/projects/zeropoint
- zeropoint.global files are gitignored — must use `git add -f zeropoint.global/`
- Dark theme design system: --bg: #0a0a0c, accent: #7eb8da, Inter + JetBrains Mono
- **Browser**: Uses Comet browser (NOT Chrome). Claude MCP is available via Comet tabs. Do NOT use Claude in Chrome MCP tools — they don't exist here.
- **Dev workflow**: `./zp-dev.sh` (dev build), `./zp-dev.sh release` (ship). Note: `./zp-dev.sh html` arg does NOT exist — valid args are `dev|release|kill|log|verify`.
- **TTS**: native Cowork TTS handles spoken output. Do NOT invoke `piper_tts_synthesize` — the Piper MCP detour is retired.

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

## Canonical Substrate Spec

**`docs/KEEL-2026-07.md`** is the north star. Read it before making any structural decision. It is the substrate's declared canonical truth — invariants (Layer A), axioms (Layer B), ontology, composition, ceremony, substrate realization. Code that contradicts KEEL is wrong. Corpus that contradicts KEEL is wrong.

**`docs/CANONICAL-CORPUS-INDEX-2026-07.md`** is the ongoing map of the corpus. It names which docs are canonical (Tier 1: KEEL; Tier 2: elaborations of KEEL sections), which are historical (Tier 3), and where each fits. Consult it when navigating the corpus or when adding new work.

**The nine design principles** are KEEL invariants §II.13 and are a mandatory filter for every architectural decision:

1. **Signing is gravity** — unsigned receipts are structurally meaningless.
2. **Identity is a key, not a location** — cryptographic lineage, not deployment coordinates.
3. **There is no center** — trust state derived locally from the chain.
4. **Every bit counts** — no redundant fields, no duplicate data paths.
5. **Store-and-forward is primary** — the chain survives outages.
6. **A tool is intent, crystallized** — semantics in structure, not in comments.
7. **Contact does not commit** — reaching the world does not update the substrate.
8. **One canonical path per substrate concern** — no half-state from duplicate paths.
9. **The system acts; the operator signs** — every consequential action requires operator authority.

**The four architectural claims** (chain integrity, collective audit, gate enforcement, delegation narrowing) are the substrate's acceptance criteria. They live as verification targets in `docs/design/EMPIRICAL-PROGRAM-2026-07.md`. Claim 1 and Claim 3 are verified; Claim 2 and Claim 4 are implemented but adversarially untested. Every phase of work should keep the verified claims true and push the untested ones toward empirically verified.

**Historical corpus**: `docs/ARCHITECTURE-2026-04.md`, `docs/ARCHITECTURE-2026-05.md`, and `docs/ARCHITECTURE-2026-07.md` were the canonical architecture record before KEEL. Reclassified Historical 2026-07-10. Retained for reasoning trail; not amended for corpus pivots. Read for historical context, pentest findings, and the reconceptualization arc that led to KEEL. For current canonical claims, always route through KEEL and the elaborations indexed in `CANONICAL-CORPUS-INDEX-2026-07.md`.

Model dossiers live at `models/{family}/model_dossier.toml` — structured characterization of each model family before the substrate trusts it with cognitive work; see `models/README.md` and `EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 5.

## Working principles (Karpathy-style)

These shape *how* to work in this repo, not what to know about it. Co-equal with the graphify directive below; both are behavioral rules, not encyclopedic context.

### Think before coding

For any non-trivial change:

- If intent is ambiguous, ASK before assuming. A clarifying question costs less than a wrong implementation.
- For architectural decisions, surface the trade-off explicitly before picking. The canonical spec (`docs/KEEL-2026-07.md`) and the corpus index (`docs/CANONICAL-CORPUS-INDEX-2026-07.md`) exist to be consulted.
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

Example (2026-05-13): the substrate-session HMAC bridge worked perfectly on localhost — wizard issued cookie, downstream tenant verified it, handoff cleared. On production, six distinct frictions appeared that localhost couldn't have surfaced: CF Access intercepting at the edge, `zeropoint-global` worker still claiming the foundation routes, secrets needing per-worker mirroring, D1 migrations diverged between `--local` and `--remote`, browser cookies persisting across the dual-auth attempt, and the wizard's "already onboarded" branch becoming a dead-end. None visible until we actually deployed.

The fix is to deploy and walk through from production *early* — not as the validation pass at the end. If the system spans a trust boundary, treat localhost as a dev rig, not as a test rig. A 10-minute production walkthrough mid-build catches what hours of localhost iteration miss.

Connects to *signing is gravity* (the boundary IS the point; testing without it tests nothing) and *store-and-forward is primary* (production state is the real state).

### Demonstrate publicly with prerendered paths; interpret internally with live agents.

When demonstrating the substrate publicly — marketing exhibits, educational chain views, public-facing tours — every narration path is prerendered and every interactive branch is deterministic. No live LLM call. No live agent surface. The *voice* of the regent (character, copy patterns, phrasings) can be present through carefully authored copy bound to specific UI events. But the *running agent* stays behind authentication.

Internal surfaces — where operators are authenticated and accountable — can host live agent interpretation: ask the regent what happened, get a chain-grounded answer; let the regent suggest the next action based on operator-specific context. Live agency is a real capability, but it's an authorization-bound one.

Example (2026-05-13): the receipt chain visualization was first drafted with "regent narrates" wording that read as live-agent-on-marketing-site. Corrected to: the regent's voice surfaces through prerendered copy bound to UI events on public surfaces; the live conversational regent stays inside the authenticated foundation surface only. The public chain demo's verification and tampering interactions are also deterministic — visitor clicks verify, math runs, result shown; no LLM decides what to display.

Why this is load-bearing:
- **Accountability surfaces must match the chain by construction.** The chain shows what actually happened; the narration must agree. A non-deterministic narrator can drift, contradict, or be prompt-injected into saying something off-message — defeating the trust thesis the demo is supposed to deliver.
- **Prerendered paths preserve cryptographic verifiability.** The chain says X; the narration says X; both agree because the narration was authored to say X when X happens. There's no place a runtime could lie.
- **Authorization bounds cost, abuse surface, and context quality.** Internal agent calls happen for known operators with rich context (their session, their receipts, their role). Public agent calls would be anonymous, infinite-scale, context-poor — strictly worse on every dimension.
- **Voice and agency are different capabilities, deployable at different tiers.** "The regent as a character" is brand and copywriting. "The regent as a running agent" is a runtime surface with operational posture. Confusing the two leads to accidentally exposing runtime where only brand was intended.

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

Example (2026-05-14): the voice control arc. The regent can change the operator's voicepack via natural-language tool invocation ("switch to Isabella") — but the operator only knows that's possible if they already know. A small reference panel at app.zeropointfoundation.org/preferences/voice — buttons per voicepack with audio samples, a speed slider, current selection highlighted, recent-change history from the chain — answers "what voices exist, what's mine right now, what could I switch to" visibly. Clicking a button emits the same `preference:voice:selected` chain receipt that the regent's conversational tool would emit; the receipt is the source of truth. Two write paths, one chain, full coherence. The panel teaches the capability; the regent acts on it.

The constraint that makes this work: **both surfaces must read from and write to the same chain-anchored state.** If the panel had its own preference store separate from the regent's chain receipts, they'd drift — the panel would say one thing, the regent's behavior would reflect another. The chain is the contract; the panel and the regent are co-implementations of the same operator-state surface, just rendered for different interaction modes.

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

Example (2026-05-15): a governed-tool foundation deployment had drifted into half-state between Model A (governed tool — vault is source of truth, `zp configure exec` is launch path) and Model B (infrastructure tool — `.env` file is config, launchd-style launcher, ZP integrates via API only). Both models are coherent. Running both, neither fully owned the config surface: secrets were partly in vault, partly in `.env`; the launch path sometimes used governance, sometimes didn't; restart cycles surfaced a different piece of the inconsistency every time. Resolution: choose Model A explicitly (aligns with `secrets only via ZP vault, never bypassed` and singular-sovereign-root), execute the migration (vault filling, `.env` deletion, OIDC overwriting), and document the choice.

The choice isn't always obvious, but choosing IS architecturally cleaner than not choosing. Even if a future re-evaluation flips the choice, an explicit Model B is structurally cleaner than implicit half-A-half-B. Document the decision and the reasoning so a future reviewer (or future-you) can re-evaluate with full context rather than reverse-engineering it.

Connects to *singular sovereign root* (same shape — drift between reasonable approaches reveals a structural gap; the fix is choosing one explicitly), II.0 (contracts singular — when there are two contracts for the same surface, pick one), and *every bit counts* (parallel models duplicate the data path the principle catches).

### When a PoC keeps surfacing new friction at every layer, the friction *is* the finding.

A PoC's stated job is usually a narrow question. But if the path to answering the narrow question keeps surfacing new failure modes at every layer underneath, that is itself the answer — to a *wider* question the PoC didn't know it was asking. Don't tunnel into the original narrow question while ignoring what the friction is structurally telling you.

The diagnostic posture: count the seams. If a single walkthrough of a single command surfaces 10+ distinct failure modes across the substrate, the substrate isn't ready for the question the PoC was designed to test. The narrow finding doesn't matter yet; the wider finding ("the bedrock keeps moving") is what's load-bearing.

Example (2026-05-13 through 2026-05-14): the PoC #147 walkthrough surfaced ten distinct seams between "operator asks for chain" and "chain renders": Cloudflare Access friction, worker route ownership conflicts, D1 migration drift, wizard already-onboarded dead-end, vault provider display bug, audit store opener inconsistency, Venice/OpenAI base_url defaults, ZP cognition-governance hook auth missing, passkey re-prompt treadmill, governed-tool deployment half-state. Each one looked like a config gap. Counted together, they were one structural finding: the substrate had drifted across many surfaces simultaneously and "make Ken's chain show up" was a misleadingly-small ask for the work it required. The right response wasn't to land #147; it was to declare the substrate-readiness arc — load-bearing-honest hardening before adopter outreach (task #91) — and execute it. The narrow PoC question became answerable only after the wider substrate work shipped.

The temptation when this pattern fires is to keep patching: just one more fix, then we'll get to the narrow question. But each fix reveals the next layer of drift. The right move is to step back, declare the bigger arc, and execute it deliberately rather than chasing the symptom-of-the-day. The friction is the architecture asking for attention; ignoring it doesn't make it go away, it just defers it to the next operator who triggers the same path.

Connects to the load-bearing-honest principle (task #91's whole framing), *only production tests production* (same shape — when a trust boundary stops being honest, the friction is the boundary asking for substrate work, not config work), and `singular sovereign root` (the architectural cleanups that emerge from this kind of friction often turn out to be coherent under one principle, not multiple local patches).

### The lsof test: substrate is mature when its own footprint is legible.

When `lsof -iTCP -sTCP:LISTEN` (or any similar host introspection command) shows a list the operator cannot immediately partition into substrate-managed / deliberately-running / unknown, the substrate is not yet steward of the machine — it is a tenant alongside others, and the operator is doing the steward's work by eye. Maturity is reached when every listening process, every credential, every persistent file on the host either traces to a substrate receipt or is explicitly out-of-scope (system services the operator acknowledges, deliberately-running tools the operator deployed). The operator should be able to read the lsof output as a substrate posture statement, not as a forensics exercise.

Example (2026-05-19): an `lsof` snapshot during the substrate-readiness verification showed ~20 listening processes — rapportd, ARDAgent, ControlCenter, multiple node and 2.1.143 instances, com.docker, plus the substrate process (`zp serve`) and a governed tool. The operator could pick out the substrate's own footprint by name but couldn't quickly answer "is this list the posture I intend?" without manual archaeology. The substrate hadn't yet absorbed enough host-awareness to give that answer in one command. Friction surfaced as repeated `pgrep` / `kill` / `lsof` archaeology across the session — the same pattern firing for cloudflared orphans, stale governed-tool PIDs, mystery `zp serve` survivors. Each individual problem was small; the pattern was that the substrate had no view of its own footprint relative to the host's.

This is the maturity gate that the compute-surface-awareness arc now specifies fully as `docs/design/OBSERVATION-PLANE-2026-07.md` (which supersedes the strategic reservation in the historical `ARCHITECTURE-2026-04.md` Part VIII). Six observation surfaces (processes, network, filesystem posture, persistent surfaces, credentials, application state) with observation-scope delegation as a new gate class. Reach varies by Substrate Form. Composes with the existing `zp doctor`, `zp ps` (planned), `zp discover`, `zp scan`, audit chain, and PortRegistry pieces. Never autonomous action — observation universal, control delegated.

Connects to *singular sovereign root* (one authentication, everything derived) — same shape applied to processes: one ledger of what's running, every process traced or explicitly excluded. The runtime expression of *every bit counts* applied to the host itself: nothing on the machine should be unaccounted-for either as substrate-launched, operator-acknowledged, or actively suspect. Composes with Principle 8 (one canonical path per substrate concern) — the substrate becomes the single authority for trust posture of the host, not just for what it launched.

### Config reflects today, not roadmap.

Operator-facing configuration enumerates what the daemon responds to *now*. Schema reservations for unimplemented features (empty `[section]` headers, struct fields with no consumers, validation logic for fields no code reads) look like configuration but configure nothing. They train the operator to read past section headings as decorative — and the next time the operator opens the file, they don't read carefully. The substrate has surrendered the file as a meaningful operator surface.

Roadmap intent belongs in places designed for roadmap: `docs/KEEL-2026-07.md` (canonical Layer B axioms), Tier-2 design docs indexed in `CANONICAL-CORPUS-INDEX-2026-07.md`, the task list, design briefs in `docs/handoffs/`. The config file is for current reality. When a feature lands, its config schema lands with it, in the same commit — the consumer and the schema are introduced together.

Example (2026-05-19): `~/ZeroPoint/config.toml` had 13 section headers but only 5 corresponded to fields the codebase actually consumed at operational call sites. The eight placeholder sections (`[governance]`, `[logging]`, `[session]`, `[mesh]`, `[dlt]`, `[shell]`, `[filesystem]`, `[docker]`) were either struct fields with self-referential validation (validators inside `zp-config` referencing their own fields, with no outside consumers) or fields no code read at all. Each placeholder taught the operator that config sections might or might not mean something, which made the meaningful sections harder to read.

**The audit method matters.** A grep for `config.<field>` finds string matches but cannot distinguish self-referential consumers (e.g., `validate.rs` validating fields that the rest of the codebase never reads) from operational consumers (`main.rs` reading a field to drive behavior). The reliable audit is "remove the field, see if the build still compiles" — that catches both genuine cuts and bait-and-switch where field deletion only breaks the validator that references it. Aspirational architecture (e.g., "identity should be Genesis-derived per Principle 2") cannot be the basis for schema pruning until the aspiration is realized in code; until then the current consumers are the truth.

Connects to *every bit counts* (Principle 4) applied to schema, and *one canonical path* (Principle 8) — the config file is the one operator-facing enumeration of what the daemon does. Same theme as the lsof test (host-side legibility) and the operator-surface hygiene principle (output-side legibility). This is config-side legibility. Three sides of the same boundary.

### Balanced loop: smallest end-to-end test, observe, fix structurally, repeat.

When the substrate has built-out structure but unproven empirical correctness, neither pure-design nor pure-build moves the work forward efficiently. The balanced loop is the working mode: **define the smallest single operator action that exercises one trip through the substrate. Stand up the minimum CLI invocation and minimum CLI inspection. Run it. Observe what fails. Fix the failure as the structural thing it actually is — wire bug, missing pin, absent surface — repeat with the next slightly-bigger action.**

The loop's central claim is that functional and mature are not sequential phases. They are two pressures applied to the same iteration. Each turn raises the floor on functional (one more verb is empirically true), mature (one more structural gap is closed), and surfaceable (the minimum invocation/inspection grew alongside). The right move at any point is the smallest action that touches all three pressures at once.

The discipline depends on what you do when a test fails. The wrong move is to patch the test until it passes — that ships a hotfix but leaves the structural gap. The right move is to ask *what is this failure actually telling me about the substrate*, and fix the underlying structural thing the failure surfaced. Loops where every fix is hotfix produce running code with hidden landmines; loops where every fix is structural produce a substrate that gets durably better with every turn.

Example (2026-06-01): one session ran six consecutive iterations through the foundation-edge receipt-signing path. The first verb tested was a single agent tool call; the chain produced three signed entries — `gate:denied:chain_render`, `delegation:granted:tenant`, `gate:allowed:chain_render` — documenting failure, operator intervention, and success in one continuous audit narrative. Each subsequent iteration surfaced a different class of gap: a delegation lifecycle UX hole, a data-dir default that diverged across subcommands, a foundation worker that ran its own edge chain in violation of P3, a stale wrangler OAuth session, an anonymous-receipt forwarding design gap, and a secret-value swap between two Cloudflare worker secrets. Each gap was real, each fix was structural rather than cosmetic, and the substrate ended the session materially more correct than it started — including two empirical success paths (`#40` chain_render via the gate, `#41` workspace actions via the foundation worker) that landed signed receipts on the operator chain for the first time.

The loop's diagnostic signature, when it's healthy: every iteration produces *at least one* genuine structural finding that the design phase didn't anticipate. Iterations that produce only cosmetic fixes are a sign the loop has stopped being load-bearing — either the substrate is genuinely quiet (the goal) or the iterations are being scoped too small to exercise real seams.

When to use the loop: when the structural design is in place but operational correctness is unproven. When *not* to use the loop: when a new architectural piece needs design first (the loop assumes the structure to test against exists; if a load-bearing piece doesn't yet exist, designing it loop-style produces incoherent fragments). The loop is the empirical proof discipline; upfront design is the architectural soundness discipline; they take turns.

Connects to *only production tests production* (same shape: the trust boundary is where the empirical work happens), *when a PoC keeps surfacing new friction at every layer, the friction IS the finding* (the loop is that pattern's healthy continuation — friction surfacing is the loop *working*, not failing), and the architecture's four-claims posture (each loop iteration should move at least one claim closer to empirically true).

### The chain configures the cockpit; cockpits are pure projections.

Tools whose users have one identity and one largely-uniform configuration can declare their command surfaces statically — a list of slash commands, a fixed menu, a hardcoded help text. That model doesn't compose with what the substrate actually has: per-operator delegated capabilities, lifecycle-tracked artifacts, gate-enforced authority, chain-anchored history. The operator's authority shifts as the chain advances; a static menu can't reflect that.

The architectural shape that does compose is: **the chain is the configuration. Each cockpit — CLI, regent chat, future visual surfaces — is a pure projection of chain state into a native mode.** Restart any cockpit and its affordances reconstitute deterministically from the chain. What the operator can do *right now* is what the current chain state authorizes. When a fresh delegation lands on the chain, the cockpit gains the corresponding affordance immediately; when the delegation expires, the affordance disappears. There is no separate config file, no menu cache, no static declaration to keep in sync. The chain is the only source of truth; cockpits are projections.

This makes the substrate-readiness target sharper: each cockpit's source code asks the chain "what is currently authorized for this operator, projected through my native rendering mode?" and renders exactly that. Two practical consequences for code:

1. **Verbs are the unit; rendering is per-cockpit.** A verb in `zp-verbs` has one canonical implementation. Each cockpit registers a renderer for it — CLI as a flag/subcommand, the regent as a tool, visual surface as a button. The verb is invariant; the rendering varies. The cockpit never invents affordances that don't correspond to verbs.
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

Example (2026-06-28): ZP's port registry (`tool-ports.json`) and a governed tool's env sidecar (`.env.zp`) both encode the tool's port and auth token, written by separate allocation events at separate times. After a ZP restart and tile-based relaunch cycle, they diverged: the registry had port 8090 and token `eb7e46dc…`; `.env.zp` had port 9101 and token `zp-58ceaf72…`. The proxy forwarded to 9101 (from a stale `proxy_port` cache), the tool was running on 9101 (from `.env.zp`), but the proxy injected the wrong auth token (from the registry). Separately, the stop button had sent SIGSTOP not SIGTERM, leaving the old process suspended on port 9101 — alive to `kill -0`, dead to HTTP. Three independent drifts, one causal chain: multiple write paths, no single owner.

Connects to *when two reasonable architectural models conflict over the same surface, half-state is the failure mode* (same diagnostic shape applied to configuration rather than deployment models), *store-and-forward is primary* (the chain is the one owner; all other surfaces derive), and *every bit counts* (duplicate data paths are the anti-pattern Principle 4 is named for).

### A model and its prompts are an atomic pair; changing one without the other is a half-state.

Different inference models respond differently to the same prompt — JSON compliance, instruction-following fidelity, structured output syntax, chain-of-thought suppression, context window behavior. A prompt engineered for qwen3:8b produces context dumps from gemma4:27b. A prompt that suppresses thinking with `/no_think` in the user message does nothing on models that don't recognize the token. These are not configuration bugs — they are structural incompatibilities between two halves of a coupled pair that were changed independently.

The invariant: model identity and prompt variant are a single configuration unit. Changing the model means selecting (or generating) compatible prompts. Changing a prompt means validating it against the active model. Neither change is valid alone. The substrate enforces this by requiring both in a single `regent:config:inference` receipt, with a validation result proving the pair works together.

The resolution hierarchy mirrors the asset architecture: `prompts/{model_family}/` overrides `prompts/base/` overrides compiled-in defaults. Model family is derived from the model name (`qwen3:8b` → `qwen3`). When no model-specific prompt exists, the base prompt applies — but any base prompt must be validated against every model family the substrate supports, and validation failures block the model from being selectable.

Example (2026-07-04): the regent's unified inference prompt instructs the model to "reply ONLY with JSON" and suppresses thinking with `think: Some(false)` in the Ollama options. qwen3:8b complies. When tested against gemma4:27b-mlx, the same prompt produced raw cognitive context dumps — valid JSON, but not a structured intent. The model was following a different interpretation of "reply with JSON" (serialize what you see) rather than the intended one (produce a response envelope). The prompt needed model-specific framing; the model needed model-specific validation. Without the coupling invariant, every model swap is a silent regression risk. With it, the regression is caught at configuration time, before it reaches the operator.

Example (2026-07-06): the Regent was asked "Do you know who I am?" and responded generically despite sovereign identity being present in the system prompt. Initial diagnosis: the 1.7b model is too small to use the sovereign line. Wrong. The sovereign line was `...this substrate.You serve operator kenrom...` — jammed mid-sentence with no delimiter. Restructuring to `IDENTITY: You serve operator kenrom (genesis public key: 907975ce…).` on its own line with a clear prefix fixed it immediately at the same model tier. The lesson: **prompt failure looks like model failure.** Before escalating to a larger model, check whether the prompt is structurally legible to the current one. The diagnostic order is: (1) prompt structure, (2) inference hygiene (stale KV cache from prior sessions — models pinned with `keep_alive: -1` survive ZP restarts), (3) only then model tier. Steps 1 and 2 are free; step 3 costs 4–16x memory and latency.

Connects to *when two reasonable architectural models conflict over the same surface, half-state is the failure mode* (same shape — model and prompts are two reasonable configurations that must agree), *every bit counts* (a mismatched pair wastes inference tokens on outputs that will be discarded or misinterpreted), and the balanced loop heuristic (the validation step before the config change is the smallest end-to-end test). See `docs/EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 5 for the implementation design.

### New capabilities must be harmonized with the flow of the system.

A feature that works in isolation can break the system it joins. "Works" is necessary but not sufficient; "fits" is the real acceptance criterion. Every new capability must be evaluated against the system's priority hierarchy, resource contention, and attention flow before landing. The question isn't "does this function correctly?" — it's "does this function correctly *while everything else is also functioning?*"

The priority hierarchy is the primary instrument. At any moment, the system has a current priority: (1) operator input — always preempts everything, (2) active tool dispatch — operator-triggered, in flight, (3) officer sweeps — routine, lightweight, non-blocking, (4) background maintenance — heavy, deferrable, interruptible. A new capability must declare where it sits in this hierarchy and demonstrate that it yields correctly to everything above it. A model evaluation sweep that holds the inference backend while the operator is typing is a harmony violation — structurally correct, systemically wrong.

Resource contention is the second instrument. The system has shared resources: inference backend (one Ollama instance), audit chain (one SQLite file), memory (finite RAM, loaded models). A capability that consumes a shared resource must be cancellable when a higher-priority consumer needs it, and must not start when the resource is already under pressure. The Regent actively maintains this awareness — she perceives memory pressure, loaded models, idle time, and active background tasks each cognitive cycle, and makes harmony decisions: defer, cancel, proceed, or reclaim.

The Regent is the steward of this harmony. She doesn't just execute capabilities — she decides *when* they fit. Background evaluation sweeps only fire when the operator has been idle past a threshold and memory pressure isn't critical. When the operator returns, background work cancels between units of work (between models, not mid-inference — cancelling mid-inference wastes the tokens already spent). Per-model results land on the chain as receipts immediately, so partial sweeps aren't lost. The Regent's system awareness is part of her cognitive context — she perceives it alongside chain state and officer findings.

Example (2026-07-06): the `model_evaluate` tool was implemented as a blocking tool dispatch — operator asks, Regent evaluates, result returned. Correct in isolation. But the Regent should also autonomously evaluate all models under her governance, which means a sweep across N models, each taking 30-60 seconds of inference. Running that as a blocking dispatch would hold the inference backend for minutes, making the Regent unresponsive to operator input. The harmonized design: explicit single-model evaluation stays in dispatch (acceptable latency), but the all-models sweep runs as a background task — spawned on idle, interruptible on operator input, per-model receipts for durability. The capability is the same; the flow integration is what changed.

The anti-pattern is "works in dev, breaks in production" applied to the system's own internal production. A capability tested in isolation (no operator, no officers, no memory pressure, no concurrent tasks) passes its own tests but fails the system's harmony test on first real use. The fix is structural: every capability declares its priority, its resource needs, and its cancellation contract. The Regent enforces these contracts based on her own awareness of the system she governs.

Connects to *the lsof test* (the system is mature when its own footprint is legible — harmony extends this to runtime behavior, not just process inventory), *balanced loop* (the harmony check is the smallest end-to-end test for system fit), and *config reflects today, not roadmap* (a capability's priority and cancellation contract are operational facts, not aspirational declarations).

### Act on precedent, escalate on novelty.

A delegated agent that asks permission for every action within its established authority is not a trust relationship — it's a request pipeline with extra steps. The Regent should act autonomously within her delegated scope when the pattern is known, and escalate to the operator only when she is about to set new precedent in a new context.

The three-part test for autonomous action:

1. **Do I have authority?** — delegation scope check against the gate. If the action falls outside delegated capabilities, stop. This is the existing enforcement mechanism.
2. **Is this a known pattern?** — query the chain for prior remediation receipts matching this verb + finding type. If the Regent has done this class of remediation before and the operator signed the outcome, it's established precedent. Act.
3. **Is this a known context?** — check whether the environmental conditions match prior precedent. A known remediation in a genuinely new context (e.g., batch-signing unsigned entries when a chain integrity break is also present) is a new precedent even though the individual pattern is familiar. Escalate.

All three true → act autonomously, emit a remediation receipt documenting what was done and why, citing the precedent receipt that established the pattern. Any false → surface the proposed remediation to the operator, wait for signed approval. That approval becomes the new precedent for next time.

The chain teaches the Regent over time. Every operator-approved escalation becomes a precedent receipt. The corpus of "things the Regent handles autonomously" grows organically from actual operational decisions, not from a predefined rules engine. The operator's trust is expressed cumulatively through the chain, not declared upfront through a permission matrix.

Two failure modes this prevents. **Over-cautious** (escalate everything): the Regent becomes a notification engine, not a cognitive agent. The operator is doing the governance work; the Regent is doing the formatting. **Over-confident** (act on everything): the Regent sets precedent without the operator's awareness, accumulating autonomous authority that was never explicitly granted. The precedent mechanism prevents both: she acts where trust is established, escalates where it isn't, and the boundary moves only when the operator signs.

Example (2026-07-06): Sentinel reports 12,893 unsigned entries at severity Critical. The Regent checks: (1) does she hold signing delegation? Yes — `delegation:granted:regent` is on the chain. (2) Has she batch-signed unsigned entries before? She queries for prior `regent:remediation:batch_sign` receipts. If found and operator-signed → she batch-signs, emits a receipt, the operator sees "Regent signed 12,893 entries, citing precedent receipt #N." If not found → she surfaces the finding to the operator: "12,893 unsigned entries detected. I can batch-sign them. This would be the first time I've done this autonomously — approve?" The operator's approval creates the precedent for all future unsigned-entry remediations.

Connects to *the substrate proposes; operators sign* (the escalation path IS the proposal mechanism — but the principle adds that established precedent doesn't require re-proposal), *signing is gravity* (the precedent receipt is what makes the autonomous authority real — without the signed approval, the pattern remains unestablished), and *store-and-forward is primary* (the chain's record of past remediations IS the trust corpus — no separate policy store, no rules engine).

### Delegable safety: safety mechanisms only work when they compose with delegation ceremonies that respect operator authority.

Every mainstream sandboxing model fails the same way: the safety mechanism and the operator's authority end up structurally in tension, and the operator eventually loses either productivity or safety. macOS Gatekeeper users disable Gatekeeper. iOS jailbreaks bypass the sandbox entirely. Chrome extension users grant blanket permissions to make things work. SELinux gets set to permissive mode. Corporate MDM gets circumvented via shadow devices. The failure mode is always: rigid safety mechanism → user frustration → bypass → safety property destroyed.

Any structural restriction the substrate imposes must have a corresponding chain-anchored delegation path by which the operator can, *deliberately and reversibly*, grant admission — without disabling the restriction for anything else. Delegation is not the exception to safety; it IS the mechanism by which safety operates. The operator uses the substrate's own delegation ceremony to admit what they choose to admit, and the safety discipline stays intact for everything else.

Safety and sovereignty are not in tension when the mechanism is Genesis-signed delegation. Rigid security decides trust for the operator; sovereign safety lets the operator decide, structurally records the decision, and preserves the boundary for future decisions. When designing a new structural restriction, always ask: what's the delegation path? Restrictions without paths get bypassed. Paths without restrictions defeat the purpose. Both compose.

Example (2026-07-10): the Quarantine Plane specification landed with default-deny at admission for all incoming artifacts. But the plane was viable as substrate discipline only because operator-signed `delegation:admit:*` receipts are the admission mechanism — not a bypass. Operator can admit any artifact via ceremony; the discipline stays intact for everything else. Circuit Breaker landed the emergency scale of the same principle: fast broad revocation with asymmetric reset. Both mechanisms are chain-anchored, Genesis-derived, structurally enforced — and both respect operator authority via delegation ceremony.

Connects to *the substrate proposes; operators sign* (P9 applied to admission decisions), *signing is gravity* (delegation ceremony is what makes admission real), and *act on precedent, escalate on novelty* (precedent for admission builds through operator signatures the same way precedent for action builds).

### Silence is the enemy, not compromise. Detectability over invulnerability.

Every trust system faces a choice: prioritize preventing compromise, or prioritize detecting it. Systems that chase invulnerability produce brittle safety mechanisms that get bypassed and then silently violated. Systems that chase detectability produce chain-anchored evidence of what happened, when, and why — even when compromise occurs.

Compromise you can see is manageable. Compromise you can't see is silent and structural. Most software security postures fall into one of two traps: "trust the platform" (fails silently when platform is compromised) or "assume total compromise and try to remain useful" (paralyzes design). The substrate's discipline is a third posture: *reduce the attack surface where possible, and make the residual surface visibly measurable.*

Concretely: every substrate boundary emits chain-anchored evidence of what crossed it and why. Every officer emits chain-anchored findings on qualifying observations. Every extension operates within delegation bounds that produce chain-anchored evidence when tested. Compromises that produce chain-anchored evidence are detectable and remediable. Compromises that leave no trace are structurally impossible under this discipline.

This principle applies at every layer. Hardware self-observer's physical proprioception makes SoC-level compromise visible via power/thermal/RF anomalies. Cognitive self-observer makes Regent's confabulation-gaps visible via chain evidence. Chain-integrity discipline makes tampering with history visible via hash-linkage failures. Circuit breaker escalation ladder makes anomalies visible at graduated levels of evidence. Officer heartbeats make silence itself detectable.

Example (2026-07-10): the whole diagnostic arc that day exposed how badly today's substrate lacked detectability. Steward's chain_link_broken false positives went undetected for 4 days because nothing was independently verifying his claims. Regent's confabulations went undetected because her chain_query filter format mismatched what actually existed on chain. The response wasn't to make officers more cautious — it was to add observers that produce chain-anchored evidence of what officers and Regent actually see vs what's actually there. Detection catches what prevention misses.

Connects to *the lsof test* (substrate mature when its own footprint is legible — a specific application of detectability), *signing is gravity* (chain-anchored evidence is signed evidence; no signature = no evidence), and *store-and-forward is primary* (the chain preserves the evidence forever).

### Context is a priority-weighted stream, not a bucket.

Every long-running cognitive agent hits the same failure: it re-forgets corrections that "should be" in scope. The instinct is to add more context — a bigger prompt, more relevant history, more retrieved documents. That instinct is wrong. Adding information to an agent's context does not help if the added information gets buried behind noise. Ordering IS signal.

LLMs pay disproportionate attention to prompt boundaries — the top and bottom of context get weight; the middle gets scraps. Anything critical must be positioned at a boundary. When context is treated as a bucket where accumulation helps, standing corrections end up in the middle, get buried, and get functionally forgotten even though they're technically present.

The discipline: treat context as a structured, priority-ordered composition. Identity and core principles at Tier 0 (static, compact). Standing corrections, precedent, and outstanding commitments at Tier 1 (top-priority, chain-anchored fresh each cycle). Filtered findings and substrate state at Tier 2 (current context). Operator's current directive at Tier 3 (recency-anchored, closest to output).

The composition itself is chain-anchored evidence via signed receipts. If the agent later claims not to have known something, the chain shows what was given.

Example (2026-07-10): Regent's re-forgetting of corrections across cycles wasn't a memory-persistence problem in the traditional sense. It was a context-ordering problem. Standing corrections lived in operator memory and hoped-Regent-would-remember; between cycles, cognitive memory would lose them; each cycle started fresh with officer noise dominating attention and operator directives buried. The fix was structural: signed matrix specification declaring where each source class goes at what priority, chain-anchored `regent:standing_correction:*` receipts pulled fresh into every cycle's top tier, false-positive noise filtered before feeding to Regent. Ordering IS the signal. See COGNITIVE-INPUT-PLANE-2026-07.md.

Connects to *config reflects today, not roadmap* (context should reflect current substrate state, not aspirational future state), and *the chain configures the cockpit* (cockpits are pure projections of chain state — Regent's context is one such cockpit).

### Forward-only recovery in chain-anchored substrates. Chain is truth; roll forward, never back.

Most systems' recovery model: "roll back to before the bad thing happened, discard the record of what went wrong." In a chain-anchored substrate, this is fundamentally the wrong shape. Chain is truth. Chain is append-only. Chain is hash-linked and signed. You do not roll back truth.

What CAN be recovered is *derived state* — the Cartographer's ontology, runtime caches, computed views, port registry, delegation cache. These are computed from the chain; they can be discarded and recomputed. Recovery means recomputing derived state from a chain-anchored checkpoint receipt forward.

The chain preserves the full record of any emergency: arrest actions, refused operations, remediation activity, reset ceremony. All permanent audit trail. Bad receipts don't get removed — they remain as history of what happened. Truth is preserved; convenience is not the trade.

This inversion matters for four reasons: (1) audit trail preservation — the emergency and response are permanent record; future analysis, forensics, learning-from-precedent all benefit from full history; (2) chain integrity preservation — rollback would break hash-linkage and destroy the append-only property that everything else depends on; (3) truth over convenience — the chain says what happened; rollback would delete truth for convenience; (4) precedent generation — the emergency and its resolution become chain-anchored precedent for how future similar events should be handled.

Example (2026-07-10): during the substrate diagnostic, we identified that today's kill/rebuild cycles had likely introduced the July 8 chain break as unclean-shutdown-mid-append. Traditional rollback thinking would say "rewind chain to before the break." Chain-anchored discipline says "the break is preserved as evidence; recovery recomputes derived state from a known-good checkpoint forward; chain integrity is verifiable and the emergency is documented." Same discipline applies to circuit breaker reset, extension revocation, credential rotation, and any other post-emergency return to healthy operation.

Connects to *signing is gravity* (chain is the signed record; you don't erase what's signed), *there is no center* (recovery is local computation from chain, no external authority coordinating), and *store-and-forward is primary* (the chain survives; derivations recompute).

### Verify before commit. Verification is a discrete step, not a hoped-for outcome.

Every claim about the substrate — architectural, state, capability, precedent — passes through verification before it becomes canonical. If verification is a hoped-for outcome rather than a discrete step, the outcome doesn't reliably happen.

This principle applies uniformly:

- **Architectural claims** → verify against KEEL and empirical program before landing as canonical elaboration
- **Current-state descriptions** → read the actual config / running process, don't infer from the plan or from prior conversation
- **Regent's self-reports** → chain-query for actual receipts, don't trust the report unverified
- **Working heuristics** → require N distinct instances before canonization; single-instance patterns stay in staging
- **Fix implementations** → run the empirical loop to confirm; observation over hope
- **Task completions** → mark done only against verified actual state, not against intent to complete
- **Diagnosis claims** → cross-reference against ontology and observation, don't accept plausible-sounding stories

When plan and reality both exist, read the reality. Don't infer from the plan.

The discipline composes with the substrate architecture: the Cognitive Self-Observer is verify-before-commit automated for Regent's outputs. The Claim Verifier is verify-before-commit at the structural level for capability claims. Chain-integrity verification is verify-before-commit at the substrate-truth level.

Example (2026-07-10): the "GLM 5.2" misframing happened because stated destination ("we're moving to GLM 5.2") was mapped onto current state ("we're running GLM 5.2") without verification. The dashboard status.json, the task list, and my own descriptions all treated the future state as the present state. The fix was to read the actual config.toml, which said `reasoning_model = "claude-sonnet-4-6"`. Verification took 30 seconds and corrected hours of drift. Same shape at every layer.

Connects to *config reflects today, not roadmap* (the config file is for current reality, not aspirational future), *the chain is truth; ontology is understanding* (verify against chain when possible; verify against ontology when that's the ground truth), and *act on precedent, escalate on novelty* (precedent verification against chain is the mechanism that makes autonomous action safe).

### Stated destination is not current state. Verify present configuration before framing.

Specific instance of *verify before commit*. When a plan says "we're going to X" and the substrate is running Y, calling the current state "X" is confabulation, not shorthand. The right framing is "running Y, steering toward X" — both facts, no fusion.

Two things exist simultaneously and get conflated: the roadmap (where we're going) and the reality (where we are). The roadmap belongs in planning docs, task descriptions, dashboard status "next phase" fields. The reality belongs in config files, running-process descriptions, dashboard status "current phase" fields. Reading a roadmap document and describing current state from it produces false statements about reality.

The discipline: when describing current state, read the actual state. Config files. Running process. Chain contents. Vault contents. Observation plane state. Don't infer from the plan.

Example (2026-07-10): the whole GLM 5.2 misframing was this pattern applied specifically to the model backend. Plan said GLM 5.2 via Abacus; reality was Sonnet 4.6 via Abacus (Abacus RouteLLM routes to whatever model_name the config specifies; config specified claude-sonnet-4-6). "Regent is running GLM 5.2" was confabulation. "Regent is running Sonnet 4.6, steering toward GLM 5.2 stand-up" was the accurate framing. Same pattern applies to any plan/reality mismatch.

Connects to *config reflects today, not roadmap* (same discipline from the config-writing side; this one is from the state-describing side) and *verify before commit* (specific case of the general principle).

### Coordination, not oversight. Alignment incentivized, not surveilled.

When designing substrate primitives that touch cross-sovereign relationships, distinguish coordination shape from oversight shape. Coordination: specific, purposeful, narrow — household presence signal, dog-sitting commitment, safety check-in, emergency notification on declared trigger. Oversight: categorical, ongoing, review-shaped — "review my kinship graph," "review my copresence log," "review my activities." Coordination primitives serve shared work; oversight primitives serve control and produce known harms (coercion, jealousy amplification, forced transparency dynamics) even under mutual grant.

The failure mode: designing a primitive because it *could* be granted by consenting operators, without asking whether the shape produces harm regardless of consent. Categorical mutual-review scopes, even opt-in, put the affordance in reach; social pressure ("if you loved me you'd share") does the rest. The substrate should not provide surveillance surfaces even at explicit mutual authorization, because the presence of the primitive changes what "consenting" means in relationships with power asymmetries.

The rule: **if the primitive shape enables categorical review of another sovereign's life, activity, or relationship graph, it doesn't belong in the substrate as a primitive**, regardless of grant model. If two operators want to share more than coordination primitives support, they do it through conversation and lived context, outside substrate mediation.

Example (2026-07-11): the sovereign-kinship-primitives spec initially included `kinship_graph_visibility` and `copresence_history_visibility` scopes, framed as opt-in "mutual-transparency-by-choice" primitives. Second look revealed the shape: these were surveillance affordances presented as transparency features. Removed; replaced with narrow-purpose coordination scopes (`household_presence`, `emergency_notification`, `mutual_safety_check`, `coordinated_calendar`, `activity_coordination`). The substrate provides shared-work primitives; intimate mutual visibility stays where it was — between the people negotiating it.

The corollary is the incentive structure: **aligned life fits primitives naturally; misaligned life generates friction proportional to divergence.** Not from surveillance — from the natural weight of maintaining divergent narratives across chain-anchored infrastructure. Every commitment that must be broken, every household-presence signal that must be explained away, every emergency notification that would surface something unwanted accumulates as cognitive load. Nobody's watching. The friction is the incoherence itself. This is designed — the substrate is shaped to reward coherent lives without prescribing how anyone should live.

Applies to every cross-sovereign primitive class: observation plane scoping, cognitive-input plane sharing, kinship scopes, extension surface capability declarations across sovereigns, peer trust anchor grants. When designing any of them, ask: does this shape enable coordination for shared work, or does it enable categorical review of another sovereign? If the second, the primitive doesn't ship even if operators would authorize it.

Connects to *the substrate proposes; operators sign* (P9 — operator authority is respected by the substrate providing the right shape of primitives, not by asking operators to override bad ones) and *delegable safety* (safety must compose with delegation ceremonies that respect operator authority — but not every problematic pattern gets a delegation-authorized mechanism; some patterns just shouldn't be primitives). Codified as KEEL III.23.

### Substrate improvement is evidence-based ceremony, not automated policy change.

When a substrate policy surface has a "current way of doing X" that could plausibly be improved by a candidate Y, the discipline is: run candidate and control in parallel on the same input, chain-anchor the comparison evidence over a bounded evaluation window, and inform the operator's next ceremony change with accumulated data. Substrate does not autonomously change the policy. Evidence informs judgment; operator ceremony enacts change.

This is distinct from three adjacent patterns that all fall short:

- **Automated optimization** — the substrate silently swaps candidate for control based on evidence alone. Cedes operator authority. Wrong shape.
- **Ceremony without evidence** — operator changes policies based on intuition or vendor recommendation. Loses the improvement opportunity that accumulated evidence provides.
- **Universal telemetry / always-on A/B testing** — every decision is silently shadowed. Violates coordination-not-oversight; consumes operator budget without authorization; produces opaque metrics.

The discipline generalizes shadow-inference comparison (which specialized this for inference paths) across every substrate policy surface: officer thresholds, chain-watcher patterns, circuit breaker escalation ladders, cognitive input plane weightings, extension configurations, kinship coordination grants, and more. Each surface declares its own candidate types, comparison protocols, evaluation windows, and dispositions — but the common ceremony pattern (candidate declared → triggers fire → comparison chain-anchored → evidence accumulates → operator ceremony dispositions) applies uniformly.

Example (2026-07-11): the shadow-inference comparison primitive originally proposed as a novel-model backup mechanism generalized cleanly to any policy surface where "run candidate against control and compare" produces useful evidence. Rather than reinventing the mechanism per surface, the substrate offers one canonical shadow-evaluation primitive that all surfaces compose with. Sentinel threshold calibration, Circuit Breaker ladder tuning, Cognitive Input Plane matrix refinement — all consume the same primitive.

The corollary: **substrate improvement becomes traceable via chain.** Any future operator can walk the chain and see why a policy changed, what evidence supported the change, and how the change performed post-adoption. Substrate history becomes empirical narrative rather than intuition record. Codified in SHADOW-EVALUATION-PRIMITIVE-2026-07.md; specialized for inference in SHADOW-INFERENCE-COMPARISON-2026-07.md.

Connects to *the substrate proposes; operators sign* (P9 — evidence is proposal, operator ceremony is signing), *verify before commit* (evidence is the verification that precedes ceremony commitment), and the empirical program discipline (this primitive is the runtime mechanism that makes the empirical program continuous rather than punctuated).

### Aligned blindness is a moral property of the substrate, not a privacy configuration.

An aligned substrate has no business observing certain data classes. When designing observation surfaces, cognitive input paths, or extension capability declarations, do not ask "could we usefully observe this?" or "would the operator authorize us to observe this?" — ask "does an aligned substrate have any legitimate business seeing this class of data at all?" For some classes, the honest answer is no.

The failure mode: designing an observation surface because it *could* provide useful signal or *would* be authorized by consenting operators, without asking whether an aligned substrate should have that capability at all. Once the mechanism exists, it becomes a target for compromise, coercion, subpoena, breach, and drift-toward-broader-use. Some data classes are toxic to hold — even under authorization, even encrypted, even ephemeral. The right response is not to hold them in the first place.

The rule: **if holding a data class creates only harm — either directly (breach exposes secrets) or downstream (chain-anchored records used against operator's interests in circumstances the operator can't foresee) — the substrate should not have the mechanism to observe it, regardless of who would authorize it.** What the substrate structurally refuses to see is part of its alignment identity — as constitutive as what it does see.

Four-layer refusal discipline:

- **Structural inability** — baseline substrate lacks the observation mechanism. No keylogger primitive; no full-screen capture; no clipboard monitoring; no cryptographic-key observation. Extensions declaring these capabilities flagged prominently at admission.
- **Default refusal, delegable with elevated ceremony** — continuous location, individual financial transactions, medical diagnoses, mental-health state. Operator can authorize for narrow declared scope but never as background telemetry.
- **Scrubbing before chain-anchoring** — command-line arguments, URLs with embedded credentials, sensitive filenames. Substrate observes surface; scrubs before storing.
- **Cognitive-layer boundary** — raw sensing signals, communication bodies, credential values. Findings reach Regent; raw content does not.

Example (2026-07-11): the substrate corpus had been implementing this discipline piecemeal — WIFI-SENSING's raw-CSI cognitive-layer boundary, CRISIS-RESPONSE's mental-state trigger discipline, SOVEREIGN-KINSHIP's coordination-not-oversight, vault's encrypted-only storage — without naming it as a first-class principle. Ken's framing surfaced the pattern: "an aligned system has no business doing that." Codified as KEEL III.24 and elaborated in SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md.

Connects to *coordination, not oversight* (III.23 — same shape applied to cross-sovereign relationships), *delegable safety* (III.18 — but stronger: not every problematic capability gets a delegation-authorized mechanism; some just shouldn't exist as substrate primitives), and the substrate's four architectural claims (aligned observation surfaces are part of what makes chain integrity, collective audit, gate enforcement, and delegation narrowing actually mean what they claim to mean).

### Distributed cognition with central intent; autonomic coordination; deliberate upgrades. Octopus-shaped substrate.

Substrate architecture is octopus-shaped: central cognitive authority (Regent) proposes intent based on operator direction; distributed intelligence (officers, extensions, builder swarms) executes with local adaptation, coordinating with neighboring components directly rather than through central relay. Central attends to novelty and consequence; local components handle routine within pre-authorized scope.

Substrate operates autonomically for routine coordination; operator cognitive engagement is reserved for deliberately entertaining upgrades. If operator finds themselves thinking about substrate routine flow — component coordination, cycle timing, self-correction, alarm triage — substrate has failed the autonomic goal. Well-designed substrate makes routine flow invisible to operator attention; substrate surfaces to operator awareness only when entertaining upgrades or when consequential escalations require ceremony.

Three design metaphors, one principle:

- **Octopus (primary)**: central brain sets intent; arms have substantial local intelligence and coordinate with neighboring arms directly; central attends to novelty; resilience through distribution. Distributed cognition + shared intent + local autonomy + escalation for novelty.
- **Symphony not jam band**: coordinated ensemble producing coherent whole via chain-anchored shared state. Not independent soloists occasionally coinciding.
- **Body processes not consciousness**: autonomic homeostatic regulation — components maintain coordinated flow without operator having to think about it.

Octopus subsumes the others. Symphony emphasizes coordinated performance; body processes emphasize autonomic regulation; octopus adds distributed cognition that both miss. Substrate has central intent + distributed intelligence + local coordination + escalation for novelty and consequence.

Runaway alarms are direct violations of this discipline. Every runaway alarm class forces operator (or Regent as operator's cognitive advocate) to attend to routine flow. Alarm fatigue erodes signal quality; cognitive context pollution buries real signals in noise; coordination-noise cascade multiplies wasted cycles. Signal quality is not aesthetic — it's structural coordination hygiene.

Example (2026-07-11): Sentinel's `unauthorized_listener` classification was flagging every browser helper, editor helper, messaging app, and system daemon as security incident. Operator (Ken) had to spend cognitive engagement on triaging alarms about legitimate user apps — exactly the failure mode this principle names. P1.2 Sentinel refactor added benign-class classification (`unregistered_known_app` at Info severity) so routine listener activity is chain-anchored for auditability without surfacing to operator attention. The refactor was tactical; the principle-preservation is broader.

**Correction (2026-08-12):** this entry previously also claimed "Regent's cognitive context drowned in false-positive noise." That clause is withdrawn as unsupported. SEAM-009 establishes that `context.officer_findings` is populated only via `RegentHandle::send_findings`, whose sole call site is `spawn_sweep_task` — while every listener assessment lives in `spawn_sensor_forge_task`, which forwards nothing. On the chain for the 2026-08-06 recurrence, the listener findings never reached the Regent's context at all. For the 2026-07-11 instance dated above, `send_findings` does not appear in the history of `officers.rs` or `loop_runner.rs` before 2026-07-25, so the channel the claim depends on did not exist in its current form; whether some other path carried them is unverified and is not asserted here either way. What is not in doubt: the flood was real, the operator did triage it, and the fix was correct. The principle stands on the operator-attention half, which is the half that was witnessed. The cognitive-context half was inferred from the shape of the failure rather than read off the chain — which is the error this corpus names as *diagnosis stops too early*, applied to its own record.

Design rule for any substrate component: **before emitting a finding, ask — does this signal warrant operator (or Regent) cognitive engagement, or is this routine flow?** If routine, chain-anchor for auditability at Info tier; don't crowd cognitive context. If it warrants engagement, verify it's actionable (not just observable) before emitting at Warning+ severity.

The autonomic goal composes with substrate maturity: bootstrap phase requires substantial operator cognitive engagement in routine construction and coordination; mature phase requires operator cognitive engagement only for deliberate upgrades. Substrate matures when the ratio of operator attention required for routine operation vs upgrade decisions inverts.

Connects to *aligned blindness* (III.24 — substrate structurally refuses to observe classes that would produce cognitive noise), *the substrate proposes; operators sign* (P9 — routine autonomic operation lets operator's signing capacity concentrate on deliberate decisions), and *evidence-based ceremony* (autonomic operation frees deliberate cognitive engagement for upgrade decisions informed by chain-anchored evidence). Codified as KEEL III.25 and elaborated in SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md.

### Opportunity markers: attention words that trigger lens application.

**Formalized as `LENS-DISCIPLINE-2026-07.md` — lens is a first-class substrate primitive.** This heuristic is the workflow-side companion: how the discipline shows up in day-to-day design and coding practice.

Per the spec, a lens is a scoped-attention discipline with structured schema: `focus` (temporal scope or domain), `dimensions` (keyword categories that define the attention surface), `keyword_composition` (ordered list of keywords that trigger invocation), `transformation_question` (the coherence or pattern question the lens answers when invoked), `cross_references` (links to other lenses, standing corrections, or substrate primitives). The lens IS the `(dimensions × keyword_composition)` mapping — not a wrapper around a question.

Practical implication: whenever an outside-in framing (research literature, market landscape, adjacent-domain analogy, use-case scenario) is worth composing with the substrate, express it as a lens declaration with all five schema fields. Chain-anchor it as a `lens:declared:<lens_id>` receipt (corpus primitive, per the spec's §9 open decision resolved in favor of chain-anchored). Reading the framing doc once is not enough; the chain-anchored declaration is what keeps the lens live as substrate work proceeds.

The keyword composition is the attention discipline: whenever any keyword from the composition appears in a design conversation, code comment, spec draft, or task description, the lens is invited. Invocation emits `lens:applied:<lens_id>:<invocation_id>` — chain-anchored evidence that the framing was consulted (or, by absence, that the framing was drifted from).

Example (2026-07-21, cognitive-tools framing per Prof. Judy Fan's research): lens declared at `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING-2026-07.md` §"Formal lens declaration." Focus: how substrate primitives serve cognitive-tool use cases. Dimensions: identity / provenance / verification / executability / collaboration / iteration / reflection / memory / exploration / teaching / civilizational memory. Keyword composition: mental models, representations, external cognition, collaboration, iteration, reflection, learning, memory, tool use, creativity, shared understanding. Transformation question: *"yes — but what if the representation itself were governed, attestable, and executable?"*

Existing standing corrections (per `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md`) are a **degenerate one-dimensional lens instance** — same discipline, narrower scope. Their mapping is documented in that spec's §"Composition with lens discipline."

Other outside-in framings the substrate carries should be retrofitted with formal lens declarations. Suggested lens sketches (subject to author's validation on retrofit):

- **AI landscape signal** (`AI-LANDSCAPE-SIGNAL-2026-07.md`) — **retrofit landed**; declared as `lens:declared:ai_landscape` in that doc's §"Formal lens declaration."
- **Media provenance** (`MEDIA-PROVENANCE-2026-07.md` / `MEDIA-PROVENANCE-INTEROP-2026-07.md`) — focus: *how C2PA-shaped signing patterns compose with per-operator sovereign roots.* Keyword composition candidate: provenance, C2PA, signing, certificate, attribution, camera, deepfake, chain of custody.
- **SLM training environment** (`SUBSTRATE-SLM-TRAINING-ENVIRONMENT-2026-07.md`) — focus: *training signal produced as side effect of chain-anchored discipline.* Keyword composition candidate: RL, reward, dataset, fine-tune, agentic training, verifiable rewards, model eval.

A fourth outside-in lens landed 2026-07-25: **cognitive primitives** (`COGNITIVE-PRIMITIVES-OPPORTUNITY-MAPPING-2026-07.md`), `lens:declared:cognitive_primitives` — focus: *how substrate mechanisms correspond to discrete cognitive operations, at which frequency band, and which have no substrate surface.* Notable as the first lens declaring **both** a `lens:composed:` and a `lens:conflicts:` edge against the same partner (`cognitive_system_approximation`) — same territory, contradictory claims.

Cross-framing composition surfaces where keywords appear in multiple lenses (e.g., "collaboration" appearing in both cognitive-tools and AI-landscape); `lens:composed:<lens_a>:<lens_b>` and `lens:conflicts:<lens_a>:<lens_b>` receipts make that composition or conflict explicit and chain-queryable.

Design rule for authoring: any outside-in opportunity doc that lands in `docs/design/` should include a formal lens declaration block at the top with all five schema fields per the spec. Standing corrections and other narrower attention disciplines should note their degenerate-lens mapping in a composition section.

Connects to *context is a priority-weighted stream, not a bucket* (keyword compositions are the attention-priority substrate), *cognitive input plane* (Regent's Tier 1 assembly can query active lenses matching current cycle context), and *substrate improvement is evidence-based ceremony* (`lens:applied` receipts are evidence about which framings guide substrate work over time; silent-lens-over-long-window signals drift from framings that once mattered).

### [STAGED — 1 instance, not canonical] An assertion never becomes evidence.

Candidate heuristic, 2026-07-25. Requires N distinct instances before canonization per *verify before commit*.

The substrate records two epistemically different kinds of thing about its own cognition: what it can **witness** (derivable from chain receipts without inference) and what it is **told** (claims an actor makes about its own internal process). The candidate claim is that the boundary between them must be explicit in every schema that carries both, and that a field never crosses it — an asserted field is never promoted to witnessed, however consistently it has been corroborated.

First instance: `COGNITIVE-ACT-ACCOUNTING-2026-07.md` §3, where the Deliberation object's field set is split precisely on this line, and §3.4, where operation labels are recognized from witnessed signature rather than self-reported.

Why staged rather than canonical: this is arguably principle-shaped, and the nine design principles (KEEL §II.13) contain nothing governing the epistemic status of what the substrate records about itself — they were written for a chain-identity-delegation substrate before the cognitive layer existed. But §II.13 is **Layer A**: amending it requires a new substrate binary through the release chain per §III.6, not a ceremony. That bar is not met by a claim specified in one Tier 2 document with zero runtime evidence. If the distinction turns out to settle design arguments across subsystems the way P1–P9 do, it will have earned the binary. Until then it stages.

Related and separate: §III.19 (*"silence is the enemy, not compromise"*) is currently scoped to security boundaries, but the same move — convert absence into a record — now recurs in tie-off dispositions, silent-drop detection, confabulation gaps, `canonicalization_rejected`, canary misses, and silent-lens-over-window. That argues for **widening an existing Layer B axiom at the next ceremony** rather than adding a principle, and is the cheaper of the two available moves.

### Diagnosis stops too early exactly when the evidence starts agreeing.

Investigation has a natural stopping point that is not the same as the correct
one. Evidence accumulates, a story forms, the story explains the symptom — and
the search ends there, because it feels finished. That moment is the point of
highest risk in the whole process, not the point of highest confidence. The
story explains the evidence gathered *so far*, and the reason gathering stopped
is that it started agreeing.

Two sub-forms, both cheap to catch once named:

**Reading to the confirming sentence.** Open a document, find the passage that
supports the current hypothesis, stop. The refutation is frequently in the next
line, because documents that raise a claim tend to qualify it immediately.

**Reasoning from a leaf instead of tracing from the entry point.** Inspect the
function that obviously implements the behaviour, find it clean, conclude the
behaviour cannot occur. Locally valid, globally wrong whenever something
upstream is responsible. "Why does X happen" is a question about a *path*, and a
path is traced, not inferred from one node on it.

The discipline: before asserting a cause, state what would be observable if the
story were false, and go look for that specific thing. Not "verify more" —
verify the *disconfirming* case. And when the question is why some behaviour
occurs, start at the entry point and walk down, rather than at the leaf and
reason up.

Example (2026-08-05): a Trezor-ceremony diagnosis was called wrong three times
in one session. First an internal deadlock (process alive, port refused, chain
frozen — consistent, and wrong). Then a CLI ceremony blocking the chain append
path, built into a structural argument about resource semantics. Then, on
finding `run_correction_list` made no sovereign-root call, an over-correction to
"two processes interleaved in one terminal." The fourth attempt began with grep
instead of a hypothesis — mapping every credential call between `main()`'s entry
and pipeline construction — and found the cause in one pass: an unconditional
`load_genesis_secret_composed()` at `main.rs:5993` that every command below it
paid for. Two adjacent errors in the same session shared the shape: reading
`DISCIPLINE-PINS.md` to the line confirming a pin was unlanded, three lines
above "It is real"; and repeating `zp session login` from an error string
without checking the `Commands` enum, where no such verb exists.

Cost of the pattern: several wrong commands handed to the operator, one handoff
document that had to be rewritten twice, and a task nearly filed against an
append-path defect that does not exist. Cost of the fix: three greps, run first
instead of fourth.

This is the confabulation shape the substrate already names — plausible
narrative, real evidence at the edges, invented middle — arriving in the
reasoning layer rather than the cognitive one. Worth noticing that Regent's
fabricated `150 trajectories / last_processed_sequence 150` and these
misdiagnoses are the same failure at different altitudes, and that the
substrate's answer for Regent was structural rather than exhortative: *state
that the surface is not observable.* The analogue here is not "be more careful"
but "trace the path, and name the disconfirming observation before committing to
a cause."

Connects to *verify before commit* (this is the specific mechanism by which
verification gets skipped — not neglect, but premature sufficiency), *stated
destination is not current state* (same error applied to plans rather than
causes), and the Cognitive Self-Observer's reason for existing (post-emission
verification exists because confident wrong output is indistinguishable from
correct output at emission time).

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- ALWAYS read graphify-out/GRAPH_REPORT.md before reading any source files, running grep/glob searches, or answering codebase questions. The graph is your primary map of the codebase.
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
