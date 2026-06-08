# State of the Substrate — 2026-05-15

*Written at the close of a marathon arc. Honest inventory of what's
built, what's designed, what's queued, what's coherent, what isn't.
Pre-commit pause before opening the next implementation arc.*

---

## What actually shipped this week

Verified empirically, not just merged:

| Task | Shipped | Property delivered |
|---|---|---|
| #150 | commits 0aab7b8 + 8c64f40 | Vault session-scoped Keychain reads — passkey treadmill eliminated |
| #151 | landed earlier | Audit store opener unified across CLI surfaces |
| #152 | commits 7f6397b + eb1975f + aba2b26 + 7a9d30d + 1ef0d06 | Singular sovereign root principle pinned (load_sovereign_root canonical loader + discipline pin + folded into ARCHITECTURE-2026-05.md §II.21) |
| #153 | commit 041c79b | ZP_SESSION_TOKEN injection from session.json into exec-launched tools |
| #154 | commit cabc916 | Regression fix on load_sovereign_root path-derivation + Fix B threading restoration |
| #163 | series this morning | IronClaw deployment unification — Model A (vault as single source of truth); ~/.ironclaw/.env deleted; OIDC/NEARAI/HTTP_WEBHOOK stale entries neutered |
| #147 | empirically evaluated | PoC chain narration: substrate-side complete; agent-rendered narration at 3/6 with structural answer (composition rules) identified |

The substrate is materially more coherent than 72 hours ago. Every secret traces to Genesis through one canonical path. The vault is the sole config source for IronClaw. Session tokens flow deterministically from server to exec wrapper to tool. The governance hook intercepts cleanly. Chain receipts render end-to-end through OpenAI in ~5 seconds. None of this was true on 2026-05-13.

## What's designed but not built

Substantial design surface accumulated during the marathon. Each is documented in a handoff or architecture note:

| Task | Surface | Doc |
|---|---|---|
| #131 | Workflow registry as workflow-kind layer of the Artifact Library | `docs/ARTIFACT-LIBRARY-2026-05.md` §11 |
| #139 | Substrate-as-Sovereign-IdP — SIWE-style sovereign-signed challenge protocol | Task description (no standalone doc yet) |
| #156 | Operator sign-in surface (the UX of #139) | Task description |
| #157 | Onboarding tightening — biometric-required + wizard narration extension | Task description |
| #158 | Trust page documenting privacy properties | Task description |
| #159 | Voice reference panel at app.zeropointfoundation.org/preferences/voice | Task description |
| #160 | Sage audio narration via local TTS through operator's voice receipt | Task description |
| #161 | voice_set Sage tool — conversational voice switching | Task description |
| #162 | Artifact Library — composition rules + cached/signed renderings | `docs/ARTIFACT-LIBRARY-2026-05.md` |
| #164 | Comet browser localhost cookie delivery investigation | Task description |

## What's still raw

Open seams that haven't been addressed and aren't yet in design:

- **Multi-tenant IronClaw** (#99, #120) — adopter onboarding for anyone but Ken is not yet wired
- **Vault-remove CLI** (#106) — needed to actually delete the stale OIDC/NEARAI entries the #163 work overwrote-but-not-deleted
- **Touch-ID-in-terminal hang** — substrate-server boot hangs when Touch ID dialog doesn't surface in terminal context; worked around with `--sovereignty login-password`, not fixed
- **Receipt signing on foundation worker** (#143) — receipts are stored as rows, not yet cryptographically signed; signing-is-gravity isn't fully true for foundation-issued receipts
- **Pilot polish bundle** (#142) — cosmetic + UX fixes from the Ken pilot, accumulated against the wizard
- **Code-signing the release binary** (#155) — funding-gated; adopter Gatekeeper friction without it

## Heuristics now codified

CLAUDE.md → Workflow heuristics now contains eight entries (five from prior weeks, three landed today):

1. Name and shape artifacts for their downstream consumer, not their immediate producer
2. For systems spanning trust boundaries, only production tests production
3. Demonstrate publicly with prerendered paths; interpret internally with live agents
4. Singular sovereign root: one authentication, everything derived
5. Pair conversational interfaces with reference surfaces that reveal the control space
6. **The substrate proposes; operators sign** (landed 2026-05-15)
7. **When two reasonable architectural models conflict, pick one explicitly. Half-state is the failure mode** (landed 2026-05-15)
8. **When a PoC keeps surfacing new friction at every layer, the friction *is* the finding** (landed 2026-05-15)

Each heuristic has a concrete worked example and explicit connections to the design principles in `docs/ARCHITECTURE-2026-04.md` §V½ (signing is gravity / identity is a key, not a location / there is no center / every bit counts) and to II.0 (contracts singular, implementations plural). The heuristic set is self-consistent: violations of one tend to manifest as violations of another.

## Architectural relationships — the picture

The pieces compose. Roughly:

```
                          ┌─────────────────────────────────────────┐
                          │  Genesis (single sovereign root, gated  │
                          │  by sovereignty provider, ceremony      │
                          │  once per process — #152 pinned)        │
                          └────────────────────┬────────────────────┘
                                               │
              ┌────────────────────────────────┼────────────────────────────────┐
              ▼                                ▼                                ▼
     ┌─────────────────┐             ┌──────────────────┐             ┌──────────────────┐
     │ Vault master    │             │ Audit signer     │             │ ZP_SESSION_TOKEN │
     │ key (BLAKE3-    │             │ seed (derive_    │             │ (file IPC,       │
     │ derived in mem) │             │ audit_signer_    │             │ session.json,    │
     │                 │             │ seed)            │             │ 0600)            │
     └────────┬────────┘             └─────────┬────────┘             └────────┬─────────┘
              │                                │                               │
              ▼                                ▼                               ▼
     ┌─────────────────┐             ┌──────────────────┐             ┌──────────────────┐
     │ Vault (encrypt- │             │ Signed receipts  │             │ Governance hook  │
     │ ed entries —    │             │ in chain         │             │ verifies tool    │
     │ tools/*, prov-  │             │                  │             │ calls            │
     │ iders/* — #163) │             │                  │             │                  │
     └────────┬────────┘             └─────────┬────────┘             └──────────────────┘
              │                                │
              │                                ▼
              ▼                       ┌──────────────────┐
     ┌─────────────────┐              │ Artifact Library │
     │ zp configure    │              │ (designed — re-  │
     │ exec (#89, #153,│              │ ceipts + comp-   │
     │ #163) — bridges │              │ osition rules +  │
     │ vault to env    │              │ voice anchor →   │
     │                 │              │ LLM → candidate  │
     │                 │              │ artifact → opera-│
     │                 │              │ tor signs → can- │
     │                 │              │ onical, citable, │
     │                 │              │ supersedable)    │
     └─────────────────┘              └─────────┬────────┘
                                                │
                                                ├──→ Backward: narrations, calendars, timelines, digests
                                                └──→ Forward: workflows (whose executions emit more chain receipts)
```

That's not the whole picture — the agentic-surface adapters (#72/#73/#74 — MCP/AG-UI/A2A), the verb-set work (#62/#63/#79), the multi-quorum sovereignty direction, and several other surfaces compose alongside. But for the operator-facing arc, this is the through-line: Genesis → derived material → encrypted-or-signed surfaces → operator-controllable artifacts and workflows.

## Critique

Worth being honest about. Three real concerns:

### 1. Design accumulated faster than implementation

Tasks #131, #139, #156, #157, #158, #159, #160, #161, #162, #163, #164 all surfaced this week. Six of them are designed in detail. Three are major architectural commitments (artifact library, sovereign-IdP, voice control arc). If we keep designing at this rate without shipping, the cognitive overhead of the queue starts to outweigh the substrate's actual readiness.

The walkthrough yesterday surfaced ten seams of friction; the response was to design ten architectural answers. Some of those are correct and durable (singular sovereign root). Some are speculative or premature (sovereign-IdP protocol depends on browser security models we haven't load-tested). Some are bundled together that probably shouldn't be (the artifact library currently covers composition rules + lifecycle + signing + library + workflows — that's four pieces under one task, even if they're related).

### 2. The Carlie pilot is the next forcing function and it's not in the queue explicitly

#136 (Carlie/Lorrie role reconciliation) is pending. #142 (pilot polish bundle) is pending. #99 (multi-tenant IronClaw on APOLLO) is pending. When Carlie actually arrives, the substrate needs to be ready in a specific shape: she can be onboarded via the wizard, she can sign in from a fresh browser, her IronClaw is multi-tenant-isolated from Ken's. None of those three pieces are built yet. The Carlie-readiness arc isn't its own task; it's spread across many.

### 3. The PoC #147 closure is honest but uncomfortable

3/6 is the rubric's "mostly passes, needs UX iteration" tier. We have a designed structural answer (composition rules). But until composition rules ship, the experience an adopter would see is mid-quality narration with format and closer drift. That's not zero — it's better than nothing — but it's not adopter-ready in the way #147's title implied. Worth being honest: agent-rendered surfaces are viable in principle, not viable in production yet.

## Sequencing questions worth pausing on

Before opening the next arc, three questions deserve explicit answers:

### Q1: What forces the work?

**Carlie is a goal, not a deadline.** She knows she joins when the substrate is coherent and load-bearing end-to-end. There is no adopter calendar pressure. The forcing function is the substrate itself: friction stops surfacing, the substrate is ready.

That recalibrates everything. The Carlie-readiness arc isn't urgent because Carlie isn't urgent. The substrate-readiness gate is what matters, and Carlie passes through when it opens. This is the load-bearing-honest principle (#91) restated: the substrate has to actually be ready, not approximately ready by a date.

What this means practically: the right work is empirical seam-finding and seam-fixing, not opening another design arc. Drive the substrate daily, surface friction, fix what surfaces, resist greenfield design until the seams stop appearing. "Loud substrate = still healing. Quiet substrate = signal it's ready."

The known unresolved seams (as of 2026-05-15): #164 Comet cookie delivery, #147 narration polish (via smallest #162 slice — composition rules), Touch-ID-in-terminal root cause, macOS code-signing for stable Always-Allow (related to #155, funding-gated), #143 receipt signing on the foundation worker, #149 IronClaw re-prompt loop. None individually large. Cumulatively they're the difference between "load-bearing in pieces" and "load-bearing end-to-end."

### Q2: Is the Artifact Library the next arc, or should it wait?

Arguments for opening #162 next:
- Closes #147 properly (composition rules)
- Enables #102 (FoundationTimeline), #103 (Calendar) cleanly
- Workflows-as-artifacts framing unifies the wizard work
- Caching benefit accumulates over time

Arguments against:
- It's the biggest architectural commitment on the table
- It doesn't directly unblock Carlie's pilot
- Composition rules alone (the smallest useful piece of #162) might be sufficient for now
- We just landed three big substrate principles; another big architectural piece risks running out of cognitive headroom

### Q3: Are we designing for the right adopter?

The substrate is shaping up for an operator who:
- Has biometric-capable hardware (#157)
- Has a local zp CLI running (#139)
- Can navigate a sign-in flow that involves deep-links or localhost handshakes (#139, #156)
- Knows what a chain receipt is (most surfaces narrate them as durable record)

That's a reasonable L4 founding-director profile. It's not a reasonable L5/L6 broader-adoption profile. Worth being explicit about: the substrate as designed assumes operator sophistication that scales linearly with sovereignty-tool literacy. Future arcs may need to design downward (lighter-touch onboarding for non-technical adopters) but that's not today's concern; today's concern is Carlie. As long as we're explicit about who we're designing for, the assumptions stay honest.

## Open question for the architect (you)

The substrate is in materially better posture than 72 hours ago. The design queue is rich. Carlie is a goal not a deadline. The forcing function is the substrate itself.

The reframe makes Option D the actual work: empirical seam-finding and seam-fixing until the friction stops surfacing. It's not a "pause" — it's the substrate-readiness arc done right. The seams to address (#164 cookie, #147 composition-rules slice, Touch-ID-in-terminal, code-signing, #143 foundation-worker receipt signing, #149 re-prompt) are each small. Working them down individually, in priority of operator impact, is the work.

The bigger architectural arcs (#162 artifact library, #156 sign-in surface, #157 onboarding tightening) don't need committing-to until the substrate's existing surfaces are quiet under daily use. Designing more while the existing surfaces still surface friction is the trap. Stay empirical.

What's the right next seam to fix? Probably #164 (Comet cookie delivery) since Ken uses Comet daily and the cookie-not-reaching path blocks the chain command at the browser layer. Secondary: smallest-#162-slice for composition rules, since that closes the #147 quality gap structurally rather than via anchor iteration ceiling.

Other open seams should surface from use rather than design speculation. Drive the substrate, fix what breaks, repeat. The substrate will signal when it's done healing.

---

## Refs

- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` § II.21
- `docs/ARTIFACT-LIBRARY-2026-05.md` — full artifact + composition + signing design
- `docs/handoffs/substrate-readiness-checkpoint-2026-05.md` — the morning plan that opened this arc
- `docs/handoffs/ironclaw-deployment-unification-design-2026-05.md` — Model A decision
- `CLAUDE.md` → Workflow heuristics — eight entries now
- Tasks #91 (the hardening pass umbrella), #147 (closed empirically), #150 / #151 / #152 / #153 / #154 / #163 (all shipped this week), #131 / #139 / #156 / #157 / #158 / #159 / #160 / #161 / #162 / #164 (queued or in design)
