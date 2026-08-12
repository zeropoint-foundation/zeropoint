# the Regent Onboarding Wizard — Interaction Script

**Document type:** Interaction spec. The conversational contract the implementation follows.

*2026-05-12. The conversational spec for the director-onboarding wizard at
`zeropointfoundation.org/onboard/`. Anchored in
AGENT-AS-UX-ARCHITECTURE-2026-05.md (the Regent's voice, Jarvis-referenced)
and STAFF-ONBOARDING.md (operational procedure). Drives the worker +
frontend implementation that follows.*

## Purpose

This document is the spec for what the Regent *says* at each phase of the
onboarding ceremony, what decision moments the director faces, what
receipts emit, and how edge cases are handled. The implementation
follows the script — endpoint shapes and UI components serve the
conversation, not the other way around.

The script is voice-first because the agent's framing is the
substrate's UX architecture. The same script works for Ken (the first
pilot) and for the four operational directors (Lorrie, Carlie, Katie,
Louise) who follow — the Regent's tone tunes slightly per director per
AGENT-AS-UX §"Per-director adaptation," but the structural shape is
shared.

## Conventions used in the script

- **the Regent says:** the literal line(s) the Regent emits to the director.
- **Director sees:** the visual / structural UI elements on the page.
- **Director decides:** the explicit decision moment.
- **Receipt emitted:** the audit-chain entry produced by the phase.
- **Edge:** named failure mode and the Regent's response.

## Phase 1 — Welcome

**Director sees:** A simple page with the Foundation logo at top. Below
it, a section titled "Active directors awaiting onboarding." Each name
appears with its role: *Ken Romero — Executive Director*, *Lorrie [last]
— Secretary*, *Carlie [last] — Advisor*, etc.

**the Regent says:**

> Welcome to ZeroPoint Foundation onboarding. I'm the Regent — the
> Foundation's assistant. To begin, identify yourself from the list
> below.

**Director decides:** Clicks their name.

**the Regent says (after click):**

> Hello, Ken. Before we begin: this ceremony establishes your
> cryptographic identity with the Foundation. Three things will happen
> — you'll generate a keypair, record a recovery path, and demonstrate
> how your authority works. Each step is yours to take. The whole
> flow runs about fifteen minutes.
>
> Your call: proceed when ready.

**Receipt emitted:**
```
claim:    onboard:start
subject:  ken
metadata: { phase: 1, browser_agent: <UA>, started_at: <ts> }
```

**Edge — director's name not in the list:** the Regent shows the active
list with an additional line: "If you don't see your name, the
substrate hasn't been notified you're joining. Reach out to Ken."

**Edge — director already onboarded (real public key in D1, not placeholder):**
the Regent says: "Ken, your operator identity is already bound to a real
key. If you're trying to recover access or re-onboard, that's a
different flow. I'll log the attempt and flag it for review."
Receipt: `onboard:start:already-onboarded`.

---

## Phase 2 — Identity

**Director sees:** A page explaining what's about to happen, with a
single "Generate" button.

**the Regent says:**

> Now I'll generate your cryptographic identity. The keypair is created
> on this device, in your browser, using Web Crypto. The private key
> never leaves this machine — not to me, not to the substrate, not to
> anyone.
>
> Your public key becomes your authority for every action you take in
> the Foundation. The private key is what proves it's you.
>
> Your call: proceed.

**Director decides:** Clicks "Generate."

(WebCrypto runs: `subtle.generateKey({name: 'Ed25519'}, true, ['sign', 'verify'])`.
Public key extracted, fingerprint computed.)

**the Regent says (after keygen):**

> Done. Your public key fingerprint is `a3f2…7c91`.
>
> Glance at the first and last four characters — `a3f2` and `7c91`.
> Those are how you'll recognize your real key on this device in the
> future. If anything ever shows a different fingerprint, stop and
> tell me.

**Director decides:** Clicks "Continue" (after looking at the
fingerprint).

**Receipt emitted:**
```
claim:    onboard:identity:generated
subject:  ken
metadata: { phase: 2, fingerprint: "a3f2…7c91", generated_at: <ts> }
```
*(No private key, no full public key — just the fingerprint. The full
public key is held in the browser until phase 3.)*

**Edge — WebCrypto unavailable:** the Regent says: "This browser doesn't
support the cryptography we need. Try Chrome, Firefox, Safari, or Edge
on a desktop. If you're on a managed device, the Foundation may need
to whitelist crypto operations. Tell me which browser you're using
and I'll flag it."
Receipt: `onboard:identity:browser-unsupported`.

---

## Phase 3 — Register

**Director sees:** Page showing the fingerprint from phase 2 + a
"Register" button.

**the Regent says:**

> Now I'll register your public key with the substrate, replacing the
> placeholder that's been holding your operator slot. This is a
> one-shot operation — once it succeeds, your key is your authority
> for every action you take here. The placeholder gets retired; future
> registration attempts on your operator-id will be refused.
>
> Your call: register now.

**Director decides:** Clicks "Register."

(Frontend POSTs to `/api/onboard/register-identity` with `{operator_id, public_key_hex}`.
Worker validates the placeholder is still in place, replaces it, emits
the substrate-side receipt.)

**the Regent says (after success):**

> Registered. Your key is now bound to operator-id `ken`. From this
> moment, the substrate accepts requests signed by your key and
> refuses anything else under your identity.

**Director decides:** Clicks "Continue."

**Receipt emitted (worker-side, signed by the substrate):**
```
claim:    operator:registered
subject:  ken
metadata: { phase: 3, public_key_hex: <hex>, registered_at: <ts>,
             replaced_placeholder: true }
```

**Edge — placeholder no longer in place (already registered or attack):**
the Regent says: "Registration refused. Your operator slot already has a
real key. If that's wrong, this is a real incident — tell me now and
I'll surface it to Ken."
Receipt: `onboard:identity:registration-refused`.

**Edge — network failure / 5xx:** the Regent says: "Couldn't reach the
substrate. Your key is still on this device, not lost. Try again in a
moment, or I'll surface this to Ken if it keeps failing."
*(Frontend retains the public key in memory; allows retry.)*

---

## Phase 4 — Recovery

**Director sees:** A page that displays 24 words in a 4×6 grid, in a
distinct monospace font, framed clearly. A warning banner above the
grid. A checkbox below. A "Continue" button that's disabled until the
checkbox is ticked. *No copy button. No share button. No screenshot
helper.*

**the Regent says:**

> Now the recovery phrase. Twenty-four words. If you ever lose this
> device or its disk fails, those words are how you regain access to
> your operator identity. No one — not me, not the substrate, not
> Ken — can recover them for you. They're yours alone.
>
> Write them down. On paper. By hand. Twice. Keep the two copies in
> physically separate places — one at home, one in a safe deposit
> box, or similar.
>
> Don't photograph them. Don't email them. Don't store them in a
> notes app or password manager. Don't read them aloud on a call
> you don't control.
>
> Take your time. Write carefully. When both copies are done, confirm
> below.

**Director decides:** Writes phrase down on paper (twice), then ticks
the "I've written this down on paper, in two places" checkbox, then
clicks "Continue."

**the Regent says (after ack):**

> Logged. The substrate has recorded that you confirmed your phrase is
> written down — not the phrase itself, just the acknowledgment. If
> you ever need recovery, the substrate will ask for the words; you'll
> read them from the paper you just wrote.

**Receipt emitted:**
```
claim:    onboard:recovery:acknowledged
subject:  ken
metadata: { phase: 4, acknowledged_at: <ts> }
```
*(No phrase content captured. The acknowledgment itself is the
recordable fact.)*

**Edge — director attempts to leave without ticking the box:** the Regent
says: "Recovery is non-skippable. Without it, a lost device costs you
your operator identity permanently. Take a moment. The substrate will
wait."

---

## Phase 5 — Passkey

**Director sees:** Page explaining what a passkey is, with two
options: "Register a passkey on this device" and "Skip for now."

**the Regent says:**

> Optional convenience: register a passkey on this device for faster
> sign-in. With a passkey, your next visit signs you in with your
> fingerprint, Face ID, or hardware key — no recovery phrase, no
> typing. It works only on this device; you can register more later
> from settings.
>
> Your call: register now, or skip.

**Director decides:** Clicks one option.

**If register:** Browser triggers `navigator.credentials.create(...)`.
Director interacts with platform authenticator (Touch ID / Face ID /
Windows Hello / hardware key).

**the Regent says (after success):**

> Registered. You'll see a "passkey ready" badge next to your name on
> the sign-in page from now on. On this device.

**If skip or if no platform authenticator:**

> Skipped. You'll sign in with your operator-id and signed requests for
> now. You can register a passkey from settings anytime.

**Receipt emitted:**
```
claim:    onboard:passkey:registered  OR  onboard:passkey:skipped
subject:  ken
metadata: { phase: 5, credential_id: <id-or-null>, registered_at: <ts> }
```

**Edge — passkey registration fails mid-flow:** the Regent says: "The
device didn't complete the passkey registration. No worries — you
can try again from settings later. Continuing without it."
Receipt: `onboard:passkey:failed { reason }` then `onboard:passkey:skipped`.

---

## Phase 5.5 — Voice

**Director sees:** A page with a small grid of voice cards — five
options. Each card shows a voice name, a one-line characterization
(e.g., "British, warm — the closest to the Jarvis reference"), and a
play button. Below the grid, a "Continue with selected" button,
disabled until one is chosen.

**the Regent says:**

> One last small choice. I can speak in a few different voices —
> pick the one you'd like me to use in our daily work. Each option
> has a short sample. All voices run locally on the Foundation's
> substrate; nothing leaves.
>
> You can change this later from settings.

**Director decides:** Plays one or more samples, picks one, clicks
"Continue."

**the Regent says (after selection, in the newly-chosen voice):**

> Selected. From now on, this is the voice you'll hear when I
> speak.

**Receipt emitted:**
```
claim:    onboard:voice:selected
subject:  ken
metadata: { phase: 5.5, voice_id: "bm_george", engine: "kokoro",
             selected_at: <ts> }
```

**The palette (v1 — Kokoro voices):**

| voice_id | Characterization |
|---|---|
| `bm_george` | British male, warm. Closest to the Jarvis reference. *(default suggested)* |
| `bm_fable` | British male, slightly drier timbre. |
| `bf_isabella` | British female, professional. |
| `am_michael` | American male, neutral / modern. |
| `af_nicole` | American female, warm. |

The exact Kokoro voicepack names should be verified against the
currently-deployed Kokoro model before the wizard ships. The five
listed cover the shape: two British male (closest to Jarvis), one
British female (professional alternative), one American male
(modern/neutral), one American female (warm alternative). Refine
based on what sounds best in practice.

**Edge — sample playback fails (browser autoplay blocked):** the Regent
says: "Your browser blocked autoplay. Click the play button on a
card to hear that voice, then make your selection."

**Edge — director skips without choosing:** Default to `bm_george`.
the Regent says: "Going with the default — British male, warm. You can
change this anytime from settings." Receipt:
`onboard:voice:selected { voice_id: "bm_george", source: "default" }`.

**Implementation note:** sample audio for each palette voice should
be pre-generated and served as static assets, not synthesized on
demand. Same sample line for each voice ("Welcome aboard, Ken. Your
call.") so the director hears the same content in each timbre. The
selected voice becomes the runtime engine for all the Regent speech in
the director's subsequent sessions.

---

## Phase 6 — Bound

**Director sees:** Page titled "How your boundaries work." Below it,
two action panels — one labeled "Allowed action," one labeled "Denied
action" — each with a "Run" button.

**the Regent says:**

> Last technical step before we hand you off to your daily surface: a
> demonstration of how your authority works. I'll attempt two actions
> on your behalf. The first should succeed because your role permits
> it. The second should fail because it doesn't. Both produce receipts
> — the failure as visibly as the success.

**Director decides:** Clicks "Run" on the allowed-action panel.

(Frontend POSTs a known-allowed action signed by Ken's key. Worker
checks capability, permits, emits receipt.)

**the Regent says (after allow):**

> Done. Your role permits `mail:read:ken`. The receipt is logged.

**Director decides:** Clicks "Run" on the denied-action panel.

(Frontend POSTs a known-denied action. Worker checks capability,
denies, emits the denial receipt.)

**the Regent says (after deny):**

> Denied — as expected. Your role doesn't permit `succession:invoke`
> right now (precondition not met). The denial is the proof your
> boundaries work: nothing happens silently, even the refusals are
> recorded.

**Director sees:** Both receipts surfaced side-by-side in plain
English. Receipt IDs visible but not the focus; the human-readable
summary is the point.

**Receipts emitted:**
```
claim:    onboard:capability:demonstrated:allow
subject:  ken
metadata: { phase: 6, capability: "mail:read:ken", outcome: "allowed",
             demonstrated_at: <ts> }

claim:    onboard:capability:demonstrated:deny
subject:  ken
metadata: { phase: 6, capability: "succession:invoke", outcome: "denied",
             reason: "precondition_not_met", demonstrated_at: <ts> }
```

**Edge — denied action unexpectedly succeeds:** the Regent says: "That
shouldn't have worked. The substrate granted an action your role
shouldn't permit. I'm flagging this as an incident — stop here, do
not continue, and tell Ken now. The receipt is in the chain; he can
review."
Receipt: `onboard:capability:incident { unexpected_allow: <capability> }`.

**Per-director capability choice:**
- Ken: allow = `mail:read:ken`, deny = `succession:invoke` (precondition gate)
- Lorrie (secretary): allow = `mail:read:louise`, deny = `workspace:admin`
- Carlie (advisor): allow = `docs:read`, deny = `mail:read:katie`
- Katie / Louise: parallel pattern

---

## Phase 7 — Handoff

**Director sees:** A "Welcome aboard" summary page with:
- Their name and role
- Public key fingerprint (so they have a visible artifact)
- Plain-English capability summary
- Passkey status badge (if registered)
- List of receipts emitted during onboarding (linkable to chain)
- A primary button: "Go to my workspace"

**the Regent says:**

> You're commissioned. Your operator identity is bound, your recovery
> is recorded, your boundaries are demonstrated. Six receipts in the
> chain mark each step; that's your record of joining.
>
> From here on, your daily surface is at `app.zeropointfoundation.org`.
> I'll be there — same voice, same patterns, with the context of your
> role and whatever work you take on.
>
> Welcome aboard, Ken.

**Director decides:** Clicks "Go to my workspace" — redirects to
`app.zeropointfoundation.org`.

**Receipt emitted:**
```
claim:    onboard:complete
subject:  ken
metadata: { phase: 7, completed_at: <ts>,
             public_key_fingerprint: "a3f2…7c91",
             passkey_registered: true,
             total_phases: 7, receipts_emitted: [<ids>] }
```

---

## Resume after interruption

If the director closes their browser between phases (or loses network
and returns), the wizard should support resumption.

**On revisit to `/onboard/`:** the Regent checks for an in-progress
onboard receipt. If found:

**the Regent says:**

> Welcome back, Ken. You stopped at phase 4 (recovery). The receipts
> from phases 1-3 are in the chain; I'll pick up where we left off.

Director resumes from the last completed phase + 1.

**If resumption attempted after Phase 3 (registration) but with a
different browser/device:** the private key from Phase 2 is *gone* (it
lived in the original browser's memory). the Regent says: "This isn't
the device where you started. Your public key registered on phase 3
is bound to a private key that lived on that device. If you've lost
access to it, this is a recovery situation — different flow. Tell me
what happened."

---

## Implementation notes for the worker / UI

The script implies the following endpoints (worker side):

- `POST /api/onboard/start` — phase 1; emits `onboard:start`
- `POST /api/onboard/identity` — phase 2; emits `onboard:identity:generated`
  (the worker doesn't see the keypair; this endpoint emits the
  acknowledgment receipt with fingerprint)
- `POST /api/onboard/register-identity` — phase 3; the one-shot;
  emits `operator:registered`
- `POST /api/onboard/recovery-ack` — phase 4; emits `onboard:recovery:acknowledged`
- `POST /api/onboard/passkey` — phase 5; accepts WebAuthn attestation,
  emits `onboard:passkey:registered` or `:skipped`
- `POST /api/onboard/capability-demo` — phase 6; runs the allowed +
  denied actions, emits both receipts
- `POST /api/onboard/complete` — phase 7; emits `onboard:complete`

Frontend (Bridge UI or separate Vite entry per the worker survey)
implements the seven phase components plus a state machine that
sequences them. the Regent's lines are presented in a consistent chat
component above each phase's interactive UI. The Jarvis-voice patterns
from AGENT-AS-UX-ARCHITECTURE-2026-05.md govern every line.

## What this script is not

- Not a chat transcript with a real LLM running. the Regent's lines are
  authored copy that the page displays. A future v2 may swap in
  agent-driven generation that follows the same voice, but v1 ships
  with the copy fixed.
- Not multi-turn open dialogue. The director can ask questions ("what
  is a passkey?") via a contextual help link or a "tell me more"
  expansion, but the wizard's main path is linear.
- Not personalized at v1. The same script runs for Ken first; the
  per-director allow/deny capabilities in phase 6 differ, and the
  director's name fills in, but the structural script is shared.

## References

- `docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md` — voice, framing, Jarvis
  reference
- `docs/STAFF-ONBOARDING.md` — operational procedure context
- `docs/FOUNDATION-ONBOARDING-2026-05.md` — member-facing context
- `docs/onboarding/{ken,lorraine,carlie,katie,louise,security-basics}.md`
  — per-director packets and shared security guidance
