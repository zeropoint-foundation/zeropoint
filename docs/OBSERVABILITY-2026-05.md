# Observability is Load-Bearing

*2026-05-11. Companion to L3 hardening (#91). Anchors tasks #111, #113,
#117–#121. Architecture II.18 candidate.*

## Context

The evening of 2026-05-11 was spent putting IronClaw behind Cloudflare
Access — a routine integration that should have taken thirty minutes.
It took five hours, and not because anything was broken. Across the
session, every architectural decision the substrate made was correct:

- ZP refused to launch IronClaw when the audit chain was unreachable
  (degrade-closed, validating claim #1).
- ZP correctly used the canonical audit DB path for read operations
  (`zp doctor`), even though writers used a buggy cwd-relative default.
- IronClaw correctly parsed every OIDC env var and constructed the
  middleware exactly as designed.
- Cloudflare Access correctly enforced its session boundary at the
  edge, redirecting unauthenticated requests before they reached the
  tunnel.

And yet for hours we believed the substrate was broken. Five times we
chased a hypothesis that turned out to be wrong; each wrong turn was
caused not by incorrect behavior but by **invisible** behavior. The
substrate was being correct in ways the operator could not see.

This is a distinct failure mode from incorrectness, and it is just as
costly. A system whose correctness cannot be perceived is operationally
indistinguishable from one that is wrong. The L3 hardening pass exists
to make the substrate honest under stress; this document captures the
companion requirement that the substrate must also be **legible** under
diagnosis.

## The six principles

These complement the original six design principles in `ARCHITECTURE-2026-04.md`
Part V½. The original six describe how the substrate should behave;
these describe how it should *show* what it is doing.

### 1. Observability is load-bearing

No execution mode may silently swallow logs. If a process is making
decisions — about auth, about chain writes, about resource ownership —
those decisions must be emitted somewhere an operator can read them.

A subscriber configured to discard all output is structurally
indistinguishable from a subscriber that was never installed. From the
outside, "we didn't tell you" and "we don't know" are the same.

**Violation observed tonight:** `main.rs:405-410` in the IronClaw fork
sets `suppress_stderr = true` whenever TUI mode is active. The OIDC
initialization log line — `OIDC JWT authentication enabled
header=cf-access-jwt-assertion jwks_url=...` — was being emitted into
the SSE `LogBroadcaster` at `/api/logs/events`, invisible to any
diagnostic flow that didn't know to subscribe to that stream.

**Task:** #117 (route TUI-mode tracing to file + TUI panel; never to
`/dev/null`). **Status: structurally enforced** — landed on
`foundation/observability-2026-05`. File appender active in all modes.

### 2. Errors must be navigable

An error message should tell the operator three things: *what was
tried*, *what was found*, and *what action would resolve it*. An error
that names only the symptom forces the operator to reconstruct the
diagnostic graph from scratch. Three lines at the error site save hours
of forensic work downstream.

The corollary: an error message is part of the substrate's API, not a
debug afterthought. It deserves the same care as a function signature.

**Violation observed tonight:** "Failed to open audit store for launch
receipt" appeared twice. The first time, the cause was `zp serve`
holding an exclusive lock; the second time, the cause was the
cwd-relative `--data-dir` default. The same message for two unrelated
causes meant the operator could not distinguish them.

**Tasks:** #111 (PID registry + navigable errors for resource
contention); #90 (audit-DB path resolution with hint when canonical
location exists nearby). **Status: structurally enforced (partial)** — #90
landed on `l3-floor-2026-05` (canonical data-dir priority chain, navigable
error message). Remaining: #111 (PID registry + resource-contention errors).

### 3. State should be queryable, not just constructed

It is not enough that a component is configured correctly at startup.
The operator must be able to ask, at any later moment, "what does the
running process currently believe?" The answer must be authoritative —
reflecting the resolved post-merge config that the process is actually
using, not whatever the config file might suggest.

This implies a `status --runtime` command on every long-running
component. The output is the truth as the process knows it, formatted
for an operator's eyes.

**Violation observed tonight:** No way to ask IronClaw "is OIDC
enforcing right now?" short of reading source. We confirmed it only by
running an end-to-end curl, which is a more expensive test than reading
the answer should be.

**Task:** #118 (`zp status --runtime` + `ironclaw status --runtime`
both surfacing resolved auth posture, channel set, capability bindings,
resource ownership). **Status: structurally enforced** — both commands
landed on `foundation/observability-2026-05` (ironclaw) and
`origin/observability-2026-05` (zeropoint).

### 4. Convergent paths must produce convergent observability

When two code paths perform the same logical operation, they must
expose identical observable behavior. If `zp doctor` and `zp run` both
open the audit chain, an error in either must produce the same error
in both. If they don't, the divergence is a defect signature even when
the divergent code path is otherwise correct.

This is not about deduplicating implementations — it is about respecting
the operator's right to expect that "the same operation" means the same
thing wherever it appears.

**Violation observed tonight:** `zp doctor` opened the audit chain
successfully (canonical path resolution); `zp run` failed (cwd-relative
default). Same logical operation, two different code paths, two
different observable behaviors. The defect was visible at the seam
between them long before we read the source.

**Tasks:** #112 (single-writer daemon delegation, eliminates two of the
divergent open paths); #90 (unified path resolution); #111 (navigable
errors that surface the divergence as an actionable error rather than a
silent contradiction). **Status: structurally enforced (partial)** — #90
landed on `l3-floor-2026-05` (canonical data-dir unification eliminates the
`zp doctor` vs `zp emit` divergence). Remaining: #112 (single-writer daemon),
#111 (navigable error for resource contention).

### 5. Stateless diagnostics for stateful systems

Stateful integrations — auth boundaries, audit chains, multi-process
coordination — accumulate complexity over time. An operator should be
able to run *one command* that exercises the integration end-to-end and
reports the result in plain language. The command's output must be
specific enough that a failure points to a single component, not "the
auth flow is broken somewhere."

Tonight we did this manually for the OIDC flow:

    cloudflared access token →
      curl localhost:3000 +JWT → 200 (IronClaw OIDC accepts) →
      curl localhost:3000 no-JWT → 401 (correctly enforced) →
      cloudflared access curl → 200 (full path through edge)

That procedure took ten minutes to assemble and zero minutes to
interpret. It should be one command, owned by the substrate, kept
correct by the people who change the auth flow.

**Task:** #119 (`zp test-auth` / `ironclaw test-auth`, with output
shaped for diagnosis rather than for tests). **Status: structurally
enforced** — `zp test-auth` landed on `origin/observability-2026-05`.
`ironclaw test-auth` deferred (ZP is primary per brief).

### 6. The boot banner is the security posture

Whatever the substrate prints at startup is the operator's first
encounter with the running configuration. It must describe what is
actually protecting the system — concisely, completely, and copyably.
A banner that lists channel names without describing the auth boundary
is decoration.

The minimum acceptable banner for a security-sensitive process states:
the auth mechanisms in effect (with their relevant parameters), the
listening endpoints (with their reachability scope), and the identity
the process is operating as.

**Violation observed tonight:** IronClaw's banner showed `channels tui
http` and a gateway URL with a bearer token. It did not state that
OIDC was enabled, what issuer it expected, what audience it required,
or what middleware was protecting which routes. The truth was emitted,
but to a tracing channel suppressed by the TUI (see Principle #1).

**Task:** #118 also covers boot-banner posture in addition to
runtime-query posture; the two share most of the formatting work.
**Status: structurally enforced** — boot banner now includes auth
posture line (OIDC issuer + audience) on `foundation/observability-2026-05`.

## Failure modes observed tonight

Each maps cleanly to one or more of the principles above. Documented
here as forensic evidence, so future architectural reviews can ask
"would this design fail the same way?"

### F1: cwd-relative `--data-dir` default

`zp emit` and `zp run` both default `--data-dir` to `./data/zeropoint`,
resolved relative to the calling shell's cwd. The canonical location
is `~/ZeroPoint/data`. The two only happen to agree when the operator
is in `~/ZeroPoint` or has otherwise structured their working
directory deliberately.

- **Symptom:** "Failed to open audit store for launch receipt" from
  any cwd that isn't `~/ZeroPoint`.
- **Diagnostic time wasted:** ~45 min.
- **Violates:** Principle #2 (error message gives no hint about path
  resolution); Principle #4 (`zp doctor` uses canonical path
  successfully, `zp run` uses cwd-relative path and fails — same
  operation, divergent observability).
- **Tracked by:** task #90.

### F2: ZP daemon holds audit chain, blocks fresh writers

A long-running `zp serve` process holds the audit DB open. When a new
`zp run` invocation tries to open the chain for a launch receipt
emit, the open fails with no indication that another ZP process is
the cause.

- **Symptom:** Same "Failed to open audit store" message, this time
  not a path issue at all.
- **Diagnostic time wasted:** ~30 min (overlapping with F1).
- **Violates:** Principle #2 (error message names no possible cause);
  Principle #4 (two writers to the same resource is the underlying
  architectural smell — see #112).
- **Tracked by:** tasks #111 (Stage 1: PID registry + navigable
  errors), #112 (Stage 2: single-writer daemon).

### F3: TUI mode suppresses tracing to stderr

IronClaw's `main.rs:405-410` short-circuits the tracing fmt layer
when TUI mode is active. The OIDC initialization log line is emitted
correctly into the SSE LogBroadcaster but never reaches the
terminal. Operators running diagnostics from a shell — the dominant
debugging stance — see nothing.

- **Symptom:** `RUST_LOG=trace` produced zero observable output.
  Hours spent believing OIDC was not initializing when in fact it
  was.
- **Diagnostic time wasted:** ~2 hours.
- **Violates:** Principle #1 (mode silently swallows logs);
  Principle #6 (boot banner does not state OIDC posture, so the
  suppressed log was the only place the truth lived).
- **Tracked by:** tasks #117 (tee to file in TUI mode), #118 (status
  command, boot banner upgrade).

### F4: Boot banner doesn't reflect auth posture

The IronClaw v0.28.0 boot banner lists model, gateway URL, channels,
and feature flags. It does not state which auth mechanisms are
enabled, what middleware is installed, or what the JWT issuer is.

- **Symptom:** Operator could not tell whether OIDC was enforcing
  even when looking directly at the boot output.
- **Diagnostic time wasted:** indirect — contributed to F3 above.
- **Violates:** Principle #6.
- **Tracked by:** task #118.

### F5: Bearer-token auto-regeneration outlives the commenting-out

When `GATEWAY_AUTH_TOKEN` is not present in OS env, IronClaw
generates a fresh 32-char token at startup and persists it to
`~/.ironclaw/.env` via `upsert_bootstrap_var`. Commenting out the
old token line in `.env` does not disable bearer auth; it triggers
the regeneration on next boot.

- **Symptom:** Even with OIDC configured, the bearer-auth path
  remained alive (a regenerated token), and the SPA's
  localStorage-cached bearer could still succeed without OIDC ever
  being reached.
- **Diagnostic time wasted:** ~20 min identifying this as
  contributory after the main OIDC question resolved.
- **Violates:** Principle #6 (boot banner shows the bearer token
  URL but doesn't state that OIDC is now the preferred path);
  Principle #4 (auth ladder treats bearer-first, regardless of
  whether OIDC is configured — convergent operations, divergent
  precedence).
- **Tracked by:** task #116 (skip auto-gen when OIDC configured)
  + #120 (multi-tenant identity mapping for the corollary UX
  issue).

## Relationship to the original six principles

The Part V½ principles in `ARCHITECTURE-2026-04.md` describe the
substrate's *behavior*. The six principles here describe the
substrate's *legibility*. They are complementary, not in tension.

| Behavior principle (V½)              | Legibility principle (here)                                  |
|--------------------------------------|--------------------------------------------------------------|
| 1. Signing is gravity                | 6. Boot banner is the security posture                       |
| 2. Identity is a key, not a location | 3. State should be queryable                                 |
| 3. There is no center                | 4. Convergent paths, convergent observability                |
| 4. Every bit counts                  | 2. Errors must be navigable                                  |
| 5. Store-and-forward is primary      | 5. Stateless diagnostics for stateful systems                |
| 6. A tool is intent, crystallized    | 1. Observability is load-bearing                             |

The mapping is not strict — several behavior principles imply several
legibility ones — but the symmetry is real. Principle 6 ("a tool is
intent, crystallized") in particular has been read narrowly as
applying to tool manifests. Tonight's session suggests it generalizes:
intent that cannot be observed has not been crystallized, only stored.

## What this means for L4

The Foundation team will be invited to operate this substrate next
week. They will encounter every failure mode catalogued here, plus
others we have not yet provoked. Their tolerance for "the system is
working correctly, you just can't see it" will be — correctly — low.

We cannot ship #117–#119 by Tuesday. We can ship the awareness that
they are coming, in two concrete forms:

1. **Onboarding doc (#81) calls out the diagnostic modes.** Foundation
   members should know to set `cli_mode = "repl"` for diagnostic runs,
   tail `/api/logs/events`, and use `cloudflared access curl` for
   end-to-end auth verification. These are workarounds for the
   legibility gaps; the workarounds being documented turns the gaps
   from blockers into known limitations.

2. **The substrate emits clear "what I did and why" messages for the
   common failure paths.** #111 (PID registry + navigable errors) is
   the minimum viable version of this. Even one week's work on #111
   would have prevented two of the five failure modes tonight.

The deeper investment — #117, #118, #119 — is then well-scoped work
across the following weeks, with each principle here giving the
acceptance criteria.

## What this is not

This document does not prescribe a logging framework, a tracing
backend, or a specific instrumentation library. Those are
implementation choices. The principles here are agnostic to whether
tracing uses `tracing-subscriber` or something else, whether status
commands are gRPC verbs or shell scripts, whether boot banners are
plain text or structured output.

What the principles require is that, for each major component, the
operator can answer four questions in one command or less:

- What is currently running?
- What is it configured to do?
- What is protecting what?
- If something is failing, what did it try, and what should I do?

Any concrete tooling that answers those four questions satisfies the
principles. Any tooling that does not satisfy them — however clever —
will reproduce tonight's failure mode at the next stressful integration.

## References

- Original architecture: `docs/ARCHITECTURE-2026-04.md` (Part V½)
- Structural audit: `docs/STRUCTURAL-AUDIT-2026-05.md`
- Multi-tenant context: `docs/MULTI-TENANT-2026-05.md`
- Restore procedure (companion L3 deliverable):
  `docs/RESTORE-2026-05.md`
- Tasks: #90, #111, #112, #113, #116, #117, #118, #119, #120, #121

## Acknowledgments

Tonight's diagnosis was advanced significantly by a terminal-Claude
session run in parallel with the Cowork session. The wiring trace
that pinpointed `suppress_stderr` (in main.rs:405-410) as the cause
of the OIDC-invisibility came from that session, after the Cowork
session had spent two hours chasing wrong hypotheses. That handoff —
Cowork for breadth and conversation, terminal Claude for depth and
iteration — is itself an operational pattern worth reproducing.
