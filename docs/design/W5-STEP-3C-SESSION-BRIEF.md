# W5 Step 3c — Session Brief

**Task:** point the Regent's `inference_endpoint` at the ZP proxy and retire the
native `/api/chat` path.
**Written:** 2026-08-12, at the end of the session that completed 3b.
**Read with:** `HARNESS-SEAM-2026-08.md` §6.1.1 (the W5 decomposition).

This brief is self-contained and assumes no conversation context.

**Constructs are named, not located.** Every prior revision of the W5 thread
carried line numbers and every one had drifted before its step was executed.
Use `grep` on the names below; do not re-add line numbers to this document.

---

## 1. State at handoff

- Branch `substrate/governed-inference-path`, clean at `0ff1f17`.
- 3b is done: the Regent holds a `GateRequestSigner`. Both `InferenceBackend`
  instances report `gate_signer=true` at startup. `cargo check --workspace`
  green, 202 tests, 34 discipline pins green.
- The endpoint has **not** moved. That is this step.

## 2. Why this is a protocol retirement, not an endpoint swap

The proxy's path allowlist for the `ollama` provider is exactly
`["v1/chat/completions", "v1/models"]`. The whole `api/*` family is excluded on
purpose — `api/pull` fetches arbitrary remote content, `api/delete` mutates
local model state — and `test_ollama_path_allowlist_excludes_native_api` in
`zp-server/src/proxy.rs` asserts it stays that way.

So `/api/chat` is not reachable through the proxy. Retiring the native path is
forced by the allowlist, not a tidy-up that can be deferred. Anything that
posts to `/api/chat` must be re-expressed as an OpenAI-wire call through the
proxy, or it stops working the moment the endpoint moves.

## 3. Nine items

Ordered roughly by how much design they need. The first two are defects that
already exist on disk — they are not created by 3c, they are *tripped* by it.

### 3.1 `model_available` silently becomes a no-op — defect, present now

`model_available` opens with `if self.protocol != InferenceProtocol::Ollama {
return Ok(true) }`. Under a proxy endpoint, `detect` returns `zp_proxy`, whose
`response_format` is `OpenAI` — so the guard fires and every model reports
available whether or not it is.

Step 2 migrated this probe to `v1/models` precisely so it would survive the
move, and its comment says it "keeps working whether the endpoint is a direct
backend or the proxy." The protocol guard defeats that. The comment describes
the intent; the guard implements something else.

Fix by keying the guard on whether the target can answer the question — the
proxy can, for the `ollama` provider — rather than on the wire protocol.

### 3.2 `health_check`'s Ollama branch is unreachable — stale comment, present now

`health_check` branches on `self.protocol`. Its Ollama arm carries the comment
"`detect()` matches on URL substrings, so a proxy path containing
`/proxy/ollama/` still resolves to this branch." **That was true before 3a and
is false now.** 3a made `detect` check `/api/v1/proxy/` first and return
`zp_proxy`, so a proxy URL resolves to the *OpenAI* arm.

The OpenAI arm sends `Authorization: Bearer <empty string>`. Against the gate
that is a 401, and it is not a ZP-Sig envelope. Health checks would report the
backend down.

### 3.3 `sign_for_gate` hardcodes `"POST"`

3b only needed to sign chat calls. `health_check` and `model_available` are
`GET`s. Signing them requires the method to be a parameter. `GateRequestSigner`
normalises the method to uppercase and binds it into the envelope — there is a
test for it in `zp-gate-envelope` — so a wrong method is a clean 401, not a
silent pass.

### 3.4 The local tier's transport disappears with the native path

`chat_local` is not a fallback. It is the transport for
`routing::InferenceTier::Local`, dispatched from `Regent::dispatch_inference`.
It posts to `self.fallback_endpoint` via `chat_ollama_at`.

Retiring `chat_ollama_at` therefore retires the local routing tier's transport,
not just a degraded path. Both the `InferenceProtocol::Ollama` arm of `chat`
and `chat_local` need re-expressing as proxy calls with `provider=ollama`.

### 3.5 Provider becomes per-request; today it is fixed at construction

`InferenceBackend::new` runs `ProviderProfile::detect` once and stores one
`endpoint` and one `provider`. The proxy encodes the provider in the path
(`/api/v1/proxy/{provider}/v1/chat/completions`).

Collapsing both endpoints onto one proxy base with the provider varying per
request moves URL construction from construction time to call time. That also
changes what `FallbackEvent` can record — `cloud_endpoint` and `cloud_provider`
become per-call values rather than fields read off `self`.

This is the largest structural item. Decide the shape before editing.

### 3.6 Three Ollama-native request fields have no home on the OpenAI wire

`InferenceRequest` carries `options`, `keep_alive` and `think`, all
`skip_serializing_if = "Option::is_none"`. `think: Some(false)` is
load-bearing — it suppresses qwen3 chain-of-thought.

The proxy round-trips the body through `serde_json::Value` (`strip_tool_strict`,
`inject_model_into_body`), so unknown fields survive to the provider. The open
question is whether Ollama's OpenAI-compatible surface *honours* them; its
native `/api/chat` does.

**Probe this empirically before deciding.** If `think` stops working, qwen3
emits reasoning into the Regent's cognitive context and it reads as a model
regression rather than a transport change — the failure mode named in CLAUDE.md
under *a model and its prompts are an atomic pair*. This is a design decision,
not a substitution.

### 3.7 Response shape

`OllamaResponse` (`message`, `done`, `total_duration`, `eval_count`) retires in
favour of the OpenAI shape. Step 2 already took a response-shape hit once in
`model_available`; expect the same class of surprise here. `total_duration` and
`eval_count` have consumers — check them before deleting the struct.

### 3.8 The config default cannot be a static literal

`regent_inference_endpoint` defaults to the literal `"http://127.0.0.1:11434"`
in **three** places: `zp-config/src/schema.rs`, `zp-server/src/lib.rs`
(`ServerConfig::default`), and `zp-hardening-tests/src/harness.rs`.

A proxy base is `http://127.0.0.1:{port}/api/v1/proxy/ollama`, and the port is
itself config. So the default has to be derived rather than written, or the
resolution has to happen after the port is known. The harness copy matters
independently — it decides what the hardening tests exercise.

Change all three or none. This is the shape that broke `zp-hardening-tests` on
2026-08-10.

### 3.9 `fallback_endpoint` finally moves

Deferred from 3b on the explicit grounds that 3c collapses both endpoints onto
one proxy base. That is this step. It is a compiled literal in
`InferenceBackend::new`.

## 4. Out of scope — deliberately

- **The auto-start probe** in `ensure_ollama_running` stays pointed at `11434`
  directly. The proxy cannot answer whether the process behind it is running.
- **`ensure_ollama_running` itself** spawns processes without a grant, without
  passing `zp-host`, without a receipt, and confirms success by an 8-second
  timeout rather than by observation. The ruling is that the Regent *should*
  hold lifecycle authority — attested, scoped, revocable — not that it should
  lose it. Tracked separately; `regent:hardware:` and `observation:hardware:`
  are reserved receipt families and may be the carriers.
- **Step 4** (extending `no_raw_provider_http_outside_canonical_layer` to
  loopback URLs) is the step after this one.

## 5. Verification

```
cargo check --workspace
cargo test -p zp-gate-envelope
cargo test -p zp-regent
cargo test -p zp-hardening-tests
```

`--workspace`, not `-p`. Adding a field to a public struct breaks every
construction site including crates you did not touch; this exact mistake broke
`zp-hardening-tests` on 2026-08-10 because only `-p` was run.

Live, after `./zp-dev.sh release`:

```
curl -s http://127.0.0.1:17010/api/v1/health
grep "inference backend initialized" /tmp/zp-serve.log
grep -c 401 /tmp/zp-serve.log
```

Unlike 3b, **3c is observable**. The endpoint in that log line should be the
proxy base, and exercising the Regent should produce signed receipts on the
chain for calls that previously produced none. A 401 means the envelope, the
method or the path is wrong — §3.3 is the first place to look.

## 6. Working note

Three consecutive W5 steps have been wider than their one-line description in
the decomposition table, and each time the honest move was to stop and re-scope
rather than plough on. This brief exists because the fourth scoping found nine
items and two live defects behind "point the endpoint at the proxy."

Read §3.1 and §3.2 first. They are true right now, at `0ff1f17`, and they are
worth confirming with a `grep` before anything else — if they have been fixed
in the meantime, the rest of this brief is still accurate but its ordering is
not.
