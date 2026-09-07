# W5 Step 3b — Session Brief

*Status: Complete (2026-08-12), executed at `7cf2e69`. The live record of what
landed is `HARNESS-SEAM-2026-08.md` §6.1.1, which supersedes this document on
every point of fact. Retained as the reasoning trail for the handoff and
**not amended for what changed during execution** — read it as the plan, never
as the state.*

*Two divergences to know before reading. §2 routes the signer through
`RegentConfig`; it does not go there — that struct is serde-derived, and the
field would have had to be `#[serde(skip)]`, a live capability that vanishes on
a round-trip without saying so. The signer stops at `ServerRegentConfig` and
reaches the backends as a parameter. §6 describes a working tree two commits
stale. §2's line numbers were all still accurate on 2026-08-12, which is the
one thing here that aged better than expected.*

**Task:** give the Regent a `GateRequestSigner` so it can authenticate to the
ZeroPoint proxy.
**Written:** 2026-08-10, at the end of the session that completed 3a and step 2.
**Read with:** `HARNESS-SEAM-2026-08.md` §6.1.1 (the W5 decomposition).

This brief is self-contained. It assumes no conversation context. Line numbers
were verified against the working tree on 2026-08-10 — re-check them before
trusting any single one.

---

## 1. Why

The Regent reaches Ollama directly on `127.0.0.1:11434` with `auth=None`,
bypassing the proxy that adds receipt signing, cost tracking and policy gating.
Every other inference path in the substrate goes through that proxy; the apex
cognitive entity does not.

Step 3a (done) taught `ProviderProfile::detect` to recognise a ZP proxy URL and
return the new `zp_proxy` profile. That profile carries
`auth: AuthStrategy::None` **as a placeholder, not a statement** — ZP-Sig is
per-request and body-bound, so it cannot be expressed as a static
`AuthStrategy`. 3b supplies the real mechanism.

### Hard constraint — 3b before 3c

Pointing `inference_endpoint` at the proxy before the Regent can sign would 401
every call and take Regent inference offline entirely. Fail-closed and correct,
but unforgiving. **Do not do 3c first.**

---

## 2. The thread

The gate signer already exists. `AppState::init` derives it beside the
verifier's `expected_kid` from one sovereign-root load, at
`crates/zp-server/src/lib.rs:707` (the tuple) and `:727` (the seed). It is
currently a local binding, consumed at `:914` for the provider pool.

To reach the Regent's request builder it must travel:

| # | Where | What |
|---|---|---|
| 1 | `zp-server/src/lib.rs` | store the signer on `AppState` (new field) |
| 2 | `zp-server/src/lib.rs:2039` | pass it into `regent::spawn_regent(...)` |
| 3 | `zp-server/src/regent.rs:2479` | new field on `ServerRegentConfig` (constructed at `lib.rs:2026`) |
| 4 | `zp-regent/src/config.rs:53` | new field on `RegentConfig` |
| 5 | `zp-regent/src/inference.rs:391` | `InferenceBackend::new` accepts and stores it |
| 6 | `zp-regent/src/inference.rs:742`, `:831` | sign when the profile is `zp_proxy` |

**There are two `RegentConfig`-shaped structs.** `zp-regent/src/config.rs:53`
and `zp-server/src/regent.rs:2479` (`ServerRegentConfig`), mapped across at
roughly `zp-server/src/regent.rs:2653`. Both need the field. Missing one is the
most likely way this half-lands.

**Two `InferenceBackend::new` call sites**, both must be updated:
`zp-regent/src/regent.rs:361` and `zp-server/src/regent.rs:2664`.

### Types

`zp-regent` already depends on `zp-core`, so no new dependency edge is needed.

- Trait: `zp_core::provider::RequestSigner`
- Concrete: `zp_gate_envelope::GateRequestSigner` (`from_seed(&[u8; 32])`)
- Carry it as `Option<Arc<dyn RequestSigner>>` — `None` pre-Genesis, where
  there is no sovereign root to sign with. That mirrors how `gate_signer` is
  already shaped in `AppState::init`.

`GateRequestSigner::authorization(method, path, body)` returns the complete
`Authorization` header value, or `None` if no credential can be produced.
Returning `None` must lead to an unauthenticated request that the gate rejects
— never to skipping authentication. Fail closed.

---

## 3. Also required — serialize once

`chat_ollama_at` (`inference.rs:759`) and `chat_openai` use `.json(request)`,
which serialises inside `reqwest`. ZP-Sig binds a BLAKE3 hash of the **exact
wire bytes**, so the body must be serialised once and those same bytes both
hashed and sent.

`.json()` would let the envelope bind one serialisation while a different one
travels. Any difference — key order, float formatting, escaping — produces a
structurally perfect header that fails verification, reported as
`envelope-signature` and indistinguishable from a wrong key.

The same correction was made to `ProxyLlmProvider` on 2026-08-09; see
`crates/zp-llm/src/providers/proxy.rs`, the block commented "Serialize ONCE".
Copy that shape.

Related trap already paid for once: `zp_receipt::verify_signed` verifies against
`value.canonical_hash()`, i.e. `blake3(canonical_preimage())` — **not** the
preimage bytes. `GateRequestSigner` already handles this correctly; do not
reimplement signing.

---

## 4. Verification

```
cargo check --workspace
cargo test -p zp-gate-envelope
cargo test -p zp-regent
```

`--workspace`, not `-p`. Adding a field to a public struct breaks every
construction site, including crates you did not touch. This exact mistake broke
`zp-hardening-tests` on 2026-08-10 because only `-p` was run.

Live check, after `./zp-dev.sh release`:

```
curl -s http://127.0.0.1:17010/api/v1/health
```

Then exercise the Regent and confirm no 401 appears in `/tmp/zp-serve.log`.
Note the Regent's endpoint does **not** move in 3b — 3b only gives it the
ability to sign. Correct 3b behaviour is: nothing observable changes, and the
signer is present and unused until 3c.

---

## 5. Out of scope — deliberately

- **`fallback_endpoint`** (`inference.rs:424`, compiled literal). 3c collapses
  both endpoints onto one proxy base with the provider varying per request, so
  a config field introduced now gets deleted then.
- **The auto-start probe** (`inference.rs:654`) stays pointed at `11434`
  directly. The proxy cannot answer whether the process behind it is running.
- **`ensure_ollama_running()`** spawns processes without a grant, without
  passing `zp-host` (the typed privileged-side-effect boundary that
  `ExecutionEngine` already honours), without a receipt, and confirms success
  by an 8-second timeout rather than observation. **The ruling is that the
  Regent should hold lifecycle authority — attested, scoped, revocable — not
  that it should lose it.** Tracked separately. `regent:hardware:` and
  `observation:hardware:` are already reserved receipt families and may be the
  intended carriers.

---

## 6. State at handoff

- Branch: `substrate/governed-inference-path`
- Last commit: `601952d` — "substrate: close the governed inference path end to end"
- **17 paths uncommitted.** Everything after `601952d` is on disk and unversioned:
  tool-pathway wiring, `SkillMatcher` removal, `zp-skills` deletion, workspace
  member removal, the three probe swaps, `zp_proxy` recognition, the W3 compiled
  local tier removal, hardening-test fixes, and both design docs. Commit before
  starting.
- `cargo check --workspace` was green as of the last change.

### Bridge caveat

If working through the Cowork device bridge, git in this folder creates lock
files it cannot unlink. `git add` succeeds but leaves `.git/index.lock`, and the
next git command fails with "File exists". `device_bash` cannot delete; `mv` the
lock aside inside the same command as the commit. Running git directly in a
terminal avoids this entirely and is the better path.

---

## 7. Working notes from the prior session

Two failure modes recurred and are worth naming:

**Verifying narrowly.** Two compile breaks came from searching only where the
work already was — a `grep` in the region being read rather than across the
file, and `cargo check -p` on touched packages rather than `--workspace`. The
compiler found both; a wider search would have found them first.

**Scope discovered by reading.** Three times, a step scoped as "one line"
turned out to be several, and each time the honest move was to stop and re-scope
rather than plough on. Step 2 was three sites, not one, and one of them needed a
response-shape change. Expect 3b to be larger than the table in §2 suggests.
