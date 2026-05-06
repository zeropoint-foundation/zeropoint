# Structural Hardening — Lessons (May 2026)

Companion to `STRUCTURAL-AUDIT-2026-05.md` (the seam map) and
`TEST-DISCIPLINE-2026-05.md` (the test-layer wire heuristic). This file
captures the lessons that survived the work — the things worth knowing
the next time we open a security audit and try to translate findings
into structure.

It is not a journal. It is the residue.

## The thesis: convention vs invariant

A *convention* is a rule developers must remember to follow. An
*invariant* is a rule the code makes impossible to violate. Almost every
finding in a serious security audit is a convention masquerading as a
design — "we always sign audit entries before storing them," "we always
use `verify_strict`," "we always write secrets atomically at mode 0600."
The audit catches the place where the discipline lapsed; the fix is not
to re-impose the convention but to find the *carrier* — the singular
function, middleware, type, or trait — that turns the rule into
something the code structurally cannot get wrong.

This is the wire heuristic. The seam map applies it to architecture; the
discipline framework applies it to the test suite itself. Both are the
same move.

## Singular carriers beat distributed discipline

When the audit said "five sites call `verify` instead of `verify_strict`,"
the wrong fix was to patch five sites. The right fix was to ask why
there were five sites in the first place. Tier 1's `verify_signature`
helper is one function. Every signature verification in the workspace
is supposed to route through it. The discipline pin
(`no_non_strict_ed25519_verify`) is its enforcement.

The pattern repeated. Canonical JSON had been spelled three different
ways with three different libraries — the carrier became
`zp-receipt::canonical`. Path resolution was scattered across helpers in
`zp-config`, `zp-cli`, `zp-server`, and `zp-preflight` — the carrier
became `zp_core::paths`. Secret writes were `std::fs::write` plus
manual `chmod` (sometimes) — the carrier became `write_secret_file`.

When you see the same thing done in five places, the bug isn't in any
of the five. The bug is the absence of a sixth thing they should all
have called.

## The audit doc IS the work

Writing `STRUCTURAL-AUDIT-2026-05.md` was not documentation of the work.
It *was* the process by which we discovered which seams existed. The act
of articulating each seam's intent, carrier, status, wire-pattern, and
blast-radius forced precise thinking that no amount of "let me grep for
the issue" could replace. Several seams were only identified after the
template was applied to a known one and the template revealed an
adjacency.

Future audits should start with this template, not end with it.

## Tests as a structural layer

Most discussion of testing is "did I cover this code path?" That is the
behavioral layer. There is a second layer underneath: "is the structural
shape of the codebase still correct?" The behavioral layer asks whether
your function does what it claims; the structural layer asks whether
the function exists in the right place, called by the right callers,
with no shadow copies elsewhere.

`zp-discipline` is small (~280 lines) but it changes what kind of test
you can write. Each Discipline declares an architectural rule and fails
the build when any file violates it. The four initial pins
(serde-preserve-order, raw-keychain-strings, std::fs::write in keyring,
non-strict ed25519 verify) are not behavior tests — they are
crystallized conventions. The test suite now refuses certain shapes of
code regardless of whether the offending code "works."

The honest framing: discipline-pin tests are not a replacement for
functional tests. They are an answer to a question functional tests
cannot answer. A functional test asserts what the code *does*. A
discipline test asserts what the code is structurally *allowed* to be.

## The `cfg!(test)` trap

`cfg!(test)` evaluates per-crate, not per-process. A cross-crate test
that wants to know "are we running in a test context?" cannot rely on
it — the macro returns `true` only when the crate it appears in is being
test-compiled. Code in `zp-keys` called from a test in `zp-server`
sees `cfg!(test) == false` because the consumer crate is `zp-server`'s
test harness, not `zp-keys`'s.

The fix is either:
1. A runtime environment variable (`ZP_KEYCHAIN_TEST_NAMESPACE`) that
   tests set explicitly — the keyring namespace function uses this.
2. An explicit feature flag (`test-support`) that downstream test
   crates opt into via `dev-dependencies`. This is what
   `zp-keys::test_helpers` uses.

Both are deliberate. `cfg!(test)` for cross-crate coordination is
silently broken in a way that takes a debugger to find.

## Process-wide caches hide test pathology

`load_genesis_from_credential_store` had a `OnceLock<Vec<u8>>` cache.
Correct for production: macOS Keychain prompts on every read, so caching
the first read suppresses repeat dialogs. Catastrophic for tests: the
first test in the run freezes its bytes for every subsequent test in
the same process, and `clear_genesis_for_test()` couldn't dislodge them.

The fix was `cfg(not(test))` on the cache. Production retains
prompt-suppression; tests get fresh reads. The lesson is broader: any
process-wide singleton in a library used by tests will eventually break
test isolation invisibly. If you cache, gate the cache off in test
builds, or build the cache around an explicit handle that tests can
discard.

## Save/load asymmetry is a structural smell

`save_operator` and `load_operator` had taken different paths through
the data for months. The save path used a credential-store fast path
when available; the load path explicitly skipped credential stores in
favor of the encrypted blob on disk. The asymmetry was invisible in
production because production never called the convenience wrapper —
it called `save_operator_with_genesis_secret`, which always wrote the
encrypted blob.

The bug only surfaced when the in-memory keyring made the convenience
path reliable in tests. A test wrote operator state via `save_operator`,
then read it back via `load_operator`, and got nothing — because the
write went only to the credential store and the read only consulted the
blob.

The fix: `save_operator` always writes the encrypted blob; the
credential store is best-effort cache. The lesson: when `save_X` and
`load_X` are not symmetric — when one writes path A and the other reads
path B — eventually one of them is wrong. Symmetry is not aesthetic; it
is a correctness invariant.

## Mock data in the codebase is sometimes the right call

The instinct to keep mocks out of the source tree was not principle, it
was reflex. The in-memory keyring builder (`zp-keys::test_helpers`)
unblocked the entire test suite from macOS Keychain ACL pathology that
had been generating seven consecutive passkey dialogs per test run. The
alternative (skip the tests, or trust developer-machine state) was
structurally worse than a 300-line `Arc<Mutex<HashMap<...>>>` behind a
`test-support` feature flag.

Mock data in the codebase is acceptable when:
1. It lives behind a feature flag that production builds never enable.
2. It is the only way to break a real-world dependency that test
   environments cannot reasonably provide.
3. It implements the same trait as production code, so the test
   exercises the same code path the production credential does.

All three were true here. The reflex was wrong.

## Bisect-perfect vs coherent commits

The structural-hardening checkpoint did not decompose cleanly into
independently-buildable commits. Phase 1, Phase 2, Tier 1, and Seam 11
all touched `zp-keys/src/keyring.rs`, `zp-cli/src/main.rs`,
`zp-audit/src/store.rs`. A 5-commit plan would have required `git
add -p` per file, which is fragile when files cross-cut.

We collapsed to one commit (`3fe7abd`). Bisect-imperfect, but the work
was genuinely one piece — the seam map is one piece, the wires close
together, and the test discipline framework is the test-layer
expression of the same move. Forcing a split would have produced
artificial seams in the history that didn't reflect the real seams in
the code.

The lesson: bisect-perfect history is a tool, not a goal. When the work
genuinely doesn't decompose, don't fake the decomposition. Write a
commit message that names the four phases inside, point at the audit
doc, and move on.

## Dependency direction is a constraint, not a hint

The first attempt at the canonical/Signable/verify modules placed them
in `zp-core` because that's where the abstract types live. Compile error:
`zp-core` already depends on `zp-receipt`, and `Signable` needed to be
implementable on `Receipt`. Adding `zp-receipt -> zp-core -> zp-receipt`
is a cycle.

The modules moved to `zp-receipt`. `zp-core` re-exports them so callers
that depend on `zp-core` can still reach them — but the actual trait
and implementations live where the trait can be impl'd on the concrete
types.

The lesson: the dependency direction in `Cargo.toml` is structural.
When something doesn't fit where you instinctively want to put it, the
right move is usually to put it where the dependency arrows say it
must go, not to fight the arrows.

## Discipline patterns catch their own documentation

The first version of `no_non_strict_ed25519_verify` flagged its own
rationale string — the rationale mentions `verifying_key.verify(...)`
when explaining why the form is forbidden. Doc comments mention it.
Module-level explanations mention it. None of those are violations.

The fix is `skip_lines_containing("//")` and
`skip_lines_containing("verify_strict")`. The first skips comments; the
second skips lines that mention the strict form, which is a near-perfect
proxy for "this line is talking about the rule, not violating it."

The general lesson: any pattern strict enough to catch real violations
will also catch the framework's own discussion of those violations.
Skip-line filters are not optional. Plan for them when you author the
pin.

## What didn't get done

Several things surfaced during the work and were deliberately deferred:

- **Tier 2 wires.** Seam 3 (fleet authentication) and Seam 8 (announce
  replay) are still convention. The seam map names them; the carriers
  do not yet exist.
- **`verify_strict` callers routing through `verify_signature`.** The
  helper exists; some call sites still call `verify_strict` directly.
  A future discipline pin (`no_direct_verify_strict_outside_helper`)
  becomes available once those sites are swept.
- **More discipline pins.** The framework supports many more than five.
  Reasonable next targets: `no_direct_serde_json_to_vec_in_signing_path`
  (Seam 17 strengthened), `no_direct_panic_in_zp_server` (operational
  hygiene), `no_anyhow_in_zp_core` (error-type discipline).
- **`zp-paths` micro-crate.** Seam 19 closure (`no_raw_home_lookup` pin)
  allowlists `zp-preflight` and `zp-config` because both are
  deliberately minimal-deps and maintain documented mirrors of
  `zp_core::paths::home`. The structural fix is to extract `paths` into
  a zero-dep micro-crate that zp-core, zp-preflight, and zp-config can
  all depend on. Until then, the mirrors are the documented exception
  and the pin's allowlist documents the carve-out.
- **Hardware-wallet sovereignty providers v0.3.** Detection-only stubs
  for YubiKey, Ledger, OnlyKey are still there. Trezor v0.2 is the
  only one with full implementation. The CLAUDE.md TODO table tracks
  these.
- **Touch ID v0.2 (Secure Enclave).** Currently application-layer via
  bioutil; the OS-level path through `security-framework` with
  `kSecAccessControlBiometryCurrentSet` is unimplemented.

None of these block the four claims advancing further. They are open
work, not unfinished work.

## The arc, in one paragraph

We started with a 10-finding security audit. We ended with a 20-seam
structural map, a singular carrier for every wire we drew, a 67-file
commit that crystallizes the carriers in code, and a test framework
that refuses to let the conventions drift back into convention. Claim 1
(chain integrity) materially advanced. Claims 2 and 4 are unaffected
but unblocked. Claim 3 (gate enforcement) advanced through the gate
parser refactor; it is not yet structurally complete, but it is no
longer convention-shaped.

The seam map is now the planning artifact. The discipline framework is
now the enforcement artifact. The four claims are now the scoring
artifact. Every future structural decision should ask: which seam,
which discipline, which claim?
