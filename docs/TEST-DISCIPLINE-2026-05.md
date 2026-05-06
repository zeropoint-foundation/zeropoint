# ZeroPoint Test Discipline — May 2026

**Document type:** Companion to `STRUCTURAL-AUDIT-2026-05.md`. This document defines the test-layer discipline system: how the substrate's test suite enforces architectural conventions as build-failing invariants, and the catalog of disciplines pinned today.

**Author:** Ken Romero, with synthesis assistance from Claude.
**Date:** 2026-05-06.
**Status:** Active. Disciplines accumulate over time as new structural commitments crystallize.

**Companion documents:**
- `docs/ARCHITECTURE-2026-04.md` — the operating spec (four claims, seven principles, the catalog vocabulary).
- `docs/STRUCTURAL-AUDIT-2026-05.md` — the seam catalog and wire heuristic. Each discipline below cites the seam or invariant it enforces.
- `crates/zp-discipline/` — the implementation: a small framework plus discipline-pin tests that run as part of `cargo test`.

---

## Part I — The Heuristic Applied to Tests

### 1. Convention vs. invariant, restated for the test layer

The structural audit's central distinction is *convention* (a rule developers must remember to follow) vs. *invariant* (a rule the code makes impossible to violate). Conventions get violated. Invariants do not — because the type system, the runtime, or the build refuses to accept the violation.

For tests, the same distinction applies one layer up:

- An *architectural convention* lives in a doc comment, a code-review heuristic, or an experienced author's memory. "Don't call `verify` outside the helper." "Don't write secret files with `std::fs::write`." Future authors may not encounter the convention before they violate it.
- An *architectural invariant* is enforced by the build. The build fails if the convention is violated. Future authors learn the rule by attempting to violate it; the failure message names the seam, cites the invariant, and points at the rationale.

Discipline-pin tests are how a convention crystallizes into an invariant when the rule can't be expressed in the type system.

### 2. Why this matters more than it might seem

Many of the seams named in `STRUCTURAL-AUDIT-2026-05.md` cannot be enforced by Rust's type system without major restructuring. "Don't call `verify_strict` outside the canonical helper" — there's no language feature for that across crate boundaries. "Don't reach the OS keychain via the literal string `zeropoint-genesis`" — the type system can't express that. "Don't reimplement `ZP_HOME` resolution outside `zp_core::paths`" — same.

Regex over source isn't as strong as type-level enforcement, but it's much stronger than a doc comment. It composes (more disciplines just means more test files), it lives in the codebase it constrains and evolves with the structural audit, and it makes the rule visible at the moment of violation rather than at code review time. The tradeoff is honest: ~150 lines of framework, ~30 lines per discipline, plus a second or two added to `cargo test` per discipline. The benefit is that the substrate stops trusting future authors to remember; it catches the violation and explains itself.

### 3. What discipline-pin tests are not

Discipline-pin tests aren't a substitute for functional tests. Functional tests verify *behavior*; discipline tests verify *form*. The two are complementary:

- A functional test asserts "feature X produces output Y for input Z."
- A discipline test asserts "feature X cannot be implemented in a forbidden way."

A discipline test that's hard to write usually means the discipline isn't expressible as a structural rule. That's a signal — maybe the discipline needs to be re-stated, or maybe it really is convention all the way down (in which case it stays a doc comment and we accept the cost).

### 4. The architectural symmetry

The catalog has M-rules that pin invariants of the substrate's *runtime* — what must be true at every step of the derivation. Discipline-pin tests pin invariants of the substrate's *source code shape* — what must be true of the source tree. They're parallel layers: M-rules ensure the runtime can't violate the grammar; discipline tests ensure the source can't violate the wire.

This is what makes discipline tests architectural rather than a clever testing trick. They're the test-layer expression of the same wire heuristic the substrate operates on at runtime.

---

## Part II — The Framework

The implementation lives in `crates/zp-discipline/src/lib.rs`. The public surface is one builder type:

```rust
use zp_discipline::Discipline;

#[test]
fn my_discipline() {
    Discipline::new("descriptive_name")
        .cite_invariant("M3 (hash-chain continuity)")
        .rationale("One-line explanation of why this rule exists.")
        .forbid_pattern(r"\.verify\b\s*\(")
        .allow_path("crates/zp-receipt/src/verify.rs")
        .skip_lines_containing("//")
        .skip_lines_containing("verify_strict")
        .assert();
}
```

The builder produces no output when the discipline is satisfied. When violated, it panics with a structured report listing every offending file/line and citing the invariant — readable directly from `cargo test` output without needing to look up which seam the rule serves.

### Builder methods

| Method | Effect |
|---|---|
| `new(name)` | Stable identifier surfaced in the panic message. Conventionally the test function's name. |
| `cite_invariant(rule)` | Catalog rule (M3, P2, etc.) or seam reference this discipline serves. Required for the discipline to be self-documenting. |
| `rationale(why)` | One-line "why this rule exists." Surfaced in the panic message so a future author understands the intent. |
| `forbid_pattern(regex)` | Add a pattern that must not appear. Multiple patterns are ORed — any match is a violation. |
| `allow_path(substring)` | Files whose path contains this substring are exempt from the discipline. Use for "the rule is forbidden everywhere except this one place that defines it." |
| `restrict_to_paths(&[..])` | Inverse of `allow_path` — only scan files matching one of these substrings. Use for "the rule applies only inside this file or subtree." |
| `skip_lines_containing(substring)` | Skip individual lines containing this substring. Common: `"//"` to skip comment lines, `"verify_strict"` to allow the strict variant when the forbidden pattern matches its prefix. |
| `scan_extensions(&["toml"])` | Override the default `["rs"]`. Disciplines that pin Cargo features scan `.toml`; SRI-style disciplines on assets would scan `.html`. |
| `assert()` | Run the check. Pass on clean; panic with a structured report on violation. |

### Limits

- **Regex isn't AST-aware.** A determined author can defeat it with formatting tricks (multi-line, unusual whitespace, macro indirection). Most disciplines we care about have stable enough surface form that this doesn't matter, but some don't. When a discipline can't be reliably expressed as a regex, it stays a doc comment and we accept the cost — or it becomes a fuller AST-based lint that lives outside this framework.
- **Doc-comment text containing the forbidden pattern triggers false positives.** The `skip_lines_containing("//")` exemption handles single-line comments. Block doc comments (`/// ...`) are also matched by `//`. Multi-line raw-string blocks (triple-quoted Markdown in doc comments, etc.) aren't handled gracefully — a per-test allowlist is the workaround.
- **Disciplines accumulate cost.** Each one walks the workspace. With 30 disciplines, the whole-workspace scan adds a second or two to `cargo test`. The framework caches nothing across disciplines today; if the cost ever becomes a real problem we'd add a shared file-content cache.

### Adjacent tooling

- **Lints (`clippy`, custom rustc lints).** Similar in intent, much heavier weight. Live in a different ecosystem with their own DSL and lifecycle. Discipline tests are just Rust code, easier to add and customize.
- **`forbid(unsafe_code)`.** The simplest possible discipline test, baked into the language. Discipline tests extend that family of mechanisms to rules the language doesn't ship a built-in for.
- **Bazel/Buck strict-deps and visibility constraints.** Same family at much heavier weight. zp-discipline is the lightweight, workspace-scoped, in-codebase version.

---

## Part III — Discipline Catalog (May 2026)

Each entry: name, seam/invariant cited, what's forbidden, where it lives.

### `no_serde_json_preserve_order_feature`

- **Seam.** Seam 17 (ZP-canonical-v1 determinism).
- **Forbidden.** The `preserve_order` feature on `serde_json` enabled anywhere in workspace `Cargo.toml` files.
- **Why.** The canonical JSON form depends on `serde_json::Map` being `BTreeMap`-backed (lexicographic keys). `preserve_order` switches to `IndexMap` (insertion order). Every signed structure in the workspace would silently shift hash, and the audit chain would break across the cut.
- **File.** `crates/zp-discipline/tests/no_serde_preserve_order.rs`.
- **Pairs with.** Runtime test `canonical::tests::preserve_order_not_enabled` in `zp-receipt`. The runtime test confirms the property *holds* at test time; this discipline test confirms it cannot be *enabled* at the manifest layer.

### `no_literal_keychain_service_in_entry_new`

- **Seam.** Seam 11 (test/production identity isolation).
- **Forbidden.** `keyring::Entry::new(...)` called with a literal string starting with `"zeropoint-genesis"` or `"zeropoint-operator"` (production namespace strings).
- **Why.** All keychain access must route through the namespace-resolution functions (`genesis_keychain_service()` etc.), which consult both `cfg!(test)` AND the `ZP_KEYCHAIN_TEST_NAMESPACE` env var. A literal string bypasses both gates and reaches production credentials from a test build.
- **File.** `crates/zp-discipline/tests/no_raw_keychain_service_strings.rs`.

### `keyring_rs_must_use_write_secret_file`

- **Seam.** Seam 7 (atomic mode-0600 secret writes / CRIT-8).
- **Forbidden.** `std::fs::write(...)` inside `crates/zp-keys/src/keyring.rs`.
- **Why.** Every secret write in `keyring.rs` must go through `write_secret_file` (atomic tmpfile + fsync + rename, mode 0600 from creation). `std::fs::write` defaults to 0644 with no atomicity guarantee — that's the exact write-then-chmod race the audit flagged as CRIT-8.
- **File.** `crates/zp-discipline/tests/no_std_fs_write_in_keyring.rs`.

### `no_non_strict_ed25519_verify`

- **Seam.** Seam 5 (verifier symmetry / CRIT-4).
- **Forbidden.** `verifying_key.verify(...)` (non-strict). Pattern: `verifying_key\.verify\b\s*\(` — the word boundary excludes `verify_strict`.
- **Why.** Non-strict `verify` is signature-malleable. `verify_strict` is the only sanctioned primitive. Phase 1.C swept the five known sites; this discipline pins the result and catches future drift.
- **File.** `crates/zp-discipline/tests/no_non_strict_ed25519_verify.rs`.
- **Known gap.** The pattern matches the canonical variable name `verifying_key`. Creative variable names (`vk`, `verifier`, etc.) aren't caught. The broader Tier 1 follow-up sweep (task #30) consolidates all verify call sites into the `zp_core::verify_signature` helper; once that lands, a tighter discipline can pin "no `verify_strict` outside the helper module" with `restrict_to_paths` set to its complement.

---

## Part IV — How to Add a New Discipline

When a structural commitment crystallizes — typically as part of a structural-audit pass or after a remediation cycle — the workflow is:

1. **Name the convention precisely.** Write down the rule as a single sentence: "X must not appear in Y." If the rule has more than one clause, split it into multiple disciplines.

2. **Cite the seam or invariant.** Open `STRUCTURAL-AUDIT-2026-05.md` and find which seam the rule serves. Or find the catalog rule (M3, P2, X1, etc.). The discipline test must cite this — it's how future readers locate the rationale.

3. **Express the rule as a regex.** Most rules are: "this pattern must not appear." Some are inverse: "this pattern must appear in this file." The framework doesn't directly support the inverse; encode it as "the *absence* of the helper indicator." When the rule resists regex expression, accept that it stays a doc-comment convention and don't force a brittle test.

4. **Build an allowlist.** Find every file where the pattern *legitimately* appears (the helper that defines the rule, error messages, doc comments). Use `allow_path` for whole-file exemptions and `skip_lines_containing` for line-level exemptions. The allowlist should be small and explicit — every entry is a place where the rule is explicitly carved out.

5. **Write the test in `crates/zp-discipline/tests/<name>.rs`.** One file per discipline. The file's doc comment should explain the seam, the rule, and any known gaps.

6. **Add an entry to Part III above.** Link the test file, cite the seam, explain why. The catalog is the index; without it, future authors can't find the rule.

7. **Run `cargo test -p zp-discipline`.** Confirm the discipline passes today against the existing codebase. If it fails on legitimate code you didn't expect, expand the allowlist explicitly (with a comment explaining why) — never relax the regex to silence a violation without understanding it.

---

## Part V — Method Notes

This document was produced as the test-layer companion to `STRUCTURAL-AUDIT-2026-05.md`. The May 2026 keychain debugging session (documented in the structural audit's Seam 11) surfaced the insight that *reliability* is part of "convention to invariant," not separate from it. Flaky tests are themselves a convention that something will work most of the time; deterministic tests are an invariant that it always will. Discipline-pin tests are the natural extension of that recognition: not just "tests should reliably pass," but "the rules the substrate operates by should be enforceable by the build, not by reviewer memory."

The framework is small on purpose. The four starter disciplines are concrete, and each one closes a real gap from Tier 1. Future versions of this document will accumulate more disciplines as more conventions crystallize. Like the structural audit and the catalog, this document is autoregressive — its v2 will be conditioned on what implementing v1's disciplines teaches us.
