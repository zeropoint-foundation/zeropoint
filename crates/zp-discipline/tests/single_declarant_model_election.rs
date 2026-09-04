//! Discipline: exactly one authority declares model election (HARNESS-SEAM
//! §3 C1 — "zp-config `llm.*`"). HARNESS-SEAM-2026-08 §4 S4 ("single
//! declarant"): "the sensor that would have caught the five-way model
//! split."
//!
//! # What this pin actually covers, and what it does not — read before
//! extending
//!
//! C1 was **VIOLATED — 5 declarants** as of the 2026-08-09 audit. As of
//! this pin landing (2026-08-26), two of those five are fixed and are what
//! this pin guards against regressing:
//!
//! 1. `zp-server::proxy::get_routing_config()`'s compiled `local` tier
//!    (named `ollama`/`mistral`) — deleted per the C1 resolution. This pin
//!    forbids it reappearing.
//! 2. `officer-inference.toml`'s `[models]` table — removed under W4
//!    (2026-08-26). **Not enforceable by this pin.** `Discipline::assert()`
//!    scans `<workspace_root>/crates` only (see `zp-discipline::lib::assert`);
//!    `officer-inference.toml` lives at the repo root and is structurally
//!    outside this scanner's reach. Regressing it would have to be caught by
//!    something else — there is currently nothing else. Disclosed, not
//!    silently assumed covered.
//!
//! # CLOSED 2026-09-01: the Regent's reasoning/routing model election
//!
//! A third declarant — `RegentConfig`'s `reasoning_model` / `routing_model`
//! — was found and closed this session. History, for a reader who wants it:
//!
//! - 2026-08-30: the pin was extended to forbid a literal
//!   `reasoning_model: "..."` / `routing_model: "..."` assignment, but
//!   investigation found the hardcode present at *six* independent sites
//!   (not the one the extension was scoped for), so all six were named and
//!   exempted via `allow_path` pending a unification decision.
//! - 2026-09-01: Ken signed off on unification. `zp_config::ZpConfig`'s
//!   `regent_reasoning_model` / `regent_routing_model` fields
//!   (`crates/zp-config/src/schema.rs`, declared once via
//!   `Sourced::default_value`) are now the **sole declarant**. Every other
//!   site derives:
//!   - `zp_regent::config::RegentConfig::default()` — **removed**.
//!     `RegentConfig` now has no `Default` impl at all; callers use
//!     `RegentConfig::from_zp_config(cfg: &ZpConfig)` or, in tests,
//!     `RegentConfig::for_tests(reasoning_model, routing_model)`. The three
//!     runtime call sites that compared live config against
//!     `RegentConfig::default()` (`Regent::new`'s pin-detection diff,
//!     `clear_operator_pin`, `reconfigure_inference`'s `"auto"` branches, all
//!     in `crates/zp-regent/src/regent.rs`) now compare against a
//!     `default_config: RegentConfig` field captured once at construction,
//!     threaded in from `zp-server::regent::spawn_regent`.
//!   - `zp-server::ServerConfig`'s own `Default` impl
//!     (`crates/zp-server/src/lib.rs`) — has zero callers in this workspace
//!     (confirmed by grep; production goes through
//!     `ServerConfig::from_zp_config`, which already correctly derived these
//!     two fields from `ZpConfig` before this session). Its two literals are
//!     now wrapped in the same `std::env::var(...).unwrap_or_else(...)`
//!     shape its `llm_provider`/`llm_model`/`llm_escalation_model` siblings
//!     in the same impl already used — consistent with that impl's existing,
//!     intentional design as a standalone env-only bootstrap path, and no
//!     longer the literal-string-assignment shape this pin forbids.
//!   - `zp-server::regent::ServerRegentConfig`'s own `Default` impl — also
//!     zero callers (the struct is always populated via the one real
//!     construction site in `lib.rs`). **Deleted outright.**
//!   - `zp-hardening-tests/src/harness.rs` (two occurrences) — a test
//!     fixture that states these fields explicitly rather than defaulting
//!     them, by design (same reasoning as its neighboring `llm_model:
//!     "test-model"` — inert, since `regent_enabled: false` in this
//!     fixture). Values changed from the real defaults to
//!     `"test-reasoning-model"` / `"test-routing-model"` so they no longer
//!     coincide with `ZpConfig`'s declaration by accident. Still a literal
//!     assignment, so still exempted — see below.
//!   - `zp-regent/src/routing.rs`'s `test_config()` — now built from
//!     `RegentConfig::for_tests("qwen3:8b", "qwen3:1.7b")`, which takes the
//!     two names positionally specifically so a caller never spells out the
//!     forbidden `reasoning_model: "..."` shape. No exemption needed.
//!
//! **What the two forbid patterns below mean now that unification is
//! real**, not merely acknowledged:
//!
//! - `(reasoning_model|routing_model):\s*"` — a literal string assigned to
//!   either field at any struct-literal construction site, anywhere in
//!   `crates/`. After this closure, nothing legitimate matches this shape
//!   except the two permanent exemptions below — so it now fires for real.
//! - `(regent_reasoning_model|regent_routing_model):\s*Sourced::default_value\(\s*"`
//!   — the `ZpConfig` authority's own declaration shape. Deliberately still
//!   forbidden everywhere *except* `zp-config/src/schema.rs` — the point is
//!   not "this shape must never exist," it's "this shape must exist in
//!   exactly the one recognized place." A second file declaring a
//!   `Sourced::default_value` for either of these field names anywhere else
//!   would be exactly the five-way-split failure mode this pin exists to
//!   catch, one authority later.
//!
//! **Two permanent exemptions remain** — not gaps, not TODOs, the intended
//! resting state:
//!
//! - `crates/zp-config/src/schema.rs` — the one recognized authority. Same
//!   role as `singular_sovereign_root.rs`'s own single exempted location.
//! - `crates/zp-hardening-tests/src/harness.rs` — inert, deliberately
//!   explicit test literals, same category as that file's own `llm_model` /
//!   `llm_provider` fields (which were never in this pin's scope to begin
//!   with, since this pin only ever targeted `reasoning_model` /
//!   `routing_model`).
//!
//! # Why a regex pin, not a semantic one
//!
//! "Exactly one declarant" is fundamentally a whole-workspace property, not
//! a single-file rule — the same limitation every discipline pin in this
//! crate has. What is checked here is the narrower, regressable-in-one-file
//! form: specific compiled literals, or the one authority's own declaration
//! shape appearing somewhere it shouldn't, must not spread to a new site.

use zp_discipline::Discipline;

/// The pins' own crate is exempt — see `singular_sovereign_root.rs` for why
/// this is not a loophole (a pin's source necessarily contains the pattern
/// it forbids, in its own `forbid_pattern` call).
const DISCIPLINE_CRATE: &str = "crates/zp-discipline/";

/// The one recognized model-election authority. Exempted from both forbid
/// patterns below, permanently — see the module doc comment.
const AUTHORITY: &str = "crates/zp-config/src/schema.rs";

/// Inert, deliberately explicit test literals — see the module doc comment.
/// Exempted permanently, same category as this file's own `llm_model`.
const HARDENING_TEST_FIXTURE: &str = "crates/zp-hardening-tests/src/harness.rs";

fn build() -> Discipline {
    Discipline::new("single_declarant_model_election")
        .cite_invariant("C1 (model election) / S4 (single declarant)")
        .rationale(
            "zp-config's llm.provider/llm.model/llm.escalation_model is the \
             sole model-election authority (HARNESS-SEAM-2026-08 §3 C1). A \
             compiled `local` tier route in get_routing_config() was a second \
             declarant, carrying a model (`mistral`) that was never even \
             installed — an inner mechanism smuggling in outer content. \
             Fixed once (see the C1 resolution comment in proxy.rs); this \
             pin keeps it fixed. Extended 2026-08-30 and closed 2026-09-01 \
             to also forbid a literal reasoning_model/routing_model \
             assignment anywhere outside ZpConfig's own declaration in \
             schema.rs — six independent declarants collapsed to one; see \
             module doc comment for the full history.",
        )
        .forbid_pattern(r"local:\s*Some\(TierRoute")
        .forbid_pattern(r#"(reasoning_model|routing_model):\s*""#)
        .forbid_pattern(r#"(regent_reasoning_model|regent_routing_model):\s*Sourced::default_value\(\s*""#)
        .allow_path(DISCIPLINE_CRATE)
        .allow_path(AUTHORITY)
        .allow_path(HARDENING_TEST_FIXTURE)
        .skip_lines_containing("//")
        .skip_lines_containing("forbid_pattern")
}

#[test]
fn single_declarant_model_election() {
    build().assert();
}

/// HARNESS-SEAM-2026-08 S4, W7. Prove the sensor is not lying: write a
/// synthetic file reproducing the exact compiled-local-tier declaration the
/// real 2026-08 fix removed, confirm the discipline catches it, delete the
/// synthetic file, confirm the discipline runs clean again.
///
/// The fixture necessarily lives under `crates/zp-discipline/tests/` (the
/// only tree this test can write into that `Discipline::assert()` also
/// scans) — but the production pin in `build()` above exempts the whole
/// `zp-discipline` crate via `DISCIPLINE_CRATE`, so it would never see a
/// fixture placed there. This test instead builds `probe()`, an identical
/// pin minus that self-exemption, so the fixture is actually visible to
/// what gets checked.
///
/// Removal is guaranteed even if an assertion here fails partway through,
/// via a drop guard — a broken test must never leave a stray fixture file
/// in the tree.
#[test]
fn single_declarant_model_election_catches_synthetic_violation_and_clears_on_fix() {
    struct CleanupGuard(std::path::PathBuf);
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // A pin identical to the production one, minus the self-exemption, so a
    // fixture placed inside zp-discipline's own tree is actually visible to
    // it. Keeping this separate from `build()` above is deliberate: it must
    // NOT inherit the exemption it exists to see past.
    fn probe() -> Discipline {
        Discipline::new("single_declarant_model_election_probe")
            .forbid_pattern(r"local:\s*Some\(TierRoute")
            .skip_lines_containing("forbid_pattern")
    }

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("__s4_synthetic_violation_fixture.rs");

    // The fixture content below is assembled from two literal halves so
    // this file's OWN source never spells out `local:` immediately
    // followed by `Some(TierRoute` on one line -- which is exactly the
    // pattern this pin's `probe()` (below) scans for, with no
    // `DISCIPLINE_CRATE` exemption, so it can see the external fixture
    // file. Without the split, this source file would trip its own probe
    // permanently, regardless of whether the external fixture exists,
    // breaking the "catches violation, clears on fix" round trip. Same
    // technique as the loopback pin's doc-comment fix (meta-notation
    // instead of the literal). The two halves concatenate at runtime into
    // the exact real-violation text, so the fixture written to disk is a
    // faithful reproduction of what W3 actually removed.
    let local_field = "local:";
    let some_tier_route = " Some(TierRoute { provider: \"ollama\".to_string(), model: \"mistral\".to_string() }), ..Default::default() }\n}\n";
    let fixture_content = format!(
        "// Synthetic S4 fixture -- reproduces the removed compiled local-tier declaration.\nfn _synthetic_reintroduction() -> RoutingConfig {{\n    RoutingConfig {{ {}{}",
        local_field, some_tier_route
    );

    std::fs::write(&fixture_path, &fixture_content).expect("write synthetic S4 fixture");
    let _guard = CleanupGuard(fixture_path.clone());

    // 1-3: violation present -> the probe must catch it (panic).
    let caught = std::panic::catch_unwind(|| probe().assert());
    assert!(
        caught.is_err(),
        "S4 must catch a reintroduced compiled local-tier model declaration"
    );

    // 4: remove the violation.
    std::fs::remove_file(&fixture_path).expect("remove synthetic S4 fixture");

    // 5: clean run -> must not panic.
    let clean = std::panic::catch_unwind(|| probe().assert());
    assert!(
        clean.is_ok(),
        "S4 must run clean once the synthetic violation is removed"
    );
}

/// HARNESS-SEAM-2026-08 S4, unification closer (2026-09-01). Prove the
/// *extended* pattern is not lying either, now that unification is
/// supposed to be real: write a synthetic file reproducing a literal
/// `reasoning_model` / `routing_model` string assignment inside a
/// `RegentConfig` construction, confirm the discipline catches it, delete
/// the synthetic file, confirm the discipline runs clean again.
///
/// Same structure as the loopback self-test above: a local `probe()` that
/// drops `build()`'s `DISCIPLINE_CRATE` exemption, so a fixture placed
/// under `crates/zp-discipline/tests/` is actually visible to what this
/// test checks. Unlike the loopback probe, this one keeps `build()`'s other
/// two *permanent* exemptions (`AUTHORITY`, `HARDENING_TEST_FIXTURE`) —
/// those are real, by-design, permanent carve-outs (see the module doc
/// comment), not artifacts of this test. Without them, `probe()` would see
/// pre-existing "violations" that are actually the intended resting state,
/// and the "clean once removed" assertion below would fail for a reason
/// that has nothing to do with the synthetic fixture. A drop guard
/// guarantees fixture removal even if an assertion here fails partway
/// through.
///
/// `probe()` here additionally skips `//` lines. The loopback probe above
/// doesn't need that (its pattern needs `Some(TierRoute` after `local:`, so
/// no comment in this file ever accidentally matches it) — but the module
/// doc comment above this line quotes `reasoning_model: "qwen3:8b"` and
/// similar shapes verbatim as prose, which the extended pattern below
/// would otherwise flag as a permanent false violation in this very file,
/// independent of whether the synthetic fixture exists. Skipping `//`
/// lines is the same treatment `build()` itself already gives every
/// pattern in this file; the self-test probe should not be stricter than
/// the production pin it is proving out.
#[test]
fn single_declarant_model_election_catches_regent_config_literal_and_clears_on_fix() {
    struct CleanupGuard(std::path::PathBuf);
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn probe() -> Discipline {
        Discipline::new("single_declarant_model_election_regent_config_probe")
            .forbid_pattern(r#"(reasoning_model|routing_model):\s*""#)
            .allow_path(AUTHORITY)
            .allow_path(HARDENING_TEST_FIXTURE)
            .skip_lines_containing("forbid_pattern")
            .skip_lines_containing("//")
    }

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("__s4_synthetic_regent_config_fixture.rs");

    // Split *before* the colon, not after: unlike the loopback pattern
    // above (which needs `Some(TierRoute` following `local:`, so a bare
    // trailing quote never satisfies it), this pattern is satisfied by
    // `reasoning_model`/`routing_model` followed by `:` and just a quote --
    // which is exactly what a Rust string literal's own closing `"` would
    // produce if the field name and its trailing colon were kept together
    // in one literal (e.g. `"reasoning_model:"` ends in `:"`, tripping the
    // probe on this source file itself). Keeping the field name and the
    // `: "value"` half in two separate literals means neither half, nor
    // this file's surrounding code, ever spells out the colon-then-quote
    // sequence contiguously.
    let reasoning_field = "reasoning_model";
    let reasoning_assign = ": \"x\".to_string(),\n";
    let routing_field = "routing_model";
    let routing_assign = ": \"y\".to_string(),\n        ..Default::default()\n    }\n}\n";
    let fixture_content = format!(
        "// Synthetic S4 fixture -- reproduces a literal reasoning/routing model \
         string assignment inside a RegentConfig construction.\nfn _synthetic_reintroduction() -> RegentConfig {{\n    RegentConfig {{\n        {}{}        {}{}",
        reasoning_field, reasoning_assign, routing_field, routing_assign
    );

    std::fs::write(&fixture_path, &fixture_content).expect("write synthetic S4 fixture");
    let _guard = CleanupGuard(fixture_path.clone());

    // 1-3: violation present -> the probe must catch it (panic).
    let caught = std::panic::catch_unwind(|| probe().assert());
    assert!(
        caught.is_err(),
        "S4 must catch a literal reasoning_model/routing_model string assignment \
         in a RegentConfig construction"
    );

    // 4: remove the violation.
    std::fs::remove_file(&fixture_path).expect("remove synthetic S4 fixture");

    // 5: clean run -> must not panic.
    let clean = std::panic::catch_unwind(|| probe().assert());
    assert!(
        clean.is_ok(),
        "S4 must run clean once the synthetic violation is removed"
    );
}
