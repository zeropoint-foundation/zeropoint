//! Discipline (DECIDED-004 MEANWHILE-3, August 2026): urgency is decided by
//! `Severity`'s two named floors, never by comparing a severity string.
//!
//! # Why
//!
//! Before 2026-08-12 there were five statements about what makes an officer
//! finding urgent, and they were reconciled nowhere:
//!
//! - `loop_runner.rs` gated the immediate cycle on `Severity::Critical`, by
//!   enum match.
//! - `regent.rs` computed `has_urgent` as `"Error" || "Critical"` — twice,
//!   independently, by string comparison.
//! - `regent.rs` filtered conversation-mode findings on `"Critical"` — a third
//!   string comparison.
//! - The `start_loop` doc comment said "immediate cycle if urgent", which reads
//!   as the `Error|Critical` sense at the one site that means `Critical` only.
//! - `Severity::Error`'s own doc said "requiring operator attention", which
//!   reads as the strongest of all of them.
//!
//! The behaviour was actually a coherent *pair* — think about it at `Error`,
//! wake up for it at `Critical` — but nothing said so, so a reader adopted
//! whichever they met first. Both floors now have names, and this pin keeps the
//! decision in one place.
//!
//! # The hazard this actually guards
//!
//! `FindingSummary::severity` is a `String`, produced for the whole life of the
//! chain by `format!("{:?}", severity)` — the capitalised spelling. `Severity`
//! also derives `Serialize` with `rename_all = "snake_case"`, so the *declared
//! wire form* is `"error"`. A perfectly reasonable-looking change — use serde
//! instead of the Debug formatter — would have made every `== "Error"` false,
//! permanently, with no compiler complaint and no test failure. The Regent
//! would have stopped reasoning about urgent findings and reported healthy.
//!
//! That is PIN-002: reporting health because it had gone blind. Two things
//! answer it — `context_str_matches_debug_spelling` in `zp-officers` pins the
//! spelling, and this pin stops new open-coded comparisons from appearing.
//!
//! # What this pin does
//!
//! Scans [`SCANNED`] for `severity == "…"` and for direct matches on
//! `Severity::Error` / `Severity::Critical` used as a threshold. Both are
//! violations: call `demands_attention()` or `interrupts()` instead.
//!
//! Constructing a finding at a severity is not a threshold decision and is not
//! matched — `severity: Severity::Critical` is a field initialiser, and the
//! patterns below are anchored to comparison and match contexts only.
//!
//! # Why the self-test matters more than the pin
//!
//! `the_scan_actually_reads_the_files` asserts every scanned file exists and is
//! non-trivial, and `the_scan_finds_the_sanctioned_predicates` asserts the
//! replacement predicates are actually present in the scanned tree. Without
//! them, moving these files or renaming the predicates would leave this pin
//! passing forever while checking nothing — the same failure it exists to
//! prevent, applied to itself. See PIN-002.

use std::path::{Path, PathBuf};

use regex::Regex;

/// Files that decide, or could decide, whether a finding is urgent.
const SCANNED: &[&str] = &[
    "crates/zp-regent/src/regent.rs",
    "crates/zp-regent/src/loop_runner.rs",
    "crates/zp-regent/src/context.rs",
];

/// The one place the floors are defined. Exempt by construction.
const SOURCE_OF_TRUTH: &str = "crates/zp-officers/src/finding.rs";

/// `severity == "Whatever"` — a stringly-typed threshold.
fn string_comparison_re() -> Regex {
    Regex::new(r#"severity\s*==\s*""#).unwrap()
}

/// `Severity::Error` or `Severity::Critical` in a comparison or match
/// position, rather than as a field initialiser.
fn open_coded_threshold_re() -> Regex {
    Regex::new(r"(?:==|>=|<=|>|<|matches!\s*\([^)]*)\s*(?:zp_officers::finding::)?Severity::(?:Error|Critical)")
        .unwrap()
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut cur: &Path = &manifest_dir;
    loop {
        let candidate = cur.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return cur.to_path_buf();
                }
            }
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => panic!("no workspace Cargo.toml above {}", manifest_dir.display()),
        }
    }
}

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// A line is exempt if it is a comment. The doc comments in these files
/// quote the old spellings deliberately, to explain what changed.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

#[test]
fn urgency_is_never_decided_by_a_severity_string() {
    let re = string_comparison_re();
    let mut violations = Vec::new();

    for rel in SCANNED {
        for (i, line) in read(rel).lines().enumerate() {
            if !is_comment(line) && re.is_match(line) {
                violations.push(format!("  {rel}:{}  {}", i + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\nUrgency decided by comparing a severity string.\n\n\
         `FindingSummary::severity` carries the `Debug` spelling; `Severity`'s\n\
         serde form is snake_case. A comparison against either is one\n\
         formatter change away from being permanently false, and nothing would\n\
         fail. Call `demands_attention()` (think about it) or `interrupts()`\n\
         (wake up for it) instead — see `Severity`'s type docs.\n\n{}\n",
        violations.join("\n")
    );
}

#[test]
fn thresholds_are_not_open_coded_against_the_enum() {
    let re = open_coded_threshold_re();
    let mut violations = Vec::new();

    for rel in SCANNED {
        for (i, line) in read(rel).lines().enumerate() {
            if !is_comment(line) && re.is_match(line) {
                violations.push(format!("  {rel}:{}  {}", i + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\nA severity threshold compared directly against an enum variant.\n\n\
         Which floor governs is a decision with a name. Spelling it inline\n\
         means the next reader has to infer whether this site meant `Error` or\n\
         `Critical` and why — which is exactly the state MEANWHILE-3 resolved.\n\
         Use `demands_attention()` or `interrupts()`.\n\n{}\n",
        violations.join("\n")
    );
}

#[test]
fn the_scan_actually_reads_the_files() {
    for rel in SCANNED {
        let src = read(rel);
        assert!(
            src.len() > 1_000,
            "{rel} is {} bytes — did it move? A scan over an empty or missing \
             file passes while checking nothing.",
            src.len()
        );
    }
}

#[test]
fn the_scan_finds_the_sanctioned_predicates() {
    let scanned: String = SCANNED.iter().map(|r| read(r)).collect();

    for predicate in ["demands_attention", "interrupts"] {
        assert!(
            scanned.contains(predicate),
            "no call to `{predicate}` anywhere in the scanned files. Either the \
             predicate was renamed — in which case this pin is now blind and \
             both patterns above need updating — or urgency moved somewhere \
             this pin does not look."
        );
    }
}

#[test]
fn the_floors_are_declared_where_this_pin_says_they_are() {
    let src = read(SOURCE_OF_TRUTH);
    for decl in ["ATTENTION_FLOOR", "INTERRUPT_FLOOR"] {
        assert!(
            src.contains(decl),
            "{SOURCE_OF_TRUTH} no longer declares {decl}. This pin's error \
             messages point readers at a definition that has moved."
        );
    }
}
