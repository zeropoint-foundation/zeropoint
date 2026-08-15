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

/// Blank every comment line, preserving line count.
///
/// # Why blank rather than drop (2026-08-14)
///
/// Both predicates below must match against the **whole file**, not line by
/// line. `open_coded_threshold_re` is written for a construct that spans
/// lines — `matches!\s*\([^)]*` followed by `Severity::Error|Critical`, where
/// `[^)]*` crosses newlines by design. Fed one line at a time it can only
/// ever match the single-line spelling, so whether the pin fires depends on
/// whether rustfmt wrapped the call — that is, on identifier length.
///
/// This was not hypothetical. At `18466fc` this pin was green while
/// `crates/zp-regent/src/loop_runner.rs:300` still read:
///
/// ```text
///     matches!(
///         f.severity,
///         zp_officers::finding::Severity::Critical
///     )
/// ```
///
/// Whole-file scan matches that. Line-by-line does not. The pin passed on a
/// formatting accident, which is the precise failure mode a discipline pin
/// exists to prevent — a rule that looks enforced and is not.
///
/// Blanking rather than deleting keeps byte offsets aligned to line numbers,
/// so `line_of` can still report where a violation is. Comment lines stay
/// exempt: these files quote the old spellings deliberately.
fn scrub_comments(src: &str) -> String {
    src.lines()
        .map(|l| if is_comment(l) { "" } else { l })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 1-indexed line number containing byte offset `at`.
fn line_of(src: &str, at: usize) -> usize {
    src[..at].bytes().filter(|b| *b == b'\n').count() + 1
}

/// Every match of `re` in `rel`, as `(line_number, that line trimmed)`.
fn violations_in(rel: &str, re: &Regex) -> Vec<String> {
    let raw = read(rel);
    let scrubbed = scrub_comments(&raw);
    let lines: Vec<&str> = raw.lines().collect();
    re.find_iter(&scrubbed)
        .map(|m| {
            let n = line_of(&scrubbed, m.start());
            let text = lines.get(n - 1).map(|l| l.trim()).unwrap_or("");
            format!("  {rel}:{n}  {text}")
        })
        .collect()
}

#[test]
fn urgency_is_never_decided_by_a_severity_string() {
    let re = string_comparison_re();
    let mut violations = Vec::new();

    for rel in SCANNED {
        violations.extend(violations_in(rel, &re));
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
        violations.extend(violations_in(rel, &re));
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

/// The pin must catch a threshold whatever way rustfmt broke the line.
///
/// This is the regression test for the 2026-08-14 finding described on
/// `scrub_comments`: the wrapped spelling below is the exact text that sat
/// green in `loop_runner.rs` at `18466fc`. If someone reverts the scan to
/// line-by-line, `wrapped` stops matching and this test fails loudly, rather
/// than the pin going quietly blind.
#[test]
fn the_scan_catches_a_threshold_however_rustfmt_wrapped_it() {
    let re = open_coded_threshold_re();

    let inline = "        if matches!(f.severity, Severity::Critical) {";
    let wrapped = "            let has_critical = latest_findings.iter().any(|f| {\n\
                   \x20               matches!(\n\
                   \x20                   f.severity,\n\
                   \x20                   zp_officers::finding::Severity::Critical\n\
                   \x20               )\n\
                   \x20           });";

    assert!(
        re.is_match(inline),
        "the single-line threshold spelling is no longer caught"
    );
    assert!(
        re.is_match(&scrub_comments(wrapped)),
        "the rustfmt-wrapped threshold spelling is no longer caught — the scan \
         has regressed to line-by-line, and the pin now fires or not depending \
         on identifier length. See `scrub_comments`."
    );

    // And a comment carrying the forbidden spelling stays exempt, or every
    // doc comment in these files becomes a violation.
    let commented = "            // matches!(f.severity, Severity::Critical)";
    assert!(
        !re.is_match(&scrub_comments(commented)),
        "comment lines are no longer exempt"
    );
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
