//! Discipline: every path that writes a delegation to the chain validates
//! issuance first.
//!
//! # Why (2026-08-13)
//!
//! `CapabilityGrant::validate_issuance` carries two unrelated refusals that
//! happen to share a call site:
//!
//! 1. **M4-3** — an `ExternalRequest`-originated grant may not carry an
//!    internal-only capability. This is the SSRF self-grant vector.
//! 2. **Non-delegable authority** — a reserved capability may not appear in a
//!    grant *at all*, regardless of who is asking, because the point is not the
//!    requester's authority but that the capability cannot be held by a grantee.
//!
//! The second is capability-intrinsic. A path that skips validation does not
//! merely relax a check about origin; it removes a refusal that was never about
//! origin in the first place. That is why this pin scans for the *write*, not
//! for the HTTP surface: any path reaching the chain must pass the same gate.
//!
//! `zp delegate` skipped it entirely — it constructed a standing grant and
//! wrote it to the chain with no validation, while `grant_handler` on the HTTP
//! path validated. One invariant, two paths, one enforcing.
//!
//! # Name collision — read before editing
//!
//! There are **two** functions called `emit_delegation_receipt`:
//!
//! - `zp_server::tool_chain::emit_delegation_receipt` — capability grants to
//!   the audit chain. **This is the one this pin is about.**
//! - `zp_core::receipt_emission::emit_delegation_receipt` — key rotation and
//!   delegation *certificates*. Unrelated; not scanned, and must not be added
//!   to `SOURCES` without rethinking what the pin asserts.
//!
//! # What this asserts
//!
//! For every non-test call to `emit_delegation_receipt(` in the scanned
//! sources, the enclosing function also mentions `validate_issuance` or
//! `validate_grant` — unless the function is named in `KNOWN_UNVALIDATED`.
//!
//! # What this deliberately does not assert
//!
//! **Ordering.** The scan is textual and cannot prove validation *precedes* the
//! write, only that the function does both. A function that wrote first and
//! validated second would pass. Accepted: "this path never validates" is the
//! failure that actually occurred. If ordering ever becomes the live failure,
//! this note is the record that it was a known gap.
//!
//! # If this fails after a rename
//!
//! The scan keys on the literal `emit_delegation_receipt(` and on function
//! headers matching `fn <name>(`. If either is renamed, update this file — do
//! not delete the pin. `the_scan_actually_finds_call_sites` exists so a rename
//! fails loudly here rather than passing vacuously.

const CLI_SOURCE: &str = include_str!("../../zp-cli/src/main.rs");
const SERVER_SOURCE: &str = include_str!("../../zp-server/src/lib.rs");

const SOURCES: &[(&str, &str)] = &[
    (CLI_SOURCE, "crates/zp-cli/src/main.rs"),
    (SERVER_SOURCE, "crates/zp-server/src/lib.rs"),
];

const WRITE_CALL: &str = "emit_delegation_receipt(";
const VALIDATORS: &[&str] = &["validate_issuance", "validate_grant"];

/// Production handlers that write a delegation without validating issuance.
///
/// **These are debt, not exemptions.** Each is a live instance of the defect
/// this pin exists to prevent; they are recorded so the pin can block *new*
/// instances today rather than waiting for the backlog to clear. Found
/// 2026-08-13 while closing the `zp delegate` hole; see the delegation
/// invariants work in `docs/handoffs/SESSION-HANDOFF-2026-08-13-rev2.md`.
///
/// The list may shrink. It may not grow — `the_debt_list_only_shrinks` fails if
/// an entry is added, and adding one is a decision that belongs in review, not
/// in a commit that needed the suite green.
const KNOWN_UNVALIDATED: &[&str] = &[
    "lease_renew_handler",
    "tool_launch_handler",
    "register_agent_handler",
];

/// Byte offset of the start of the function enclosing `idx`, if found.
fn enclosing_fn_start(src: &str, idx: usize) -> Option<usize> {
    const HEADERS: &[&str] = &[
        "\nfn ",
        "\npub fn ",
        "\npub(crate) fn ",
        "\npub(super) fn ",
        "\nasync fn ",
        "\npub async fn ",
        "\n    fn ",
        "\n    pub fn ",
        "\n    pub(crate) fn ",
        "\n    async fn ",
        "\n    pub async fn ",
    ];
    // Each pattern begins with `\n`, so `rfind` returns the offset OF that
    // newline. Return the offset after it, so the slice starts at the header
    // text — otherwise `src[fn_start..].lines().next()` yields the empty string
    // before the newline and every name parses as "".
    HEADERS
        .iter()
        .filter_map(|h| src[..idx].rfind(h))
        .max()
        .map(|i| i + 1)
}

/// The bare function name from a header line like `async fn foo(` .
fn fn_name(header_line: &str) -> &str {
    header_line
        .split("fn ")
        .nth(1)
        .unwrap_or("")
        .split(|c: char| c == '(' || c == '<' || c == ' ')
        .next()
        .unwrap_or("")
}

/// Whether the function starting at `fn_start` carries a test attribute.
///
/// Test functions always have `#[test]` or `#[tokio::test]` immediately above
/// the header, so a short lookback is sufficient and avoids having to reason
/// about where `#[cfg(test)]` modules begin and end.
fn is_test_fn(src: &str, fn_start: usize) -> bool {
    let window_start = fn_start.saturating_sub(200);
    let window = &src[window_start..fn_start];
    window.contains("#[test]") || window.contains("#[tokio::test]")
}

/// Every non-test `emit_delegation_receipt(` call site, with its enclosing fn.
fn call_sites() -> Vec<(&'static str, usize, String)> {
    let mut out = Vec::new();
    for &(src, path) in SOURCES {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(WRITE_CALL) {
            let idx = from + rel;
            from = idx + WRITE_CALL.len();

            let line_start = src[..idx].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line_end = src[idx..].find('\n').map(|e| idx + e).unwrap_or(src.len());
            let line = &src[line_start..line_end];
            if line.contains("fn emit_delegation_receipt") || line.trim_start().starts_with("use ") {
                continue;
            }

            let Some(fn_start) = enclosing_fn_start(src, idx) else {
                out.push((path, idx, String::new()));
                continue;
            };
            if is_test_fn(src, fn_start) {
                continue;
            }
            let header = src[fn_start..idx].lines().next().unwrap_or("").trim();
            let name = fn_name(header);
            // Two different failures used to collapse into one empty string and
            // one misleading message. Keep them apart: an empty name means no
            // header was found at all; `<unparsed:…>` means a header was found
            // and `fn_name` could not read it.
            if name.is_empty() {
                out.push((path, idx, format!("<unparsed:{header}>")));
            } else {
                out.push((path, idx, name.to_string()));
            }
        }
    }
    out
}

#[test]
fn every_delegation_write_validates_issuance() {
    let mut violations: Vec<String> = Vec::new();

    for (path, idx, name) in call_sites() {
        let src = SOURCES
            .iter()
            .find(|(_, p)| *p == path)
            .map(|(s, _)| *s)
            .expect("path came from SOURCES");
        let line_no = src[..idx].matches('\n').count() + 1;

        if name.is_empty() {
            violations.push(format!(
                "{path}:{line_no} — no enclosing function found. The header \
                 patterns in `enclosing_fn_start` need updating."
            ));
            continue;
        }
        if name.starts_with("<unparsed:") {
            violations.push(format!(
                "{path}:{line_no} — found an enclosing header but could not read \
                 its name: {name}. `fn_name` needs updating."
            ));
            continue;
        }
        if KNOWN_UNVALIDATED.contains(&name.as_str()) {
            continue;
        }

        let fn_start = enclosing_fn_start(src, idx).expect("resolved above");
        let body = &src[fn_start..idx];
        if !VALIDATORS.iter().any(|v| body.contains(v)) {
            violations.push(format!(
                "{path}:{line_no} — `{name}` writes a delegation to the chain \
                 without calling validate_issuance / validate_grant first. A \
                 path that skips validation also skips the non-delegable \
                 reserved-set refusal, which is capability-intrinsic and must \
                 fire regardless of who is asking. Fix the path; do not add it \
                 to KNOWN_UNVALIDATED without review."
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "delegation writes must validate issuance first:\n  {}",
        violations.join("\n  ")
    );
}

/// The debt list may shrink; it may not grow, and it may not go stale.
#[test]
fn the_debt_list_only_shrinks() {
    assert!(
        KNOWN_UNVALIDATED.len() <= 3,
        "KNOWN_UNVALIDATED grew to {}. Adding an unvalidated delegation write is \
         a governance decision, not a way to get the suite green.",
        KNOWN_UNVALIDATED.len()
    );

    // A name that no longer appears as an unvalidated site is stale — either it
    // was fixed (delete the entry) or renamed (update it). Either way, leaving
    // it here would silently exempt a future function that reuses the name.
    let live: Vec<String> = call_sites()
        .into_iter()
        .filter(|(path, idx, name)| {
            let src = SOURCES
                .iter()
                .find(|(_, p)| p == path)
                .map(|(s, _)| *s)
                .expect("path came from SOURCES");
            let Some(fn_start) = enclosing_fn_start(src, *idx) else {
                return false;
            };
            let body = &src[fn_start..*idx];
            !name.is_empty() && !VALIDATORS.iter().any(|v| body.contains(v))
        })
        .map(|(_, _, name)| name)
        .collect();

    for known in KNOWN_UNVALIDATED {
        assert!(
            live.iter().any(|n| n.as_str() == *known),
            "`{known}` is in KNOWN_UNVALIDATED but is no longer an unvalidated \
             delegation write. If it was fixed, remove the entry — a stale entry \
             silently exempts any future function that reuses the name."
        );
    }
}

/// Guards the pin against passing vacuously after a rename.
#[test]
fn the_scan_actually_finds_call_sites() {
    let sites = call_sites();
    assert!(
        sites.len() >= 2,
        "expected at least 2 non-test emit_delegation_receipt call sites \
         (CLI + server); found {}. If the function was renamed or moved, update \
         this pin — do not delete it.",
        sites.len()
    );

    let paths: Vec<&str> = sites.iter().map(|(p, _, _)| *p).collect();
    for expected in ["crates/zp-cli/src/main.rs", "crates/zp-server/src/lib.rs"] {
        assert!(
            paths.contains(&expected),
            "expected a delegation write in {expected}; found sites in {paths:?}."
        );
    }
}

/// Guards the enclosing-function and test-detection helpers directly.
#[test]
fn the_scan_helpers_behave() {
    let src = "fn outer() {\n    let _ = 1;\n}\n\nasync fn target() {\n    emit_delegation_receipt(&store);\n}\n";
    let idx = src.find(WRITE_CALL).expect("fixture contains the call");
    let start = enclosing_fn_start(src, idx).expect("fixture has an enclosing fn");
    // Regression: `enclosing_fn_start` once returned the offset of the newline
    // rather than the character after it, so this line was the empty string and
    // every real call site reported "could not locate the enclosing function".
    assert!(
        src[start..].starts_with("async fn target"),
        "offset must land on the header text, not the newline before it; got {:?}",
        &src[start..(start + 24).min(src.len())]
    );
    assert_eq!(fn_name(src[start..].lines().next().unwrap_or("").trim()), "target");
    assert!(!is_test_fn(src, start), "plain fn must not read as a test");

    let tsrc = "#[tokio::test]\nasync fn t() {\n    emit_delegation_receipt(&s);\n}\n";
    let tidx = tsrc.find(WRITE_CALL).expect("fixture contains the call");
    let tstart = enclosing_fn_start(tsrc, tidx).expect("fixture has an enclosing fn");
    assert!(is_test_fn(tsrc, tstart), "test fn must read as a test");
}
