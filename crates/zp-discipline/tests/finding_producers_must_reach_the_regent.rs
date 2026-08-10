//! Discipline (SEAM-009, August 2026): a task that produces officer findings
//! must forward them to the Regent.
//!
//! # Why
//!
//! `Regent::reason` decides whether to think at all. One of its four inputs is
//! `has_urgent` — true when any officer finding carries `Severity::Error` or
//! `Critical`. That predicate reads `context.officer_findings`, which is
//! populated *only* from `latest_findings` in `loop_runner.rs`, which is set
//! *only* by `RegentMessage::OfficerFindings`, which is sent *only* by
//! `RegentHandle::send_findings`.
//!
//! On 2026-08-09 `send_findings` had exactly one call site in the workspace:
//! `spawn_sweep_task`, the 300s periodic sweep. Every listener assessment —
//! `assess_unauthorized_listener`, `assess_unregistered_listener`, and the
//! `unregistered_known_app` split — lives in `spawn_sensor_forge_task`, which
//! writes findings to the audit chain and forwards nothing.
//!
//! The consequence was invisible in every direction you could look. All 17
//! `Error`-severity findings on the chain were listener findings, so the only
//! officer actually producing urgency did so on the far side of a missing wire.
//! `has_urgent` read as a working safety net in every file you could open; the
//! chain showed the findings; the Regent showed cycles. Nothing showed the gap.
//! It surfaced only because two measurements taken for unrelated reasons
//! disagreed.
//!
//! This pin makes the wire structural. A new officer task that produces
//! findings and does not forward them fails the build.
//!
//! # What this pin does
//!
//! Within [`FINDING_SOURCE`], split the file into top-level functions and
//! classify each:
//!
//! - **producer** — calls `.assess_*(` (an officer assessment) or
//!   `emit_finding(` (the chain-emission funnel).
//! - **forwarder** — mentions `send_findings`.
//!
//! A producer that is not a forwarder is a violation, unless it is listed in
//! [`KNOWN_UNFORWARDED`] with a reason.
//!
//! # On the exception list
//!
//! [`KNOWN_UNFORWARDED`] is a list of **defects**, not exemptions. Every entry
//! is a place where a finding cannot reach the thing that decides whether to
//! act on it.
//!
//! It is cross-checked in both directions, because this exact pattern has
//! already rotted once in this codebase: `KNOWN_ORPHAN_READS` in
//! `zp-core/src/receipt_extensions.rs` listed six keys as unwired, three were
//! wired the same afternoon, and the list went stale within the hour. A list
//! that only fails when reality gets *worse* silently accumulates lies as
//! reality gets better. So `known_unforwarded_entries_are_still_violations`
//! fails when an entry is fixed and left listed.
//!
//! # Why the self-test matters more than the pin
//!
//! `the_scan_actually_finds_producers` asserts the scan matched at least one
//! producer and at least one forwarder. Without it, renaming `officers.rs`,
//! moving the tasks to another crate, or changing the `assess_` convention
//! would make this pin pass forever while checking nothing — reporting health
//! because it had gone blind. That is PIN-002, and it is the failure mode this
//! whole file exists to answer, so it applies to the file itself.

use std::path::{Path, PathBuf};

use regex::Regex;

/// The file that owns officer task wiring. If the tasks move, the self-test
/// below fails rather than this pin silently passing.
const FINDING_SOURCE: &str = "crates/zp-server/src/officers.rs";

/// Functions that produce findings and do not forward them.
///
/// Each entry is a known defect with a reason and a review date — never a
/// blanket exemption. Remove the entry when the wire is added; the test below
/// fails if you fix it and leave it listed.
const KNOWN_UNFORWARDED: &[(&str, &str)] = &[(
    "spawn_sensor_forge_task",
    "SEAM-009. Deferred deliberately by DECIDED-004 until the port registry \
     becomes an attestation surface (DECIDED-003). Forwarding now would deliver \
     ~394 unclearable findings per window into the Regent's context, at least 17 \
     of them Error, making has_urgent true on nearly every cycle — permanent \
     inference on findings nobody can act on. Review after 2026-09-09.",
)];

/// A function that calls an officer assessment, or emits a finding to the chain.
fn producer_re() -> Regex {
    Regex::new(r"\.assess_\w+\s*\(|\bemit_finding\s*\(").unwrap()
}

/// A function that hands findings to the Regent's cognitive loop.
fn forwarder_re() -> Regex {
    Regex::new(r"\bsend_findings\b").unwrap()
}

/// `(name, first_line, body)` for each top-level function, in source order.
///
/// The body runs to the next top-level `fn` rather than to a matched closing
/// brace. That is deliberate: brace matching would need to understand strings,
/// char literals and raw strings to be correct, and getting it subtly wrong
/// would shift a body boundary and silently change what this pin sees. Running
/// declaration-to-declaration can only ever *over*-attribute — a producer call
/// is never lost, at worst it is credited to the function above it. This pin
/// fails loudly on a false positive and goes quiet on a false negative, so the
/// error is pointed in the safe direction.
fn functions(src: &str) -> Vec<(String, usize, String)> {
    let decl =
        Regex::new(r"(?m)^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)").unwrap();
    let marks: Vec<(String, usize)> = decl
        .captures_iter(src)
        .map(|c| {
            (
                c.get(1).unwrap().as_str().to_string(),
                c.get(0).unwrap().start(),
            )
        })
        .collect();

    let mut out = Vec::with_capacity(marks.len());
    for (i, (name, off)) in marks.iter().enumerate() {
        let end = marks.get(i + 1).map_or(src.len(), |(_, next)| *next);
        let line = src[..*off].matches('\n').count() + 1;
        out.push((name.clone(), line, src[*off..end].to_string()));
    }
    out
}

fn source() -> String {
    let path = workspace_root().join(FINDING_SOURCE);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn every_finding_producer_forwards_to_the_regent() {
    let src = source();
    let (producer, forwarder) = (producer_re(), forwarder_re());

    let mut violations = Vec::new();
    for (name, line, body) in functions(&src) {
        // The funnel itself is not a producer — it is where producers pass
        // through. Counting it would make the pin unfixable.
        if name == "emit_finding" {
            continue;
        }
        if producer.is_match(&body) && !forwarder.is_match(&body) {
            violations.push((name, line));
        }
    }

    let unexpected: Vec<_> = violations
        .iter()
        .filter(|(n, _)| !KNOWN_UNFORWARDED.iter().any(|(k, _)| k == n))
        .collect();

    if !unexpected.is_empty() {
        let mut msg = String::from(
            "\nOfficer findings that cannot reach the Regent.\n\n\
             These functions produce findings and never call `send_findings`, so\n\
             `has_urgent` in `Regent::reason` can never see them. A finding that\n\
             carries Severity::Error and cannot reach the cognitive layer is an\n\
             alarm wired to nothing — it will read as covered in every file you\n\
             open. See SEAM-009 in docs/DELIBERATION-LOG-2026-08.md.\n\n",
        );
        for (name, line) in unexpected {
            msg.push_str(&format!("  {FINDING_SOURCE}:{line}  fn {name}\n"));
        }
        msg.push_str(
            "\nEither forward the findings, or add the function to\n\
             KNOWN_UNFORWARDED with a reason and a review date. Do not add it\n\
             without one — an undated exception is how a deferral becomes a\n\
             permanent silence.\n",
        );
        panic!("{msg}");
    }
}

#[test]
fn known_unforwarded_entries_are_still_violations() {
    let src = source();
    let (producer, forwarder) = (producer_re(), forwarder_re());

    let mut stale = Vec::new();
    let mut missing = Vec::new();

    for (listed, _reason) in KNOWN_UNFORWARDED {
        match functions(&src).into_iter().find(|(n, _, _)| n == listed) {
            None => missing.push(*listed),
            Some((_, _, body)) => {
                let still_broken = producer.is_match(&body) && !forwarder.is_match(&body);
                if !still_broken {
                    stale.push(*listed);
                }
            }
        }
    }

    assert!(
        stale.is_empty(),
        "\nKNOWN_UNFORWARDED is stale — these now forward, or no longer produce:\n  {}\n\n\
         Remove them from the list. A list of defects that keeps entries after they\n\
         are fixed stops being evidence and starts being decoration — `KNOWN_ORPHAN_READS`\n\
         rotted this way within an hour of being written, and the tool that read it\n\
         then recommended deleting the record of six live defects.\n",
        stale.join("\n  ")
    );

    assert!(
        missing.is_empty(),
        "\nKNOWN_UNFORWARDED names functions that no longer exist:\n  {}\n\n\
         They were renamed or removed. Update the list — a pin that points at\n\
         nothing passes for the wrong reason.\n",
        missing.join("\n  ")
    );
}

#[test]
fn the_scan_actually_finds_producers() {
    let src = source();
    let (producer, forwarder) = (producer_re(), forwarder_re());
    let fns = functions(&src);

    assert!(
        !fns.is_empty(),
        "no top-level functions parsed out of {FINDING_SOURCE} — the declaration \
         regex has drifted from the source, and both pins above are passing blind"
    );

    let producers = fns.iter().filter(|(_, _, b)| producer.is_match(b)).count();
    let forwarders = fns.iter().filter(|(_, _, b)| forwarder.is_match(b)).count();

    assert!(
        producers > 0,
        "found no finding producers in {FINDING_SOURCE}. Either the officer tasks \
         moved to another file, or the `.assess_*` / `emit_finding` convention \
         changed. Until this is corrected the pin above checks nothing while \
         reporting success — PIN-002, in the file written to prevent it."
    );
    assert!(
        forwarders > 0,
        "found no call to `send_findings` in {FINDING_SOURCE}. If forwarding moved \
         elsewhere this pin can no longer see it, and its silence means nothing."
    );
}

/// Walk up from `CARGO_MANIFEST_DIR` until we find a Cargo.toml with
/// `[workspace]`. Same logic as the framework's private workspace_root.
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
            None => panic!(
                "could not find workspace root from {}",
                manifest_dir.display()
            ),
        }
    }
}
