//! Discipline: a prompt never quotes the output it is forbidding.
//!
//! # The failure this pins
//!
//! `compose.md` carried this line:
//!
//! ```text
//! "I have no mechanism for that", on its own, is not an acceptable response.
//! ```
//!
//! On 2026-08-20, given a `substrate_validate` result reporting
//! `posture=degraded`, qwen3:8b composed for seventeen seconds over 6,337
//! tokens of context and answered:
//!
//! ```text
//! I have no mechanism for that.
//! ```
//!
//! Verbatim, on its own — the exact shape the line forbids. It was the only
//! quoted example phrase in the template, and the routing tier had already
//! drafted something coherent from the same context, so the content was
//! reachable. The prohibition supplied the string.
//!
//! This is not a model defect and cannot be fixed by a better model, only made
//! rarer. An instruction of the form *never say X* has to name X, and naming X
//! puts X in the context window as the single most salient candidate
//! completion for the situation it describes. Under load — long context, small
//! model, high prompt-eval cost — that candidate wins. The instruction is a
//! demonstration.
//!
//! The fix is not a stronger prohibition. It is to state the requirement
//! positively and let the bad output have no exemplar. `compose.md` already
//! did that in the three numbered states directly above the line; the line
//! added nothing except a phrase to copy.
//!
//! # What this checks
//!
//! Every `crates/zp-regent/prompts/*.md` for a double-quoted span followed
//! closely by a clause marking it unacceptable. Both halves are required: a
//! quoted phrase alone is fine (templates quote operator turns, JSON keys and
//! enum values), and a prohibition alone is fine and often necessary. It is
//! the pairing that hands the model a script.
//!
//! # What this does not check
//!
//! Prohibitions phrased without a quoted exemplar, which are the intended
//! form. Nor does it judge whether a prohibition should exist at all — only
//! that it is not accompanied by a copyable example. A model can still emit a
//! refusal it was never shown; this removes the case where the substrate
//! taught it one.

use std::fs;
use std::path::PathBuf;

use regex::Regex;

fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("Cargo.toml").exists()
            && fs::read_to_string(dir.join("Cargo.toml"))
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
        {
            return dir;
        }
        if !dir.pop() {
            panic!("workspace root not found");
        }
    }
}

/// Clauses that mark the thing just quoted as output the model must not
/// produce. Deliberately a closed list: a prompt is prose, and an open-ended
/// notion of "sounds disapproving" would flag the substrate's own vocabulary
/// (`never widen`, `do not recite these`) which is about behaviour, not text.
const FORBIDDING: &[&str] = &[
    "is not an acceptable",
    "is not acceptable",
    "not an acceptable response",
    "is unacceptable",
    "never say",
    "do not say",
    "don't say",
    "do not respond with",
    "do not answer with",
    "is not a valid response",
    "is never a valid",
    "is not a response",
];

/// How far from the quote the clause may appear, on either side. Long enough
/// for `", on its own, is not an acceptable response."` trailing, and for
/// `Never say ` leading, and short enough that an unrelated neighbouring
/// sentence does not implicate an innocent quotation.
///
/// Both directions are checked because English puts the clause on either side:
/// `"X" is not acceptable` trails, `Never say "X"` leads. The first version of
/// this pin looked only forward and its own table of phrasings caught it.
const WINDOW: usize = 64;

/// Clip an index to a char boundary, moving in `dir` (-1 or +1). Prompts carry
/// em dashes, arrows and curly quotes, so naive slicing panics.
fn boundary(text: &str, mut i: usize, dir: isize) -> usize {
    while i > 0 && i < text.len() && !text.is_char_boundary(i) {
        i = if dir < 0 { i - 1 } else { i + 1 };
    }
    i.min(text.len())
}

/// Quoted spans that are followed by a forbidding clause, as (phrase, clause).
fn quoted_then_forbidden(text: &str) -> Vec<(String, String)> {
    // Straight and typographic quotes both — prompts are hand-written prose
    // and an editor may have curled them.
    let re = Regex::new(r#"["\u{201c}]([^"\u{201c}\u{201d}\n]{4,120})["\u{201d}]"#).unwrap();
    let lower = text.to_lowercase();
    let mut hits = Vec::new();
    for m in re.find_iter(text) {
        let after = {
            let start = m.end();
            let end = boundary(text, (start + WINDOW).min(text.len()), -1);
            &lower[start..end.max(start)]
        };
        let before = {
            let end = m.start();
            let start = boundary(text, end.saturating_sub(WINDOW), 1);
            &lower[start.min(end)..end]
        };
        let found = FORBIDDING
            .iter()
            .find(|c| after.contains(**c) || before.contains(**c));
        if let Some(clause) = found {
            let phrase = re
                .captures(m.as_str())
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| m.as_str().to_string());
            hits.push((phrase, (*clause).to_string()));
        }
    }
    hits
}

#[test]
fn no_prompt_quotes_the_output_it_forbids() {
    let dir = workspace_root().join("crates/zp-regent/prompts");
    assert!(dir.is_dir(), "prompt directory missing at {}", dir.display());

    let mut scanned = 0usize;
    let mut violations = Vec::new();
    for entry in fs::read_dir(&dir).expect("read prompts dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        scanned += 1;
        let text = fs::read_to_string(&path).expect("read prompt");
        for (phrase, clause) in quoted_then_forbidden(&text) {
            violations.push(format!(
                "  {}\n    quotes: \"{}\"\n    then:   \"{}\"",
                path.file_name().unwrap().to_string_lossy(),
                phrase,
                clause
            ));
        }
    }

    assert!(scanned > 0, "no prompt templates found — scan is not reading anything");
    assert!(
        violations.is_empty(),
        "prompt quotes the output it forbids — the prohibition supplies the phrase, \
         and a small model under long context will produce it. State the requirement \
         positively instead; see this file's header for the 2026-08-20 case.\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_scan_actually_finds_the_original_defect() {
    // The exact line removed from compose.md. If the detector cannot see this,
    // it is decoration.
    let planted = "Answer directly.\n\
                   \"I have no mechanism for that\", on its own, is not an acceptable response.\n";
    let hits = quoted_then_forbidden(planted);
    assert_eq!(hits.len(), 1, "should flag the original line, got {hits:?}");
    assert_eq!(hits[0].0, "I have no mechanism for that");
}

#[test]
fn the_scan_leaves_innocent_quotations_alone() {
    // Every one of these appears in a live template. A pin that flagged them
    // would be turned off within a week.
    for ok in [
        "Operator preferences (\"call me X\", \"stop doing Y\") are standing corrections.",
        "\"failed_limb\": \"why you cannot just do it — one of: no authority | no mechanism\",",
        "The chain is the source of truth; everything else derives from it.",
        "Never offer an action that is not on this list.",
        "SUBSTRATE CONCEPTS (for depth, not jargon — do not recite these)",
        "A delegation narrows authority; it can never widen what the operator granted.",
    ] {
        assert!(
            quoted_then_forbidden(ok).is_empty(),
            "false positive on innocent text: {ok}"
        );
    }
}

#[test]
fn the_scan_catches_the_other_phrasings() {
    for bad in [
        "\"I cannot help with that\" is not acceptable.",
        "Never say \"as an AI language model\" in a reply.",
        "Do not respond with \"unable to comply\" under any circumstances.",
    ] {
        assert!(
            !quoted_then_forbidden(bad).is_empty(),
            "missed a forbidding phrasing: {bad}"
        );
    }
}
