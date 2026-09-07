//! Discipline: every prompt-template placeholder is substituted by every
//! renderer of that template.
//!
//! # The failure this pins
//!
//! Prompt templates live in `crates/zp-regent/prompts/*.md` and carry
//! `{placeholder}` slots. They are rendered by more than one caller — the
//! production path in `regent.rs` and the model-validation battery in
//! `evaluation.rs` — and a renderer that misses a slot sends the literal
//! `{placeholder}` to the model.
//!
//! Nothing fails when that happens. The prompt is still valid text, inference
//! still returns, and the only symptom is a model behaving slightly worse for
//! reasons no one can name.
//!
//! Found 2026-08-06, three at once. `{substrate_ground_section}` had been added
//! to three templates that day and wired only into the production renderers.
//! `{standing_corrections_section}` and `{available_actions}` had been leaking
//! from the battery's renders for an unknown period before that. The symptom
//! was phi4-reasoning opening replies with *"there's contradictory
//! instructions?"* — which reads as a model-quality problem and was a prompt
//! defect.
//!
//! It matters most in the battery, because that is what decides whether a model
//! is fit to serve as Regent. A suitability judgement measured against a
//! malformed prompt, and then written into a model dossier, is wrong in a way
//! that outlives the defect.
//!
//! # What this checks
//!
//! For each template, the set of `{placeholder}` tokens it contains, against
//! the set each renderer substitutes. A renderer missing any token fails.
//!
//! # What this does not check
//!
//! That the substituted *value* is correct — only that substitution happens.
//! A renderer passing the wrong string, or the empty string where content was
//! required, passes here. Emptiness is legitimate (the battery has no live
//! context, and `build_substrate_ground_section` returns empty when all
//! invariants hold), so it cannot be distinguished structurally.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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

/// Placeholders appearing in a template.
fn placeholders_in(text: &str) -> BTreeSet<String> {
    let re = Regex::new(r"\{([a-z][a-z0-9_]*)\}").unwrap();
    re.captures_iter(text).map(|c| c[1].to_string()).collect()
}

/// Placeholders a source file substitutes, from its `.replace("{…}", …)` calls.
fn substituted_in(src: &str) -> BTreeSet<String> {
    let re = Regex::new(r#"\.replace\(\s*"\{([a-z][a-z0-9_]*)\}""#).unwrap();
    re.captures_iter(src).map(|c| c[1].to_string()).collect()
}

#[test]
fn every_renderer_substitutes_every_placeholder() {
    let root = workspace_root();
    let prompts = root.join("crates/zp-regent/prompts");

    // Renderers, and which templates each one renders. Kept explicit rather
    // than inferred: a renderer that stops using a template should be a
    // deliberate edit here, not a silently narrowing check.
    let renderers: &[(&str, &[&str])] = &[
        (
            "crates/zp-regent/src/regent.rs",
            &["unified_system.md", "compose.md", "propose.md"],
        ),
        (
            "crates/zp-regent/src/evaluation.rs",
            &["unified_system.md", "compose.md"],
        ),
    ];

    let mut failures: Vec<String> = Vec::new();

    for (rel_src, templates) in renderers {
        let src_path = root.join(rel_src);
        let src = match fs::read_to_string(&src_path) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{rel_src}: unreadable ({e})"));
                continue;
            }
        };
        let substituted = substituted_in(&src);

        for tpl in *templates {
            let tpl_path: &Path = &prompts.join(tpl);
            let text = match fs::read_to_string(tpl_path) {
                Ok(t) => t,
                Err(e) => {
                    failures.push(format!("{tpl}: unreadable ({e})"));
                    continue;
                }
            };
            for ph in placeholders_in(&text) {
                if !substituted.contains(&ph) {
                    failures.push(format!(
                        "{rel_src} renders {tpl} but never substitutes {{{ph}}} \
                         — the literal token reaches the model"
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "\n\nPrompt placeholders reaching the model unsubstituted:\n  {}\n\n\
         Add a `.replace(\"{{…}}\", …)` for each. Empty string is correct where \
         the renderer has no context for that slot.\n",
        failures.join("\n  ")
    );
}
