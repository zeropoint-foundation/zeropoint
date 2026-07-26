//! Discipline: the Regent's tool surface has exactly one source, and every
//! capability in it is dispatchable.
//!
//! # Why (2026-07-26)
//!
//! The Regent could not answer "what model are you running?" for two days.
//! Standing correction `b4e7a18d` forbids citing a model name "without
//! verifying against current substrate"; verification requires
//! `self_configure`; `self_configure` was granted, declared, implemented and
//! dispatchable — and absent from the routing model's hand-maintained tool
//! menu. Routing could only ever emit `respond`, so the precondition was
//! unsatisfiable and a conditional prohibition became absolute.
//!
//! Fixing that surfaced a second instance of the same defect. The routing menu
//! was re-derived from `context.active_delegations` — but that list is what the
//! Regent *perceives*, not what the gate *honours*, and the two had drifted:
//! `browser_use` was in the perceived list and absent from the
//! `CapabilityGrant`. Deriving from belief made a denied capability selectable,
//! which is worse than the bug it replaced.
//!
//! Root cause in both cases: **two hand-maintained lists for one fact.**
//! `REGENT_TOOLS` in `zp-server/src/regent.rs` is now the single source; the
//! grant and the delegation summaries are both projected from it.
//!
//! # What this asserts
//!
//! **Dispatchability.** Every capability in `REGENT_TOOLS` has a `"name" =>`
//! dispatch arm. A granted tool with no arm fails at invocation. The converse
//! is deliberately not asserted — nested sub-dispatch (browser sub-actions)
//! legitimately adds arms that are not top-level capabilities.
//!
//! **Single source.** Neither the `CapabilityGrant` tool vector nor the
//! `delegations` binding may be a literal list again. Re-splitting them
//! reintroduces the exact drift that cost two days.
//!
//! # On parser drift
//!
//! This pin parses `REGENT_TOOLS`. If that declaration is renamed or reshaped,
//! the pin fails loudly rather than silently passing. **Fix the parser; do not
//! delete the pin.** It has already caught two live defects and one of its own
//! obsolescence.

use std::collections::BTreeSet;
use std::fs;

const SOURCE: &str = "crates/zp-server/src/regent.rs";

fn repo_root() -> std::path::PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    while !p.join("Cargo.lock").exists() {
        if !p.pop() {
            panic!("could not locate workspace root from cwd");
        }
    }
    p
}

/// Capability names from the `REGENT_TOOLS: &[(&str, &str)]` declaration.
fn regent_tools(src: &str) -> BTreeSet<String> {
    let start = src.find("const REGENT_TOOLS").unwrap_or_else(|| {
        panic!(
            "`const REGENT_TOOLS` not found in {SOURCE}. This pin parses that \
             declaration as the single source of the Regent's tool surface. If it \
             was renamed or moved, update this parser — do not delete the pin."
        )
    });
    let rest = &src[start..];
    let end = rest
        .find("];")
        .expect("`const REGENT_TOOLS` is not terminated by `];`");
    let body = &rest[..end];

    // Each entry is ("capability", "scope") — take the first of each pair.
    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            if !l.starts_with("(\"") {
                return None;
            }
            let after = &l[2..];
            let j = after.find('"')?;
            Some(after[..j].to_string())
        })
        .collect()
}

#[test]
fn regent_tools_are_single_sourced_and_dispatchable() {
    let root = repo_root();
    let src = fs::read_to_string(root.join(SOURCE))
        .unwrap_or_else(|e| panic!("cannot read {SOURCE}: {e}"));

    let tools = regent_tools(&src);
    assert!(
        tools.len() >= 5,
        "parsed only {} capabilities from REGENT_TOOLS — the parser has drifted \
         from the source, which is itself a failure. Fix the parser.",
        tools.len()
    );

    // Every granted capability must be dispatchable.
    let undispatchable: Vec<_> = tools
        .iter()
        .filter(|c| !src.contains(&format!("\"{c}\" =>")))
        .collect();
    assert!(
        undispatchable.is_empty(),
        "capabilities in REGENT_TOOLS have no dispatch arm: {undispatchable:?}\n\
         Invocation will fail at runtime. Every granted tool needs a `\"name\" =>` arm."
    );

    // The grant must be projected from REGENT_TOOLS, not restated.
    let grant_start = src
        .find("GrantedCapability::ToolCall")
        .expect("GrantedCapability::ToolCall not found");
    let grant_window = &src[grant_start..(grant_start + 400).min(src.len())];
    assert!(
        grant_window.contains("REGENT_TOOLS"),
        "the CapabilityGrant tool list is not derived from REGENT_TOOLS.\n\
         A literal tool vector here is the drift that caused the 2026-07-26 \
         browser_use inconsistency — the gate honoured one list while the Regent \
         perceived another. Project it: \
         `REGENT_TOOLS.iter().map(|(c, _)| c.to_string()).collect()`"
    );

    // The perceived-delegation list must be projected too.
    let deleg_start = src
        .find("let delegations")
        .expect("`let delegations` binding not found");
    let deleg_window = &src[deleg_start..(deleg_start + 400).min(src.len())];
    assert!(
        deleg_window.contains("REGENT_TOOLS"),
        "the DelegationSummary list is not derived from REGENT_TOOLS.\n\
         This list is what the Regent *perceives* she may do; the CapabilityGrant \
         is what the gate *honours*. When they are maintained separately they \
         drift, and a capability she believes she holds gets denied — or worse, \
         a denied capability reaches her routing menu."
    );
}
