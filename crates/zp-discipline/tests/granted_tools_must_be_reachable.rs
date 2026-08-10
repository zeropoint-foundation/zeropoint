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
//!
//! # Where the single source lives (updated 2026-08-09)
//!
//! It moved. SEAM-005 found a *third* copy — two more `const TOOLS: &[&str]`
//! inside `zp-regent/src/regent.rs`, in `recover_execute_intent` and
//! `sanitize_tool_name` — and collapsed all three into
//! [`TOOLS_SOURCE`] as `pub const REGENT_TOOLS: &[RegentTool]`, which
//! `zp-server` now imports. The shape changed with the move: entries were
//! `("name", "scope")` tuples and are now `RegentTool { name, scope }` structs.
//!
//! **This pin failed for two days across that change and the failure was not
//! noticed**, because the workspace test suite was not run after the fix. The
//! pin did exactly what it promised — it panicked with "if it was renamed or
//! moved, update this parser" — and the message went unread. A pin that fails
//! into an unread log is not materially better than the pin that never existed,
//! which is the thing SEAM-005 was originally about.
//!
//! # What this asserts
//!
//! **Dispatchability.** Every capability in `REGENT_TOOLS` has a `"name" =>`
//! dispatch arm in [`DISPATCH_SOURCE`]. A granted tool with no arm fails at
//! invocation. The converse is deliberately not asserted — nested sub-dispatch
//! (browser sub-actions) legitimately adds arms that are not top-level
//! capabilities.
//!
//! **Single source.** Neither the `CapabilityGrant` tool vector nor the
//! `delegations` binding may be a literal list again. Re-splitting them
//! reintroduces the exact drift that cost two days.
//!
//! **Two files, one fact.** The declaration and its dispatch now live in
//! different crates, so this pin reads both. That split is itself a risk the
//! pin exists to hold: `zp-server` depends on `zp-regent`, so the dependency
//! runs the direction needed — a claim SEAM-005 found stated backwards in a
//! doc comment, unchecked, for long enough to justify keeping three copies.
//!
//! # On parser drift
//!
//! This pin parses `REGENT_TOOLS`. If that declaration is renamed or reshaped,
//! the pin fails loudly rather than silently passing. **Fix the parser; do not
//! delete the pin.** It has now caught two live defects, one of its own
//! obsolescence, and one refactor that moved the thing it guards.

use std::collections::BTreeSet;
use std::fs;

/// The single declaration of the Regent's tool surface.
const TOOLS_SOURCE: &str = "crates/zp-regent/src/tools.rs";

/// Where those capabilities are dispatched, granted, and projected into
/// delegation summaries.
const DISPATCH_SOURCE: &str = "crates/zp-server/src/regent.rs";

fn repo_root() -> std::path::PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    while !p.join("Cargo.lock").exists() {
        if !p.pop() {
            panic!("could not locate workspace root from cwd");
        }
    }
    p
}

/// Capability names from `pub const REGENT_TOOLS: &[RegentTool]`.
///
/// Parses `name: "..."` rather than positional text, so reordering the struct
/// fields or reformatting the entries does not silently change what is parsed.
fn regent_tools(src: &str) -> BTreeSet<String> {
    let start = src.find("const REGENT_TOOLS").unwrap_or_else(|| {
        panic!(
            "`const REGENT_TOOLS` not found in {TOOLS_SOURCE}. This pin parses that \
             declaration as the single source of the Regent's tool surface. If it \
             was renamed or moved, update this parser — do not delete the pin."
        )
    });
    let rest = &src[start..];
    let end = rest
        .find("];")
        .expect("`const REGENT_TOOLS` is not terminated by `];`");
    let body = &rest[..end];

    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with("//") {
                return None;
            }
            let i = l.find("name:")? + "name:".len();
            let after = l[i..].trim_start();
            let after = after.strip_prefix('"')?;
            let j = after.find('"')?;
            Some(after[..j].to_string())
        })
        .collect()
}

/// True if `needle` appears within `radius` bytes either side of `anchor`.
///
/// Looks backwards as well as forwards, which the previous version did not.
/// The projection is now bound to a local a few lines *above* the grant
/// (`let tools: Vec<String> = REGENT_TOOLS.iter()...`), so a forward-only
/// window would report a correctly-projected grant as a literal list.
fn near(src: &str, anchor: usize, needle: &str, radius: usize) -> bool {
    let lo = anchor.saturating_sub(radius);
    let hi = (anchor + radius).min(src.len());
    src[lo..hi].contains(needle)
}

#[test]
fn regent_tools_are_single_sourced_and_dispatchable() {
    let root = repo_root();
    let tools_src = fs::read_to_string(root.join(TOOLS_SOURCE))
        .unwrap_or_else(|e| panic!("cannot read {TOOLS_SOURCE}: {e}"));
    let src = fs::read_to_string(root.join(DISPATCH_SOURCE))
        .unwrap_or_else(|e| panic!("cannot read {DISPATCH_SOURCE}: {e}"));

    let tools = regent_tools(&tools_src);
    assert!(
        tools.len() >= 5,
        "parsed only {} capabilities from REGENT_TOOLS — the parser has drifted \
         from the source, which is itself a failure. Fix the parser.",
        tools.len()
    );

    // The dispatching crate must consume the declaration, not restate it.
    assert!(
        src.contains("REGENT_TOOLS"),
        "{DISPATCH_SOURCE} no longer references REGENT_TOOLS. If the tool surface \
         was re-declared locally, that is the third-copy defect SEAM-005 removed \
         — it drifted twice before anyone noticed, and the second time a granted \
         tool dispatched as 'unknown tool' for two days."
    );

    // Every granted capability must be dispatchable.
    let undispatchable: Vec<_> = tools
        .iter()
        .filter(|c| !src.contains(&format!("\"{c}\" =>")))
        .collect();
    assert!(
        undispatchable.is_empty(),
        "capabilities in REGENT_TOOLS have no dispatch arm in {DISPATCH_SOURCE}: \
         {undispatchable:?}\n\
         Invocation will fail at runtime. Every granted tool needs a `\"name\" =>` arm."
    );

    // The grant must be projected from REGENT_TOOLS, not restated.
    let grant_start = src
        .find("GrantedCapability::ToolCall")
        .expect("GrantedCapability::ToolCall not found");
    assert!(
        near(&src, grant_start, "REGENT_TOOLS", 600),
        "the CapabilityGrant tool list is not derived from REGENT_TOOLS.\n\
         A literal tool vector here is the drift that caused the 2026-07-26 \
         browser_use inconsistency — the gate honoured one list while the Regent \
         perceived another. Project it: \
         `REGENT_TOOLS.iter().map(|t| t.name.to_string()).collect()`"
    );

    // The perceived-delegation list must be projected too.
    let deleg_start = src
        .find("let delegations")
        .expect("`let delegations` binding not found");
    assert!(
        near(&src, deleg_start, "REGENT_TOOLS", 600),
        "the DelegationSummary list is not derived from REGENT_TOOLS.\n\
         This list is what the Regent *perceives* she may do; the CapabilityGrant \
         is what the gate *honours*. When they are maintained separately they \
         drift, and a capability she believes she holds gets denied — or worse, \
         a denied capability reaches her routing menu."
    );
}

/// The scope column exists to be read. `browser_use` advertises
/// `web:allowed_domains` while `ALLOWED_DOMAINS` is hardcoded in the dispatch
/// arm — recorded as SEAM-005 CARRIED, not fixed. This asserts only that every
/// entry declares one, so a new tool cannot arrive with an empty scope and look
/// governed.
#[test]
fn every_tool_declares_a_scope() {
    let root = repo_root();
    let tools_src = fs::read_to_string(root.join(TOOLS_SOURCE))
        .unwrap_or_else(|e| panic!("cannot read {TOOLS_SOURCE}: {e}"));

    let start = tools_src
        .find("const REGENT_TOOLS")
        .expect("`const REGENT_TOOLS` not found");
    let rest = &tools_src[start..];
    let body = &rest[..rest.find("];").expect("unterminated REGENT_TOOLS")];

    let mut scopeless = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        if l.starts_with("//") || !l.contains("name:") {
            continue;
        }
        let name = l
            .split_once("name:")
            .and_then(|(_, r)| r.trim_start().strip_prefix('"'))
            .and_then(|r| r.split_once('"'))
            .map(|(n, _)| n.to_string())
            .unwrap_or_else(|| l.to_string());
        let scope_ok = l
            .split_once("scope:")
            .and_then(|(_, r)| r.trim_start().strip_prefix('"'))
            .and_then(|r| r.split_once('"'))
            .map(|(s, _)| !s.trim().is_empty())
            .unwrap_or(false);
        if !scope_ok {
            scopeless.push(name);
        }
    }

    assert!(
        scopeless.is_empty(),
        "tools declared with no scope: {scopeless:?}\n\
         A capability with an empty scope reads as governed and is not. \
         PIN-001: adding to this list grants a capability — it is an authority \
         decision, never a lint fix."
    );
}
