//! Discipline (Architecture II.0 ripple, May 2026): every file that
//! implements a known port trait must carry a module-level doc comment
//! documenting the adapter it provides.
//!
//! # Why
//!
//! `docs/ARCHITECTURE-2026-05.md` Part II.0 establishes the meta-principle
//! that contracts (ports) are singular and implementations (adapters) are
//! plural. The counterbalance to plurality is *per-instance justification*:
//! every adapter must document **what port it adapts** and **what
//! operator class, external dependency, or use case it serves**. Without
//! that documentation, plurality drifts into sprawl — adapters accumulate
//! without anyone being able to answer "why does this exist?"
//!
//! This pin makes the documentation requirement structural. Adding a
//! new adapter without a doc comment fails the build.
//!
//! # What this pin does
//!
//! For every `.rs` file under `crates/`:
//!
//! 1. If the file contains `impl <KnownPortTrait> for ...` for a trait in
//!    [`PORT_TRAITS`], AND
//! 2. the file does NOT also contain `pub trait <KnownPortTrait>` (which
//!    would mean the file defines the trait, not adapts it),
//!
//! then the file is treated as an adapter. The pin then requires:
//!
//! 3. A module-level doc comment (`//!`) at the top of the file, AND
//! 4. At least one line of that doc comment matches the documentation
//!    marker — words like *adapter*, *adapts*, *implements*, *provider*,
//!    *backend*, *implementation*. The marker is a fuzzy heuristic: it
//!    catches the most common phrasings without being prescriptive about
//!    style.
//!
//! Files matching exempt path patterns ([`EXEMPT_PATH_FRAGMENTS`]) are
//! skipped — `mod.rs` and `lib.rs` are typically port-defining or
//! organizational, not adapter implementations.
//!
//! # Why fuzzy markers, not strict templates
//!
//! A strict template ("the doc comment must say 'Adapter for X serving
//! Y'") would catch drift but would also force authors to use awkward
//! phrasing. A fuzzy marker requires *some* documentation language while
//! letting authors write naturally. The cost of fuzziness is that a
//! doc comment that mentions the right words but doesn't actually
//! document what it should can pass — but that's a code-review concern,
//! not something a regex can catch. The pin enforces presence; humans
//! enforce quality.
//!
//! # Extending the port-trait list
//!
//! When a new port trait is formalized in the codebase, add its name to
//! [`PORT_TRAITS`] below. The pin will start scanning for adapters of
//! that port immediately. Adapters that exist before the trait is
//! added to the list are not retroactively required to be documented;
//! the pin is forward-looking.

use std::path::{Path, PathBuf};

use regex::Regex;
use walkdir::WalkDir;

/// Known port traits whose adapter implementations must be documented.
///
/// Add to this list when a new port trait is formalized. The pin will
/// then start scanning for adapter files that implement the new trait.
const PORT_TRAITS: &[&str] = &[
    // zp-keys: sovereignty providers (Touch ID, Trezor, YubiKey, etc.)
    "SovereigntyProvider",
    // zp-mesh: peer-transport interface (Reticulum, TCP, Loopback, libp2p when added)
    "Interface",
    // zp-mesh: discovery backend (Reticulum discovery, web discovery, etc.)
    "DiscoveryBackend",
];

/// Path fragments that exempt a file from the adapter-documentation check.
///
/// `mod.rs` and `lib.rs` are typically port-defining or organizational —
/// they declare traits and re-export adapter modules, but aren't themselves
/// adapter implementations.
///
/// `/tests/` files are test scaffolding, not production adapters.
const EXEMPT_PATH_FRAGMENTS: &[&str] = &["/mod.rs", "/lib.rs", "/tests/", "/benches/"];

/// Adapters that pre-date this discipline pin (introduced May 2026 as a
/// ripple of Architecture II.0). Each entry is a path-suffix match against
/// the relative file path. The list should *shrink over time*, not grow —
/// when an adapter here gets a proper `//!` doc comment naming the port
/// it adapts and the operator class it serves, remove its entry.
///
/// **Adding a new entry is a code smell.** New adapters must be documented
/// from the start. This list captures the legacy gap, not the steady state.
///
/// **As of May 8 2026 (task 57): empty.** All 12 pre-discipline adapters
/// were swept in a single commit; every adapter implementation in the
/// codebase now carries a `//!` module doc comment naming the port it
/// adapts. The list is preserved (rather than removed entirely) so that
/// any future adapter that for some reason cannot be documented from
/// the start has a sanctioned path to landing without disabling the
/// discipline globally.
const KNOWN_UNDOCUMENTED_ADAPTERS: &[&str] = &[];

#[test]
fn adapters_must_carry_documentation() {
    let workspace_root = workspace_root();
    let crates_dir = workspace_root.join("crates");
    assert!(
        crates_dir.is_dir(),
        "expected crates/ at {} — discipline cannot scan",
        crates_dir.display()
    );

    // Build per-trait regexes once.
    let impl_patterns: Vec<(&'static str, Regex, Regex)> = PORT_TRAITS
        .iter()
        .map(|trait_name| {
            let impl_re = Regex::new(&format!(
                r"impl(?:<[^>]*>)?\s+{}\s+for\s+",
                regex::escape(trait_name)
            ))
            .unwrap();
            let define_re =
                Regex::new(&format!(r"pub\s+trait\s+{}\b", regex::escape(trait_name))).unwrap();
            (*trait_name, impl_re, define_re)
        })
        .collect();

    // The fuzzy documentation marker. A module doc comment line
    // (`//! ...`) containing any of these word *stems* satisfies the
    // requirement. Case-insensitive, and matches conjugations:
    //   - "adapter", "Adapter", "adapters", "Adapters"
    //   - "implement", "implements", "implementing", "implementation"
    //   - "provider", "Provider", "providers"
    //   - "backend", "Backend", "backends"
    //
    // No trailing `\b` — by anchoring at word start only, common
    // suffix forms (-s, -ing, -ation, -ers) all match. This is the
    // forgiveness layer: authors should write naturally, not contort
    // their prose to match a regex.
    let doc_marker = Regex::new(r"(?im)^//!.*\b(adapter|implement|provider|backend)").unwrap();

    let mut violations: Vec<Violation> = Vec::new();

    for entry in WalkDir::new(&crates_dir)
        .into_iter()
        .filter_entry(|e| !is_excluded_dir(e.file_name().to_string_lossy().as_ref()))
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        let path_str = path.to_string_lossy().replace('\\', "/");
        if EXEMPT_PATH_FRAGMENTS
            .iter()
            .any(|frag| path_str.contains(frag))
        {
            continue;
        }

        // Pre-discipline adapters get a grace period via the
        // KNOWN_UNDOCUMENTED list. Tracked as cleanup; not a license
        // for new violations.
        let rel_for_allow = path
            .strip_prefix(&workspace_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if KNOWN_UNDOCUMENTED_ADAPTERS
            .iter()
            .any(|exempt| rel_for_allow == *exempt)
        {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Find which port traits this file implements (excluding files
        // that also define the trait — those are port files, not
        // adapter files).
        let mut implementing_traits: Vec<&'static str> = Vec::new();
        for (trait_name, impl_re, define_re) in &impl_patterns {
            if impl_re.is_match(&content) && !define_re.is_match(&content) {
                implementing_traits.push(*trait_name);
            }
        }
        if implementing_traits.is_empty() {
            continue;
        }

        // This is an adapter file. Check the documentation requirement.
        if !doc_marker.is_match(&content) {
            let rel = path
                .strip_prefix(&workspace_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            violations.push(Violation {
                path: rel,
                traits: implementing_traits,
            });
        }
    }

    if violations.is_empty() {
        return;
    }

    let mut msg = String::from(
        "\n\nDiscipline violation: adapters_must_be_documented\n\
         \n\
         Invariant: Architecture II.0 (contracts singular; implementations\n\
         plural). The counterbalance to plurality at the implementation\n\
         layer is per-instance justification: every adapter must document\n\
         **what port it adapts** and **what operator class, external\n\
         dependency, or use case it serves**.\n\
         \n\
         How to fix:\n\
         Add a module-level doc comment (`//! ...`) at the top of the\n\
         offending file, naming the port and the adapted thing. Use\n\
         words like 'adapter', 'adapts', 'implements', 'provider', or\n\
         'backend' so this pin recognizes the documentation.\n\
         \n\
         Example shape:\n\
         //! Touch ID sovereignty provider — adapts SovereigntyProvider\n\
         //! to macOS Touch ID, serving operators on Apple hardware\n\
         //! who want OS-level biometric unlock.\n\
         \n",
    );
    msg.push_str(&format!(
        "  {} adapter(s) without documentation:\n",
        violations.len()
    ));
    for v in &violations {
        msg.push_str(&format!(
            "    {} — implements: {}\n",
            v.path,
            v.traits.join(", ")
        ));
    }
    msg.push('\n');
    panic!("{}", msg);
}

#[derive(Debug)]
struct Violation {
    path: String,
    traits: Vec<&'static str>,
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

fn is_excluded_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules" | ".git" | "target" | ".cargo" | "dist" | "build"
    )
}
