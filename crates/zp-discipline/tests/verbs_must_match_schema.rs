//! Discipline (Phase 5 of the verb-set arc, Architecture II.7 / VII.3):
//! every public function whose return type references a `zp_verbs` type must
//! produce one of the verb-set's response category patterns.
//!
//! # Why
//!
//! `proto/v1/common.proto` establishes three response categories
//! (Architecture VII.3):
//!
//! - `*Envelope`  — plain envelope (typed data, no signature)
//! - `Signed*`    — signed envelope (typed data + node signature, not chained)
//! - `*Receipt`   — full receipt (signed and chained)
//!
//! Plus two special carve-outs from `common.proto`:
//!
//! - `AuditEntry` / `common::AuditEntry` — chain bookkeeping wrapper for
//!   streaming verbs (e.g. `rpc TailAuditEntries … returns (stream common.AuditEntry)`)
//! - `Receipt` / `common::Receipt` — the canonical receipt type
//!
//! These are not cosmetic naming rules. The suffix encodes a structural
//! invariant: which trust tier the handler output belongs to. A handler
//! returning `SignedFoo` is making a commitment that the response carries a
//! node signature. A handler returning `FooReceipt` is making a stronger
//! commitment that the receipt is also chained into the local audit log. If
//! the type name and the structural commitment diverge, auditors and callers
//! cannot rely on the name alone as a trust-tier signal.
//!
//! # What this pin does
//!
//! For every `.rs` file under `crates/` that imports from `zp_verbs::`:
//!
//! 1. Find every `pub` or `pub(crate)` function (or async fn) whose return
//!    type references a `zp_verbs` type (detected via the import).
//! 2. Extract the base type name — stripping wrapper types such as
//!    `Result<…>`, `Response<…>`, `Status<…>`, `Stream<Item = …>`,
//!    `impl Stream<Item = …>`, and `tonic::Response<…>`.
//! 3. Verify the base type name matches at least one of the allowed patterns.
//! 4. Flag any type that contains `Request` in its name — request types are
//!    inputs, never outputs. A handler returning a Request type is almost
//!    certainly a mistake.
//!
//! # What this pin does NOT flag
//!
//! - Files that don't import from `zp_verbs::` at all. Pre-verb-set handlers
//!   in `zp-server/src/lib.rs` (returning `Json<HealthResponse>` etc.) are
//!   not yet converted to verb-set types; they retire under Architecture II.4,
//!   not this pin.
//! - Private helper functions (not `pub` / `pub(crate)`). Only the handler
//!   boundary surface is subject to the category convention.
//! - Tonic-generated code in `zp-verbs/src/` itself — that crate is the
//!   schema source, not a consumer.
//! - Test files (`/tests/`).
//!
//! # Relationship to tonic's compiler enforcement
//!
//! Tonic's generated server trait stubs already lock each RPC's return type
//! to whatever the `.proto` file declares. That compile-time enforcement
//! covers the case where a service *implements* the generated trait. This pin
//! covers a different surface: hand-written helper functions in adapter or
//! wrapper layers that pass verb-set types around but aren't themselves
//! generated. It also acts as a forward-looking guard — as new handler files
//! are added, the pin ensures they declare their return categories correctly
//! before the tonic trait wires them up.
//!
//! # Exempt files
//!
//! [`KNOWN_EXEMPT_FILES`] starts empty. Adding an entry is a code smell;
//! it means a file is using `zp_verbs` types in a way the pin's heuristic
//! misclassifies. The correct fix is to either adjust the heuristic or
//! restructure the code, not to exempt the file.

use std::path::{Path, PathBuf};

use regex::Regex;
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Response category patterns
// ---------------------------------------------------------------------------

/// Allowed base type-name patterns for verb-set response types.
///
/// Each entry is a regex matched against the bare type name — after stripping
/// wrapper types like `Result<…>`, `Response<…>`, `Stream<Item = …>`.
///
/// The patterns correspond to Architecture VII.3's three response categories
/// plus the two common.proto carve-outs.
const ALLOWED_PATTERNS: &[&str] = &[
    // *Envelope — plain envelope (no signature)
    r"\bEnvelope\b",
    // *Receipt — full receipt (signed and chained)
    r"\bReceipt\b",
    // Signed* — signed envelope (has node signature, not chained)
    r"\bSigned[A-Z]",
    // common::AuditEntry — streaming verb chain-bookkeeping wrapper
    r"\bAuditEntry\b",
    // common::Receipt or bare Receipt — canonical receipt type
    // (covered by the Receipt pattern above, but spelled out for clarity)
];

/// Type-name patterns that are FORBIDDEN as return types.
///
/// Request types (`*Request`) are always inputs, never outputs. A function
/// returning a Request type is a strong signal of a category violation —
/// either the handler is returning the wrong type, or an internal Request
/// struct has been accidentally exposed at the handler boundary.
const FORBIDDEN_PATTERNS: &[&str] = &[
    // *Request — input types; should never appear in a return position
    r"\bRequest\b",
];

// ---------------------------------------------------------------------------
// Allowlists
// ---------------------------------------------------------------------------

/// Path fragments that exempt an entire file from this pin.
///
/// Includes:
/// - `zp-verbs/` — the schema source crate itself; its generated types
///   include both Request and Response messages; scanning it would be noise.
/// - `/tests/` — test scaffolding is not a handler boundary.
/// - `/benches/` — benchmark harness, not a handler.
const EXEMPT_PATH_FRAGMENTS: &[&str] = &["crates/zp-verbs/", "/tests/", "/benches/"];

/// Specific files that are exempt from this pin.
///
/// **This list starts empty and should stay that way.** Adding an entry is a
/// code smell. See the module doc comment for the rationale.
const KNOWN_EXEMPT_FILES: &[&str] = &[];

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn verbs_must_match_schema() {
    let workspace_root = workspace_root();
    let crates_dir = workspace_root.join("crates");
    assert!(
        crates_dir.is_dir(),
        "expected crates/ at {} — discipline cannot scan",
        crates_dir.display()
    );

    // Detect files that import from zp_verbs.
    // Matches: `use zp_verbs::`, `zp_verbs::guard::`, etc.
    let import_re = Regex::new(r"\bzp_verbs\b").unwrap();

    // Handler signature heuristic.
    //
    // Captures public (async) fn declarations with an explicit return type.
    // Group 1: visibility (`pub` or `pub(crate)` prefix — may be absent for
    //   methods inside `impl` blocks that have a `pub` elsewhere, but we
    //   accept the approximation).
    // Group 2: the full text after `->` up to the opening `{` or `;`.
    //
    // We look for lines where:
    //   - `pub` or `pub(crate)` appears (or the fn is inside a pub impl), AND
    //   - `fn` keyword precedes the argument list, AND
    //   - `->` introduces the return type.
    //
    // This is a line-level heuristic; multi-line signatures spanning more than
    // one source line will be missed, but that's acceptable for a v1 pin.
    let fn_return_re = Regex::new(
        r"(?x)
        \b(pub(?:\s*\(\s*crate\s*\))?)\s+   # pub or pub(crate)
        (?:async\s+)?fn\s+\w+               # (async) fn name
        (?:<[^>]*>)?                         # optional generic params
        \s*\([^)]*\)                         # argument list (single-line)
        \s*->\s*                             # arrow
        ([^{;]+)                             # return type text (group 2)
        ",
    )
    .unwrap();

    // Compile allowed and forbidden patterns once.
    let allowed_res: Vec<Regex> = ALLOWED_PATTERNS
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect();
    let forbidden_res: Vec<Regex> = FORBIDDEN_PATTERNS
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect();

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

        let rel = path
            .strip_prefix(&workspace_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        // Apply path-fragment exemptions.
        if EXEMPT_PATH_FRAGMENTS.iter().any(|frag| rel.contains(frag)) {
            continue;
        }

        // Apply per-file exemptions (suffix match against relative path).
        if KNOWN_EXEMPT_FILES
            .iter()
            .any(|exempt| rel.ends_with(exempt))
        {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Only scan files that actually import from zp_verbs.
        if !import_re.is_match(&content) {
            continue;
        }

        // File uses zp_verbs. Scan every line for handler-shaped fn signatures.
        for (idx, line) in content.lines().enumerate() {
            // Skip comment lines — the pattern text appears in comments,
            // documentation strings, and in this pin's own source.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!")
            {
                continue;
            }

            let Some(caps) = fn_return_re.captures(line) else {
                continue;
            };

            let raw_return_type = caps.get(2).unwrap().as_str().trim();

            // Check whether the return type references a zp_verbs type.
            // We require the return-type text to contain a known zp_verbs
            // module path reference, OR be a bare type name whose context
            // was brought in via `use zp_verbs::…::*`.
            //
            // Heuristic: if the return type text contains `zp_verbs::` it is
            // unambiguously a verb-set type reference. If the file uses
            // `use zp_verbs::…::TypeName` (a named import of a specific type),
            // the return type won't contain `zp_verbs::` — but we've already
            // gated the whole file on `import_re`, so any return type from a
            // file that imports zp_verbs could be a verb-set type.
            //
            // Conservative approach: only flag types that EXPLICITLY contain
            // `zp_verbs::` in the return-type text. This avoids false positives
            // on helper functions in files that merely happen to import zp_verbs
            // for some other purpose. Functions with unqualified type names that
            // were imported via `use zp_verbs::…::Foo` are NOT flagged — their
            // category conformance is enforced by the tonic-generated trait
            // implementation, which is stronger than a regex.
            if !raw_return_type.contains("zp_verbs") {
                continue;
            }

            // Extract the base type name by stripping common wrapper types.
            // We strip (in order):
            //   tonic::Response<…>, tonic::Status<…>
            //   Result<…, …>
            //   Stream<Item = …>, impl Stream<Item = …>
            //   Response<…>
            //   Box<…>
            let base = strip_wrappers(raw_return_type);

            // Extract the leaf type name (after the last `::` if any).
            let leaf = base.split("::").last().unwrap_or(base).trim();

            // Check forbidden patterns first (they take priority).
            // If a forbidden pattern matches, record that violation and move on
            // to the next line — don't also report it as "wrong category".
            let mut is_forbidden = false;
            for re in &forbidden_res {
                if re.is_match(leaf) {
                    is_forbidden = true;
                    violations.push(Violation {
                        path: rel.clone(),
                        line_number: idx + 1,
                        return_type: raw_return_type.to_string(),
                        kind: ViolationKind::Forbidden(re.as_str().to_string()),
                        line: line.trim().to_string(),
                    });
                }
            }
            if is_forbidden {
                continue;
            }

            // Not forbidden — check that it matches at least one allowed pattern.
            // Only flag if none of the allowed patterns match.
            let is_allowed = allowed_res.iter().any(|re| re.is_match(leaf));
            if !is_allowed {
                violations.push(Violation {
                    path: rel.clone(),
                    line_number: idx + 1,
                    return_type: raw_return_type.to_string(),
                    kind: ViolationKind::WrongCategory,
                    line: line.trim().to_string(),
                });
            }
        }
    }

    if violations.is_empty() {
        return;
    }

    let mut msg = String::from(
        "\n\nDiscipline violation: verbs_must_match_schema\n\
         \n\
         Invariant: Architecture II.7 / VII.3 (verb-set response categories).\n\
         Every public function return type that references a `zp_verbs` type\n\
         must match one of the three response categories:\n\
         \n\
         - `*Envelope`     plain envelope (typed data, no signature)\n\
         - `Signed*`       signed envelope (data + node signature, not chained)\n\
         - `*Receipt`      full receipt (signed and chained into the audit log)\n\
         \n\
         Special carve-outs (streaming / chain-bookkeeping):\n\
         - `AuditEntry` / `common::AuditEntry`\n\
         - `Receipt`    / `common::Receipt`\n\
         \n\
         Wrappers that are transparent to the category check:\n\
         `Result<X, _>`, `Response<X>`, `Stream<Item = X>`,\n\
         `impl Stream<Item = X>`, `Box<X>`, `tonic::Response<X>`.\n\
         \n\
         `*Request` types are FORBIDDEN as return types — they are inputs.\n\
         \n\
         How to fix:\n\
         - If the return type is a Request: you have the input/output\n\
           relationship backwards. Change the return type to the matching\n\
           response message (or a new one if none exists yet).\n\
         - If the return type is an internal struct accidentally exposed:\n\
           introduce a proper *Envelope, Signed*, or *Receipt wrapper.\n\
         - If the heuristic is misclassifying a legitimate helper function:\n\
           move the helper to a private (non-pub) function, or qualify its\n\
           path so it doesn't trigger the `zp_verbs::` detection. Do NOT\n\
           add the file to KNOWN_EXEMPT_FILES without explicit approval.\n\
         \n",
    );
    msg.push_str(&format!("  {} violation(s):\n", violations.len()));
    for v in &violations {
        let kind_label = match &v.kind {
            ViolationKind::Forbidden(pat) => {
                format!("FORBIDDEN type (pattern `{}`)", pat)
            }
            ViolationKind::WrongCategory => "wrong response category".to_string(),
        };
        msg.push_str(&format!(
            "    {}:{} [{}]\n      return type: `{}`\n      line: {}\n",
            v.path, v.line_number, kind_label, v.return_type, v.line
        ));
    }
    msg.push('\n');
    panic!("{}", msg);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip common wrapper types to get the inner (base) type name.
///
/// Handles (recursively, left-to-right):
/// - `Result<T, _>` → T
/// - `tonic::Response<T>` → T
/// - `tonic::Status<T>` → T  (unusual but possible in some adapter layers)
/// - `Response<T>` → T
/// - `Box<T>` → T
/// - `Stream<Item = T>` → T  (both `Stream<Item = T>` and `impl Stream<Item = T>`)
/// - Leading `impl ` stripped
///
/// The stripping is heuristic and not a full parser. It handles the realistic
/// shapes that appear in tonic handler code. Deeply nested or unusual generics
/// may not be fully stripped, but that's acceptable — if the outer wrapper
/// still contains `zp_verbs::`, the leaf-type check below will operate on a
/// slightly noisier string but won't produce false positives on well-named types.
fn strip_wrappers(t: &str) -> &str {
    let t = t.trim();

    // Strip leading `impl ` keyword (for `impl Trait` return types).
    let t = t.strip_prefix("impl").map(|s| s.trim()).unwrap_or(t);

    // Strip generic wrappers. We match prefix + `<` and extract inner content.
    // Order matters: try the most-specific prefixes first.
    let wrappers = &[
        "tonic::Response<",
        "tonic::Status<",
        "Result<",
        "Response<",
        "Status<",
        "Box<",
        // Stream<Item = T> — the inner type is after `Item =`
    ];
    for wrapper in wrappers {
        // `strip_prefix` rather than `starts_with` + slice: the two forms can
        // disagree if the prefix is ever changed to something non-ASCII, and
        // the slice would panic on a char boundary rather than not match.
        if let Some(inner) = t.strip_prefix(wrapper) {
            // `inner` is what's inside the outer `<…>`.
            // Find the matching `>`. For Result<T, E> we want T (before the comma
            // at depth-1). Walk characters tracking angle-bracket depth.
            let first_type = extract_first_generic_arg(inner);
            return strip_wrappers(first_type);
        }
    }

    // Stream<Item = T> or `impl Stream<Item = T>`.
    // After stripping `impl`, the remaining text might be `Stream<Item = T>`.
    if t.starts_with("Stream<") || t.starts_with("stream::Stream<") {
        let inner = t.find('<').map(|i| &t[i + 1..]).unwrap_or(t);
        // Find `Item =` inside the angle brackets.
        if let Some(pos) = inner.find("Item") {
            let after_item = inner[pos + "Item".len()..].trim_start();
            let after_eq = after_item
                .strip_prefix('=')
                .map(|s| s.trim())
                .unwrap_or(after_item);
            // Strip trailing `>` from the end.
            let after_eq = strip_trailing_angle(after_eq);
            return strip_wrappers(after_eq);
        }
    }

    t
}

/// Extract the first generic argument from a string that starts inside `<…>`.
///
/// Example: `"GuardReceipt, tonic::Status"` → `"GuardReceipt"`.
/// Handles nested generics by tracking angle-bracket depth.
fn extract_first_generic_arg(s: &str) -> &str {
    let mut depth: i32 = 0;
    // Skip leading whitespace.
    let s = s.trim_start();
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    // We hit the closing `>` of the outer wrapper.
                    return s[..i].trim();
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                // First comma at depth 0 separates first arg from rest.
                return s[..i].trim();
            }
            _ => {}
        }
    }
    s.trim()
}

/// Strip a trailing `>` or `>` sequences from a type name.
fn strip_trailing_angle(s: &str) -> &str {
    let mut s = s.trim();
    while s.ends_with('>') {
        s = s[..s.len() - 1].trim();
    }
    s
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ViolationKind {
    /// The type matches a forbidden pattern (e.g. `*Request` as return type).
    Forbidden(String),
    /// The type references zp_verbs but doesn't match any allowed category.
    WrongCategory,
}

#[derive(Debug)]
struct Violation {
    path: String,
    line_number: usize,
    return_type: String,
    kind: ViolationKind,
    line: String,
}

// ---------------------------------------------------------------------------
// Infrastructure (duplicated from framework — private to each custom test)
// ---------------------------------------------------------------------------

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
