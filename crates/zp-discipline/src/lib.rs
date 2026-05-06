//! Discipline-pin test framework.
//!
//! # The wire (Test System, May 2026)
//!
//! ZeroPoint's structural-audit work treats *convention vs. invariant* as
//! the central architectural distinction (see
//! `docs/STRUCTURAL-AUDIT-2026-05.md`). A *convention* is a rule
//! developers must remember to follow. An *invariant* is a rule the code
//! makes impossible to violate.
//!
//! Discipline-pin tests are the test-layer carrier for the same idea.
//! Each one declares an architectural rule, scans the workspace for
//! violations, and fails the `cargo test` build when found. They convert
//! "discipline written in a doc comment that someone might miss" into
//! "the build refuses to be green if you violate it." That's the same
//! convention→invariant move applied to the test suite itself.
//!
//! # Usage
//!
//! ```rust,no_run
//! use zp_discipline::Discipline;
//!
//! #[test]
//! fn no_non_strict_ed25519_verify() {
//!     Discipline::new("ed25519_verify_must_be_strict")
//!         .cite_invariant("M4 (signature integrity)")
//!         .rationale("Non-strict `verify` is signature-malleable; \
//!                     `verify_strict` is the only sanctioned primitive.")
//!         .forbid_pattern(r"\.verify\b\s*\(")
//!         .allow_path("crates/zp-receipt/src/verify.rs")
//!         .skip_lines_containing("verify_strict")
//!         .skip_lines_containing("//")
//!         .assert();
//! }
//! ```
//!
//! # What this is not
//!
//! Discipline-pin tests aren't a substitute for functional tests. They
//! pin *structural* properties — "this regex must not appear outside
//! this allowlist" — not behavior. They complement functional tests:
//! the functional test asserts what the code does; the discipline test
//! asserts what the code is structurally allowed to be.
//!
//! A discipline test that's hard to write usually means the discipline
//! itself isn't expressible as a structural rule. That's a signal: maybe
//! the discipline needs to be re-stated, or maybe it really is convention
//! all the way down.

use std::path::{Path, PathBuf};

use regex::Regex;
use walkdir::WalkDir;

/// A single architectural discipline pinned as a test.
///
/// Builder pattern. Construct, configure, call [`Discipline::assert`].
/// Failure produces a structured panic listing every violation with file
/// path and line number — meant to be readable in `cargo test` output.
pub struct Discipline {
    name: &'static str,
    invariant: Option<&'static str>,
    rationale: Option<&'static str>,
    forbidden: Vec<Regex>,
    /// Path substrings that, when matched, exempt the entire file from
    /// the discipline. Substring match against `path.to_string_lossy()`.
    allowed_paths: Vec<&'static str>,
    /// Line content substrings that, when present, exempt the line from
    /// the discipline. Useful for skipping comment lines, doc strings,
    /// or lines that mention the forbidden pattern legitimately (e.g.
    /// in a rationale comment).
    skip_lines: Vec<&'static str>,
    /// File extensions to scan. Defaults to ["rs"]; can be overridden
    /// for disciplines that scan Cargo.toml, html, etc.
    extensions: Vec<&'static str>,
    /// If non-empty, ONLY scan files whose path contains one of these
    /// substrings. Inverse of `allowed_paths` — useful for disciplines
    /// that apply only to a specific file or subtree (e.g. "no
    /// `std::fs::write` inside `zp-keys/src/keyring.rs`"). Empty means
    /// "scan everything that matches the extension filter."
    restrict_paths: Vec<&'static str>,
}

impl Discipline {
    /// Construct a new discipline. `name` should be a stable identifier
    /// that appears in the panic message — typically the test function's
    /// own name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            invariant: None,
            rationale: None,
            forbidden: Vec::new(),
            allowed_paths: Vec::new(),
            skip_lines: Vec::new(),
            extensions: vec!["rs"],
            restrict_paths: Vec::new(),
        }
    }

    /// Cite the catalog rule this discipline enforces (M3, P2, X1, etc.)
    /// or one of the four claims. Surfaced in the panic message so a
    /// future reader knows what the discipline is protecting.
    pub fn cite_invariant(mut self, rule: &'static str) -> Self {
        self.invariant = Some(rule);
        self
    }

    /// One-line explanation of why this discipline exists. Surfaced in
    /// the panic message.
    pub fn rationale(mut self, why: &'static str) -> Self {
        self.rationale = Some(why);
        self
    }

    /// Add a regex that must NOT appear in scanned files.
    ///
    /// # Panics
    ///
    /// Panics at test build time if the regex is malformed. The pattern
    /// is treated as authored by a human; we'd rather fail loudly than
    /// silently skip a malformed pattern.
    pub fn forbid_pattern(mut self, pattern: &str) -> Self {
        let re = Regex::new(pattern)
            .unwrap_or_else(|e| panic!("invalid forbidden pattern {:?}: {}", pattern, e));
        self.forbidden.push(re);
        self
    }

    /// Add a path substring that exempts a file from this discipline.
    /// Substring match against the full path. E.g. passing
    /// `"zp-receipt/src/verify.rs"` exempts only that file; passing
    /// `"tests/"` exempts every test file in the workspace.
    pub fn allow_path(mut self, path_substring: &'static str) -> Self {
        self.allowed_paths.push(path_substring);
        self
    }

    /// Skip any line containing this substring. Common uses:
    /// `"verify_strict"` to allow lines that mention the strict variant
    /// when the forbidden pattern matches its prefix; `"//"` to skip
    /// all comment lines.
    pub fn skip_lines_containing(mut self, substring: &'static str) -> Self {
        self.skip_lines.push(substring);
        self
    }

    /// Override the default file extensions. Default is `["rs"]`;
    /// override to e.g. `["toml"]` for disciplines that pin Cargo
    /// features, or `["html"]` for SRI-style disciplines on assets.
    pub fn scan_extensions(mut self, exts: &[&'static str]) -> Self {
        self.extensions = exts.to_vec();
        self
    }

    /// Restrict the scan to files whose path contains one of these
    /// substrings. Inverse of [`Discipline::allow_path`]. Use when a
    /// discipline applies only to a specific file or subtree:
    ///
    /// ```rust,no_run
    /// # use zp_discipline::Discipline;
    /// // "no std::fs::write inside the keyring module"
    /// Discipline::new("keyring_uses_write_secret_file")
    ///     .restrict_to_paths(&["crates/zp-keys/src/keyring.rs"])
    ///     .forbid_pattern(r"std::fs::write\s*\(")
    ///     .assert();
    /// ```
    pub fn restrict_to_paths(mut self, paths: &[&'static str]) -> Self {
        self.restrict_paths = paths.to_vec();
        self
    }

    /// Run the discipline check. Panics with a structured violation
    /// report if any forbidden pattern appears in a non-allowlisted file
    /// on a non-skipped line. Returns silently when clean.
    pub fn assert(self) {
        let root = workspace_root();
        let scan_root = root.join("crates");

        let mut violations: Vec<Violation> = Vec::new();

        for entry in WalkDir::new(&scan_root)
            .into_iter()
            .filter_entry(|e| !is_excluded_dir(e.file_name().to_string_lossy().as_ref()))
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext_ok = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| self.extensions.iter().any(|wanted| *wanted == e))
                .unwrap_or(false);
            if !ext_ok {
                continue;
            }
            // Path-relative for stable output; allowlist is matched
            // against the relative form so the substring `"crates/foo"`
            // works regardless of where cargo is run from.
            let rel = path.strip_prefix(&root).unwrap_or(path);
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if self.allowed_paths.iter().any(|a| rel_str.contains(a)) {
                continue;
            }
            if !self.restrict_paths.is_empty()
                && !self.restrict_paths.iter().any(|r| rel_str.contains(r))
            {
                continue;
            }

            // Read once. Discipline-pin tests are expected to scan the
            // whole workspace, so file I/O cost is the dominant term;
            // we don't try to be clever about it.
            let content = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(_) => continue, // not UTF-8 or unreadable — skip
            };

            for (idx, line) in content.lines().enumerate() {
                if self.skip_lines.iter().any(|s| line.contains(s)) {
                    continue;
                }
                for re in &self.forbidden {
                    if re.is_match(line) {
                        violations.push(Violation {
                            path: rel_str.clone(),
                            line_number: idx + 1,
                            line: line.trim().to_string(),
                            pattern: re.as_str().to_string(),
                        });
                    }
                }
            }
        }

        if violations.is_empty() {
            return;
        }

        let mut msg = format!(
            "\n\nDiscipline violation: {}\n",
            self.name
        );
        if let Some(rule) = self.invariant {
            msg.push_str(&format!("  Invariant: {}\n", rule));
        }
        if let Some(why) = self.rationale {
            msg.push_str(&format!("  Rationale: {}\n", why));
        }
        msg.push_str(&format!(
            "  {} violation(s):\n",
            violations.len()
        ));
        for v in &violations {
            msg.push_str(&format!(
                "    {}:{} (pattern `{}`):  {}\n",
                v.path, v.line_number, v.pattern, v.line
            ));
        }
        msg.push('\n');
        panic!("{}", msg);
    }
}

/// A single discipline violation.
#[derive(Debug, Clone)]
struct Violation {
    path: String,
    line_number: usize,
    line: String,
    pattern: String,
}

/// Find the workspace root by walking up from `CARGO_MANIFEST_DIR` until
/// we hit a Cargo.toml that has `[workspace]`.
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

/// Names of directories the scanner always skips. Avoids walking into
/// `target/`, `.git/`, build artifacts, dependencies, etc.
fn is_excluded_dir(name: &str) -> bool {
    matches!(name, "target" | ".git" | "node_modules" | ".cargo")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: the scanner can find the workspace root from inside this
    /// crate. If this test ever fails, every discipline test will too.
    #[test]
    fn workspace_root_is_reachable() {
        let root = workspace_root();
        assert!(
            root.join("Cargo.toml").exists(),
            "workspace root must contain Cargo.toml"
        );
    }

    /// Sanity: a Discipline with no patterns passes trivially.
    #[test]
    fn empty_discipline_is_a_pass() {
        Discipline::new("empty")
            .cite_invariant("none")
            .assert();
    }

    /// Self-test: a Discipline that looks for a string nobody could
    /// have typed into the source passes. Confirms the scanner walks
    /// files but doesn't false-positive on absence.
    ///
    /// The pattern is built at runtime from a hash of a stable seed,
    /// so the literal byte sequence doesn't appear anywhere in the
    /// source tree — including inside this test. (An earlier version
    /// hardcoded a "definitely-absent" string into the source, which
    /// the framework correctly found, demonstrating that the framework
    /// catches what's typed regardless of the author's intent.)
    #[test]
    fn impossible_pattern_passes() {
        // Build a token that's not in any source file. The hex of a
        // BLAKE3 hash of a seed is the simplest way to get bytes that
        // don't collide with anything a human would write.
        let token = blake3::hash(b"zp-discipline self-test seed v1")
            .to_hex()
            .to_string();
        let pattern = format!("zpd_{}", token);
        Discipline::new("impossible_pattern")
            .forbid_pattern(&pattern)
            .assert();
    }
}
