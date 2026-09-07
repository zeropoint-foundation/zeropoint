//! Discipline (Seam 10): every external `<script>` and external
//! `<link rel="stylesheet">` on the public site must carry an
//! `integrity=` and `crossorigin=` attribute.
//!
//! # Why
//!
//! The public site loads JavaScript that runs in a user's browser
//! under the `zeropoint.global` origin. Without Subresource Integrity
//! (SRI):
//!
//! - A CDN compromise (or cache poisoning) replaces our scripts with
//!   attacker-controlled bytes; the browser executes whatever arrived.
//! - A network MITM injects different bytes than what we published;
//!   TLS bounds the threat but doesn't eliminate it (e.g. compromised
//!   intermediate CA).
//! - A version drift on the CDN side silently changes behaviour.
//!
//! ZeroPoint's claim is that *trust is structural, not asserted*. A
//! site that asks a CDN to "please send us the right bytes" without
//! checking is making an assertion. SRI converts the assertion into
//! an enforced invariant: the browser refuses to execute bytes that
//! don't match the pinned hash.
//!
//! This pin closes the loop: the discipline test refuses to be green
//! if any HTML file under `zeropoint.global/` references an external
//! resource without an `integrity=` and `crossorigin=` attribute.
//! Combined with `docs/SUPPLY-CHAIN-MANIFEST.md` (the singular record
//! of pinned URL → hash mappings), every byte the user's browser is
//! told to execute is one we deliberately published or refused to
//! ship.
//!
//! # Pattern
//!
//! For each line in `zeropoint.global/**/*.html`:
//!
//! - If it contains `<script ... src="https?://...">` (external
//!   script) — require `integrity=` AND `crossorigin=` on the same
//!   line.
//! - If it contains `<link ... href="https?://...">` and `rel="..."`
//!   includes `stylesheet` (external stylesheet) — same requirement.
//!
//! Multi-line `<script>` / `<link>` tags would defeat the line-based
//! check; the convention on this site is single-line tags, and the
//! pin assumes that. If a future tag spans lines, the pin will miss
//! it — but that same tag will also be hard to read in review, which
//! is its own forcing function.
//!
//! # Exemptions
//!
//! - **Google Fonts CSS** (`fonts.googleapis.com`, `fonts.gstatic.com`).
//!   Google serves different CSS bytes per User-Agent (different font
//!   formats per browser), so a single SRI hash isn't workable. The
//!   alternative — vendoring the fonts — costs more than the residual
//!   risk; we accept that trade-off and exempt these hosts.
//! - **Metadata-only `<link>` tags** — `rel="canonical"`,
//!   `rel="preconnect"`, `rel="preload"` (without `as=script` /
//!   `as=style`), `rel="alternate"`, `rel="icon"`, etc. don't load
//!   executable bytes. SRI is for `<script>` and `rel="stylesheet"`;
//!   other `rel` values are not in scope.
//!
//! # Allowlisted directories
//!
//! Only `zeropoint.global/` is scanned. Internal HTML in
//! `crates/zp-server/assets/` ships compiled-in via `include_str!()`
//! and isn't subject to CDN supply-chain risk in the same way (an
//! attacker tampering with the binary already has worse options than
//! swapping a CDN script).

use std::path::{Path, PathBuf};

use regex::Regex;
use walkdir::WalkDir;

/// Hosts for which `integrity=` is *not* required.
///
/// Each entry is matched as a substring against the URL inside the
/// `src=` / `href=` attribute. Keep this list short — every entry is
/// a piece of trust we're *not* enforcing structurally.
const SRI_EXEMPT_HOSTS: &[&str] = &[
    // Google Fonts serves per-User-Agent CSS, so a single hash can't
    // cover the response. The alternative is self-hosting the fonts;
    // see docs/SUPPLY-CHAIN-MANIFEST.md.
    "fonts.googleapis.com",
    "fonts.gstatic.com",
];

#[test]
fn external_resources_must_carry_integrity_attribute() {
    let public_site = workspace_root().join("zeropoint.global");
    assert!(
        public_site.is_dir(),
        "expected zeropoint.global/ at {} — discipline cannot scan",
        public_site.display()
    );

    // External <script src="https://..."> — captures any quoting style.
    let script_re = Regex::new(r#"<script\b[^>]*\bsrc\s*=\s*["'](https?://[^"']+)["']"#).unwrap();

    // External <link ... href="https://..."> — we'll filter for
    // rel="stylesheet" inside the loop because rel and href can
    // appear in either order.
    let link_re = Regex::new(r#"<link\b[^>]*\bhref\s*=\s*["'](https?://[^"']+)["']"#).unwrap();

    // Captures rel="..." regardless of attribute order on the tag.
    let rel_re = Regex::new(r#"\brel\s*=\s*["']([^"']+)["']"#).unwrap();

    let mut violations: Vec<Violation> = Vec::new();

    for entry in WalkDir::new(&public_site)
        .into_iter()
        .filter_entry(|e| !is_excluded_dir(e.file_name().to_string_lossy().as_ref()))
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let rel_path = path
            .strip_prefix(workspace_root())
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        for (idx, line) in content.lines().enumerate() {
            // Skip HTML comments — `<!-- ... -->` blocks may legitimately
            // mention forbidden patterns when documenting the discipline.
            // This is a line-level skip; multi-line comments are not
            // perfectly handled but the public site doesn't use them
            // around script/link tags.
            let trimmed = line.trim_start();
            if trimmed.starts_with("<!--") {
                continue;
            }

            // <script src="https://..."> — always require SRI unless host is exempt.
            if let Some(caps) = script_re.captures(line) {
                let url = caps.get(1).unwrap().as_str();
                if !is_exempt(url) && !line_has_integrity_and_crossorigin(line) {
                    violations.push(Violation {
                        path: rel_path.clone(),
                        line_number: idx + 1,
                        url: url.to_string(),
                        kind: ResourceKind::Script,
                        line: line.trim().to_string(),
                    });
                }
            }

            // <link href="https://..."> — only stylesheets (or preloads
            // with as=script/style) need SRI; metadata links don't.
            if let Some(caps) = link_re.captures(line) {
                let url = caps.get(1).unwrap().as_str();
                let rel = rel_re
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_lowercase())
                    .unwrap_or_default();
                let needs_sri = rel.split_ascii_whitespace().any(|t| t == "stylesheet")
                    || (rel.split_ascii_whitespace().any(|t| t == "preload")
                        && line.contains("as=\"script\"")
                        || line.contains("as='script'")
                        || line.contains("as=\"style\"")
                        || line.contains("as='style'"));
                if needs_sri && !is_exempt(url) && !line_has_integrity_and_crossorigin(line) {
                    violations.push(Violation {
                        path: rel_path.clone(),
                        line_number: idx + 1,
                        url: url.to_string(),
                        kind: ResourceKind::Stylesheet,
                        line: line.trim().to_string(),
                    });
                }
            }
        }
    }

    if violations.is_empty() {
        return;
    }

    let mut msg = String::from(
        "\n\nDiscipline violation: no_external_script_without_integrity\n\
         \n\
         Invariant: Seam 10 (public-page supply chain). Every external \n\
         resource the user's browser loads from `zeropoint.global/` \n\
         must be pinned by SHA-384 via an `integrity=` attribute, with \n\
         `crossorigin=\"anonymous\"` so the browser can fetch and \n\
         compare the hash.\n\
         \n\
         How to fix:\n\
         1. Compute the hash:\n\
            curl -fsSL '<URL>' | openssl dgst -sha384 -binary | openssl base64 -A\n\
         2. Add `integrity=\"sha384-<value>\" crossorigin=\"anonymous\"` to the tag.\n\
         3. Record the URL + hash in `docs/SUPPLY-CHAIN-MANIFEST.md`.\n\
         \n\
         Exempt hosts (Google Fonts) are listed in this pin's source.\n\
         \n",
    );
    msg.push_str(&format!("  {} violation(s):\n", violations.len()));
    for v in &violations {
        msg.push_str(&format!(
            "    {}:{}  [{}]  {}\n      {}\n",
            v.path,
            v.line_number,
            v.kind.label(),
            v.url,
            v.line
        ));
    }
    msg.push('\n');
    panic!("{}", msg);
}

fn is_exempt(url: &str) -> bool {
    SRI_EXEMPT_HOSTS.iter().any(|host| url.contains(host))
}

fn line_has_integrity_and_crossorigin(line: &str) -> bool {
    line.contains("integrity=") && line.contains("crossorigin=")
}

#[derive(Debug)]
enum ResourceKind {
    Script,
    Stylesheet,
}

impl ResourceKind {
    fn label(&self) -> &'static str {
        match self {
            ResourceKind::Script => "script",
            ResourceKind::Stylesheet => "stylesheet",
        }
    }
}

#[derive(Debug)]
struct Violation {
    path: String,
    line_number: usize,
    url: String,
    kind: ResourceKind,
    line: String,
}

/// Walk up from `CARGO_MANIFEST_DIR` until we find a Cargo.toml with
/// `[workspace]`. Same logic as the framework's `workspace_root()` —
/// duplicated here because that function is private to `lib.rs`.
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
