//! Governed Codebase API — self-describing trust infrastructure.
//!
//! Exposes ZeroPoint's own source code through the governance API so
//! governed tools can learn about the system that manages them.
//! Every file access produces a receipt on the audit chain:
//!
//!   `tool:codebase:tree:{tool}`   — directory listing
//!   `tool:codebase:read:{tool}`   — file read (path in detail)
//!
//! **Read-only**.  Tools cannot modify their governance layer.
//! **Sanitized**.  Path traversal and sensitive files are blocked.
//! **Audited**.    The chain records what each tool looked at and when.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

use crate::tool_chain;
use crate::AppState;

// ── Configuration ───────────────────────────────────────────────────────

/// Files and patterns that are never exposed through the codebase API.
/// These could contain secrets, credentials, or private keys.
const SENSITIVE_PATTERNS: &[&str] = &[
    ".env",
    ".env.zp",
    ".env.local",
    ".env.production",
    "secrets",
    "credentials",
    ".git",
    "target", // build artifacts — huge, not useful
    "node_modules",
    ".cargo",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "genesis.encrypted",
    "enrollment.json",
];

/// Maximum file size we'll serve (1 MB).  Source files larger than this
/// are almost certainly generated or binary.
const MAX_FILE_SIZE: u64 = 1_048_576;

/// Maximum directory depth to prevent runaway recursion.
const MAX_TREE_DEPTH: usize = 8;

// ── Request / Response types ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CodebaseQuery {
    /// Relative path within the ZeroPoint project (e.g., "crates/zp-server/src/lib.rs")
    pub path: Option<String>,
    /// Which tool is making the request (for receipt attribution)
    pub tool: Option<String>,
    /// Max depth for tree listing (default: 3)
    pub depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct TreeEntry {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub kind: &'static str, // "file" or "dir"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<TreeEntry>,
}

#[derive(Debug, Serialize)]
pub struct FileContent {
    pub path: String,
    pub size: u64,
    pub content: String,
    pub lines: usize,
    /// Language hint from file extension
    pub language: Option<String>,
}

// ── Path safety ─────────────────────────────────────────────────────────

/// Resolve and validate a relative path within the codebase root.
/// Returns None if the path escapes the root or hits a sensitive pattern.
fn safe_resolve(root: &Path, relative: &str) -> Option<PathBuf> {
    // Reject obvious traversal attempts
    if relative.contains("..") || relative.starts_with('/') || relative.starts_with('\\') {
        return None;
    }

    let candidate = root.join(relative);

    // Canonicalize to resolve any symlinks and verify we're still under root
    let canonical = candidate.canonicalize().ok()?;
    let root_canonical = root.canonicalize().ok()?;

    if !canonical.starts_with(&root_canonical) {
        warn!(
            "Codebase path traversal blocked: {} escapes {}",
            relative,
            root.display()
        );
        return None;
    }

    // Check against sensitive patterns
    if is_sensitive(relative) {
        debug!("Codebase access blocked (sensitive): {}", relative);
        return None;
    }

    Some(canonical)
}

/// Check if a path matches any sensitive pattern.
fn is_sensitive(path: &str) -> bool {
    let components: Vec<&str> = path.split('/').collect();
    for component in &components {
        for pattern in SENSITIVE_PATTERNS {
            if let Some(suffix) = pattern.strip_prefix('*') {
                // Glob suffix match: "*.pem" matches "server.pem"
                if component.ends_with(suffix) {
                    return true;
                }
            } else if *component == *pattern {
                return true;
            }
        }
    }
    false
}

/// Detect programming language from file extension.
fn detect_language(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?;
    Some(
        match ext {
            "rs" => "rust",
            "toml" => "toml",
            "json" => "json",
            "js" => "javascript",
            "ts" => "typescript",
            "html" => "html",
            "css" => "css",
            "py" => "python",
            "sh" | "bash" => "bash",
            "sql" => "sql",
            "md" => "markdown",
            "yml" | "yaml" => "yaml",
            "lock" => "lockfile",
            _ => ext,
        }
        .to_string(),
    )
}

// ── Tree builder ────────────────────────────────────────────────────────

#[allow(clippy::only_used_in_recursion)]
fn build_tree(
    root: &Path,
    dir: &Path,
    relative_prefix: &str,
    depth: usize,
    max_depth: usize,
) -> Vec<TreeEntry> {
    if depth >= max_depth {
        return vec![];
    }

    let mut entries = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return vec![];
    };

    // Collect and sort entries for deterministic output
    let mut dir_entries: Vec<_> = read_dir.filter_map(|e| e.ok()).collect();
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in dir_entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let rel_path = if relative_prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", relative_prefix, name)
        };

        // Skip sensitive paths
        if is_sensitive(&rel_path) || name.starts_with('.') {
            continue;
        }

        let Ok(metadata) = entry.metadata() else {
            continue;
        };

        if metadata.is_dir() {
            let children = build_tree(root, &entry.path(), &rel_path, depth + 1, max_depth);
            entries.push(TreeEntry {
                name,
                path: rel_path,
                kind: "dir",
                size: None,
                children,
            });
        } else if metadata.is_file() {
            entries.push(TreeEntry {
                name,
                path: rel_path,
                kind: "file",
                size: Some(metadata.len()),
                children: vec![],
            });
        }
    }

    entries
}

// ── Handlers ────────────────────────────────────────────────────────────

/// ZeroPoint project root — the repo directory.
fn zp_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join("projects")
        .join("zeropoint")
}

/// `GET /api/v1/codebase/tree` — list the ZeroPoint directory structure.
///
/// Query params:
///   - `path`: subdirectory to list (default: root)
///   - `tool`: requesting tool name (for receipt attribution)
///   - `depth`: max recursion depth (default: 3, max: 8)
pub async fn tree_handler(
    State(state): State<AppState>,
    Query(params): Query<CodebaseQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let root = zp_root();
    if !root.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "ZeroPoint project not found",
                "expected": root.display().to_string(),
            })),
        );
    }

    let subpath = params.path.as_deref().unwrap_or("");
    let tool = params.tool.as_deref().unwrap_or("unknown");
    let max_depth = params.depth.unwrap_or(3).min(MAX_TREE_DEPTH);

    let dir = if subpath.is_empty() {
        root.clone()
    } else {
        match safe_resolve(&root, subpath) {
            Some(p) if p.is_dir() => p,
            Some(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "Path is a file, not a directory. Use /codebase/read instead.",
                    })),
                );
            }
            None => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "Path not accessible",
                    })),
                );
            }
        }
    };

    let tree = build_tree(&root, &dir, subpath, 0, max_depth);

    // Emit receipt
    let event = format!("tool:codebase:tree:{}", tool);
    let detail = format!(
        "path={} depth={} entries={}",
        subpath,
        max_depth,
        count_entries(&tree)
    );
    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "root": subpath,
            "depth": max_depth,
            "entries": tree,
        })),
    )
}

/// `GET /api/v1/codebase/read` — read a single file from the ZeroPoint project.
///
/// Query params:
///   - `path`: relative file path (required)
///   - `tool`: requesting tool name (for receipt attribution)
pub async fn read_handler(
    State(state): State<AppState>,
    Query(params): Query<CodebaseQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let root = zp_root();

    let path = match params.path.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Missing 'path' parameter",
                    "hint": "Use /codebase/tree to discover available files",
                })),
            );
        }
    };

    let tool = params.tool.as_deref().unwrap_or("unknown");

    let resolved = match safe_resolve(&root, path) {
        Some(p) if p.is_file() => p,
        Some(p) if p.is_dir() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Path is a directory. Use /codebase/tree instead.",
                })),
            );
        }
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Path not accessible",
                })),
            );
        }
    };

    // Check file size
    let metadata = match std::fs::metadata(&resolved) {
        Ok(m) => m,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "File not found" })),
            );
        }
    };

    if metadata.len() > MAX_FILE_SIZE {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "File too large",
                "size": metadata.len(),
                "max": MAX_FILE_SIZE,
            })),
        );
    }

    // Read content
    let content = match std::fs::read_to_string(&resolved) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "File is binary or not UTF-8",
                    "hint": "Only text source files are served",
                })),
            );
        }
    };

    let lines = content.lines().count();
    let language = detect_language(&resolved);

    // Emit receipt
    let event = format!("tool:codebase:read:{}", tool);
    let detail = format!("path={} size={} lines={}", path, metadata.len(), lines);
    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "path": path,
            "size": metadata.len(),
            "lines": lines,
            "language": language,
            "content": content,
        })),
    )
}

/// `GET /api/v1/codebase/search` — search for a pattern across the codebase.
///
/// Query params:
///   - `pattern`: text to search for (required)
///   - `tool`: requesting tool name (for receipt attribution)
pub async fn search_handler(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let root = zp_root();

    let pattern = match params.pattern.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Missing 'pattern' parameter",
                })),
            );
        }
    };

    let tool = params.tool.as_deref().unwrap_or("unknown");
    let max_results = params.limit.unwrap_or(50).min(200);

    // Walk the source tree and grep
    let mut results = Vec::new();
    let mut files_searched = 0u32;
    search_recursive(
        &root,
        &root,
        pattern,
        &mut results,
        &mut files_searched,
        max_results,
    );

    // Emit receipt
    let event = format!("tool:codebase:search:{}", tool);
    let detail = format!(
        "pattern={} matches={} files_searched={}",
        pattern,
        results.len(),
        files_searched
    );
    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "pattern": pattern,
            "matches": results,
            "files_searched": files_searched,
            "truncated": results.len() >= max_results,
        })),
    )
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub pattern: Option<String>,
    pub tool: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct SearchMatch {
    path: String,
    line: usize,
    content: String,
}

fn search_recursive(
    root: &Path,
    dir: &Path,
    pattern: &str,
    results: &mut Vec<SearchMatch>,
    files_searched: &mut u32,
    max_results: usize,
) {
    if results.len() >= max_results {
        return;
    }

    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };

    // Known source extensions
    let source_exts: HashSet<&str> = [
        "rs", "toml", "json", "js", "ts", "html", "css", "py", "sh", "sql", "md", "yml", "yaml",
        "txt",
    ]
    .into_iter()
    .collect();

    for entry in read_dir.filter_map(|e| e.ok()) {
        if results.len() >= max_results {
            return;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        let full_path = entry.path();
        let Ok(rel) = full_path.strip_prefix(root) else {
            continue;
        };
        let rel_str = rel.to_string_lossy().to_string();

        if is_sensitive(&rel_str) || name.starts_with('.') {
            continue;
        }

        let Ok(metadata) = entry.metadata() else {
            continue;
        };

        if metadata.is_dir() {
            search_recursive(
                root,
                &entry.path(),
                pattern,
                results,
                files_searched,
                max_results,
            );
        } else if metadata.is_file() && metadata.len() <= MAX_FILE_SIZE {
            // Only search text source files
            let has_ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| source_exts.contains(e))
                .unwrap_or(false);
            if !has_ext {
                continue;
            }

            *files_searched += 1;
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                let pattern_lower = pattern.to_lowercase();
                for (i, line) in content.lines().enumerate() {
                    if results.len() >= max_results {
                        return;
                    }
                    if line.to_lowercase().contains(&pattern_lower) {
                        results.push(SearchMatch {
                            path: rel_str.clone(),
                            line: i + 1,
                            content: line.trim().to_string(),
                        });
                    }
                }
            }
        }
    }
}

/// Count total entries in a tree (for receipt detail).
fn count_entries(tree: &[TreeEntry]) -> usize {
    tree.iter().map(|e| 1 + count_entries(&e.children)).sum()
}
