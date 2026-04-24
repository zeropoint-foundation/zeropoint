//! Launch inference helpers shared by `detect_launch` (cockpit cmd
//! generation) and the preflight `launch_method` check.
//!
//! Three responsibilities:
//!   1. Read a per-tool `.zp-launch.toml` override (Fix A).
//!   2. Validate that any `npm run X` / `pnpm run X` referenced in a
//!      generated command actually exists in `package.json` (Fix B).
//!   3. Detect Python entry points so polyglot projects (Hermes, etc.)
//!      whose `package.json` is just for browser tooling deps don't get
//!      misclassified as Node apps (Fix C).

use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

/// Per-tool launch override loaded from `.zp-launch.toml` at the tool root.
///
/// When present, this fully replaces inference. The runtime still prepends
/// `cd '<tool_path>' &&` so users only need to write the command body.
#[derive(Debug, Clone, Deserialize)]
pub struct LaunchOverride {
    pub launch: LaunchOverrideBody,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LaunchOverrideBody {
    /// Reported launch kind — surfaced in the cockpit tile and preflight.
    /// Free-form: "python", "cli", "web", "docker", "native", etc.
    pub kind: String,
    /// Command body. `cd '<tool_path>' && ` will be prepended automatically.
    pub cmd: String,
    /// Optional listening port — used to compose the URL the tile shows.
    #[serde(default)]
    pub port: Option<u16>,
    /// Optional URL override — defaults to `http://localhost:{port}` if `port` is set.
    #[serde(default)]
    pub url: Option<String>,
}

/// Read `.zp-launch.toml` from a tool directory if present and parseable.
/// Parse errors are logged at warn level and treated as no-override.
pub fn read_launch_override(tool_path: &Path) -> Option<LaunchOverride> {
    let p = tool_path.join(".zp-launch.toml");
    if !p.exists() {
        return None;
    }
    match std::fs::read_to_string(&p) {
        Ok(s) => match toml::from_str::<LaunchOverride>(&s) {
            Ok(o) => Some(o),
            Err(e) => {
                tracing::warn!("Failed to parse {}: {}", p.display(), e);
                None
            }
        },
        Err(e) => {
            tracing::warn!("Failed to read {}: {}", p.display(), e);
            None
        }
    }
}

/// Read the set of npm script names from `package.json`.
/// Returns `None` if the file is absent, unreadable, or malformed.
pub fn read_npm_scripts(tool_path: &Path) -> Option<HashSet<String>> {
    let p = tool_path.join("package.json");
    let raw = std::fs::read_to_string(&p).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let scripts = v.get("scripts")?.as_object()?;
    Some(scripts.keys().cloned().collect())
}

/// Pull every `npm run <name>` or `pnpm run <name>` reference out of a shell
/// command. Used by the preflight to verify the generated command is runnable.
///
/// Catches the typical patterns: `npm run build`, `pnpm run dev`, and
/// chained `&& pnpm start` (start is implicit, treated like `run start`).
pub fn extract_referenced_scripts(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        let is_pkg_mgr = t == "npm" || t == "pnpm" || t == "yarn";
        if is_pkg_mgr && i + 1 < tokens.len() {
            let next = tokens[i + 1];
            if next == "run" && i + 2 < tokens.len() {
                let name = tokens[i + 2].trim_end_matches(&[';', '&'][..]).to_string();
                if !name.is_empty() {
                    out.push(name);
                }
                i += 3;
                continue;
            }
            // Package-manager subcommands that are implicit script invocations.
            // `npm start` ⇄ `npm run start`; same for `test` and `stop`.
            if matches!(next, "start" | "test" | "stop") {
                out.push(next.to_string());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Validate that every npm script referenced by `cmd` exists in `package.json`.
/// Returns `Ok(())` when fine (or when there's nothing npm-shaped to check),
/// `Err(message)` listing the missing scripts.
pub fn validate_launch_scripts(tool_path: &Path, cmd: &str) -> Result<(), String> {
    let referenced = extract_referenced_scripts(cmd);
    if referenced.is_empty() {
        return Ok(());
    }
    let scripts = match read_npm_scripts(tool_path) {
        Some(s) => s,
        None => {
            // package.json missing or malformed but cmd references npm scripts.
            return Err(format!(
                "Cannot verify scripts {:?} — package.json missing or malformed",
                referenced
            ));
        }
    };
    let missing: Vec<String> = referenced
        .into_iter()
        .filter(|s| !scripts.contains(s))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "package.json missing scripts: {} — generated command will fail",
            missing.join(", ")
        ))
    }
}

/// Choose the right Python interpreter for a tool. Prefers a project-local
/// `.venv` (uv/python -m venv style) over the ambient `python`, so installed
/// project deps are actually importable.
pub fn python_invocation(tool_path: &Path) -> String {
    let venv_py = tool_path.join(".venv").join("bin").join("python");
    if venv_py.exists() {
        return venv_py.display().to_string();
    }
    let venv_py_alt = tool_path.join("venv").join("bin").join("python");
    if venv_py_alt.exists() {
        return venv_py_alt.display().to_string();
    }
    "python".to_string()
}

/// Conventional Python entry-point file in the tool root, in priority order.
/// Returns the file name (e.g., `"run_agent.py"`) — the caller composes the
/// command (typically `python <file>`).
pub fn detect_python_entrypoint(tool_path: &Path) -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "run_agent.py",
        "main.py",
        "app.py",
        "server.py",
        "run.py",
        "__main__.py",
    ];
    CANDIDATES
        .iter()
        .find(|f| tool_path.join(f).exists())
        .map(|s| s.to_string())
}

/// Whether the tool looks like a runnable Python project. True when either:
///   * a top-level Python entry-point file exists, or
///   * `pyproject.toml` declares `[project.scripts]`.
///
/// Used to *deprioritize* a Node classification when `package.json` is only
/// present for tooling/deps (Hermes-style polyglot).
pub fn looks_like_python_project(tool_path: &Path) -> bool {
    if detect_python_entrypoint(tool_path).is_some() {
        return true;
    }
    let pyproject = tool_path.join("pyproject.toml");
    if !pyproject.exists() {
        return false;
    }
    let raw = match std::fs::read_to_string(&pyproject) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if let Ok(v) = raw.parse::<toml::Value>() {
        if let Some(scripts) = v
            .get("project")
            .and_then(|p| p.get("scripts"))
            .and_then(|s| s.as_table())
        {
            return !scripts.is_empty();
        }
        if let Some(scripts) = v
            .get("tool")
            .and_then(|t| t.get("poetry"))
            .and_then(|p| p.get("scripts"))
            .and_then(|s| s.as_table())
        {
            return !scripts.is_empty();
        }
    }
    false
}

/// Whether `package.json` has a usable launch surface (a `start` script,
/// a `bin`, or a `main` entry). False means `package.json` is present but
/// the project isn't actually a Node app you can `npm start` — common in
/// polyglot projects where Node is just used to install browser tooling.
pub fn package_json_is_runnable(tool_path: &Path) -> bool {
    let p = tool_path.join("package.json");
    let raw = match std::fs::read_to_string(&p) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(x) => x,
        Err(_) => return false,
    };
    if v.get("bin").is_some() || v.get("main").is_some() {
        return true;
    }
    v.get("scripts")
        .and_then(|s| s.get("start"))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_npm_run_basic() {
        let cmd = "cd '/x' && npm run build && npm start";
        let scripts = extract_referenced_scripts(cmd);
        assert_eq!(scripts, vec!["build", "start"]);
    }

    #[test]
    fn extract_pnpm_chained() {
        let cmd = "cd '/x' && pnpm run build && pnpm start";
        let scripts = extract_referenced_scripts(cmd);
        assert_eq!(scripts, vec!["build", "start"]);
    }

    #[test]
    fn extract_no_npm() {
        let cmd = "cd '/x' && python run_agent.py";
        let scripts = extract_referenced_scripts(cmd);
        assert!(scripts.is_empty());
    }
}
