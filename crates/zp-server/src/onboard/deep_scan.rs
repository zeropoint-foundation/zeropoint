//! Deep Scan — pre-launch configuration analysis.
//!
//! Cross-references docker-compose.yml, .env.example, and Cargo.toml to
//! catch misconfigurations that would cause launch failures. Inspired by
//! the "RTFM" principle: read the tool's own config files before trying
//! to start it.
//!
//! The scanner produces `DeepScanResult` containing:
//!   - Corrected env vars (e.g. DATABASE_URL with proper credentials)
//!   - Warnings (e.g. dotenvy dependency that overrides shell env)
//!   - An archetype classification for the tool's stack
//!
//! Results integrate into preflight as additional `PreflightCheck` entries
//! and feed corrected env vars into the launch pipeline.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};

// ── Types ──────────────────────────────────────────────────────────────

/// Classification of a tool's technology stack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ToolArchetype {
    /// Rust binary with Cargo.toml (may use sqlx, diesel, dotenvy, etc.)
    RustNative,
    /// Node.js app (Express, Next.js, etc.)
    NodeJs,
    /// Python app (Django, FastAPI, Flask, etc.)
    Python,
    /// Docker-only (no local source, just compose)
    DockerOnly,
    /// Unknown stack
    Unknown,
}

impl std::fmt::Display for ToolArchetype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolArchetype::RustNative => write!(f, "rust-native"),
            ToolArchetype::NodeJs => write!(f, "node-js"),
            ToolArchetype::Python => write!(f, "python"),
            ToolArchetype::DockerOnly => write!(f, "docker-only"),
            ToolArchetype::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single finding from the deep scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub severity: FindingSeverity,
    pub category: String,
    pub message: String,
    /// Optional corrective action (env var override, etc.)
    pub correction: Option<EnvCorrection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingSeverity {
    /// Will cause launch failure if not addressed
    Error,
    /// May cause issues — addressed by env injection
    Warning,
    /// Informational (e.g. archetype classification)
    Info,
}

/// An env var correction to apply at launch time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvCorrection {
    pub key: String,
    pub value: String,
    pub reason: String,
}

/// Full result of a deep scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanResult {
    pub archetype: ToolArchetype,
    pub findings: Vec<ScanFinding>,
    /// Corrected env vars to inject via cmd.env() at launch time.
    pub corrected_env: HashMap<String, String>,
    /// Cargo dependencies that affect launch behavior.
    pub cargo_deps: Vec<String>,
}

impl DeepScanResult {
    pub fn errors(&self) -> Vec<&ScanFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Error)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&ScanFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Warning)
            .collect()
    }
}

// ── Docker Compose parsing ─────────────────────────────────────────────

/// Credentials extracted from docker-compose.yml service environment.
#[derive(Debug, Default)]
struct ComposeCredentials {
    postgres_user: Option<String>,
    postgres_password: Option<String>,
    postgres_db: Option<String>,
    postgres_port: Option<u16>,
    redis_password: Option<String>,
    redis_port: Option<u16>,
}

/// Parse docker-compose.yml for service credentials.
///
/// Handles both mapping and list forms of `environment:`:
/// ```yaml
/// environment:
///   POSTGRES_USER: myuser        # mapping form
/// environment:
///   - POSTGRES_USER=myuser       # list form
/// ```
fn parse_compose_credentials(tool_path: &Path) -> Option<ComposeCredentials> {
    let compose_file = find_compose_file(tool_path)?;
    let contents = std::fs::read_to_string(&compose_file).ok()?;

    let mut creds = ComposeCredentials::default();

    // Simple line-by-line parser — handles both YAML mapping and list forms.
    // We don't need a full YAML parser for the handful of env vars we care about.
    for line in contents.lines() {
        let trimmed = line.trim();

        // Mapping form: KEY: value
        // List form:    - KEY=value
        let (key, val) = if let Some(rest) = trimmed.strip_prefix("- ") {
            // List form: - KEY=value
            if let Some((k, v)) = rest.split_once('=') {
                (k.trim(), v.trim().trim_matches('"').trim_matches('\''))
            } else {
                continue;
            }
        } else if trimmed.contains(':') && !trimmed.starts_with('#') {
            // Mapping form: KEY: value (but skip YAML structure keys like `services:`)
            if let Some((k, v)) = trimmed.split_once(':') {
                let k = k.trim();
                let v = v.trim().trim_matches('"').trim_matches('\'');
                // Only match env-var-looking keys (UPPER_SNAKE_CASE)
                if k.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                    && !v.is_empty()
                {
                    (k, v)
                } else {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        };

        match key {
            "POSTGRES_USER" => creds.postgres_user = Some(val.to_string()),
            "POSTGRES_PASSWORD" => creds.postgres_password = Some(val.to_string()),
            "POSTGRES_DB" => creds.postgres_db = Some(val.to_string()),
            "REDIS_PASSWORD" => creds.redis_password = Some(val.to_string()),
            _ => {}
        }
    }

    // Extract port mappings (e.g., "5433:5432")
    let mut in_ports = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "ports:" {
            in_ports = true;
            continue;
        }
        if in_ports {
            if trimmed.starts_with("- ") {
                let port_spec = trimmed
                    .strip_prefix("- ")
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim_matches('\'');
                if let Some((host, container)) = port_spec.split_once(':') {
                    let host_port: Option<u16> = host.parse().ok();
                    let container_port: Option<u16> = container.parse().ok();
                    match (host_port, container_port) {
                        (Some(hp), Some(5432)) => creds.postgres_port = Some(hp),
                        (Some(hp), Some(6379)) => creds.redis_port = Some(hp),
                        _ => {}
                    }
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                in_ports = false;
            }
        }
    }

    Some(creds)
}

fn find_compose_file(tool_path: &Path) -> Option<std::path::PathBuf> {
    for name in &[
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ] {
        let p = tool_path.join(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

// ── .env.example parsing ───────────────────────────────────────────────

/// Parse .env.example for declared variables and their defaults.
fn parse_env_example(tool_path: &Path) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let env_example = tool_path.join(".env.example");

    if let Ok(contents) = std::fs::read_to_string(&env_example) {
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() || !trimmed.contains('=') {
                continue;
            }
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"').trim_matches('\'');
                vars.insert(key.to_string(), val.to_string());
            }
        }
    }

    vars
}

// ── Cargo.toml parsing ────────────────────────────────────────────────

/// Dependencies from Cargo.toml that affect launch behavior.
///
/// We care about:
/// - `dotenvy` / `dotenv` — overrides shell env from .env files at runtime
/// - `sqlx` — needs DATABASE_URL at compile time for query checking
/// - `diesel` — needs DATABASE_URL for schema/migration operations
/// - `axum` / `actix-web` / `rocket` — web framework (expects port binding)
/// - `tokio` — async runtime (expected for all modern Rust web tools)
fn parse_cargo_deps(tool_path: &Path) -> Vec<String> {
    let cargo_toml = tool_path.join("Cargo.toml");
    let mut deps = Vec::new();

    if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
        let interesting = &[
            "dotenvy", "dotenv", "sqlx", "diesel", "axum", "actix-web", "rocket",
            "tokio", "warp", "tide", "poem", "tower-http",
        ];

        // Check both [dependencies] and [workspace.dependencies] sections.
        // Simple approach: if the crate name appears as a key in a TOML table, it's a dep.
        for dep_name in interesting {
            // Match patterns like: dotenvy = "0.15" or dotenvy = { version = ... }
            // Also match workspace member Cargo.tomls that reference workspace deps
            let patterns = [
                format!("{} = ", dep_name),
                format!("{} = {{", dep_name),
                format!("\"{}\"", dep_name),
            ];
            if patterns.iter().any(|p| contents.contains(p)) {
                deps.push(dep_name.to_string());
            }
        }

        // Also check workspace members' Cargo.tomls
        if contents.contains("[workspace]") {
            // This is a workspace root — check member Cargo.tomls
            if let Some(members) = extract_workspace_members(&contents) {
                for member in members {
                    let member_toml = tool_path.join(&member).join("Cargo.toml");
                    if let Ok(member_contents) = std::fs::read_to_string(&member_toml) {
                        for dep_name in interesting {
                            if !deps.contains(&dep_name.to_string()) {
                                let patterns = [
                                    format!("{} = ", dep_name),
                                    format!("{} = {{", dep_name),
                                    format!("\"{}\"", dep_name),
                                ];
                                if patterns.iter().any(|p| member_contents.contains(p)) {
                                    deps.push(dep_name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    deps
}

/// Extract workspace member paths from Cargo.toml.
fn extract_workspace_members(cargo_contents: &str) -> Option<Vec<String>> {
    // Simple extraction: find `members = [...]` and parse the entries.
    let mut members = Vec::new();
    let mut in_members = false;

    for line in cargo_contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("members") && trimmed.contains('[') {
            in_members = true;
            // Handle single-line members = ["a", "b"]
            if let Some(bracket_content) = trimmed.split('[').nth(1) {
                if let Some(inner) = bracket_content.strip_suffix(']') {
                    for entry in inner.split(',') {
                        let entry = entry.trim().trim_matches('"').trim_matches('\'');
                        if !entry.is_empty() {
                            // Handle glob patterns like "crates/*"
                            if entry.contains('*') {
                                if let Some(base) = entry.strip_suffix("/*") {
                                    let base_path = std::path::PathBuf::from(base);
                                    if let Ok(entries) = std::fs::read_dir(&base_path) {
                                        for e in entries.flatten() {
                                            if e.path().join("Cargo.toml").exists() {
                                                members.push(
                                                    e.path().display().to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                            } else {
                                members.push(entry.to_string());
                            }
                        }
                    }
                    in_members = false;
                }
            }
            continue;
        }
        if in_members {
            if trimmed.contains(']') {
                in_members = false;
            }
            let entry = trimmed
                .trim_end_matches(']')
                .trim_end_matches(',')
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if !entry.is_empty() && !entry.starts_with('#') {
                members.push(entry.to_string());
            }
        }
    }

    if members.is_empty() {
        None
    } else {
        Some(members)
    }
}

// ── Core analysis ──────────────────────────────────────────────────────

/// Run deep scan analysis on a tool directory.
///
/// This is the main entry point. It:
///   1. Classifies the tool's archetype
///   2. Parses docker-compose.yml for service credentials
///   3. Parses .env.example for declared variables
///   4. Parses Cargo.toml for behavioral dependencies
///   5. Cross-references everything to detect misconfigurations
///   6. Returns corrected env vars and findings
pub fn analyze_tool(tool_name: &str, tool_path: &Path) -> DeepScanResult {
    let mut findings = Vec::new();
    let mut corrected_env: HashMap<String, String> = HashMap::new();

    // ── 1. Classify archetype ──────────────────────────────
    let archetype = classify_archetype(tool_path);
    findings.push(ScanFinding {
        severity: FindingSeverity::Info,
        category: "archetype".into(),
        message: format!("Tool classified as: {}", archetype),
        correction: None,
    });
    info!(
        "Deep scan [{}]: archetype={}, path={}",
        tool_name,
        archetype,
        tool_path.display()
    );

    // ── 2. Parse configurations ────────────────────────────
    let compose_creds = parse_compose_credentials(tool_path);
    let env_vars = parse_env_example(tool_path);
    let cargo_deps = parse_cargo_deps(tool_path);

    // ── 3. dotenvy detection ───────────────────────────────
    if cargo_deps.contains(&"dotenvy".to_string()) || cargo_deps.contains(&"dotenv".to_string()) {
        let dep_name = if cargo_deps.contains(&"dotenvy".to_string()) {
            "dotenvy"
        } else {
            "dotenv"
        };
        findings.push(ScanFinding {
            severity: FindingSeverity::Warning,
            category: "env_override".into(),
            message: format!(
                "Cargo dependency '{}' detected — this crate loads .env files at \
                 runtime, potentially overriding shell environment variables. \
                 Port and auth vars MUST be injected via cmd.env() to prevent \
                 shadow conflicts.",
                dep_name
            ),
            correction: None,
        });
        warn!(
            "Deep scan [{}]: {} dependency detected — shell env may be overridden",
            tool_name, dep_name
        );
    }

    // ── 4. DATABASE_URL cross-reference ────────────────────
    if let Some(ref creds) = compose_creds {
        if let Some(declared_url) = env_vars.get("DATABASE_URL") {
            let corrected = build_database_url(creds, declared_url);
            if let Some(ref corrected_url) = corrected {
                if corrected_url != declared_url {
                    findings.push(ScanFinding {
                        severity: FindingSeverity::Warning,
                        category: "database_url".into(),
                        message: format!(
                            "DATABASE_URL in .env.example ({}) doesn't match docker-compose \
                             credentials (user={}, pass={}, db={}). Corrected.",
                            redact_url(declared_url),
                            creds.postgres_user.as_deref().unwrap_or("?"),
                            if creds.postgres_password.is_some() {
                                "***"
                            } else {
                                "?"
                            },
                            creds.postgres_db.as_deref().unwrap_or("?"),
                        ),
                        correction: Some(EnvCorrection {
                            key: "DATABASE_URL".into(),
                            value: corrected_url.clone(),
                            reason: "Aligned with docker-compose credentials".into(),
                        }),
                    });
                    corrected_env.insert("DATABASE_URL".into(), corrected_url.clone());
                    info!(
                        "Deep scan [{}]: corrected DATABASE_URL to match compose credentials",
                        tool_name
                    );
                } else {
                    findings.push(ScanFinding {
                        severity: FindingSeverity::Info,
                        category: "database_url".into(),
                        message: "DATABASE_URL matches docker-compose credentials".into(),
                        correction: None,
                    });
                }
            }
        }

        // Also check for DATABASE_URL when sqlx/diesel is present but no URL declared
        if !env_vars.contains_key("DATABASE_URL")
            && (cargo_deps.contains(&"sqlx".to_string())
                || cargo_deps.contains(&"diesel".to_string()))
        {
            let user = creds.postgres_user.as_deref().unwrap_or("postgres");
            let pass = creds.postgres_password.as_deref().unwrap_or("postgres");
            let db = creds
                .postgres_db
                .as_deref()
                .unwrap_or(tool_name);
            let port = creds.postgres_port.unwrap_or(5432);

            let url = format!("postgres://{}:{}@localhost:{}/{}", user, pass, port, db);
            findings.push(ScanFinding {
                severity: FindingSeverity::Warning,
                category: "database_url".into(),
                message: format!(
                    "sqlx/diesel dependency found but no DATABASE_URL in .env.example. \
                     Synthesized from docker-compose: {}",
                    redact_url(&url)
                ),
                correction: Some(EnvCorrection {
                    key: "DATABASE_URL".into(),
                    value: url.clone(),
                    reason: "Synthesized from docker-compose credentials".into(),
                }),
            });
            corrected_env.insert("DATABASE_URL".into(), url);
        }
    }

    // ── 5. Port conflict pre-detection ─────────────────────
    // Check if the tool declares a port that's commonly in use
    let common_conflict_ports = [3000_u16, 8080, 8000, 5000, 4000];
    for port_var in &[
        "PORT",
        "HTTP_PORT",
        "APP_PORT",
        "SERVER_PORT",
        "GATEWAY_PORT",
    ] {
        if let Some(val) = env_vars.get(*port_var) {
            if let Ok(port) = val.parse::<u16>() {
                if common_conflict_ports.contains(&port) {
                    findings.push(ScanFinding {
                        severity: FindingSeverity::Info,
                        category: "port_conflict_risk".into(),
                        message: format!(
                            "{}={} is a commonly used port — ZP port allocator will \
                             override this via .env.zp to prevent conflicts.",
                            port_var, port
                        ),
                        correction: None,
                    });
                }
            }
        }
    }

    // ── 6. Missing critical env vars ───────────────────────
    // Check if .env.example declares vars that look like they need real values
    // but have obviously placeholder defaults
    let placeholder_patterns = &[
        "your-", "xxx", "sk-...", "xoxb-...", "change-me", "replace-",
        "TODO", "FIXME", "...",
    ];
    for (key, val) in &env_vars {
        let lower_val = val.to_lowercase();
        if placeholder_patterns
            .iter()
            .any(|p| lower_val.contains(&p.to_lowercase()))
        {
            // Skip if this is in a comment-like context (value starts with #)
            if val.starts_with('#') {
                continue;
            }
            findings.push(ScanFinding {
                severity: FindingSeverity::Info,
                category: "placeholder_value".into(),
                message: format!(
                    "{}={} looks like a placeholder — will need real value from vault or operator",
                    key, val
                ),
                correction: None,
            });
        }
    }

    // ── 7. Pool size sanity ────────────────────────────────
    if let Some(pool_size) = env_vars.get("DATABASE_POOL_SIZE") {
        if let Ok(size) = pool_size.parse::<u32>() {
            if size > 20 {
                findings.push(ScanFinding {
                    severity: FindingSeverity::Warning,
                    category: "pool_size".into(),
                    message: format!(
                        "DATABASE_POOL_SIZE={} is high for a dev environment. \
                         Consider 5-10 for local development.",
                        size
                    ),
                    correction: None,
                });
            }
        }
    }

    debug!(
        "Deep scan [{}]: {} findings, {} corrections, {} cargo deps",
        tool_name,
        findings.len(),
        corrected_env.len(),
        cargo_deps.len()
    );

    DeepScanResult {
        archetype,
        findings,
        corrected_env,
        cargo_deps,
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn classify_archetype(tool_path: &Path) -> ToolArchetype {
    if tool_path.join("Cargo.toml").exists() {
        ToolArchetype::RustNative
    } else if tool_path.join("package.json").exists() {
        ToolArchetype::NodeJs
    } else if tool_path.join("pyproject.toml").exists()
        || tool_path.join("requirements.txt").exists()
        || tool_path.join("setup.py").exists()
    {
        ToolArchetype::Python
    } else if find_compose_file(tool_path).is_some() {
        ToolArchetype::DockerOnly
    } else {
        ToolArchetype::Unknown
    }
}

/// Build a corrected DATABASE_URL from compose credentials.
///
/// Parses the existing URL to extract scheme/host/path structure, then
/// replaces user/password/db/port with compose-derived values.
fn build_database_url(creds: &ComposeCredentials, existing_url: &str) -> Option<String> {
    // Parse existing URL to get structure
    // postgres://user:pass@host:port/dbname
    let scheme = if existing_url.starts_with("postgres://") {
        "postgres"
    } else if existing_url.starts_with("postgresql://") {
        "postgresql"
    } else {
        return None; // Not a postgres URL
    };

    let user = creds.postgres_user.as_deref().unwrap_or("postgres");
    let pass = creds.postgres_password.as_deref().unwrap_or("postgres");
    let port = creds.postgres_port.unwrap_or(5432);

    // Determine host — usually localhost for dev
    let host = "localhost";

    // Determine database name
    let db = creds.postgres_db.as_deref().unwrap_or_else(|| {
        // Try to extract from existing URL
        existing_url
            .rsplit('/')
            .next()
            .unwrap_or("postgres")
    });

    Some(format!(
        "{}://{}:{}@{}:{}/{}",
        scheme, user, pass, host, port, db
    ))
}

/// Redact password from a database URL for safe logging.
fn redact_url(url: &str) -> String {
    // Replace password portion: postgres://user:PASSWORD@... → postgres://user:***@...
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            // Find the scheme separator
            if let Some(scheme_end) = url.find("://") {
                if colon_pos > scheme_end + 3 {
                    return format!("{}***{}", &url[..colon_pos + 1], &url[at_pos..]);
                }
            }
        }
    }
    url.to_string()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_classify_archetype_rust() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
        assert_eq!(classify_archetype(dir.path()), ToolArchetype::RustNative);
    }

    #[test]
    fn test_classify_archetype_node() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(classify_archetype(dir.path()), ToolArchetype::NodeJs);
    }

    #[test]
    fn test_classify_archetype_python() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("requirements.txt"), "flask\n").unwrap();
        assert_eq!(classify_archetype(dir.path()), ToolArchetype::Python);
    }

    #[test]
    fn test_redact_url() {
        assert_eq!(
            redact_url("postgres://user:secret@localhost/db"),
            "postgres://user:***@localhost/db"
        );
        assert_eq!(
            redact_url("postgres://localhost/db"),
            "postgres://localhost/db"
        );
    }

    #[test]
    fn test_build_database_url() {
        let creds = ComposeCredentials {
            postgres_user: Some("myuser".into()),
            postgres_password: Some("mypass".into()),
            postgres_db: Some("mydb".into()),
            postgres_port: Some(5433),
            redis_password: None,
            redis_port: None,
        };
        let result =
            build_database_url(&creds, "postgres://localhost/old_db").unwrap();
        assert_eq!(result, "postgres://myuser:mypass@localhost:5433/mydb");
    }

    #[test]
    fn test_build_database_url_defaults() {
        let creds = ComposeCredentials::default();
        let result =
            build_database_url(&creds, "postgres://localhost/testdb").unwrap();
        assert_eq!(result, "postgres://postgres:postgres@localhost:5432/testdb");
    }

    #[test]
    fn test_parse_env_example() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".env.example"),
            "# Database\nDATABASE_URL=postgres://localhost/test\nPORT=8080\n# Comment\n",
        )
        .unwrap();

        let vars = parse_env_example(dir.path());
        assert_eq!(vars.get("DATABASE_URL").unwrap(), "postgres://localhost/test");
        assert_eq!(vars.get("PORT").unwrap(), "8080");
        assert!(vars.get("Comment").is_none());
    }

    #[test]
    fn test_dotenvy_detection() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n\n[dependencies]\ndotenvy = \"0.15\"\naxum = \"0.7\"\n",
        )
        .unwrap();

        let deps = parse_cargo_deps(dir.path());
        assert!(deps.contains(&"dotenvy".to_string()));
        assert!(deps.contains(&"axum".to_string()));
    }

    #[test]
    fn test_analyze_tool_with_mismatch() {
        let dir = TempDir::new().unwrap();

        // Create Cargo.toml with dotenvy
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n\n[dependencies]\ndotenvy = \"0.15\"\nsqlx = { version = \"0.7\" }\n",
        )
        .unwrap();

        // Create docker-compose.yml with credentials
        fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_USER: myapp\n      POSTGRES_PASSWORD: secret123\n      POSTGRES_DB: myapp_dev\n    ports:\n      - \"5433:5432\"\n",
        )
        .unwrap();

        // Create .env.example with wrong DATABASE_URL
        fs::write(
            dir.path().join(".env.example"),
            "DATABASE_URL=postgres://localhost/myapp_dev\nHTTP_PORT=8080\n",
        )
        .unwrap();

        let result = analyze_tool("test-tool", dir.path());

        assert_eq!(result.archetype, ToolArchetype::RustNative);
        assert!(result.cargo_deps.contains(&"dotenvy".to_string()));
        assert!(result.corrected_env.contains_key("DATABASE_URL"));

        let corrected = result.corrected_env.get("DATABASE_URL").unwrap();
        assert!(corrected.contains("myapp"));
        assert!(corrected.contains("secret123"));
        assert!(corrected.contains("5433"));
    }
}
