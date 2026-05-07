//! Discipline: tool-launch code MUST NOT use `Command::new("sh")` /
//! `Command::new("bash")` patterns chained with `.arg("-c")`.
//!
//! # Why (Seam 9a)
//!
//! The cockpit launch endpoint historically built shell-interpreted
//! command strings — `let logged_cmd = format!("{{ {} ; }} > '{}' 2>&1",
//! preamble + start_cmd, log_path)` — and handed them to
//! `Command::new("sh").arg("-c").arg(&logged_cmd)`. The `start_cmd`
//! flowed from project-config files (`package.json` `scripts.start`,
//! docker-compose service commands, detected `start.sh`) which are
//! NOT ZP-controlled. A malicious tool could put `innocuous && evil`
//! in its config and the shell would execute the evil part.
//!
//! Seam 9a (May 2026) closed the launch site by introducing
//! `crate::tool_launch::ToolSpec`, which:
//!
//! - Parses the start command with shlex (POSIX word-splitting,
//!   no execution semantics).
//! - Refuses any input containing shell metacharacters that imply
//!   multi-command flow (`;`, `&&`, `||`, `|`, `$(...)`, backticks,
//!   redirection, newline).
//! - Spawns argv-form: `Command::new(argv[0]).args(&argv[1..])`.
//! - Replaces shell-sourced `.env` files with the
//!   `load_dotenv_layered` helper (Rust-side parser).
//! - Replaces shell `>` redirection with `Stdio::from(file_handle)`.
//!
//! This pin keeps future drift from re-introducing
//! `Command::new("sh").arg("-c")` patterns into the tool-launch
//! surface. The pattern is restricted to `crates/zp-server/src/`
//! because that's where tool-launch endpoints live; legitimate
//! `sh -c` uses elsewhere (e.g. one-off install scripts during
//! tests, OS-level sandbox setup) are not in scope for this pin.
//!
//! # Pattern
//!
//! Forbids the joint occurrence of `Command::new("sh")` (or `bash`,
//! or absolute-path variants) with `.arg("-c")`. Each is forbidden
//! individually because a single-line check is enough — most code
//! that passes `-c` to a shell does so on the same or adjacent
//! line as the `Command::new`.
//!
//! # Allowlist
//!
//! - `crates/zp-server/src/tool_launch.rs` and its docs may mention
//!   the forbidden pattern in prose explaining the rule. The
//!   `skip_lines_containing("//")` filter handles those.
//! - `forbid_pattern` declarations in this file are skipped via
//!   `skip_lines_containing("forbid_pattern")`.

use zp_discipline::Discipline;

#[test]
fn tool_launch_must_not_use_shell_interpretation() {
    Discipline::new("no_sh_c_in_tool_launch")
        .cite_invariant("Seam 9a — argv-form tool launch (no sh -c)")
        .rationale(
            "Tool-launch code path must use argv-form (Command::new + \
             .args) via the ToolSpec carrier in tool_launch.rs. \
             Shell-interpreted launch (Command::new(shell).arg(-c)) \
             accepts attacker-influenced input from project configs \
             and re-introduces the multi-command injection class \
             this seam was built to close.",
        )
        // Match Command::new with the common shell program names. The
        // closing paren is included so foo_sh_helper isn't matched.
        .forbid_pattern(r#"Command::new\(\s*"sh"\s*\)"#)
        .forbid_pattern(r#"Command::new\(\s*"/bin/sh"\s*\)"#)
        .forbid_pattern(r#"Command::new\(\s*"bash"\s*\)"#)
        .forbid_pattern(r#"Command::new\(\s*"/bin/bash"\s*\)"#)
        // Match the .arg("-c") pattern. This catches the case where
        // someone constructs the shell command with a variable shell
        // path (e.g. via SHELL env var).
        .forbid_pattern(r#"\.arg\(\s*"-c"\s*\)"#)
        // Restrict the scan to zp-server. Other crates (CLI, install
        // scripts, etc.) may legitimately invoke `sh -c` outside the
        // tool-launch surface. If those grow, narrow this restriction
        // further (e.g. to `crates/zp-server/src/tool_*.rs` only)
        // rather than broadening the pin.
        .restrict_to_paths(&["crates/zp-server/src/"])
        // Skip comments — module-level prose mentions the forbidden
        // forms when explaining why they're forbidden.
        .skip_lines_containing("//")
        // Skip pin-declaration lines.
        .skip_lines_containing("forbid_pattern")
        .assert();
}
