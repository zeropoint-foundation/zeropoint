//! Runtime executors — one per language (Python, Node.js, Shell).
//!
//! Each executor knows how to:
//! 1. Detect if its runtime is installed
//! 2. Set up a sandboxed execution environment
//! 3. Run code and capture output
//! 4. Report resource usage

use crate::error::{ExecutionError, ExecutionResult};
use crate::sandbox::SandboxConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Supported execution runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    Python,
    #[serde(alias = "node", alias = "javascript")]
    NodeJs,
    #[serde(alias = "bash", alias = "sh", alias = "zsh", alias = "terminal")]
    Shell,
}

impl Runtime {
    /// Canonical string identifier
    pub fn as_str(&self) -> &'static str {
        match self {
            Runtime::Python => "python",
            Runtime::NodeJs => "nodejs",
            Runtime::Shell => "shell",
        }
    }

    /// Parse from a string, with alias support (matching the shim's runtime field)
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "python" | "python3" => Some(Runtime::Python),
            "nodejs" | "node" | "javascript" => Some(Runtime::NodeJs),
            "shell" | "bash" | "sh" | "zsh" | "terminal" => Some(Runtime::Shell),
            _ => None,
        }
    }

    /// Default file extension for this runtime
    pub fn extension(&self) -> &'static str {
        match self {
            Runtime::Python => "py",
            Runtime::NodeJs => "js",
            Runtime::Shell => "sh",
        }
    }
}

/// Result of a single code execution
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub wall_ms: u64,
    pub timed_out: bool,
}

/// Detect available runtimes on the host system.
///
/// Returns a Vec of (Runtime, version_string, binary_path) for each detected runtime.
/// Errors during detection are logged via tracing rather than silently ignored,
/// so operators can diagnose missing runtimes from logs.
pub async fn detect_runtimes() -> Vec<(Runtime, String, PathBuf)> {
    let mut found = Vec::new();

    for (runtime, candidates) in [
        (Runtime::Python, vec!["python3", "python"]),
        (Runtime::NodeJs, vec!["node"]),
        (Runtime::Shell, vec!["bash", "sh"]),
    ] {
        let mut detected = false;
        for cmd in &candidates {
            match tokio::process::Command::new("which")
                .arg(cmd)
                .output()
                .await
            {
                Ok(output) if output.status.success() => {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    // Get version
                    let version_flag = match runtime {
                        Runtime::Python => "--version",
                        Runtime::NodeJs => "--version",
                        Runtime::Shell => "--version",
                    };
                    let version = match tokio::process::Command::new(cmd)
                        .arg(version_flag)
                        .output()
                        .await
                    {
                        Ok(o) => {
                            let out = String::from_utf8_lossy(&o.stdout);
                            let err = String::from_utf8_lossy(&o.stderr);
                            // Python prints to stderr on some systems
                            let combined = if out.trim().is_empty() { err } else { out };
                            combined
                                .trim()
                                .lines()
                                .next()
                                .unwrap_or("unknown")
                                .to_string()
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Runtime {} found at {} but version check failed: {}",
                                runtime.as_str(),
                                path,
                                e
                            );
                            "unknown".to_string()
                        }
                    };

                    found.push((runtime, version, PathBuf::from(path)));
                    detected = true;
                    break; // Use the first found candidate for each runtime
                }
                Ok(_) => {
                    // `which` ran but didn't find the binary — not an error, try next candidate
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to run `which {}` for runtime {}: {}",
                        cmd,
                        runtime.as_str(),
                        e
                    );
                }
            }
        }
        if !detected {
            tracing::info!(
                "Runtime {} not detected on this host (checked candidates: {:?})",
                runtime.as_str(),
                candidates
            );
        }
    }

    found
}

/// Execute code in a sandboxed subprocess.
///
/// This is the core execution function. It:
/// 1. Creates a temp directory as the sandbox root
/// 2. Writes the code to a file in the sandbox
/// 3. Builds the sandbox command wrapper (OS isolation)
/// 4. Spawns the process with restricted env
/// 5. Captures stdout/stderr with output limits
/// 6. Enforces timeout via tokio::time::timeout
/// 7. Returns ExecOutput with timing
pub async fn execute_sandboxed(
    runtime: Runtime,
    code: &str,
    sandbox_dir: &Path,
    interpreter_path: &Path,
    config: &SandboxConfig,
) -> ExecutionResult<ExecOutput> {
    let start = Instant::now();

    // Write code to a file in the sandbox
    let code_file = sandbox_dir.join(format!("exec.{}", runtime.extension()));
    tokio::fs::write(&code_file, code).await?;

    // Build the command
    let sandbox_wrapper = crate::sandbox::build_sandbox_wrapper(config, sandbox_dir);

    let mut cmd = tokio::process::Command::new(if sandbox_wrapper.is_empty() {
        interpreter_path.to_string_lossy().to_string()
    } else {
        sandbox_wrapper[0].clone()
    });

    // Add sandbox wrapper args
    if !sandbox_wrapper.is_empty() {
        for arg in &sandbox_wrapper[1..] {
            cmd.arg(arg);
        }
        cmd.arg(interpreter_path);
    }

    // Runtime-specific args
    match runtime {
        Runtime::Python => {
            cmd.arg("-u"); // Unbuffered
            cmd.arg(&code_file);
        }
        Runtime::NodeJs => {
            cmd.arg("--max-old-space-size=256"); // Limit V8 heap
            cmd.arg(&code_file);
        }
        Runtime::Shell => {
            cmd.arg(&code_file);
        }
    }

    // Restricted environment
    cmd.env_clear();
    cmd.env("HOME", sandbox_dir);
    cmd.env("TMPDIR", sandbox_dir);
    cmd.env("PATH", minimal_path());
    cmd.env("LANG", "en_US.UTF-8");

    // Add any policy-granted env vars
    for (key, value) in &config.env_vars {
        cmd.env(key, value);
    }

    // Working directory is the sandbox
    cmd.current_dir(sandbox_dir);

    // Pipe everything
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    // Spawn
    let mut child = cmd.spawn().map_err(|e| {
        ExecutionError::SpawnFailed(format!(
            "Failed to spawn {} at {}: {}",
            runtime.as_str(),
            interpreter_path.display(),
            e
        ))
    })?;

    // Take stdout/stderr handles before waiting so we can still kill on timeout.
    // `wait_with_output()` consumes `child`, preventing a later `kill()`.
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let timeout = tokio::time::Duration::from_millis(config.timeout_ms);
    let result = tokio::time::timeout(timeout, child.wait()).await;

    let wall_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(status)) => {
            // Read captured output from the pipes
            use tokio::io::AsyncReadExt;
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            if let Some(mut out) = child_stdout {
                let _ = out.read_to_end(&mut stdout_buf).await;
            }
            if let Some(mut err) = child_stderr {
                let _ = err.read_to_end(&mut stderr_buf).await;
            }

            let stdout = String::from_utf8_lossy(&stdout_buf);
            let stderr = String::from_utf8_lossy(&stderr_buf);

            // Check output limits
            if stdout.len() + stderr.len() > config.max_output_bytes {
                return Err(ExecutionError::OutputLimitExceeded(
                    stdout.len() + stderr.len(),
                    config.max_output_bytes,
                ));
            }

            Ok(ExecOutput {
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
                exit_code: status.code().unwrap_or(-1),
                wall_ms,
                timed_out: false,
            })
        }
        Ok(Err(e)) => Err(ExecutionError::IoError(e)),
        Err(_) => {
            // Timeout — kill the process (child is still alive since wait() doesn't consume it)
            let _ = child.kill().await;
            Err(ExecutionError::Timeout(config.timeout_ms))
        }
    }
}

/// Minimal PATH for sandboxed execution — only essential runtime dirs.
fn minimal_path() -> String {
    if cfg!(target_os = "macos") {
        // Include Homebrew paths for Apple Silicon (/opt/homebrew) and Intel (/usr/local)
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin".to_string()
    } else {
        "/usr/local/bin:/usr/bin:/bin".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_from_str_loose() {
        assert_eq!(Runtime::from_str_loose("python"), Some(Runtime::Python));
        assert_eq!(Runtime::from_str_loose("python3"), Some(Runtime::Python));
        assert_eq!(Runtime::from_str_loose("node"), Some(Runtime::NodeJs));
        assert_eq!(Runtime::from_str_loose("nodejs"), Some(Runtime::NodeJs));
        assert_eq!(Runtime::from_str_loose("javascript"), Some(Runtime::NodeJs));
        assert_eq!(Runtime::from_str_loose("bash"), Some(Runtime::Shell));
        assert_eq!(Runtime::from_str_loose("terminal"), Some(Runtime::Shell));
        assert_eq!(Runtime::from_str_loose("lua"), None);
    }

    #[test]
    fn test_runtime_extension() {
        assert_eq!(Runtime::Python.extension(), "py");
        assert_eq!(Runtime::NodeJs.extension(), "js");
        assert_eq!(Runtime::Shell.extension(), "sh");
    }
}
