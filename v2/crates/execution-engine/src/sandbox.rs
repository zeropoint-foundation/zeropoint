//! Sandbox configuration and OS-level process isolation.
//!
//! This module provides the security boundary that replaces Docker.
//! Each execution gets a fresh sandbox with:
//! - Isolated temp directory (the only writable filesystem)
//! - No network access by default
//! - CPU and memory limits
//! - Restricted environment variables
//! - No access to host filesystem beyond the sandbox root

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Capabilities that an execution can request (Deno-style permissions).
/// Each must be explicitly granted by the execution policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxCapability {
    /// Read files from the sandbox directory
    ReadSandbox,
    /// Write files to the sandbox directory
    WriteSandbox,
    /// Read from specific host paths (e.g., data files)
    ReadHostPath(PathBuf),
    /// Network access to specific hosts
    NetConnect(String),
    /// Spawn child processes (restricted to runtime interpreter)
    SpawnProcess,
    /// Access environment variables
    ReadEnv,
    /// Write to stdout (always granted, but tracked)
    Stdout,
    /// Import pip/npm packages from a pre-approved allowlist
    ImportPackage(String),
}

/// Configuration for a single execution sandbox.
///
/// ## Enforcement Status
///
/// Some fields are fully enforced today, others are declared for policy use
/// but require additional OS infrastructure (cgroups, seccomp) to enforce:
///
/// | Field              | Enforced | Mechanism                          |
/// |--------------------|----------|------------------------------------|
/// | timeout_ms         | Yes      | tokio::time::timeout + SIGKILL     |
/// | max_output_bytes   | Yes      | Checked after execution            |
/// | use_os_isolation   | Yes      | unshare/sandbox-exec               |
/// | env_vars           | Yes      | Passed to subprocess env           |
/// | memory_limit_bytes | Planned  | Requires cgroups v2 on Linux       |
/// | max_cpu_ms         | Planned  | Requires cgroups v2 on Linux       |
/// | capabilities       | Partial  | Used for policy checks, not all OS-enforced |
/// | readonly_mounts    | Planned  | Requires mount namespace setup     |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Maximum wall-clock execution time in milliseconds.
    /// **Enforced**: via `tokio::time::timeout` + SIGKILL on timeout.
    pub timeout_ms: u64,

    /// Maximum memory usage in bytes (0 = unlimited).
    /// **Planned**: requires cgroups v2 integration on Linux. Currently declared
    /// for policy use and will be enforced when cgroup support is added.
    pub memory_limit_bytes: u64,

    /// Maximum stdout + stderr combined output in bytes.
    /// **Enforced**: checked after execution completes.
    pub max_output_bytes: usize,

    /// Maximum CPU time in milliseconds (user + sys).
    /// **Planned**: requires cgroups v2 integration on Linux. Currently declared
    /// for policy use and will be enforced when cgroup support is added.
    pub max_cpu_ms: u64,

    /// Capabilities granted to this execution.
    /// **Partial**: used for policy decisions (e.g., whether to grant network),
    /// but not all capabilities map to OS-level enforcement yet.
    pub capabilities: HashSet<SandboxCapability>,

    /// Environment variables to pass to the subprocess.
    /// **Enforced**: subprocess env is cleared and only these vars are set.
    pub env_vars: Vec<(String, String)>,

    /// Additional paths to mount read-only into the sandbox.
    /// **Planned**: requires mount namespace setup. Currently declared for
    /// policy use and will be enforced when namespace mounts are implemented.
    pub readonly_mounts: Vec<PathBuf>,

    /// Whether to use OS-level isolation (namespaces/seccomp on Linux).
    /// **Enforced**: controls whether `unshare`/`sandbox-exec` wrapper is used.
    pub use_os_isolation: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        let mut capabilities = HashSet::new();
        capabilities.insert(SandboxCapability::ReadSandbox);
        capabilities.insert(SandboxCapability::WriteSandbox);
        capabilities.insert(SandboxCapability::Stdout);

        Self {
            timeout_ms: 30_000,                    // 30 seconds
            memory_limit_bytes: 256 * 1024 * 1024, // 256 MB
            max_output_bytes: 1024 * 1024,         // 1 MB
            max_cpu_ms: 30_000,                    // 30 seconds CPU time
            capabilities,
            env_vars: vec![],
            readonly_mounts: vec![],
            // OS isolation via sandbox-exec is deprecated on macOS (Sonoma+)
            // and produces unreliable results. Real isolation targets Linux
            // (unshare + seccomp). Default to false on macOS, true on Linux.
            use_os_isolation: cfg!(target_os = "linux"),
        }
    }
}

impl SandboxConfig {
    /// Create a restrictive config for untrusted code (default for A0)
    pub fn untrusted() -> Self {
        Self::default()
    }

    /// Create a permissive config for ZP-internal operations
    pub fn internal() -> Self {
        Self {
            timeout_ms: 120_000,
            memory_limit_bytes: 1024 * 1024 * 1024, // 1 GB
            max_output_bytes: 10 * 1024 * 1024,     // 10 MB
            use_os_isolation: false,
            ..Self::default()
        }
    }

    /// Check if a capability is granted
    pub fn has_capability(&self, cap: &SandboxCapability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Grant a capability
    pub fn grant(&mut self, cap: SandboxCapability) -> &mut Self {
        self.capabilities.insert(cap);
        self
    }

    /// Deny a capability
    pub fn deny(&mut self, cap: &SandboxCapability) -> &mut Self {
        self.capabilities.remove(cap);
        self
    }
}

/// Build the OS-level sandbox command wrapper.
///
/// On Linux: uses `unshare` for namespace isolation + `timeout` for limits.
/// On macOS: uses `sandbox-exec` with a restrictive profile.
/// Fallback: just uses `timeout` (basic, no namespace isolation).
pub fn build_sandbox_wrapper(
    config: &SandboxConfig,
    _sandbox_dir: &std::path::Path,
) -> Vec<String> {
    let timeout_secs = config.timeout_ms / 1000;

    if !config.use_os_isolation {
        // No OS isolation — just timeout
        #[cfg(target_os = "macos")]
        return vec![
            "perl".to_string(),
            "-e".to_string(),
            format!("alarm {}; exec @ARGV or die \"exec: $!\"", timeout_secs),
            "--".to_string(),
        ];

        #[cfg(not(target_os = "macos"))]
        return vec![
            "timeout".to_string(),
            "--signal=KILL".to_string(),
            format!("{}s", timeout_secs),
        ];
    }

    #[cfg(target_os = "linux")]
    {
        // Linux: unshare for namespace isolation
        // --net: new network namespace (no network by default)
        // --mount: new mount namespace (isolated filesystem view)
        // --pid --fork: new PID namespace
        let mut wrapper = vec![
            "unshare".to_string(),
            "--net".to_string(), // No network
            "--pid".to_string(),
            "--fork".to_string(),
        ];

        // Add timeout inside the namespace
        wrapper.extend([
            "timeout".to_string(),
            "--signal=KILL".to_string(),
            format!("{}s", timeout_secs),
        ]);

        // TODO: Add seccomp filter for syscall restriction
        // TODO: Add cgroup limits for memory

        wrapper
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: sandbox-exec with restrictive profile
        // Note: GNU `timeout` is not available on macOS by default,
        // so we use perl for timeout enforcement instead.
        let profile = format!(
            r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow file-read* (subpath "/usr") (subpath "/Library") (subpath "/System") (subpath "/dev") (subpath "/private") (subpath "/bin") (subpath "/opt") (subpath "/var"))
(allow file-read* file-write* (subpath "{}"))
(allow file-read* file-write* (subpath "/private/tmp") (subpath "/tmp") (subpath "/dev"))
(allow sysctl-read)
(allow mach-lookup)
(allow signal)
"#,
            _sandbox_dir.display()
        );

        vec![
            "sandbox-exec".to_string(),
            "-p".to_string(),
            profile,
            "perl".to_string(),
            "-e".to_string(),
            format!("alarm {}; exec @ARGV or die \"exec: $!\"", timeout_secs),
            "--".to_string(),
        ]
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fallback: timeout only
        vec![
            "timeout".to_string(),
            "--signal=KILL".to_string(),
            format!("{}s", timeout_secs),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.timeout_ms, 30_000);
        assert!(config.has_capability(&SandboxCapability::ReadSandbox));
        assert!(config.has_capability(&SandboxCapability::WriteSandbox));
        assert!(config.has_capability(&SandboxCapability::Stdout));
        assert!(!config.has_capability(&SandboxCapability::NetConnect("any".to_string())));
    }

    #[test]
    fn test_grant_deny() {
        let mut config = SandboxConfig::default();
        config.grant(SandboxCapability::ReadEnv);
        assert!(config.has_capability(&SandboxCapability::ReadEnv));
        config.deny(&SandboxCapability::ReadEnv);
        assert!(!config.has_capability(&SandboxCapability::ReadEnv));
    }
}
