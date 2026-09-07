//! Process context enrichment for human-readable process identification.
//!
//! When the sensor layer discovers an unknown listener, a PID and port
//! alone are meaningless to the operator. This module gathers rich
//! process metadata — binary path, command line, owning user, parent
//! process, start time — so that officers and cockpits can present
//! actionable information.
//!
//! Platform-specific: full enrichment on macOS via `proc_pidpath()`,
//! `sysctl KERN_PROCARGS2`, and `proc_bsdinfo`. Graceful degradation
//! on other platforms (fields become `None`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Enriched process metadata gathered at sensor discovery time.
///
/// Every field except `pid` and `name` is best-effort — the process may
/// have exited between discovery and enrichment, or the system call may
/// fail for permission reasons. Officers and cockpits should handle
/// `None` gracefully.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    /// Process ID.
    pub pid: u32,
    /// Process name (from the `listeners` crate or `proc_name`).
    pub name: String,
    /// Full path to the executable binary.
    pub binary_path: Option<String>,
    /// Full command line (executable + arguments).
    pub command_line: Option<String>,
    /// Username of the process owner.
    pub user: Option<String>,
    /// Parent process ID.
    pub parent_pid: Option<u32>,
    /// Parent process name (resolved from parent_pid).
    pub parent_name: Option<String>,
    /// When the process started (if available from system APIs).
    pub started_at: Option<DateTime<Utc>>,
}

impl ProcessContext {
    /// Create a minimal context with only pid and name.
    /// Used as fallback when enrichment fails entirely.
    pub fn minimal(pid: u32, name: String) -> Self {
        Self {
            pid,
            name,
            binary_path: None,
            command_line: None,
            user: None,
            parent_pid: None,
            parent_name: None,
            started_at: None,
        }
    }

    /// Human-readable one-line summary for cockpit display.
    pub fn display_summary(&self) -> String {
        let identity = self.binary_path.as_deref().unwrap_or(&self.name);
        let user_part = self
            .user
            .as_deref()
            .map(|u| format!(" (user: {u})"))
            .unwrap_or_default();
        let parent_part = self
            .parent_name
            .as_deref()
            .map(|p| format!(" via {p}"))
            .unwrap_or_default();
        format!(
            "{identity}{user_part}{parent_part} [pid {pid}]",
            pid = self.pid
        )
    }
}

/// Gather enriched process context for a given PID.
///
/// Best-effort: each field is gathered independently, so partial
/// enrichment is the norm rather than the exception. If the process
/// has already exited, returns `ProcessContext::minimal`.
pub fn gather_process_context(pid: u32, process_name: &str) -> ProcessContext {
    let mut ctx = ProcessContext::minimal(pid, process_name.to_string());

    #[cfg(target_os = "macos")]
    {
        macos::enrich(&mut ctx);
    }

    #[cfg(target_os = "linux")]
    {
        linux::enrich(&mut ctx);
    }

    ctx
}

// ── macOS implementation ────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos {
    use super::ProcessContext;
    use chrono::{DateTime, Utc};
    use tracing::trace;

    /// Maximum path length for proc_pidpath.
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
    }

    /// Enrich a ProcessContext with macOS-specific system calls.
    pub(super) fn enrich(ctx: &mut ProcessContext) {
        let pid = ctx.pid as i32;

        // Binary path via proc_pidpath()
        if let Some(path) = get_binary_path(pid) {
            ctx.binary_path = Some(path);
        }

        // Command line via sysctl KERN_PROCARGS2
        if let Some(cmdline) = get_command_line(pid) {
            ctx.command_line = Some(cmdline);
        }

        // Parent PID, UID, start time via sysctl KERN_PROC
        if let Some(info) = get_proc_info(pid) {
            ctx.parent_pid = Some(info.ppid);
            ctx.user = resolve_username(info.uid);
            ctx.started_at = info.start_time;

            // Resolve parent name
            if info.ppid > 0 {
                if let Some(parent_path) = get_binary_path(info.ppid as i32) {
                    ctx.parent_name = Some(
                        parent_path
                            .rsplit('/')
                            .next()
                            .unwrap_or(&parent_path)
                            .to_string(),
                    );
                }
            }
        }

        trace!(
            pid = ctx.pid,
            binary = ?ctx.binary_path,
            user = ?ctx.user,
            parent = ?ctx.parent_name,
            "process context enriched"
        );
    }

    fn get_binary_path(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
        let ret = unsafe { proc_pidpath(pid, buf.as_mut_ptr(), buf.len() as u32) };
        if ret > 0 {
            buf.truncate(ret as usize);
            String::from_utf8(buf).ok()
        } else {
            None
        }
    }

    fn get_command_line(pid: i32) -> Option<String> {
        use std::mem;

        let mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];

        // First call: get buffer size
        let mut size: libc::size_t = 0;
        let ret = unsafe {
            libc::sysctl(
                mib.as_ptr() as *mut _,
                3,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 || size == 0 {
            return None;
        }

        // Second call: get the data
        let mut buf = vec![0u8; size];
        let ret = unsafe {
            libc::sysctl(
                mib.as_ptr() as *mut _,
                3,
                buf.as_mut_ptr() as *mut _,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 {
            return None;
        }
        buf.truncate(size);

        // KERN_PROCARGS2 layout:
        // [argc: i32] [exec_path\0] [padding\0...] [arg0\0] [arg1\0] ...
        if buf.len() < mem::size_of::<i32>() {
            return None;
        }

        let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
        let rest = &buf[4..];

        // Skip exec_path (null-terminated)
        let exec_end = rest.iter().position(|&b| b == 0)?;
        let mut pos = exec_end + 1;

        // Skip padding nulls
        while pos < rest.len() && rest[pos] == 0 {
            pos += 1;
        }

        // Collect argc arguments
        let mut args = Vec::with_capacity(argc);
        for _ in 0..argc {
            if pos >= rest.len() {
                break;
            }
            let arg_end = rest[pos..].iter().position(|&b| b == 0)?;
            if let Ok(arg) = std::str::from_utf8(&rest[pos..pos + arg_end]) {
                args.push(arg.to_string());
            }
            pos += arg_end + 1;
        }

        if args.is_empty() {
            None
        } else {
            Some(args.join(" "))
        }
    }

    struct ProcInfo {
        ppid: u32,
        uid: u32,
        start_time: Option<DateTime<Utc>>,
    }

    // proc_pidinfo flavor for BSD task info.
    const PROC_PIDTBSDINFO: i32 = 3;

    /// BSD-level task info returned by proc_pidinfo(PROC_PIDTBSDINFO).
    /// Layout from <sys/proc_info.h> — only the fields we read.
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct proc_bsdinfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        _reserved: u32,
        pbi_comm: [u8; 16], // MAXCOMLEN
        pbi_name: [u8; 32], // 2 * MAXCOMLEN
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;
    }

    fn get_proc_info(pid: i32) -> Option<ProcInfo> {
        use std::mem;

        let mut info: proc_bsdinfo = unsafe { mem::zeroed() };
        let size = mem::size_of::<proc_bsdinfo>() as i32;

        let ret = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };

        if ret <= 0 {
            return None;
        }

        let start_time = if info.pbi_start_tvsec > 0 {
            DateTime::from_timestamp(
                info.pbi_start_tvsec as i64,
                (info.pbi_start_tvusec * 1000) as u32,
            )
        } else {
            None
        };

        Some(ProcInfo {
            ppid: info.pbi_ppid,
            uid: info.pbi_uid,
            start_time,
        })
    }

    fn resolve_username(uid: u32) -> Option<String> {
        use std::ffi::CStr;

        let pwd = unsafe { libc::getpwuid(uid) };
        if pwd.is_null() {
            return Some(format!("uid:{uid}"));
        }
        let name = unsafe { CStr::from_ptr((*pwd).pw_name) };
        name.to_str().ok().map(|s| s.to_string())
    }
}

// ── Linux implementation ────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::ProcessContext;
    use chrono::{DateTime, Utc};
    use std::fs;
    use tracing::trace;

    pub(super) fn enrich(ctx: &mut ProcessContext) {
        let pid = ctx.pid;
        let proc_dir = format!("/proc/{pid}");

        // Binary path via /proc/PID/exe symlink
        ctx.binary_path = fs::read_link(format!("{proc_dir}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        // Command line via /proc/PID/cmdline (null-separated)
        ctx.command_line = fs::read(format!("{proc_dir}/cmdline"))
            .ok()
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| std::str::from_utf8(s).ok())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .filter(|s| !s.is_empty());

        // Parent PID and UID from /proc/PID/status
        if let Ok(status) = fs::read_to_string(format!("{proc_dir}/status")) {
            for line in status.lines() {
                if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
                    ctx.parent_pid = ppid_str.trim().parse().ok();
                } else if let Some(uid_str) = line.strip_prefix("Uid:\t") {
                    // First field is the real UID
                    if let Some(uid) = uid_str.split_whitespace().next() {
                        ctx.user = uid.parse::<u32>().ok().and_then(|uid| {
                            // Try to resolve via getpwuid
                            let pwd = unsafe { libc::getpwuid(uid) };
                            if pwd.is_null() {
                                Some(format!("uid:{uid}"))
                            } else {
                                let name = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_name) };
                                name.to_str().ok().map(|s| s.to_string())
                            }
                        });
                    }
                }
            }
        }

        // Resolve parent name
        if let Some(ppid) = ctx.parent_pid {
            ctx.parent_name = fs::read_to_string(format!("/proc/{ppid}/comm"))
                .ok()
                .map(|s| s.trim().to_string());
        }

        trace!(
            pid = ctx.pid,
            binary = ?ctx.binary_path,
            user = ?ctx.user,
            parent = ?ctx.parent_name,
            "process context enriched"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_context_has_pid_and_name() {
        let ctx = ProcessContext::minimal(42, "test-proc".to_string());
        assert_eq!(ctx.pid, 42);
        assert_eq!(ctx.name, "test-proc");
        assert!(ctx.binary_path.is_none());
        assert!(ctx.command_line.is_none());
        assert!(ctx.user.is_none());
        assert!(ctx.parent_pid.is_none());
        assert!(ctx.parent_name.is_none());
        assert!(ctx.started_at.is_none());
    }

    #[test]
    fn display_summary_minimal() {
        let ctx = ProcessContext::minimal(123, "node".to_string());
        assert_eq!(ctx.display_summary(), "node [pid 123]");
    }

    #[test]
    fn display_summary_with_binary_path() {
        let mut ctx = ProcessContext::minimal(456, "node".to_string());
        ctx.binary_path = Some("/usr/local/bin/node".to_string());
        assert_eq!(ctx.display_summary(), "/usr/local/bin/node [pid 456]");
    }

    #[test]
    fn display_summary_with_user_and_parent() {
        let mut ctx = ProcessContext::minimal(789, "example-tool".to_string());
        ctx.binary_path = Some("/Users/ken/.cargo/bin/example-tool".to_string());
        ctx.user = Some("ken".to_string());
        ctx.parent_name = Some("zsh".to_string());
        assert_eq!(
            ctx.display_summary(),
            "/Users/ken/.cargo/bin/example-tool (user: ken) via zsh [pid 789]"
        );
    }

    #[test]
    fn gather_own_process() {
        // Enrich our own PID — should succeed on any platform.
        let pid = std::process::id();
        let ctx = gather_process_context(pid, "cargo-test");
        assert_eq!(ctx.pid, pid);
        assert_eq!(ctx.name, "cargo-test");
        // On macOS/Linux, we should get at least a binary path.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            assert!(
                ctx.binary_path.is_some(),
                "expected binary_path for own process"
            );
            assert!(ctx.user.is_some(), "expected user for own process");
            assert!(
                ctx.parent_pid.is_some(),
                "expected parent_pid for own process"
            );
        }
    }

    #[test]
    fn gather_nonexistent_pid() {
        // PID 99999999 almost certainly doesn't exist.
        let ctx = gather_process_context(99999999, "ghost");
        assert_eq!(ctx.pid, 99999999);
        assert_eq!(ctx.name, "ghost");
        // All enrichment fields should be None.
        assert!(ctx.binary_path.is_none());
        assert!(ctx.command_line.is_none());
    }

    #[test]
    fn serialization_roundtrip() {
        let mut ctx = ProcessContext::minimal(100, "test".to_string());
        ctx.binary_path = Some("/bin/test".to_string());
        ctx.user = Some("root".to_string());

        let json = serde_json::to_string(&ctx).expect("serialize");
        let deserialized: ProcessContext = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.pid, 100);
        assert_eq!(deserialized.binary_path.as_deref(), Some("/bin/test"));
        assert_eq!(deserialized.user.as_deref(), Some("root"));
    }
}
