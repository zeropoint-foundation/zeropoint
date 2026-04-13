//! Individual pre-flight checks.
//!
//! Each public function takes a `&Platform` and returns a `CheckResult`.
//! Checks shell out to system tools rather than linking native crates —
//! keeping the binary small and compilation fast.

use crate::platform::{self, install_cmd, Os, PackageManager, Platform};
use crate::report::CheckResult;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

// ═══════════════════════════════════════════════════════════════
// Rust toolchain
// ═══════════════════════════════════════════════════════════════

const MIN_RUST_VERSION: (u32, u32) = (1, 77);

pub fn check_rust_toolchain(plat: &Platform) -> CheckResult {
    let rustc = platform::run_stdout("rustc", &["--version"]);

    match rustc {
        None => CheckResult::fail(
            "rust-toolchain",
            "Rust compiler (rustc)",
            "rustc not found on PATH",
            install_cmd(&plat.pkg_mgr, "rust"),
        ),
        Some(version_str) => {
            // Parse "rustc 1.82.0 (f6e511eec 2024-10-15)"
            let version = version_str
                .split_whitespace()
                .nth(1)
                .unwrap_or("0.0.0");
            let parts: Vec<u32> = version
                .split('.')
                .take(2)
                .filter_map(|s| s.parse().ok())
                .collect();
            let (major, minor) = (parts.first().copied().unwrap_or(0), parts.get(1).copied().unwrap_or(0));

            if (major, minor) >= MIN_RUST_VERSION {
                CheckResult::pass(
                    "rust-toolchain",
                    "Rust compiler (rustc)",
                    format!("rustc {version} (>= {}.{} required)", MIN_RUST_VERSION.0, MIN_RUST_VERSION.1),
                )
            } else {
                CheckResult::fail(
                    "rust-toolchain",
                    "Rust compiler (rustc)",
                    format!(
                        "rustc {version} is too old (>= {}.{} required)",
                        MIN_RUST_VERSION.0, MIN_RUST_VERSION.1
                    ),
                    "rustup update stable",
                )
            }
        }
    }
}

pub fn check_wasm_target(_plat: &Platform) -> CheckResult {
    let output = platform::run_stdout("rustup", &["target", "list", "--installed"]);

    match output {
        None => CheckResult::warn(
            "wasm-target",
            "WASM compilation target",
            "rustup not found — cannot verify wasm32-unknown-unknown target",
            "rustup target add wasm32-unknown-unknown",
        ),
        Some(targets) => {
            if targets.lines().any(|l| l.trim() == "wasm32-unknown-unknown") {
                CheckResult::pass(
                    "wasm-target",
                    "WASM compilation target",
                    "wasm32-unknown-unknown installed",
                )
            } else {
                CheckResult::warn(
                    "wasm-target",
                    "WASM compilation target",
                    "wasm32-unknown-unknown not installed (only needed for custom WASM policies)",
                    "rustup target add wasm32-unknown-unknown",
                )
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// System libraries
// ═══════════════════════════════════════════════════════════════

pub fn check_libssl(plat: &Platform) -> CheckResult {
    if check_pkg_config("openssl") || check_pkg_config("libssl") {
        return CheckResult::pass(
            "libssl",
            "OpenSSL development headers",
            "pkg-config finds openssl",
        );
    }

    // macOS: Homebrew openssl lives outside default paths
    if plat.os == Os::MacOS {
        let brew_prefix = platform::run_stdout("brew", &["--prefix", "openssl@3"]);
        if brew_prefix.is_some() {
            return CheckResult::pass(
                "libssl",
                "OpenSSL development headers",
                "Homebrew openssl@3 found",
            );
        }
    }

    CheckResult::fail(
        "libssl",
        "OpenSSL development headers",
        "libssl-dev / openssl-devel not found",
        install_cmd(&plat.pkg_mgr, "libssl"),
    )
}

pub fn check_pkg_config_tool(plat: &Platform) -> CheckResult {
    if platform::which("pkg-config") {
        CheckResult::pass("pkg-config", "pkg-config", "found on PATH")
    } else {
        CheckResult::fail(
            "pkg-config",
            "pkg-config",
            "pkg-config not found on PATH",
            install_cmd(&plat.pkg_mgr, "pkg-config"),
        )
    }
}

pub fn check_libdbus(plat: &Platform) -> CheckResult {
    // Only required on Linux for Secret Service integration
    if plat.os != Os::Linux {
        return CheckResult::skip(
            "libdbus",
            "D-Bus development headers",
            "Not required on this platform (only Linux/Secret Service)",
        );
    }

    if check_pkg_config("dbus-1") {
        CheckResult::pass(
            "libdbus",
            "D-Bus development headers",
            "pkg-config finds dbus-1",
        )
    } else {
        CheckResult::warn(
            "libdbus",
            "D-Bus development headers",
            "libdbus-1-dev not found (only needed if os-keychain feature is enabled)",
            install_cmd(&plat.pkg_mgr, "libdbus"),
        )
    }
}

pub fn check_libusb(plat: &Platform) -> CheckResult {
    if check_pkg_config("libusb-1.0") || check_pkg_config("libusb") {
        CheckResult::pass(
            "libusb",
            "libusb (hardware wallet support)",
            "pkg-config finds libusb-1.0",
        )
    } else {
        CheckResult::warn(
            "libusb",
            "libusb (hardware wallet support)",
            "libusb not found (only needed if hw-trezor feature is enabled)",
            install_cmd(&plat.pkg_mgr, "libusb"),
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// Disk space
// ═══════════════════════════════════════════════════════════════

/// Minimum free space for build (in MB).
const MIN_BUILD_SPACE_MB: u64 = 2048;
/// Minimum free space for runtime data (in MB).
const MIN_RUNTIME_SPACE_MB: u64 = 512;

pub fn check_disk_space(_plat: &Platform) -> CheckResult {
    let home = dirs_home();
    let free_mb = disk_free_mb(&home);

    match free_mb {
        None => CheckResult::warn(
            "disk-space",
            "Available disk space",
            "Could not determine free space",
            "",
        ),
        Some(mb) if mb >= MIN_BUILD_SPACE_MB => CheckResult::pass(
            "disk-space",
            "Available disk space",
            format!("{mb} MB free (>= {MIN_BUILD_SPACE_MB} MB required for build)"),
        ),
        Some(mb) if mb >= MIN_RUNTIME_SPACE_MB => CheckResult::warn(
            "disk-space",
            "Available disk space",
            format!(
                "{mb} MB free — enough for runtime but may not be enough for source build ({MIN_BUILD_SPACE_MB} MB recommended)"
            ),
            "Free up disk space, or use pre-built binary install instead of source build",
        ),
        Some(mb) => CheckResult::fail(
            "disk-space",
            "Available disk space",
            format!("{mb} MB free — {MIN_RUNTIME_SPACE_MB} MB minimum required"),
            "Free up disk space before proceeding",
        ),
    }
}

// ═══════════════════════════════════════════════════════════════
// Port availability
// ═══════════════════════════════════════════════════════════════

const DEFAULT_PORT: u16 = 3000;

pub fn check_port(_plat: &Platform) -> CheckResult {
    check_port_number(DEFAULT_PORT)
}

pub fn check_port_number(port: u16) -> CheckResult {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => CheckResult::pass(
            "port",
            format!("Port {port} availability"),
            format!("Port {port} is available"),
        ),
        Err(_) => {
            // Try to identify what's using the port
            let occupant = identify_port_user(port);
            let detail = match &occupant {
                Some(proc) => format!("Port {port} is in use by {proc}"),
                None => format!("Port {port} is in use"),
            };
            CheckResult::warn(
                "port",
                format!("Port {port} availability"),
                detail,
                format!("Free port {port}, or configure ZeroPoint to use another: zp config set port <other>"),
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Network connectivity
// ═══════════════════════════════════════════════════════════════

pub fn check_network_crates_io(_plat: &Platform) -> CheckResult {
    // Quick DNS + TCP check to crates.io (HTTPS on port 443)
    if tcp_connect("crates.io", 443) {
        CheckResult::pass(
            "network-crates",
            "Network: crates.io",
            "Can reach crates.io:443",
        )
    } else {
        CheckResult::fail(
            "network-crates",
            "Network: crates.io",
            "Cannot reach crates.io — source builds will fail",
            "Check your internet connection, firewall, or proxy settings",
        )
    }
}

pub fn check_network_github(_plat: &Platform) -> CheckResult {
    if tcp_connect("github.com", 443) {
        CheckResult::pass(
            "network-github",
            "Network: github.com",
            "Can reach github.com:443",
        )
    } else {
        CheckResult::warn(
            "network-github",
            "Network: github.com",
            "Cannot reach github.com — binary downloads will fail",
            "Check your internet connection, firewall, or proxy settings",
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// OS-specific capabilities
// ═══════════════════════════════════════════════════════════════

pub fn check_keychain_capability(plat: &Platform) -> CheckResult {
    match plat.os {
        Os::MacOS => {
            // Check security command exists (ships with macOS)
            if platform::which("security") {
                CheckResult::pass(
                    "os-keychain",
                    "macOS Keychain",
                    "security command available — Keychain integration will work",
                )
            } else {
                CheckResult::warn(
                    "os-keychain",
                    "macOS Keychain",
                    "'security' command not found (unusual for macOS)",
                    "Keychain integration may not work — file-based key storage will be used as fallback",
                )
            }
        }
        Os::Linux => {
            // Check for Secret Service (gnome-keyring or KWallet)
            let has_secret_service = platform::run_stdout(
                "dbus-send",
                &[
                    "--session",
                    "--dest=org.freedesktop.secrets",
                    "--print-reply",
                    "/org/freedesktop/secrets",
                    "org.freedesktop.DBus.Peer.Ping",
                ],
            )
            .is_some();

            if has_secret_service {
                CheckResult::pass(
                    "os-keychain",
                    "Linux Secret Service",
                    "D-Bus Secret Service API responding — keychain integration will work",
                )
            } else {
                CheckResult::warn(
                    "os-keychain",
                    "Linux Secret Service",
                    "No Secret Service provider found (gnome-keyring or KWallet)",
                    "Install gnome-keyring, or ZeroPoint will use file-based key storage as fallback",
                )
            }
        }
        _ => CheckResult::skip(
            "os-keychain",
            "OS Keychain",
            "Keychain check not implemented for this platform",
        ),
    }
}

// ═══════════════════════════════════════════════════════════════
// Docker (optional)
// ═══════════════════════════════════════════════════════════════

pub fn check_docker(plat: &Platform) -> CheckResult {
    if !platform::which("docker") {
        return CheckResult::warn(
            "docker",
            "Docker (optional)",
            "Docker not found — only needed for containerized tool execution",
            install_cmd(&plat.pkg_mgr, "docker"),
        );
    }

    // Check if daemon is running
    let running = Command::new("docker")
        .args(["info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if running {
        CheckResult::pass("docker", "Docker (optional)", "Docker daemon running")
    } else {
        CheckResult::warn(
            "docker",
            "Docker (optional)",
            "Docker installed but daemon not running",
            "Start Docker Desktop or: sudo systemctl start docker",
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn check_pkg_config(lib: &str) -> bool {
    Command::new("pkg-config")
        .args(["--exists", lib])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tcp_connect(host: &str, port: u16) -> bool {
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    let addr = format!("{host}:{port}");
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|addr| {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok()
        })
        .unwrap_or(false)
}

fn identify_port_user(port: u16) -> Option<String> {
    // Linux: ss or lsof
    if let Some(out) = platform::run_stdout("lsof", &["-i", &format!(":{port}"), "-t"]) {
        if let Some(pid) = out.lines().next() {
            if let Some(name) = platform::run_stdout("ps", &["-p", pid, "-o", "comm="]) {
                return Some(format!("{name} (pid {pid})"));
            }
            return Some(format!("pid {pid}"));
        }
    }
    None
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn disk_free_mb(path: &PathBuf) -> Option<u64> {
    // Use `df` — available on all Unix-like systems
    let path_str = path.to_string_lossy();
    let output = platform::run_stdout("df", &["-m", &path_str])?;
    // Parse second line, fourth column (Available)
    let line = output.lines().nth(1)?;
    let available = line.split_whitespace().nth(3)?;
    available.parse().ok()
}
