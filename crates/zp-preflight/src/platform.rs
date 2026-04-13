//! Platform and package-manager detection.
//!
//! We detect OS, architecture, and the preferred package manager so that
//! fix suggestions contain *exact* commands the operator can copy-paste.

use serde::Serialize;
use std::process::Command;

// ─── OS / arch ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Os {
    MacOS,
    Linux,
    Windows,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Arch {
    X86_64,
    Aarch64,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Zypper,
    Apk,
    Brew,
    /// No recognised manager — fall back to generic instructions.
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct Platform {
    pub os: Os,
    pub arch: Arch,
    pub pkg_mgr: PackageManager,
    pub os_version: String,
}

impl Platform {
    pub fn detect() -> Self {
        let os = detect_os();
        let arch = detect_arch();
        let pkg_mgr = detect_package_manager(os);
        let os_version = detect_os_version(os);
        Self {
            os,
            arch,
            pkg_mgr,
            os_version,
        }
    }
}

// ─── Detection helpers ───────────────────────────────────────

fn detect_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::MacOS
    } else if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "windows") {
        Os::Windows
    } else {
        Os::Unknown
    }
}

fn detect_arch() -> Arch {
    if cfg!(target_arch = "x86_64") {
        Arch::X86_64
    } else if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::Unknown
    }
}

fn detect_package_manager(os: Os) -> PackageManager {
    match os {
        Os::MacOS => {
            if which("brew") {
                PackageManager::Brew
            } else {
                PackageManager::None
            }
        }
        Os::Linux => {
            if which("apt-get") {
                PackageManager::Apt
            } else if which("dnf") {
                PackageManager::Dnf
            } else if which("yum") {
                PackageManager::Yum
            } else if which("pacman") {
                PackageManager::Pacman
            } else if which("zypper") {
                PackageManager::Zypper
            } else if which("apk") {
                PackageManager::Apk
            } else {
                PackageManager::None
            }
        }
        _ => PackageManager::None,
    }
}

fn detect_os_version(os: Os) -> String {
    match os {
        Os::MacOS => run_stdout("sw_vers", &["-productVersion"]).unwrap_or_default(),
        Os::Linux => {
            // Try /etc/os-release first (most distros), fall back to uname
            std::fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|s| {
                    s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                        l.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string()
                    })
                })
                .unwrap_or_else(|| run_stdout("uname", &["-r"]).unwrap_or_default())
        }
        _ => String::from("unknown"),
    }
}

// ─── Install-command templates ───────────────────────────────

/// Returns the exact package-install command for a system library.
pub fn install_cmd(pkg_mgr: &PackageManager, lib_name: &str) -> String {
    match (pkg_mgr, lib_name) {
        // ── libssl ──
        (PackageManager::Apt, "libssl") => "sudo apt-get install -y libssl-dev".into(),
        (PackageManager::Dnf, "libssl") => "sudo dnf install -y openssl-devel".into(),
        (PackageManager::Yum, "libssl") => "sudo yum install -y openssl-devel".into(),
        (PackageManager::Pacman, "libssl") => "sudo pacman -S --noconfirm openssl".into(),
        (PackageManager::Zypper, "libssl") => "sudo zypper install -y libopenssl-devel".into(),
        (PackageManager::Apk, "libssl") => "sudo apk add openssl-dev".into(),
        (PackageManager::Brew, "libssl") => "brew install openssl@3".into(),

        // ── pkg-config ──
        (PackageManager::Apt, "pkg-config") => "sudo apt-get install -y pkg-config".into(),
        (PackageManager::Dnf, "pkg-config") => "sudo dnf install -y pkgconf-pkg-config".into(),
        (PackageManager::Yum, "pkg-config") => "sudo yum install -y pkgconfig".into(),
        (PackageManager::Pacman, "pkg-config") => "sudo pacman -S --noconfirm pkgconf".into(),
        (PackageManager::Zypper, "pkg-config") => "sudo zypper install -y pkg-config".into(),
        (PackageManager::Apk, "pkg-config") => "sudo apk add pkgconf".into(),
        (PackageManager::Brew, "pkg-config") => "brew install pkg-config".into(),

        // ── libdbus ──
        (PackageManager::Apt, "libdbus") => "sudo apt-get install -y libdbus-1-dev".into(),
        (PackageManager::Dnf, "libdbus") => "sudo dnf install -y dbus-devel".into(),
        (PackageManager::Yum, "libdbus") => "sudo yum install -y dbus-devel".into(),
        (PackageManager::Pacman, "libdbus") => "sudo pacman -S --noconfirm dbus".into(),
        (PackageManager::Zypper, "libdbus") => "sudo zypper install -y dbus-1-devel".into(),
        (PackageManager::Apk, "libdbus") => "sudo apk add dbus-dev".into(),
        (PackageManager::Brew, "libdbus") | (PackageManager::None, "libdbus") => {
            "Not required on macOS (uses native IOKit)".into()
        }

        // ── libusb ──
        (PackageManager::Apt, "libusb") => "sudo apt-get install -y libusb-1.0-0-dev".into(),
        (PackageManager::Dnf, "libusb") => "sudo dnf install -y libusb1-devel".into(),
        (PackageManager::Yum, "libusb") => "sudo yum install -y libusb1-devel".into(),
        (PackageManager::Pacman, "libusb") => "sudo pacman -S --noconfirm libusb".into(),
        (PackageManager::Zypper, "libusb") => "sudo zypper install -y libusb-1_0-devel".into(),
        (PackageManager::Apk, "libusb") => "sudo apk add libusb-dev".into(),
        (PackageManager::Brew, "libusb") => "brew install libusb".into(),

        // ── Rust toolchain ──
        (_, "rust") => "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh".into(),

        // ── Docker ──
        (PackageManager::Apt, "docker") => {
            "sudo apt-get install -y docker.io && sudo systemctl enable --now docker".into()
        }
        (PackageManager::Brew, "docker") => "brew install --cask docker".into(),
        (_, "docker") => "See https://docs.docker.com/engine/install/".into(),

        // ── Fallback ──
        (PackageManager::None, lib) => {
            format!("Install '{lib}' using your system's package manager")
        }
        (_, lib) => format!("Install '{lib}' using your system's package manager"),
    }
}

// ─── Utility ─────────────────────────────────────────────────

/// Check if a binary is on PATH.
pub fn which(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command and capture trimmed stdout.
pub fn run_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
