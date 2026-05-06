//! Atomic, mode-0600 file writes for secret material.
//!
//! Closes the chmod-after-write race documented as **CRIT-8** in the
//! 2026-04 security audit. Pre-Phase-2 code wrote secret bytes to disk
//! at the OS default mode (typically 0644 — world-readable on macOS
//! and most Linux distros), then `chmod`'d 0600 immediately after. The
//! window between those two syscalls — short, but real — let any other
//! local user read the bytes.
//!
//! [`write_atomic`] closes the window by:
//!
//! 1. Opening a tempfile in the target's parent directory with
//!    `O_CREAT | O_EXCL | mode 0600` (atomic — no other process has
//!    seen the file at any other mode).
//! 2. Writing the bytes and `fsync`-ing them to disk.
//! 3. Renaming the tempfile over the target. POSIX guarantees rename(2)
//!    is atomic within the same filesystem, so the target either has
//!    the old contents or the new — never a partial write, never wrong
//!    permissions.
//!
//! # When to use
//!
//! Any path under `~/ZeroPoint/keys/` or any file containing sovereignty
//! material, signing keys, encrypted secrets, or recoverable wrapping-
//! key inputs. Public certificates and identity-record JSON files (e.g.
//! `genesis.json`, `operator.json`) are also written through this helper
//! because they contain capability metadata an attacker could use even
//! without the secret half.
//!
//! # When NOT to use
//!
//! Generic config files, log files, and runtime state. Atomic-rename is
//! more expensive than `fs::write` (extra syscall, fsync, rename), and
//! mode 0600 is too restrictive for files an admin tool legitimately
//! needs to read.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;

/// Atomically write `data` to `path` with permissions 0600 (Unix) /
/// default (Windows). Crash-safe and race-safe.
///
/// On Unix: temp file is created with `O_EXCL` and mode 0600 in one
/// syscall, then renamed over the target. The target is replaced
/// atomically; readers either see the old version or the new, never a
/// partial write.
///
/// On non-Unix: tempfile is created with `O_EXCL`, written, and renamed.
/// Mode is set after rename via [`set_mode_600`], which is a no-op on
/// platforms without POSIX permissions.
pub fn write_atomic(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let tmp_path = tempfile_path(path, parent);

    {
        let mut file = create_excl_secret(&tmp_path)?;
        // Write + flush + fsync. fsync ensures the bytes hit the disk
        // before the rename, so a crash mid-write doesn't leave a
        // truncated target after the rename completes.
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
    }

    // rename(2) — atomic on POSIX, best-effort elsewhere. If this fails,
    // try to clean up the tempfile so we don't leave secret bytes lying
    // around at a path the caller didn't expect.
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // On non-Unix the tempfile didn't get a 0600 mode at creation time;
    // try to apply it now after rename. Failure is non-fatal — the
    // platform may not support POSIX modes (Windows).
    set_mode_600(path)?;

    Ok(())
}

/// Construct the tempfile path used by [`write_atomic`].
///
/// The tempfile lives in the same directory as the target so `rename(2)`
/// stays within the same filesystem (atomic rename only holds across the
/// same FS). The suffix is 8 random bytes so concurrent writers can't
/// collide on the same temp name.
fn tempfile_path(target: &Path, parent: &Path) -> PathBuf {
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let basename = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let suffix_hex: String = suffix.iter().map(|b| format!("{:02x}", b)).collect();
    parent.join(format!("{}.tmp.{}", basename, suffix_hex))
}

/// Open a file exclusively (fail if it exists) with mode 0600 on Unix.
#[cfg(unix)]
fn create_excl_secret(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Non-Unix: best-effort exclusive creation. Mode bits aren't honored.
#[cfg(not(unix))]
fn create_excl_secret(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Force mode 0600 on the file (Unix). No-op on platforms without POSIX
/// permissions. Used as a belt-and-suspenders after rename on non-Unix
/// where the create-with-mode trick isn't available.
#[cfg(unix)]
fn set_mode_600(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_mode_600(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_data_at_target_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");

        write_atomic(&path, b"hello-secret").unwrap();
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read, b"hello-secret");
    }

    #[cfg(unix)]
    #[test]
    fn newly_created_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");

        write_atomic(&path, b"x").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // Lower 9 bits are the perm triplet. 0o600 = owner rw only.
        assert_eq!(
            mode & 0o777,
            0o600,
            "expected mode 0o600, got 0o{:o}",
            mode & 0o777
        );
    }

    #[cfg(unix)]
    #[test]
    fn overwrite_preserves_mode_0600() {
        // The audit MED finding called out the chmod-after-write race
        // window. Even on overwrite, the new file (which is rename(2)'d
        // in from a tempfile) must be mode 0600 with no race.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");

        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read, b"second");
    }

    #[test]
    fn no_temp_files_left_behind_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");

        write_atomic(&path, b"x").unwrap();
        write_atomic(&path, b"y").unwrap();

        // Only the target file should exist; no .tmp.* tempfiles.
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            found.push(name);
        }
        assert_eq!(found, vec!["secret.bin"]);
    }
}
