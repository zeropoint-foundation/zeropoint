//! Discipline: `std::fs::write` MUST NOT appear inside `zp-keys/keyring.rs`.
//!
//! # Why (Seam 7 / CRIT-8)
//!
//! `keyring.rs` writes secret material (Genesis certificates, operator
//! certificates, agent keys, encrypted operator blobs). Every secret-
//! material write must go through `crate::secret_file::write_atomic`
//! (re-exported as `zp_keys::write_secret_file`), which:
//!
//! 1. Creates the file with `O_CREAT | O_EXCL | mode 0600` atomically.
//!    No window where the file is briefly readable at 0644.
//! 2. Writes the bytes.
//! 3. `fsync`s.
//! 4. Renames over the target. Atomic on POSIX.
//!
//! `std::fs::write` does none of that — it creates at default mode (0644
//! on most systems) and doesn't fsync. Phase 2 swept every secret-write
//! call site in `keyring.rs` to use the helper. This discipline pins
//! the result: a future PR that introduces a new secret-write path with
//! `std::fs::write` directly fails the build.
//!
//! Other files in `zp-keys` that legitimately write secrets (the various
//! sovereignty providers) also go through `write_atomic`; their files
//! could be added here if we want belt-and-suspenders coverage. For v1
//! we pin `keyring.rs` because it's the highest-traffic secret-writing
//! file and the only one where the entire write surface should be
//! covered.

use zp_discipline::Discipline;

#[test]
fn keyring_rs_must_use_write_secret_file() {
    Discipline::new("keyring_rs_must_use_write_secret_file")
        .cite_invariant("Seam 7 (atomic mode-0600 secret writes)")
        .rationale(
            "Secret writes in keyring.rs must go through write_secret_file \
             (atomic tmpfile + fsync + rename, mode 0600 from creation). \
             std::fs::write defaults to 0644 with no atomicity guarantee.",
        )
        .restrict_to_paths(&["crates/zp-keys/src/keyring.rs"])
        .forbid_pattern(r"std::fs::write\s*\(")
        .skip_lines_containing("//")
        .assert();
}
