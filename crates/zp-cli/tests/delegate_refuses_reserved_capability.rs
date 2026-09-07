//! End-to-end: `zp delegate` refuses a reserved capability before it can reach
//! the chain.
//!
//! # Why this exists (2026-08-13)
//!
//! `run_delegate` built a standing grant and wrote it to the audit chain with no
//! issuance validation at all. That was defect 5 of the delegation-invariants
//! sweep. The fix adds `with_issued_via` + `validate_issuance` before the write,
//! and a discipline pin (`zp-discipline/tests/delegation_writes_must_validate_issuance.rs`)
//! asserts the call exists.
//!
//! **The pin cannot assert that the refusal fires.** It reads source text; it
//! cannot know whether `validate_issuance` returns `Err` for anything reachable
//! from this command, or whether the non-zero exit happens before the chain
//! write. This test closes that gap, which is the difference between defect 5
//! being *fixed* and being *closed*.
//!
//! # Why the probe is the right instrument
//!
//! `RESERVED_CAPABILITY_NAMES` currently holds exactly one row:
//! `zp:reserved:probe` (`ReservedReason::Probe`, member id `N0`). Its stated
//! purpose is to keep the enforcement path live while the real spec members
//! (N1–N5) are unimplemented. This test is that purpose being used: if the
//! probe ever stops refusing, the enforcement path has gone dark and every
//! future spec member would be added to a table nothing consults.
//!
//! # Why validation is reachable without a genesis secret
//!
//! `validate_issuance` runs *before* `harden_zp_home()` and
//! `load_genesis_secret_composed()` in `run_delegate`. That ordering is load-
//! bearing for this test and worth preserving: it means a refused grant never
//! touches the operator's home directory, never opens the audit store, and
//! never prompts the sovereignty provider. If someone moves the validation
//! below the genesis load, this test will start prompting for a hardware touch
//! in CI — which is the loud failure you want, not a silent one.

use std::path::PathBuf;
use std::process::Command;

/// A scratch directory that is not the operator's real `~/ZeroPoint`.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zp-delegate-test-{}-{tag}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Run `zp delegate` with the given capability spec, fully sandboxed.
fn run_delegate(capabilities: &str, tag: &str) -> (Option<i32>, String, String) {
    let dir = scratch(tag);
    let out = Command::new(env!("CARGO_BIN_EXE_zp"))
        // Belt and braces: even though a refused grant never reaches the store,
        // point every home/data lookup at the scratch dir so a future ordering
        // change cannot write into the operator's real chain from a test.
        .env("ZP_HOME", &dir)
        .env("ZP_DATA_DIR", &dir)
        .arg("--data-dir")
        .arg(&dir)
        .arg("delegate")
        .arg("--subject")
        .arg("reserved-probe-subject")
        .arg("--capabilities")
        .arg(capabilities)
        .arg("--audit-db")
        .arg(dir.join("audit.db"))
        .output()
        .expect("failed to run the zp binary");

    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn delegate_refuses_the_reserved_probe_capability() {
    let (code, stdout, stderr) = run_delegate("zp:reserved:probe", "reserved");

    assert_eq!(
        code,
        Some(2),
        "expected exit 2 on a reserved capability.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Assert on the specific refusal, not merely on a non-zero exit. `zp
    // delegate` has several other exit-2 paths (bad duration, missing genesis,
    // unwritable store); passing on any of them would make this test agree with
    // a broken build.
    assert!(
        stderr.contains("grant issuance rejected"),
        "expected the issuance-validation refusal, got a different failure.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("reserved to the sovereign operator"),
        "expected the reserved-capability message from IssuanceError.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("(N0)"),
        "expected the reserved member id N0 (the liveness probe). If the probe \
         was replaced by real spec members, update this test deliberately — do \
         not relax it.\nstderr: {stderr}"
    );
}

/// The refusal must happen before anything is written.
///
/// A refusal that still opened the store, hardened the home directory, or
/// prompted the sovereignty provider would be a refusal in name only.
#[test]
fn a_refused_grant_touches_no_store() {
    let dir = scratch("no-store");
    let db = dir.join("audit.db");

    let out = Command::new(env!("CARGO_BIN_EXE_zp"))
        .env("ZP_HOME", &dir)
        .env("ZP_DATA_DIR", &dir)
        .arg("--data-dir")
        .arg(&dir)
        .arg("delegate")
        .arg("--subject")
        .arg("reserved-probe-subject")
        .arg("--capabilities")
        .arg("zp:reserved:probe")
        .arg("--audit-db")
        .arg(&db)
        .output()
        .expect("failed to run the zp binary");

    let db_exists = db.exists();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !db_exists,
        "a refused grant created an audit store at {}. The validation must \
         precede `AuditStore::open_signed`.\nstderr: {stderr}",
        db.display()
    );
}

/// Known gap, asserted so it cannot change silently.
///
/// `run_delegate` validates `caps[0]` only. Every capability after the first
/// becomes a `Constraint::Custom { name: "capability:<name>" }` rather than a
/// `GrantedCapability`, so `validate_issuance` never sees it — a reserved name
/// in a secondary position is not refused.
///
/// Whether that is a *defect* is a real question: a constraint is not a granted
/// capability, and nothing in the gate reads `capability:` constraints as
/// authority today. But the asymmetry is invisible from the command line —
/// `--capabilities zp:reserved:probe` is refused and
/// `--capabilities read,zp:reserved:probe` is not — and an operator would not
/// predict that.
///
/// Ignored rather than asserted, because exercising it requires a non-reserved
/// primary, which runs past validation into `load_genesis_secret_composed` and
/// can prompt the hardware sovereignty provider. Run it deliberately:
///
/// ```text
/// cargo test -p zp-cli --test delegate_refuses_reserved_capability -- --ignored
/// ```
#[test]
#[ignore = "runs past validation into the sovereignty provider; may prompt for a hardware touch"]
fn reserved_in_a_secondary_position_is_currently_not_refused() {
    let (_code, _stdout, stderr) = run_delegate("read,zp:reserved:probe", "secondary");

    assert!(
        !stderr.contains("grant issuance rejected"),
        "a reserved capability in a secondary position is now being refused. \
         That is an improvement — update this test to assert the new behaviour \
         rather than deleting it.\nstderr: {stderr}"
    );
}
