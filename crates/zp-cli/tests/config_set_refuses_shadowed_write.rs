//! `zp config set` refuses a write that would be silently shadowed by a
//! higher-precedence config layer (W6, HARNESS-SEAM sensor S5).
//!
//! # Why this exists
//!
//! HARNESS-SEAM's opening audit: "`zp config set` was observed reporting
//! success while changing nothing." `config_set` always wrote to
//! `~/ZeroPoint/config.toml` (the system-config layer) unconditionally,
//! even when a higher-precedence layer -- project-local `./zeropoint.toml`
//! or a `ZP_*` env var -- already set the same key and would keep winning
//! at resolve time. The write succeeded; the resolved value never moved.
//!
//! The fix resolves every layer before writing and refuses when the
//! current winner outranks the layer about to be written, printing a
//! diagnostic that names the shadowing layer and its value, with a
//! `--force` escape hatch for the "I know, write it anyway" case. This
//! test exercises the real `zp` binary end to end, the same way
//! `delegate_refuses_reserved_capability.rs` does for the delegation
//! refusal -- a discipline pin or unit test can assert the *code path
//! exists*; only a process-level test can assert the *refusal actually
//! fires* with the right exit code and message.
//!
//! # Isolation
//!
//! Every case points `ZP_HOME` at a fresh scratch directory so the system-
//! config layer never touches the operator's real `~/ZeroPoint/config.toml`,
//! and sets the subprocess's working directory to a second, sibling scratch
//! directory for the project-config layer (`find_project_config` walks up
//! from `cwd` looking for `zeropoint.toml` with no stop condition other than
//! filesystem root, so an empty, freshly-created directory under the OS temp
//! root is what keeps the "no shadow" cases from picking up a stray
//! `zeropoint.toml` from an ancestor directory).

use std::path::PathBuf;
use std::process::Command;

/// A scratch directory pair: `home` becomes `ZP_HOME` (the system-config
/// layer target); `project` becomes the subprocess's cwd (where a
/// project-local `zeropoint.toml`, if any, is planted).
struct Scratch {
    home: PathBuf,
    project: PathBuf,
}

fn scratch(tag: &str) -> Scratch {
    let base = std::env::temp_dir().join(format!(
        "zp-config-set-test-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let home = base.join("home");
    let project = base.join("project");
    std::fs::create_dir_all(&home).expect("scratch home dir");
    std::fs::create_dir_all(&project).expect("scratch project dir");
    Scratch { home, project }
}

/// Run `zp config set <key> <value> [--force]` in the given scratch pair.
fn run_config_set(
    s: &Scratch,
    key: &str,
    value: &str,
    force: bool,
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zp"));
    cmd.env("ZP_HOME", &s.home)
        .current_dir(&s.project)
        .arg("config")
        .arg("set")
        .arg(key)
        .arg(value);
    if force {
        cmd.arg("--force");
    }
    let out = cmd.output().expect("failed to run the zp binary");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn set_succeeds_when_nothing_shadows_the_key() {
    let s = scratch("no-shadow");
    let (code, stdout, stderr) = run_config_set(&s, "llm.model", "foo-model", false);

    assert_eq!(
        code,
        Some(0),
        "expected a clean write.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("llm.model = foo-model"),
        "expected the success line.\nstdout: {stdout}"
    );
    assert!(
        stderr.is_empty(),
        "no diagnostic expected on a non-shadowed write.\nstderr: {stderr}"
    );

    let written = std::fs::read_to_string(s.home.join("config.toml")).expect("config.toml written");
    assert!(
        written.contains("foo-model"),
        "the value must actually be on disk.\nfile: {written}"
    );

    let _ = std::fs::remove_dir_all(s.home.parent().unwrap());
}

#[test]
fn set_refuses_when_a_higher_layer_shadows_the_key() {
    let s = scratch("shadowed");
    std::fs::write(
        s.project.join("zeropoint.toml"),
        "[llm]\nmodel = \"baz-model\"\n",
    )
    .expect("write project config fixture");

    let (code, stdout, stderr) = run_config_set(&s, "llm.model", "foo-model", false);

    assert_eq!(
        code,
        Some(1),
        "expected a refusal exit code.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("refusing to write shadowed key"),
        "expected the shadow refusal diagnostic.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("key:           llm.model"),
        "diagnostic must name the key.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("target layer:  ~/ZeroPoint/config.toml"),
        "diagnostic must name the target layer.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("shadowed by:   ./zeropoint.toml (currently sets: baz-model)"),
        "diagnostic must name the shadowing layer and its current value.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "diagnostic must name the --force escape hatch.\nstderr: {stderr}"
    );

    let untouched = !s.home.join("config.toml").exists();
    assert!(
        untouched,
        "a refused write must not touch the target file at all"
    );

    let _ = std::fs::remove_dir_all(s.home.parent().unwrap());
}

#[test]
fn set_force_writes_anyway_and_warns() {
    let s = scratch("forced");
    std::fs::write(
        s.project.join("zeropoint.toml"),
        "[llm]\nmodel = \"baz-model\"\n",
    )
    .expect("write project config fixture");

    let (code, stdout, stderr) = run_config_set(&s, "llm.model", "foo-model", true);

    assert_eq!(
        code,
        Some(0),
        "--force must write successfully, not refuse.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("llm.model = foo-model"),
        "expected the success line.\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("shadowed by") && stdout.contains("baz-model"),
        "expected a warn-level note that the write remains shadowed.\nstdout: {stdout}"
    );

    let written = std::fs::read_to_string(s.home.join("config.toml")).expect("config.toml written");
    assert!(
        written.contains("foo-model"),
        "--force must actually write the target layer even though it stays shadowed.\nfile: {written}"
    );

    let _ = std::fs::remove_dir_all(s.home.parent().unwrap());
}

#[test]
fn set_twice_on_the_same_layer_is_not_treated_as_shadow() {
    let s = scratch("self-supersede");

    let (code1, _stdout1, stderr1) = run_config_set(&s, "llm.model", "first-model", false);
    assert_eq!(
        code1,
        Some(0),
        "first write must succeed (nothing shadows it yet).\nstderr: {stderr1}"
    );

    // Same layer, same key, new value -- this is a self-supersede, not a
    // shadow. The already-written system-config layer resolving as itself
    // must not be mistaken for a higher layer shadowing the write.
    let (code2, stdout2, stderr2) = run_config_set(&s, "llm.model", "second-model", false);
    assert_eq!(
        code2,
        Some(0),
        "overwriting the same layer's own prior value must succeed, not refuse.\nstdout: {stdout2}\nstderr: {stderr2}"
    );
    assert!(
        stderr2.is_empty(),
        "self-supersede must not print a shadow diagnostic.\nstderr: {stderr2}"
    );

    let written = std::fs::read_to_string(s.home.join("config.toml")).expect("config.toml written");
    assert!(
        written.contains("second-model") && !written.contains("first-model"),
        "the second write must have actually replaced the first.\nfile: {written}"
    );

    let _ = std::fs::remove_dir_all(s.home.parent().unwrap());
}
