//! The host boundary's fail-closed properties, tested by observing side effects.
//!
//! # Why this file exists (2026-08-15)
//!
//! Before this, `zp-host` had **zero tests** — across all five source files.
//! It is the crate that holds the gate-then-append-then-execute ordering, the
//! crate `docs/design/HOST-BROKER-2026-08.md` argues is the most
//! security-critical in the tree, and the crate whose four fail-open paths were
//! closed on 2026-08-14. None of that was covered by anything.
//!
//! # These tests assert on the effect, not on the error
//!
//! Each spawn test asks the host boundary to run `touch <marker>` and then
//! checks whether the marker exists. Asserting only on the returned error would
//! pass even if the refusal happened *after* the process ran — which is exactly
//! the bug class being tested for, since the pre-2026-08-14 code logged a
//! warning and spawned anyway. A file that does not exist is evidence the
//! effect did not happen; an `Err` on its own is not.
//!
//! Corresponds to `docs/design/THREAT-MODEL-2026-08.md` §7 tests 1 and 4.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use zp_audit::AuditStore;
use zp_host::{HostContext, HostError, SpawnRequest, SystemHostContext};
use zp_policy::GovernanceGate;

// `AuditStore::open_unsigned` is `#[cfg(any(test, feature = "test-support"))]`
// — deliberately, since `open_signed` is the only production entry point. This
// file reaches it through zp-host's dev-dependency on zp-audit with
// `features = ["test-support"]`, which applies to test targets only and leaves
// `cargo build` unable to see it. Same arrangement zp-hardening-tests uses.

/// `touch` lives here on both macOS and Linux. Chosen over `echo` because it
/// leaves an artifact: the test can observe whether the effect occurred rather
/// than trusting the return value.
const TOUCH: &str = "/usr/bin/touch";

struct Harness {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    store: Arc<Mutex<AuditStore>>,
    gate: Arc<GovernanceGate>,
}

fn harness() -> Harness {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().to_path_buf();
    let store = AuditStore::open_unsigned(&dir.join("audit.db")).expect("open audit store");
    Harness {
        _tmp: tmp,
        dir,
        store: Arc::new(Mutex::new(store)),
        gate: Arc::new(GovernanceGate::new("zp-host-fail-closed-tests")),
    }
}

impl Harness {
    fn marker(&self) -> PathBuf {
        self.dir.join("SPAWNED")
    }

    fn touch_request(&self, tool_name: &str) -> SpawnRequest {
        SpawnRequest {
            program: TOUCH.to_string(),
            args: vec![self.marker().to_string_lossy().into_owned()],
            cwd: self.dir.to_string_lossy().into_owned(),
            actor_label: "fail-closed-test".to_string(),
            tool_name: tool_name.to_string(),
            env_vars: None,
        }
    }

    /// Poison the audit mutex the way a panic-while-holding would in production.
    fn poison_audit_store(&self) {
        let store = Arc::clone(&self.store);
        let _ = std::thread::spawn(move || {
            let _guard = store.lock().expect("lock before poisoning");
            panic!("deliberate panic to poison the audit mutex");
        })
        .join();
        assert!(
            self.store.lock().is_err(),
            "the mutex should be poisoned; if this fails the test below proves nothing"
        );
    }
}

/// THREAT-MODEL §7 test 1 — an unrecordable chain refuses the effect.
///
/// Before 2026-08-14 this path logged a warning, set `gate_receipt_hash` to
/// `None`, and spawned anyway — the effect happening with no verifiable record
/// of it, which is the document's definition of failing open.
#[tokio::test]
async fn poisoned_audit_store_refuses_and_nothing_spawns() {
    let h = harness();
    h.poison_audit_store();

    let host = SystemHostContext::new(Arc::clone(&h.gate), Arc::clone(&h.store));
    let result = host.spawn_process(h.touch_request("benign-tool")).await;

    match result {
        Err(HostError::AuditError(msg)) => {
            assert!(
                msg.contains("spawn_process"),
                "the error should name the host function, got: {msg}"
            );
        }
        Err(other) => panic!("expected AuditError, got {other:?}"),
        Ok(_) => panic!("a poisoned audit store must not yield a spawn"),
    }

    assert!(
        !h.marker().exists(),
        "REGRESSION: the process ran despite the chain being unwritable. \
         This is the exact fail-open shape closed on 2026-08-14 — the effect \
         happened and nothing recorded it."
    );
}

/// A gate denial refuses the effect, and the refusal is not merely reported.
#[tokio::test]
async fn blocked_gate_refuses_and_nothing_spawns() {
    let h = harness();

    // `HarmPrincipleRule` blocks on harmful tool names; "surveillance" is one
    // of the substrings it matches. If that rule is ever renamed or its match
    // set changes, this test fails loudly rather than silently passing against
    // a gate that no longer blocks anything.
    let host = SystemHostContext::new(Arc::clone(&h.gate), Arc::clone(&h.store));
    let result = host
        .spawn_process(h.touch_request("surveillance-toolkit"))
        .await;

    match result {
        Err(HostError::GateDenied { reason }) => {
            assert!(!reason.is_empty(), "a denial must carry a reason");
        }
        Err(other) => panic!("expected GateDenied, got {other:?}"),
        Ok(_) => panic!(
            "the gate did not block a harmful tool name — either HarmPrincipleRule \
             changed or the gate is no longer consulted before spawn"
        ),
    }

    assert!(
        !h.marker().exists(),
        "the process ran despite the gate denying it"
    );
}

/// The allowed path still works, and carries a sealed receipt hash.
///
/// This is the control. Without it, the two tests above would pass against a
/// host boundary that refuses everything, which would be fail-closed and
/// useless.
#[tokio::test]
async fn allowed_spawn_runs_and_carries_a_receipt_hash() {
    let h = harness();

    let host = SystemHostContext::new(Arc::clone(&h.gate), Arc::clone(&h.store));
    let result = host.spawn_process(h.touch_request("benign-tool")).await;

    let mut spawned = match result {
        Ok(s) => s,
        Err(e) => panic!("benign spawn should be allowed, got {e:?}"),
    };

    assert!(
        spawned.gate_receipt_hash.is_some(),
        "an allowed spawn must carry the hash of its sealed gate receipt — \
         `None` here would mean the append was skipped rather than required"
    );

    // Reap the child so the effect is observable and no zombie is left behind.
    let status = spawned.child.wait().await.expect("wait on touch");
    assert!(status.success(), "touch should succeed");

    assert!(
        h.marker().exists(),
        "the control case must actually spawn, or the refusal tests prove nothing"
    );
}

/// The chain records denials too, not only permitted actions.
///
/// `system.rs` appends the gate decision *before* honouring it, precisely so a
/// refusal is on the record. A chain that only contains what was allowed
/// answers a different and much weaker question.
#[tokio::test]
async fn a_denial_is_recorded_on_the_chain() {
    let h = harness();

    let before = h.store.lock().expect("lock").entry_count().unwrap_or(0);

    let host = SystemHostContext::new(Arc::clone(&h.gate), Arc::clone(&h.store));
    let _ = host
        .spawn_process(h.touch_request("surveillance-toolkit"))
        .await;

    let after = h.store.lock().expect("lock").entry_count().unwrap_or(0);

    assert!(
        after > before,
        "a denied spawn left no chain entry — denials must be recorded, \
         or the chain describes only what succeeded"
    );
}
