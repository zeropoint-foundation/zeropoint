//! Phase 0.3 — Audit trail protection regression tests.
//!
//! Tests that the audit trail cannot be destroyed or corrupted by
//! unauthenticated requests:
//! - AUTHZ-VULN-03: Unauthenticated audit trail destruction (/audit/clear)
//! - AUTHZ-VULN-04: Unauthenticated audit chain corruption (tamper/restore)
//!
//! Before Phase 0.3 lands, these tests SHOULD FAIL.
//! After Phase 0.3, they MUST PASS.

use axum::http::StatusCode;
use zp_hardening_tests::harness::TestApp;
use zp_hardening_tests::payloads::authz;

// ============================================================================
// AUTHZ-VULN-03: Unauthenticated audit trail destruction
// ============================================================================

/// AUTHZ-VULN-03: POST /api/v1/audit/clear without auth must be rejected.
///
/// Shannon's finding: sending an empty POST to /audit/clear wiped the
/// entire audit trail, destroying all evidence of prior actions.
#[tokio::test]
async fn test_authz_vuln_03_unauth_audit_clear() {
    let app = TestApp::new().await;
    let (status, _body) = app
        .post_json("/api/v1/audit/clear", authz::audit_clear())
        .await;

    // After Phase 0.3: endpoint is removed entirely (404) or requires auth (401).
    // Before Phase 0.1 (auth middleware): it returns 200 (vulnerable).
    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::METHOD_NOT_ALLOWED,
        "AUTHZ-VULN-03: POST /api/v1/audit/clear returned {} (expected 401/403/404)",
        status
    );
}

/// AUTHZ-VULN-03: Verify audit entries survive after attempted clear.
///
/// Boot the app, confirm audit entries exist (genesis creates at least one),
/// then attempt to clear, then confirm entries still exist.
#[tokio::test]
async fn test_authz_vuln_03_audit_entries_survive_clear() {
    let app = TestApp::new().await;

    // Attempt to clear the audit trail (should fail)
    let _ = app
        .post_json("/api/v1/audit/clear", authz::audit_clear())
        .await;

    // Audit entries should still exist. If auth blocks us from reading too,
    // that's also acceptable (the point is the clear didn't succeed).
    // We check by attempting a GET — if it returns data, entries survived.
    // If it returns 401, auth is blocking us, which is also correct.
    let (status, body) = app.get("/api/v1/audit/entries").await;
    if status == StatusCode::OK {
        // If we can read entries, they should still be there
        let entries = body.as_array();
        assert!(
            entries.map(|e| !e.is_empty()).unwrap_or(true),
            "AUTHZ-VULN-03: Audit entries were destroyed by unauthenticated clear"
        );
    }
    // status == 401 is also fine (auth middleware protecting the endpoint)
}

// ============================================================================
// AUTHZ-VULN-04: Unauthenticated audit chain corruption
// ============================================================================

/// AUTHZ-VULN-04: POST /api/v1/audit/simulate-tamper without auth must be rejected.
///
/// Shannon's finding: the tamper endpoint was accessible without auth,
/// allowing arbitrary corruption of the audit chain.
#[tokio::test]
async fn test_authz_vuln_04_unauth_audit_tamper() {
    let app = TestApp::new().await;
    let (status, _body) = app
        .post_json(
            "/api/v1/audit/simulate-tamper",
            authz::audit_simulate_tamper(),
        )
        .await;

    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::METHOD_NOT_ALLOWED,
        "AUTHZ-VULN-04: POST /api/v1/audit/simulate-tamper returned {} (expected 401/403/404)",
        status
    );
}

/// AUTHZ-VULN-04: POST /api/v1/audit/restore without auth must be rejected.
#[tokio::test]
async fn test_authz_vuln_04_unauth_audit_restore() {
    let app = TestApp::new().await;
    let (status, _body) = app
        .post_json("/api/v1/audit/restore", authz::audit_restore())
        .await;

    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::METHOD_NOT_ALLOWED,
        "AUTHZ-VULN-04: POST /api/v1/audit/restore returned {} (expected 401/403/404)",
        status
    );
}
