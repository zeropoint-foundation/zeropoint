//! Phase 0.1 — AUTH-VULN regression tests.
//!
//! These tests verify that the auth middleware is wired to the Axum router
//! and that all protected endpoints reject unauthenticated requests.
//!
//! Before Phase 0.1 lands, these tests SHOULD FAIL (Shannon succeeded).
//! After Phase 0.1, they MUST PASS.

use axum::http::StatusCode;
use zp_hardening_tests::harness::TestApp;
use zp_hardening_tests::payloads::auth;

/// Helper: every GET endpoint in the list must return 401 without credentials.
async fn assert_all_get_require_auth(app: &TestApp, endpoints: &[&str]) {
    for endpoint in endpoints {
        let (status, _body) = app.get(endpoint).await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "AUTH-VULN-01: GET {} returned {} (expected 401/403 without auth)",
            endpoint,
            status
        );
    }
}

/// Helper: every POST endpoint in the list must return 401 without credentials.
async fn assert_all_post_require_auth(app: &TestApp, endpoints: &[&str]) {
    for endpoint in endpoints {
        let (status, _body) = app.post_json(endpoint, serde_json::json!({})).await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "AUTH-VULN-01: POST {} returned {} (expected 401/403 without auth)",
            endpoint,
            status
        );
    }
}

// ============================================================================
// AUTH-VULN-01: Auth middleware not wired to router
// ============================================================================

/// AUTH-VULN-01: All protected GET endpoints must reject unauthenticated access.
///
/// Shannon's finding: every single API endpoint returned 200 without any
/// credentials. This is the foundational auth gap — all other AUTHZ-VULNs
/// depend on this being open.
#[tokio::test]
async fn test_auth_vuln_01_unauth_get_endpoints() {
    let app = TestApp::new().await;
    assert_all_get_require_auth(&app, auth::PROTECTED_ENDPOINTS_GET).await;
}

/// AUTH-VULN-01: All protected POST endpoints must reject unauthenticated access.
#[tokio::test]
async fn test_auth_vuln_01_unauth_post_endpoints() {
    let app = TestApp::new().await;
    assert_all_post_require_auth(&app, auth::PROTECTED_ENDPOINTS_POST).await;
}

/// AUTH-VULN-01: Health endpoint SHOULD remain accessible without auth.
/// This is a negative test — health is intentionally exempt.
#[tokio::test]
async fn test_auth_health_exempt() {
    let app = TestApp::new().await;
    let (status, body) = app.get("/api/v1/health").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Health endpoint should be accessible without auth, got {}",
        status
    );
    assert_eq!(body["status"], "ok");
}

/// AUTH-VULN-01: Root redirect SHOULD remain accessible without auth.
#[tokio::test]
async fn test_auth_root_exempt() {
    let app = TestApp::new().await;
    let (status, _body) = app.get("/").await;
    // Root may return 200 (dashboard) or 303 (redirect to onboard)
    assert!(
        status == StatusCode::OK
            || status == StatusCode::SEE_OTHER
            || status == StatusCode::TEMPORARY_REDIRECT,
        "Root should be accessible without auth, got {}",
        status
    );
}

/// AUTH-VULN-01: Verify that an invalid bearer token is rejected.
#[tokio::test]
async fn test_auth_invalid_token_rejected() {
    let app = TestApp::new().await;
    let (status, _body) = app.get_authed("/api/v1/identity", "totally-fake-token").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Invalid token should be rejected"
    );
}

/// AUTH-VULN-01: Verify that an empty Authorization header is rejected.
#[tokio::test]
async fn test_auth_empty_bearer_rejected() {
    let app = TestApp::new().await;
    let (status, _body) = app.get_authed("/api/v1/identity", "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Empty token should be rejected"
    );
}
