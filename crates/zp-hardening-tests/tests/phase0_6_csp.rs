//! Phase 0.6 — Content-Security-Policy header regression tests.
//!
//! Tests that CSP headers are present on all responses to mitigate:
//! - XSS-VULN-01: Auto-fire stored XSS via tool.name (dashboard)
//! - XSS-VULN-06: Auto-fire stored XSS via tool.name (ecosystem)
//! - XSS-VULN-09: Auto-fire stored XSS via tool_name (onboard scan)
//!
//! Before Phase 0.6 lands, these tests SHOULD FAIL.
//! After Phase 0.6, they MUST PASS.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use zp_hardening_tests::harness::TestApp;

/// Helper: check that a response includes a Content-Security-Policy header.
async fn assert_has_csp(app: &TestApp, path: &str) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;

    let csp = resp.headers().get("content-security-policy");
    assert!(
        csp.is_some(),
        "XSS: Response to GET {} is missing Content-Security-Policy header",
        path
    );

    let csp_value = csp.unwrap().to_str().unwrap_or("");

    // CSP must at minimum include script-src restrictions
    assert!(
        csp_value.contains("script-src"),
        "XSS: CSP header on {} does not restrict script-src: '{}'",
        path,
        csp_value
    );

    // Must not allow unsafe-inline for scripts (that defeats the purpose)
    assert!(
        !csp_value.contains("script-src 'unsafe-inline'")
            && !csp_value.contains("script-src *"),
        "XSS: CSP header on {} allows unsafe-inline or wildcard scripts: '{}'",
        path,
        csp_value
    );
}

// ============================================================================
// XSS-VULN-01/06/09: CSP headers on all page responses
// ============================================================================

/// XSS-VULN-01: Dashboard response must include CSP header.
#[tokio::test]
async fn test_xss_vuln_01_dashboard_csp() {
    let app = TestApp::new().await;
    assert_has_csp(&app, "/dashboard").await;
}

/// XSS-VULN-06: Ecosystem page response must include CSP header.
#[tokio::test]
async fn test_xss_vuln_06_ecosystem_csp() {
    let app = TestApp::new().await;
    assert_has_csp(&app, "/ecosystem").await;
}

/// XSS-VULN-09: Onboard page response must include CSP header.
#[tokio::test]
async fn test_xss_vuln_09_onboard_csp() {
    let app = TestApp::new().await;
    assert_has_csp(&app, "/onboard").await;
}

/// Health endpoint should also have CSP (defense in depth).
#[tokio::test]
async fn test_csp_on_health() {
    let app = TestApp::new().await;
    assert_has_csp(&app, "/api/v1/health").await;
}

/// Root redirect should also have CSP.
#[tokio::test]
async fn test_csp_on_root() {
    let app = TestApp::new().await;
    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    // Root may redirect, but should still have CSP on the redirect response
    let csp = resp.headers().get("content-security-policy");
    assert!(
        csp.is_some(),
        "XSS: Root response is missing Content-Security-Policy header"
    );
}
