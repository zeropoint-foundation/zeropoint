//! Test harness — boots zp-server in-process for regression replay.
//!
//! Two modes:
//! 1. `TestApp` — in-process Router for fast HTTP-only tests (no network).
//! 2. `TestServer` — real TCP listener for WebSocket tests.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// In-process test app — wraps the Axum router for `oneshot` requests.
///
/// Each test gets its own `TestApp` with an isolated temp data directory,
/// so tests never interfere with each other or with a running ZP instance.
pub struct TestApp {
    pub router: Router,
    pub config: zp_server::ServerConfig,
    _temp_dir: tempfile::TempDir,
}

impl TestApp {
    /// Create a new test app with an isolated temporary data directory.
    ///
    /// The server is configured with:
    /// - LLM disabled (no external API calls)
    /// - Random high port (irrelevant for oneshot tests, but set for consistency)
    /// - Dashboard open disabled
    /// - Bind to 127.0.0.1
    pub async fn new() -> Self {
        let temp_dir = tempfile::TempDir::new().expect("failed to create temp dir");
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("failed to create data dir");

        // Create a minimal home directory structure with canon permissions (0700)
        // so enforce_canon_permissions() doesn't process::exit(1) the test runner.
        let home_dir = temp_dir.path().to_path_buf();
        let keys_dir = home_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).expect("failed to create keys dir");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home_dir, std::fs::Permissions::from_mode(0o700))
                .expect("failed to chmod home_dir");
            std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))
                .expect("failed to chmod keys_dir");
        }

        let config = zp_server::ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            port: 0, // unused for oneshot tests
            data_dir: data_dir.to_string_lossy().to_string(),
            home_dir,
            open_dashboard: false,
            llm_enabled: false,
            operator_name: "hardening-test".to_string(),
            bridge_dir: None,
        };

        let state = zp_server::AppState::init(&config).await;
        let router = zp_server::build_app(state, &config);

        Self {
            router,
            config,
            _temp_dir: temp_dir,
        }
    }

    /// Send an HTTP request through the router and return the response.
    ///
    /// This is the core test primitive. Each call clones the router (Axum
    /// routers are cheaply cloneable) and sends one request through it.
    pub async fn request(&self, req: Request<Body>) -> Response<Body> {
        self.router
            .clone()
            .oneshot(req)
            .await
            .expect("oneshot request failed")
    }

    /// Convenience: GET a path, return status code + JSON body.
    pub async fn get(&self, path: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = self.request(req).await;
        let status = resp.status();
        let body = collect_body(resp).await;
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// Convenience: POST JSON to a path, return status code + JSON body.
    pub async fn post_json(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        let resp = self.request(req).await;
        let status = resp.status();
        let body = collect_body(resp).await;
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// Convenience: POST JSON with Authorization header.
    pub async fn post_json_authed(
        &self,
        path: &str,
        payload: serde_json::Value,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        let resp = self.request(req).await;
        let status = resp.status();
        let body = collect_body(resp).await;
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// Convenience: GET with Authorization header.
    pub async fn get_authed(&self, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let resp = self.request(req).await;
        let status = resp.status();
        let body = collect_body(resp).await;
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }
}

/// A test server with a real TCP listener for WebSocket tests.
///
/// WebSocket upgrades require a real HTTP connection, so these tests
/// bind to a random port on localhost and connect via tokio-tungstenite.
pub struct TestServer {
    pub addr: SocketAddr,
    pub config: zp_server::ServerConfig,
    pub session_token: String,
    _temp_dir: tempfile::TempDir,
    _server_handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Boot a real server on a random port. Returns once the listener is ready.
    pub async fn new() -> Self {
        let temp_dir = tempfile::TempDir::new().expect("failed to create temp dir");
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("failed to create data dir");

        let home_dir = temp_dir.path().to_path_buf();
        let keys_dir = home_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).expect("failed to create keys dir");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home_dir, std::fs::Permissions::from_mode(0o700))
                .expect("failed to chmod home_dir");
            std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))
                .expect("failed to chmod keys_dir");
        }

        // Bind to port 0 to get a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let addr = listener.local_addr().expect("failed to get local addr");

        let config = zp_server::ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            port: addr.port(),
            data_dir: data_dir.to_string_lossy().to_string(),
            home_dir,
            open_dashboard: false,
            llm_enabled: false,
            operator_name: "hardening-test".to_string(),
            bridge_dir: None,
        };

        let state = zp_server::AppState::init(&config).await;
        let session_token = state.session_token();
        let app = zp_server::build_app(state, &config);

        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        Self {
            addr,
            config,
            session_token,
            _temp_dir: temp_dir,
            _server_handle: server_handle,
        }
    }

    /// Base URL for HTTP requests (e.g., "http://127.0.0.1:12345").
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// WebSocket URL (e.g., "ws://127.0.0.1:12345/ws/exec").
    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}?token={}", self.addr, path, self.session_token)
    }
}

/// Collect a response body into bytes.
async fn collect_body(resp: Response<Body>) -> Vec<u8> {
    use http_body_util::BodyExt;
    let body = resp.into_body();
    let collected = body.collect().await.expect("failed to collect body");
    collected.to_bytes().to_vec()
}
