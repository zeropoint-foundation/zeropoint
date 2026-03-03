//! ZeroPoint v2 HTTP Server
//!
//! Thin wrapper around `zp_server::run_server()`.
//! For the unified CLI, use `zp serve` instead.

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("zp=debug".parse().unwrap()))
        .init();

    // Standalone server mode: don't auto-open browser
    let config = zp_server::ServerConfig {
        open_dashboard: false,
        ..zp_server::ServerConfig::default()
    };

    if let Err(e) = zp_server::run_server(config).await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}
