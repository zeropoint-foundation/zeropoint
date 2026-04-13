//! ZeroPoint HTTP Server
//!
//! Thin wrapper around `zp_server::run_server()`.
//! For the unified CLI, use `zp serve` instead.

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Resolve configuration: defaults → system config → project config → env vars
    let zp_cfg = zp_config::ConfigResolver::resolve_standard();

    // Initialise logging at the configured level
    let filter = format!("zp=debug,{}", zp_cfg.log_level.value);
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(filter.parse().unwrap_or_else(|_| "zp=debug".parse().unwrap())))
        .init();

    // Log the provenance banner so operators can see where each setting came from
    eprintln!("{}", zp_cfg.provenance_banner());

    // Validate config
    let errors = zp_config::validate(&zp_cfg);
    for err in &errors {
        tracing::warn!("Config: {}", err);
    }

    // Standalone server mode: don't auto-open browser
    let mut config = zp_server::ServerConfig::from_zp_config(&zp_cfg);
    config.open_dashboard = false;

    if let Err(e) = zp_server::run_server(config).await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}
