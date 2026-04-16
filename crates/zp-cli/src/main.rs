//! ZeroPoint CLI — terminal interface for developers.

mod chat;
mod commands;
mod configure;
mod guard;
mod init;
mod mesh_commands;
mod recover;
mod onboard;
#[cfg(feature = "policy-wasm")]
mod policy_commands;
mod secure;

use clap::{Parser, Subcommand};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use zp_core::{OperatorIdentity, TrustTier};
use zp_pipeline::{MeshConfig, Pipeline, PipelineConfig};

#[derive(Parser)]
#[command(name = "zp", about = "ZeroPoint CLI", version)]
struct Args {
    #[arg(global = true, long, default_value = "./data/zeropoint")]
    data_dir: PathBuf,

    #[arg(global = true, long, default_value = "tier0")]
    trust_tier: String,

    /// Enable mesh networking
    #[arg(global = true, long)]
    mesh: bool,

    /// TCP listen address for mesh (e.g. 127.0.0.1:4242)
    #[arg(global = true, long)]
    mesh_listen: Option<String>,

    /// Comma-separated TCP peer addresses (e.g. 10.0.0.2:4242,10.0.0.3:4242)
    #[arg(global = true, long)]
    mesh_peers: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the ZeroPoint server with verification surface
    Serve {
        /// Bind address (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,

        /// Port (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Don't open the dashboard in browser
        #[arg(long)]
        no_open: bool,
    },
    /// Interactive chat with the pipeline
    Chat,
    /// System health check
    Health,
    /// Audit trail operations
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Mesh networking operations
    #[command(subcommand)]
    Mesh(MeshCmd),
    /// Local-first command security evaluator
    Guard {
        /// The command to evaluate
        command: String,

        /// Silent mode — only output on deny
        #[arg(short, long)]
        silent: bool,

        /// Strict mode — require approval for high-risk commands
        #[arg(long)]
        strict: bool,

        /// Non-interactive mode — block instead of prompting
        #[arg(long)]
        non_interactive: bool,

        /// Actor type: human, codex, or agent
        #[arg(long, default_value = "human")]
        actor: String,
    },
    /// Secure your compute space — guided setup wizard
    Secure {
        /// Accept smart defaults without prompting
        #[arg(long)]
        accept_defaults: bool,

        /// Run in wizard mode (customize every choice)
        #[arg(long)]
        wizard: bool,

        /// Governance posture: permissive, balanced, strict
        #[arg(long, default_value = "balanced")]
        posture: String,

        /// Skip specific phases (comma-separated: shell,ai,network,filesystem)
        #[arg(long)]
        skip: Option<String>,
    },
    /// Show current governance status
    Status,
    /// Manage WASM policy modules
    #[command(subcommand)]
    Policy(PolicyCmd),

    /// Configure tools from vault (Semantic Sed)
    #[command(subcommand)]
    Configure(ConfigureCmd),

    /// Initialize a new ZeroPoint environment
    ///
    /// Three tiers:
    ///   zp init                        Tier A: Quick Start (30 seconds, auto-detect everything)
    ///   zp init --wizard               Tier B: Guided Setup (choose sovereignty, posture, etc.)
    ///   zp init --config genesis.toml  Tier C: Headless (CI/CD, fleet deploy)
    Init {
        /// Operator name (defaults to system username)
        #[arg(long)]
        name: Option<String>,

        /// Directory to initialize (defaults to current directory)
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Sovereignty mode: how the genesis secret is gated.
        /// Options: auto (default), touch-id, fingerprint, face-enroll, windows-hello,
        ///          yubikey, ledger, trezor, onlykey, login-password, file-based
        #[arg(long, default_value = "auto")]
        sovereignty: String,

        /// Tier B: Interactive wizard — choose sovereignty mode, posture, mesh, DLT
        #[arg(long)]
        wizard: bool,

        /// Tier C: Headless — read all answers from a TOML file (no interactive prompts)
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Interactive setup — discover tools, add credentials, configure everything
    Onboard {
        /// Directory to scan for tools (defaults to current directory)
        #[arg(long, default_value = ".")]
        path: PathBuf,

        /// Scan depth (1 = immediate children, 2 = grandchildren)
        #[arg(long, default_value = "2")]
        depth: usize,

        /// ZP server port for proxy mode (default: 3000)
        #[arg(long, default_value = "3000")]
        proxy_port: u16,
    },

    /// Key lifecycle management
    #[command(subcommand)]
    Keys(KeysCmd),

    /// Restore genesis identity from 24-word recovery mnemonic
    ///
    /// Use this when the OS credential store has been lost (Keychain wiped,
    /// machine migration, factory reset). Reads 24 BIP-39 words, verifies
    /// against the genesis certificate, and re-seals the secret.
    Recover,

    /// Gate evaluation and management
    #[command(subcommand)]
    Gate(GateCmd),

    /// Run the catalog grammar verifier (zp-verify v0: P1, M3, M4) over the audit chain
    Verify {
        /// Path to the audit SQLite store (default: <data-dir>/audit.db)
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit machine-readable JSON instead of formatted text
        #[arg(long)]
        json: bool,
    },

    /// Manage ZeroPoint configuration
    #[command(subcommand, name = "config")]
    Cfg(CfgCmd),

    /// Run post-install diagnostics — check everything and report problems
    Doctor {
        /// Output as JSON (machine-readable)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Load a WASM policy module from a file
    Load {
        /// Path to the .wasm policy module
        path: String,
    },
    /// List installed policy modules
    List,
    /// Show full policy engine status (native rules + WASM modules)
    Status,
    /// Verify integrity of installed WASM modules
    Verify,
    /// Remove an installed policy module by name or hash prefix
    Remove {
        /// Module name or content hash prefix
        identifier: String,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Show recent audit entries
    Log {
        /// Number of entries to show (default: 20)
        #[arg(long, default_value = "20")]
        limit: usize,

        /// Filter by category (e.g. "gate", "key", "policy")
        #[arg(long)]
        category: Option<String>,
    },
    /// Verify audit chain integrity
    Verify,
}

#[derive(Subcommand)]
enum MeshCmd {
    /// Show mesh node status, identity, and runtime stats
    Status,
    /// List known peers and their reputation
    Peers,
    /// Challenge a peer's audit trail
    Challenge {
        /// The peer address (hex) to challenge
        peer: String,
        /// Only challenge since this hash (optional)
        #[arg(long)]
        since: Option<String>,
    },
    /// Grant a capability to a peer
    Grant {
        /// The peer address (hex) to grant to
        peer: String,
        /// Capability type: read, write, execute, api, mesh-send, or config
        #[arg(long, default_value = "read")]
        capability: String,
        /// Scope paths (comma-separated)
        #[arg(long, default_value = "*")]
        scope: String,
    },
    /// Save current mesh state to persistent store
    Save,
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Issue a new agent key with scoped capabilities
    Issue {
        /// Agent name / subject
        #[arg(long)]
        name: String,

        /// Comma-separated capabilities (e.g. "tool:*,llm:query")
        #[arg(long)]
        capabilities: Option<String>,

        /// Expiration in days (default: 90)
        #[arg(long, default_value = "90")]
        expires_days: u64,
    },
    /// List all keys in the keyring
    List,
    /// Revoke an agent key by name
    Revoke {
        /// Agent name to revoke
        name: String,
    },
}

#[derive(Subcommand)]
enum GateCmd {
    /// Evaluate a request against the full gate stack
    Eval {
        /// Action to evaluate (e.g. "read sensor data", "delete all logs")
        action: String,

        /// Resource path (e.g. "/etc/passwd")
        #[arg(long)]
        resource: Option<String>,

        /// Agent identity (public key hex prefix)
        #[arg(long)]
        agent: Option<String>,
    },
    /// Install a custom WASM gate
    Add {
        /// Path to .wasm policy module
        path: String,
    },
    /// List installed gates (constitutional + custom)
    List,
}

#[derive(Subcommand)]
enum ConfigureCmd {
    /// Configure a tool's .env from the ZP vault
    Tool {
        /// Path to the tool's project directory (containing .env.example)
        #[arg(long)]
        path: PathBuf,

        /// Tool name (used for policy context and audit)
        #[arg(long)]
        name: String,

        /// Dry run — show what would be resolved without writing
        #[arg(long)]
        dry_run: bool,
    },
    /// List providers registered in the vault
    Providers,
    /// Add a credential to the vault
    VaultAdd {
        /// Provider name (e.g., anthropic, openai, ollama)
        #[arg(long)]
        provider: String,

        /// Field name (e.g., api_key, password, secret)
        #[arg(long)]
        field: String,

        /// Credential value (omit to read from stdin)
        #[arg(long)]
        value: Option<String>,
    },
    /// Scan for configurable tools and report readiness
    Scan {
        /// Directory to scan (defaults to current directory)
        #[arg(long, default_value = ".")]
        path: PathBuf,

        /// Scan depth: 1 = immediate children, 2 = grandchildren too
        #[arg(long, default_value = "2")]
        depth: usize,
    },
    /// Auto-configure all discovered tools that have sufficient vault credentials
    Auto {
        /// Directory to scan (defaults to current directory)
        #[arg(long, default_value = ".")]
        path: PathBuf,

        /// Scan depth: 1 = immediate children, 2 = grandchildren too
        #[arg(long, default_value = "2")]
        depth: usize,

        /// Dry run — show what would be configured without writing
        #[arg(long)]
        dry_run: bool,

        /// Overwrite existing .env files (default: skip them)
        #[arg(long)]
        overwrite: bool,

        /// Route API calls through ZP proxy for governance, metering, and receipts.
        /// Rewrites all provider base URLs to http://localhost:{port}/api/v1/proxy/{provider}.
        #[arg(long)]
        proxy: bool,

        /// ZP server port for proxy mode (default: 3000)
        #[arg(long, default_value = "3000")]
        proxy_port: u16,

        /// Validate credentials against live APIs after configuration
        #[arg(long)]
        validate: bool,
    },
    /// Generate a .zp-configure.toml manifest for a tool (MVC)
    Manifest {
        /// Path to the tool's project directory
        #[arg(long)]
        path: PathBuf,
    },
    /// Validate vault credentials against provider APIs (live connection test)
    Validate {
        /// Only validate a specific provider (e.g., "openai", "anthropic")
        #[arg(long)]
        provider: Option<String>,

        /// Output results as JSON instead of formatted text
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CfgCmd {
    /// Show all configuration with provenance (where each value came from)
    Show,
    /// Set a configuration value in ~/.zeropoint/config.toml
    Set {
        /// Config key (e.g. "port", "posture", "log_level")
        key: String,
        /// New value
        value: String,
    },
    /// Validate configuration for internal consistency
    Validate {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Serve runs the HTTP server with verification surface
    if let Some(Commands::Serve {
        bind,
        port,
        no_open,
    }) = &args.command
    {
        #[cfg(feature = "embedded-server")]
        {
            let config = zp_server::ServerConfig {
                bind_addr: bind.clone(),
                port: *port,
                open_dashboard: !no_open,
                ..zp_server::ServerConfig::default()
            };
            if let Err(e) = zp_server::run_server(config).await {
                eprintln!("Server error: {}", e);
                std::process::exit(1);
            }
            return Ok(());
        }
        #[cfg(not(feature = "embedded-server"))]
        {
            // Without the embedded-server feature, launch zp-server as a subprocess
            let mut cmd = std::process::Command::new("zp-server");
            cmd.env("ZP_BIND", bind);
            cmd.env("ZP_PORT", port.to_string());
            if *no_open {
                cmd.env("ZP_NO_OPEN", "1");
            }
            match cmd.status() {
                Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("Failed to launch zp-server: {}", e);
                    eprintln!("Ensure zp-server is installed and on your PATH,");
                    eprintln!(
                        "or rebuild zp-cli with: cargo build -p zp-cli --features embedded-server"
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    // Guard runs synchronously without needing the pipeline
    if let Some(Commands::Guard {
        command: cmd,
        silent,
        strict,
        non_interactive,
        actor,
    }) = &args.command
    {
        let actor: guard::Actor = actor.parse().unwrap_or_default();
        let config = guard::GuardConfig {
            silent: *silent,
            strict: *strict,
            interactive: !*non_interactive,
            actor,
        };
        let exit_code = guard::run(&config, cmd);
        std::process::exit(exit_code);
    }

    // Secure runs the guided setup wizard — no pipeline needed
    if let Some(Commands::Secure {
        accept_defaults,
        wizard,
        posture,
        skip,
    }) = &args.command
    {
        let skip_phases: Vec<String> = skip
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_lowercase())
            .collect();

        let config = secure::SecureConfig {
            accept_defaults: *accept_defaults,
            wizard: *wizard,
            posture: posture.parse().unwrap_or(secure::Posture::Balanced),
            skip_phases,
        };
        let exit_code = secure::run(&config);
        std::process::exit(exit_code);
    }

    // Status shows current governance state — no pipeline needed
    if matches!(&args.command, Some(Commands::Status)) {
        let exit_code = secure::status();
        std::process::exit(exit_code);
    }

    // Configure — semantic sed for tool .env files, no pipeline needed
    if let Some(Commands::Configure(cmd)) = &args.command {
        // Resolve vault master key: Genesis secret (Keychain) → derive → vault key
        let home_zp = commands::resolve_zp_home();
        let keyring = zp_keys::Keyring::open(home_zp.join("keys")).ok();
        let resolved = match &keyring {
            Some(kr) => match zp_keys::resolve_vault_key(kr) {
                Ok(r) => r,
                Err(ref e) if e.to_string().contains("credential store") => {
                    eprintln!();
                    eprintln!("  \x1b[31mCould not access OS credential store.\x1b[0m");
                    eprintln!("  {}", e);
                    eprintln!();
                    if cfg!(target_os = "macos") {
                        eprintln!(
                            "  On macOS: Ensure Keychain Access is available and not locked."
                        );
                        eprintln!("  If you denied Keychain access, open Keychain Access → find");
                        eprintln!("  'zeropoint-genesis' → delete it, then re-run `zp init`.");
                    } else if cfg!(target_os = "linux") {
                        eprintln!("  On Linux: Requires a running Secret Service (GNOME Keyring, KWallet).");
                        eprintln!("  Install: `sudo apt install gnome-keyring` or `sudo dnf install gnome-keyring`");
                        eprintln!(
                            "  For headless/CI: set SECRETS_MASTER_KEY env var (64 hex chars)."
                        );
                    }
                    eprintln!();
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!();
                    eprintln!("  \x1b[31mCould not resolve vault key.\x1b[0m");
                    eprintln!("  {}", e);
                    eprintln!();
                    eprintln!("  Run `zp init` to create your Genesis key.");
                    eprintln!();
                    std::process::exit(1);
                }
            },
            None => {
                eprintln!();
                eprintln!("  \x1b[31mNo keyring found at ~/.zeropoint/keys/\x1b[0m");
                eprintln!();
                eprintln!("  Run `zp init` to create your Genesis key.");
                eprintln!();
                std::process::exit(1);
            }
        };
        if resolved.source == zp_keys::VaultKeySource::LegacyEnvVar {
            eprintln!();
            eprintln!("  \x1b[33mNote:\x1b[0m Using SECRETS_MASTER_KEY env var (deprecated).");
            eprintln!("  Run `zp init` to switch to Genesis-derived vault key.");
        }
        if resolved.source == zp_keys::VaultKeySource::LegacyFileMigrated {
            eprintln!();
            eprintln!("  \x1b[33mNote:\x1b[0m Genesis secret loaded from disk file (legacy).");
            eprintln!("  It will auto-migrate to the OS credential store on next access with Keychain available.");
        }
        let padded_key = *resolved.key;

        // Allow-all policy for configure operations (vault access is the gate)
        fn configure_policy(
            _skill_id: &str,
            _credential_name: &str,
            _context: &zp_trust::injector::PolicyContext,
        ) -> Result<(), zp_trust::injector::InjectorError> {
            Ok(())
        }

        let vault_path = commands::resolve_zp_home().join("vault.json");

        let exit_code = match cmd {
            ConfigureCmd::Tool {
                path,
                name,
                dry_run,
            } => match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                Ok(vault) => configure::run_tool(path, name, *dry_run, &vault, configure_policy),
                Err(e) => {
                    eprintln!("Error loading vault: {}", e);
                    1
                }
            },
            ConfigureCmd::Providers => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => configure::run_providers(&vault),
                    Err(e) => {
                        eprintln!("Error loading vault: {}", e);
                        1
                    }
                }
            }
            ConfigureCmd::VaultAdd {
                provider,
                field,
                value,
            } => match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                Ok(mut vault) => {
                    let val = value.clone().unwrap_or_else(|| {
                        eprint!("Enter value for {}/{}: ", provider, field);
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input).unwrap_or(0);
                        input.trim().to_string()
                    });
                    configure::run_vault_add(&mut vault, provider, field, &val, &vault_path)
                }
                Err(e) => {
                    eprintln!("Error loading vault: {}", e);
                    1
                }
            },
            ConfigureCmd::Scan { path, depth } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => configure::run_scan(path, &vault, *depth),
                    Err(e) => {
                        eprintln!("Error loading vault: {}", e);
                        1
                    }
                }
            }
            ConfigureCmd::Auto {
                path,
                depth,
                dry_run,
                overwrite,
                proxy,
                proxy_port,
                validate,
            } => {
                let proxy_opt = if *proxy { Some(*proxy_port) } else { None };
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => {
                        let exit = configure::run_auto(
                            path,
                            &vault,
                            configure_policy,
                            *depth,
                            *dry_run,
                            *overwrite,
                            proxy_opt,
                        );
                        if *validate && exit == 0 && !*dry_run {
                            println!();
                            let v_exit = configure::run_validate(&vault, None, false);
                            if v_exit != 0 {
                                v_exit
                            } else {
                                exit
                            }
                        } else {
                            exit
                        }
                    }
                    Err(e) => {
                        eprintln!("Error loading vault: {}", e);
                        1
                    }
                }
            }
            ConfigureCmd::Manifest { path } => configure::run_manifest(path),
            ConfigureCmd::Validate { provider, json } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => configure::run_validate(&vault, provider.as_deref(), *json),
                    Err(e) => {
                        eprintln!("Error loading vault: {}", e);
                        1
                    }
                }
            }
        };
        std::process::exit(exit_code);
    }

    // Onboard — interactive credential wizard, no pipeline needed
    if let Some(Commands::Onboard {
        path,
        depth,
        proxy_port,
    }) = &args.command
    {
        let home_zp = commands::resolve_zp_home();
        let keyring = zp_keys::Keyring::open(home_zp.join("keys")).ok();
        let resolved = match &keyring {
            Some(kr) => match zp_keys::resolve_vault_key(kr) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!();
                    eprintln!("  \x1b[31mCould not resolve vault key.\x1b[0m {}", e);
                    eprintln!("  Run `zp init` first to create your Genesis key.");
                    eprintln!();
                    std::process::exit(1);
                }
            },
            None => {
                eprintln!();
                eprintln!("  \x1b[31mNo keyring found.\x1b[0m Run `zp init` first.");
                eprintln!();
                std::process::exit(1);
            }
        };
        let padded_key = *resolved.key;
        let vault_path = home_zp.join("vault.json");
        let mut vault =
            match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error loading vault: {}", e);
                    std::process::exit(1);
                }
            };
        let config = onboard::OnboardConfig {
            scan_path: path.clone(),
            depth: *depth,
            offer_proxy: true,
            proxy_port: *proxy_port,
        };
        std::process::exit(onboard::run(&config, &mut vault, &padded_key, &vault_path));
    }

    // Init — bootstrap a new ZeroPoint environment, no pipeline needed
    if let Some(Commands::Init {
        name,
        dir,
        sovereignty,
        wizard,
        config: genesis_config,
    }) = &args.command
    {
        let operator_name = name.clone().unwrap_or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "operator".to_string())
        });
        let project_dir = dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        // ── Tier C: Headless (from TOML config file) ──
        if let Some(config_path) = genesis_config {
            if !config_path.exists() {
                eprintln!(
                    "\x1b[31m✗\x1b[0m Genesis config not found: {}",
                    config_path.display()
                );
                std::process::exit(1);
            }
            let toml_str = match std::fs::read_to_string(config_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("\x1b[31m✗\x1b[0m Failed to read genesis config: {}", e);
                    std::process::exit(1);
                }
            };
            // Parse operator name and sovereignty mode from TOML
            let parsed: toml::Value = match toml_str.parse() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("\x1b[31m✗\x1b[0m Invalid TOML: {}", e);
                    std::process::exit(1);
                }
            };
            let cfg_name = parsed
                .get("operator")
                .and_then(|v: &toml::Value| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| operator_name.clone());
            let cfg_sov = parsed
                .get("sovereignty")
                .and_then(|v: &toml::Value| v.as_str())
                .map(zp_keys::SovereigntyMode::from_onboard_str)
                .unwrap_or_else(zp_keys::SovereigntyMode::auto_detect);

            let init_config = init::InitConfig {
                operator_name: cfg_name,
                project_dir,
                store_genesis_secret: true,
                sovereignty_mode: cfg_sov,
            };
            std::process::exit(init::run(&init_config));
        }

        // ── Tier B: Interactive Wizard ──
        if *wizard {
            eprintln!();
            eprintln!("  \x1b[1mZeroPoint Genesis — Guided Setup\x1b[0m");
            eprintln!("  \x1b[2m(Tier B: deliberate choices with sensible defaults)\x1b[0m");
            eprintln!();

            // Detect available providers and let the user choose
            let caps = zp_keys::detect_all_providers();
            let available: Vec<_> = caps.iter().filter(|c| c.available).collect();

            eprintln!("  Available sovereignty providers:");
            for (i, cap) in available.iter().enumerate() {
                let marker = if i == 0 { " (recommended)" } else { "" };
                eprintln!(
                    "    [{}] {} — {}{}",
                    i + 1,
                    cap.mode.display_name(),
                    cap.description,
                    marker
                );
            }
            eprint!("  Choose [1]: ");
            let mut choice = String::new();
            let _ = std::io::stdin().read_line(&mut choice);
            let idx: usize = choice.trim().parse().unwrap_or(1);
            let sovereignty_mode = available
                .get(idx.saturating_sub(1))
                .map(|c| c.mode)
                .unwrap_or_else(zp_keys::SovereigntyMode::auto_detect);

            let init_config = init::InitConfig {
                operator_name,
                project_dir,
                store_genesis_secret: true,
                sovereignty_mode,
            };
            std::process::exit(init::run(&init_config));
        }

        // ── Tier A: Quick Start (default) ──
        // Auto-detect everything. Single question: operator name.
        let sovereignty_mode = if sovereignty == "auto" {
            zp_keys::SovereigntyMode::auto_detect()
        } else {
            zp_keys::SovereigntyMode::from_onboard_str(sovereignty)
        };

        let init_config = init::InitConfig {
            operator_name,
            project_dir,
            store_genesis_secret: true,
            sovereignty_mode,
        };
        std::process::exit(init::run(&init_config));
    }

    // Keys — key lifecycle management, no pipeline needed
    if let Some(Commands::Keys(cmd)) = &args.command {
        let exit_code = match cmd {
            KeysCmd::Issue {
                name,
                capabilities,
                expires_days,
            } => commands::keys_issue(name, capabilities.as_deref(), *expires_days),
            KeysCmd::List => commands::keys_list(),
            KeysCmd::Revoke { name } => commands::keys_revoke(name),
        };
        std::process::exit(exit_code);
    }

    // Recover — restore genesis identity from mnemonic, no pipeline needed
    if let Some(Commands::Recover) = &args.command {
        std::process::exit(recover::run());
    }

    // Gate — gate evaluation and management, no pipeline needed
    if let Some(Commands::Gate(cmd)) = &args.command {
        let exit_code = match cmd {
            GateCmd::Eval {
                action,
                resource,
                agent,
            } => commands::gate_eval(action, resource.as_deref(), agent.as_deref()),
            #[cfg(feature = "policy-wasm")]
            GateCmd::Add { path } => policy_commands::load(path),
            #[cfg(not(feature = "policy-wasm"))]
            GateCmd::Add { .. } => {
                eprintln!("WASM policy loading requires the 'policy-wasm' feature.\nRebuild with: cargo build --features policy-wasm");
                1
            }
            GateCmd::List => commands::gate_list(),
        };
        std::process::exit(exit_code);
    }

    // Verify — run the catalog grammar verifier over the audit chain. No pipeline needed.
    if let Some(Commands::Verify { audit_db, json }) = &args.command {
        let db_path = audit_db
            .clone()
            .unwrap_or_else(|| args.data_dir.join("audit.db"));
        let store = match zp_audit::AuditStore::open(&db_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error opening audit store at {}: {}", db_path.display(), e);
                std::process::exit(2);
            }
        };
        let report = match store.verify_with_catalog() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error verifying chain: {}", e);
                std::process::exit(2);
            }
        };
        if *json {
            match serde_json::to_string_pretty(&report) {
                Ok(s) => println!("{}", s),
                Err(e) => {
                    eprintln!("Error serializing report: {}", e);
                    std::process::exit(2);
                }
            }
        } else {
            println!("zp-verify v0 — catalog rules: P1, M3, M4");
            println!("audit_db:        {}", db_path.display());
            println!("receipts_checked: {}", report.receipts_checked);
            if report.violations().is_empty() {
                println!(
                    "result:          \x1b[32mACCEPT\x1b[0m — chain parses against the v0 grammar"
                );
            } else {
                println!(
                    "result:          \x1b[31mREJECT\x1b[0m — {} violation(s)",
                    report.violations().len()
                );
                println!();
                println!("violations:");
                for v in report.violations() {
                    println!("  [{}] entry={} {}", v.rule, v.entry_id, v.description);
                }
            }
        }
        std::process::exit(if report.violations().is_empty() { 0 } else { 1 });
    }

    // Config subcommand — unified configuration management
    if let Some(Commands::Cfg(cmd)) = &args.command {
        match cmd {
            CfgCmd::Show => {
                let cfg = zp_config::ConfigResolver::resolve_standard();
                println!("{}", cfg.show());
            }
            CfgCmd::Set { key, value } => match zp_config::resolve::config_set(key, value) {
                Ok(()) => {
                    println!("\x1b[32m✓\x1b[0m {} = {}", key, value);
                    println!("  Written to ~/.zeropoint/config.toml");
                }
                Err(e) => {
                    eprintln!("\x1b[31m✗\x1b[0m {}", e);
                    std::process::exit(1);
                }
            },
            CfgCmd::Validate { json } => {
                let cfg = zp_config::ConfigResolver::resolve_standard();
                let errors = zp_config::validate(&cfg);
                if *json {
                    let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                    println!(
                        "{}",
                        serde_json::json!({
                            "valid": errors.is_empty(),
                            "errors": msgs
                        })
                    );
                } else if errors.is_empty() {
                    println!("\x1b[32m✓\x1b[0m Configuration is valid");
                } else {
                    for e in &errors {
                        eprintln!("\x1b[31m✗\x1b[0m {}", e);
                    }
                    std::process::exit(1);
                }
            }
        }
        std::process::exit(0);
    }

    // Doctor — post-install diagnostics
    if let Some(Commands::Doctor { json }) = &args.command {
        let cfg = zp_config::ConfigResolver::resolve_standard();
        let home = &cfg.home_dir.value;
        let data = &cfg.data_dir.value;

        struct Check {
            label: String,
            status: &'static str, // "pass", "fail", "warn"
            detail: String,
            fix: String,
        }

        let mut checks: Vec<Check> = Vec::new();

        // 1. Binary version
        let ver = env!("CARGO_PKG_VERSION");
        checks.push(Check {
            label: "Binary version".into(),
            status: "pass",
            detail: format!("zp {ver}"),
            fix: String::new(),
        });

        // 2. Genesis key
        let genesis_path = home.join("genesis.json");
        if genesis_path.exists() {
            checks.push(Check {
                label: "Genesis key".into(),
                status: "pass",
                detail: format!("{}", genesis_path.display()),
                fix: String::new(),
            });
        } else {
            checks.push(Check {
                label: "Genesis key".into(),
                status: "fail",
                detail: "genesis.json not found".into(),
                fix: "Run: zp init".into(),
            });
        }

        // 3. Config file
        let config_path = home.join("config.toml");
        if config_path.exists() {
            let cfg_errors = zp_config::validate(&cfg);
            if cfg_errors.is_empty() {
                checks.push(Check {
                    label: "Configuration".into(),
                    status: "pass",
                    detail: format!("{} (valid)", config_path.display()),
                    fix: String::new(),
                });
            } else {
                checks.push(Check {
                    label: "Configuration".into(),
                    status: "warn",
                    detail: format!("{} ({} issue(s))", config_path.display(), cfg_errors.len()),
                    fix: "Run: zp config validate".into(),
                });
            }
        } else {
            checks.push(Check {
                label: "Configuration".into(),
                status: "warn",
                detail: "No config file — using defaults".into(),
                fix: format!("Run: zp config set port {}", cfg.port.value),
            });
        }

        // 4. Data directory
        if data.exists() {
            let perms = {
                #[cfg(unix)]
                {
                    std::fs::metadata(data)
                        .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
                        .unwrap_or_else(|_| "?".into())
                }
                #[cfg(not(unix))]
                {
                    "n/a".to_string()
                }
            };
            checks.push(Check {
                label: "Data directory".into(),
                status: "pass",
                detail: format!("{} (mode {})", data.display(), perms),
                fix: String::new(),
            });
        } else {
            checks.push(Check {
                label: "Data directory".into(),
                status: "warn",
                detail: "Not created yet — will be created on first run".into(),
                fix: format!("mkdir -p {}", data.display()),
            });
        }

        // 5. Port availability
        let port = cfg.port.value;
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(_) => {
                checks.push(Check {
                    label: format!("Port {port}"),
                    status: "pass",
                    detail: "available".into(),
                    fix: String::new(),
                });
            }
            Err(_) => {
                checks.push(Check {
                    label: format!("Port {port}"),
                    status: "warn",
                    detail: "in use (server may already be running)".into(),
                    fix: "Kill the process or: zp config set port <other>".to_string(),
                });
            }
        }

        // 6. Audit chain
        let audit_db = data.join("audit.db");
        if audit_db.exists() {
            if let Ok(store) = zp_audit::AuditStore::open(&audit_db) {
                match store.verify_with_catalog() {
                    Ok(report) => {
                        if report.violations().is_empty() {
                            checks.push(Check {
                                label: "Audit chain".into(),
                                status: "pass",
                                detail: format!(
                                    "{} entries, integrity verified",
                                    report.receipts_checked
                                ),
                                fix: String::new(),
                            });
                        } else {
                            checks.push(Check {
                                label: "Audit chain".into(),
                                status: "fail",
                                detail: format!("{} violation(s) found", report.violations().len()),
                                fix: "Run: zp verify --audit-db for details".into(),
                            });
                        }
                    }
                    Err(e) => {
                        checks.push(Check {
                            label: "Audit chain".into(),
                            status: "warn",
                            detail: format!("verification error: {e}"),
                            fix: String::new(),
                        });
                    }
                }
            }
        } else {
            checks.push(Check {
                label: "Audit chain".into(),
                status: "pass",
                detail: "No audit data yet (clean install)".into(),
                fix: String::new(),
            });
        }

        // ── Output ──
        let fail_count = checks.iter().filter(|c| c.status == "fail").count();
        let warn_count = checks.iter().filter(|c| c.status == "warn").count();

        if *json {
            let entries: Vec<serde_json::Value> = checks
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "label": c.label,
                        "status": c.status,
                        "detail": c.detail,
                        "fix": c.fix
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "checks": entries,
                    "failures": fail_count,
                    "warnings": warn_count,
                    "healthy": fail_count == 0
                })
            );
        } else {
            println!();
            println!("  \x1b[1mzp doctor\x1b[0m");
            println!("  ─────────────────────────────────────────");
            for c in &checks {
                let icon = match c.status {
                    "pass" => "\x1b[32m✓\x1b[0m",
                    "fail" => "\x1b[31m✗\x1b[0m",
                    "warn" => "\x1b[33m⚠\x1b[0m",
                    _ => "?",
                };
                println!("  {icon} {}: {}", c.label, c.detail);
                if !c.fix.is_empty() && c.status != "pass" {
                    println!("    → Fix: {}", c.fix);
                }
            }
            println!();
            if fail_count == 0 {
                println!("  \x1b[32m✓ System healthy\x1b[0m ({warn_count} warning(s))");
            } else {
                println!("  \x1b[31m✗ {fail_count} failure(s), {warn_count} warning(s)\x1b[0m");
            }
            println!();
        }

        std::process::exit(if fail_count == 0 { 0 } else { 1 });
    }

    // Policy subcommand — manages WASM policy modules (requires policy-wasm feature)
    if let Some(Commands::Policy(_cmd)) = &args.command {
        #[cfg(feature = "policy-wasm")]
        let exit_code = match _cmd {
            PolicyCmd::Load { path } => policy_commands::load(path),
            PolicyCmd::List => policy_commands::list(),
            PolicyCmd::Status => policy_commands::status(),
            PolicyCmd::Verify => policy_commands::verify(),
            PolicyCmd::Remove { identifier } => policy_commands::remove(identifier),
        };
        #[cfg(not(feature = "policy-wasm"))]
        let exit_code = {
            eprintln!("WASM policy management requires the 'policy-wasm' feature.\nRebuild with: cargo build --features policy-wasm");
            1
        };
        std::process::exit(exit_code);
    }

    let trust_tier = match args.trust_tier.as_str() {
        "tier0" => TrustTier::Tier0,
        "tier1" => TrustTier::Tier1,
        "tier2" => TrustTier::Tier2,
        _ => TrustTier::Tier0,
    };

    // Build mesh config if --mesh flag is set or a mesh subcommand is used
    let needs_mesh = args.mesh || matches!(args.command, Some(Commands::Mesh(_)));
    let mesh_config = if needs_mesh {
        Some(MeshConfig {
            tcp_listen: args.mesh_listen.clone(),
            tcp_peers: args
                .mesh_peers
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            ..Default::default()
        })
    } else {
        None
    };

    let config = PipelineConfig {
        operator_identity: OperatorIdentity::default(),
        trust_tier,
        data_dir: args.data_dir,
        mesh: mesh_config.clone(),
    };

    // Stage 3 (AUDIT-03): CLI owns the single AuditStore and hands it to
    // the pipeline. No second handle is ever opened for the same process.
    let audit_db = config.data_dir.join("audit.db");
    std::fs::create_dir_all(&config.data_dir).ok();
    let audit_store = std::sync::Arc::new(std::sync::Mutex::new(
        zp_audit::AuditStore::open(&audit_db)
            .map_err(|e| anyhow::anyhow!("audit store open: {}", e))?,
    ));
    let mut pipeline = Pipeline::new(config, audit_store)?;

    // Initialize execution engine (detect available runtimes)
    if let Err(e) = pipeline.init_execution_engine().await {
        eprintln!("Warning: execution engine unavailable: {}", e);
    }

    // Initialize mesh if needed
    if let Some(ref mc) = mesh_config {
        if let Err(e) = pipeline.init_mesh(mc).await {
            eprintln!("Error: failed to initialize mesh: {}", e);
            std::process::exit(1);
        }
    }

    match args.command {
        None | Some(Commands::Chat) => chat::run(&pipeline).await?,
        Some(Commands::Health) => commands::health(&pipeline).await?,
        Some(Commands::Audit(AuditCmd::Verify)) => commands::audit_verify(&pipeline).await?,
        Some(Commands::Audit(AuditCmd::Log { limit, category })) => {
            commands::audit_log(&pipeline, limit, category.as_deref()).await?
        }
        Some(Commands::Guard { .. }) => unreachable!(), // handled above
        Some(Commands::Serve { .. }) => unreachable!(), // handled above
        Some(Commands::Secure { .. }) => unreachable!(), // handled above
        Some(Commands::Status) => unreachable!(),       // handled above
        Some(Commands::Policy(_)) => unreachable!(),    // handled above
        Some(Commands::Configure(_)) => unreachable!(), // handled above
        Some(Commands::Init { .. }) => unreachable!(),  // handled above
        Some(Commands::Onboard { .. }) => unreachable!(), // handled above
        Some(Commands::Keys(_)) => unreachable!(),      // handled above
        Some(Commands::Recover) => unreachable!(),      // handled above
        Some(Commands::Gate(_)) => unreachable!(),      // handled above
        Some(Commands::Verify { .. }) => unreachable!(), // handled above
        Some(Commands::Cfg(_)) => unreachable!(),       // handled above
        Some(Commands::Doctor { .. }) => unreachable!(), // handled above
        Some(Commands::Mesh(cmd)) => match cmd {
            MeshCmd::Status => mesh_commands::status(&pipeline).await?,
            MeshCmd::Peers => mesh_commands::peers(&pipeline).await?,
            MeshCmd::Challenge { peer, since } => {
                mesh_commands::challenge(&pipeline, &peer, since.as_deref()).await?
            }
            MeshCmd::Grant {
                peer,
                capability,
                scope,
            } => mesh_commands::grant(&pipeline, &peer, &capability, &scope).await?,
            MeshCmd::Save => mesh_commands::save(&pipeline).await?,
        },
    }

    Ok(())
}
