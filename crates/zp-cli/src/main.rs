//! ZeroPoint CLI — terminal interface for developers.

mod chat;
mod commands;
mod configure;
mod guard;
mod init;
mod mesh_commands;
mod onboard;
mod policy_commands;
mod secure;

use clap::{Parser, Subcommand};
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
    Init {
        /// Operator name (defaults to system username)
        #[arg(long)]
        name: Option<String>,

        /// Directory to initialize (defaults to current directory)
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Sovereignty mode: how the genesis secret is gated.
        /// Options: touch-id, fingerprint, face-enroll, windows-hello,
        ///          yubikey, ledger, trezor, onlykey,
        ///          login-password, file-based
        /// Default: auto-detect (best available biometric/hardware, else login-password)
        #[arg(long, default_value = "auto")]
        sovereignty: String,
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

    /// Gate evaluation and management
    #[command(subcommand)]
    Gate(GateCmd),
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
                        eprintln!("  On macOS: Ensure Keychain Access is available and not locked.");
                        eprintln!("  If you denied Keychain access, open Keychain Access → find");
                        eprintln!("  'zeropoint-genesis' → delete it, then re-run `zp init`.");
                    } else if cfg!(target_os = "linux") {
                        eprintln!("  On Linux: Requires a running Secret Service (GNOME Keyring, KWallet).");
                        eprintln!("  Install: `sudo apt install gnome-keyring` or `sudo dnf install gnome-keyring`");
                        eprintln!("  For headless/CI: set SECRETS_MASTER_KEY env var (64 hex chars).");
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
            ConfigureCmd::Tool { path, name, dry_run } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => configure::run_tool(path, name, *dry_run, &vault, configure_policy),
                    Err(e) => {
                        eprintln!("Error loading vault: {}", e);
                        1
                    }
                }
            }
            ConfigureCmd::Providers => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => configure::run_providers(&vault),
                    Err(e) => {
                        eprintln!("Error loading vault: {}", e);
                        1
                    }
                }
            }
            ConfigureCmd::VaultAdd { provider, field, value } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
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
                }
            }
            ConfigureCmd::Scan { path, depth } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => configure::run_scan(path, &vault, *depth),
                    Err(e) => {
                        eprintln!("Error loading vault: {}", e);
                        1
                    }
                }
            }
            ConfigureCmd::Auto { path, depth, dry_run, overwrite, proxy, proxy_port, validate } => {
                let proxy_opt = if *proxy { Some(*proxy_port) } else { None };
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => {
                        let exit = configure::run_auto(path, &vault, configure_policy, *depth, *dry_run, *overwrite, proxy_opt);
                        if *validate && exit == 0 && !*dry_run {
                            println!();
                            let v_exit = configure::run_validate(&vault, None, false);
                            if v_exit != 0 { v_exit } else { exit }
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
            ConfigureCmd::Manifest { path } => {
                configure::run_manifest(path)
            }
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
    if let Some(Commands::Onboard { path, depth, proxy_port }) = &args.command {
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
        let mut vault = match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
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
    if let Some(Commands::Init { name, dir, sovereignty }) = &args.command {
        let operator_name = name.clone().unwrap_or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "operator".to_string())
        });
        let project_dir = dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        // Resolve sovereignty mode: "auto" detects the best available provider
        let sovereignty_mode = if sovereignty == "auto" {
            // Auto-detect: pick the best available provider
            let caps = zp_keys::detect_all_providers();
            if let Some(best) = caps.iter().find(|c| c.available && c.mode.requires_hardware()) {
                eprintln!("  {} detected: {} — using {} sovereignty mode",
                    best.mode.display_name(), best.description, best.mode.display_name());
                best.mode
            } else if caps.iter().any(|c| c.available && c.mode == zp_keys::SovereigntyMode::LoginPassword) {
                zp_keys::SovereigntyMode::LoginPassword
            } else {
                zp_keys::SovereigntyMode::FileBased
            }
        } else {
            zp_keys::SovereigntyMode::from_onboard_str(&sovereignty)
        };

        let config = init::InitConfig {
            operator_name,
            project_dir,
            store_genesis_secret: true,
            sovereignty_mode,
        };
        std::process::exit(init::run(&config));
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

    // Gate — gate evaluation and management, no pipeline needed
    if let Some(Commands::Gate(cmd)) = &args.command {
        let exit_code = match cmd {
            GateCmd::Eval {
                action,
                resource,
                agent,
            } => commands::gate_eval(action, resource.as_deref(), agent.as_deref()),
            GateCmd::Add { path } => policy_commands::load(path),
            GateCmd::List => commands::gate_list(),
        };
        std::process::exit(exit_code);
    }

    // Policy subcommand — manages WASM policy modules, no pipeline needed
    if let Some(Commands::Policy(cmd)) = &args.command {
        let exit_code = match cmd {
            PolicyCmd::Load { path } => policy_commands::load(path),
            PolicyCmd::List => policy_commands::list(),
            PolicyCmd::Status => policy_commands::status(),
            PolicyCmd::Verify => policy_commands::verify(),
            PolicyCmd::Remove { identifier } => policy_commands::remove(identifier),
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

    let mut pipeline = Pipeline::new(config)?;

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
        Some(Commands::Init { .. }) => unreachable!(),     // handled above
        Some(Commands::Onboard { .. }) => unreachable!(), // handled above
        Some(Commands::Keys(_)) => unreachable!(),       // handled above
        Some(Commands::Gate(_)) => unreachable!(),      // handled above
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
