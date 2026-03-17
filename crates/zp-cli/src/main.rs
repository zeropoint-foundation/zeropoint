//! ZeroPoint CLI — terminal interface for developers.

mod chat;
mod commands;
mod guard;
mod init;
mod mesh_commands;
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

    /// Initialize a new ZeroPoint environment
    Init {
        /// Operator name (defaults to system username)
        #[arg(long)]
        name: Option<String>,

        /// Directory to initialize (defaults to current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
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

    // Init — bootstrap a new ZeroPoint environment, no pipeline needed
    if let Some(Commands::Init { name, dir }) = &args.command {
        let operator_name = name.clone().unwrap_or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "operator".to_string())
        });
        let project_dir = dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let config = init::InitConfig {
            operator_name,
            project_dir,
            store_genesis_secret: true,
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
        Some(Commands::Init { .. }) => unreachable!(),  // handled above
        Some(Commands::Keys(_)) => unreachable!(),      // handled above
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
