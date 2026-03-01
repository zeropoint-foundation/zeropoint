//! ZeroPoint v2 CLI — terminal interface for developers.

mod chat;
mod commands;
mod guard;
mod mesh_commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use zp_core::{OperatorIdentity, TrustTier};
use zp_pipeline::{MeshConfig, Pipeline, PipelineConfig};

#[derive(Parser)]
#[command(name = "zp", about = "ZeroPoint v2 CLI", version)]
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
}

#[derive(Subcommand)]
enum AuditCmd {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

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
        Some(Commands::Guard { .. }) => unreachable!(), // handled above
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
