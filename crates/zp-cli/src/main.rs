//! ZeroPoint CLI — terminal interface for developers.

mod chat;
mod commands;
use zp_configure as configure;
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

        /// Port (default: 17770)
        #[arg(long, default_value = "17770")]
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

        /// ZP server port for proxy mode (default: 17770)
        #[arg(long, default_value = "17770")]
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

        /// R6-3: Reconstitute trust state from the audit chain and report anomalies
        #[arg(long)]
        reconstitute: bool,

        /// #176: Walk `epoch:anchored:*` receipts, recompute Merkle roots
        /// from the entry ranges, and report epoch-level integrity
        /// (epoch count, coverage %, mismatches).
        #[arg(long)]
        anchors: bool,
    },

    /// #176 — Force an immediate Merkle epoch seal.
    ///
    /// Issues an `OperatorRequested` anchor: collects every chain entry
    /// since the last sealed epoch, builds the Merkle tree, calls the
    /// configured `TruthAnchor` backend, and records an `epoch:anchored:N`
    /// receipt. Useful for compliance checkpoints and pre-deployment
    /// verification regardless of whether trigger events have fired.
    Anchor {
        /// Path to the audit SQLite store (default: <data-dir>/audit.db)
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Human-readable reason recorded on the anchor commitment.
        #[arg(long, default_value = "operator-requested checkpoint")]
        reason: String,

        /// Emit JSON instead of formatted text.
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

    /// Memory lifecycle management (G5-2: review gate)
    #[command(subcommand)]
    Memory(MemoryCmd),

    /// F3 — content-scan MCP tool definitions for hostile payloads before canon.
    ///
    /// Falsifies tool JSON manifests against prompt-injection patterns,
    /// typosquatting (Levenshtein ≤ 2 against canon'd tools), capability
    /// escalation, suspicious encodings (base64 / invisible unicode), and
    /// overlong descriptions. Exit codes: 0 clean, 1 flagged, 2 blocked.
    Scan {
        /// File or directory to scan. A directory is walked for tool.json,
        /// mcp.json, manifest.json, and any *.json under a `tools/` folder.
        path: PathBuf,

        /// Emit findings as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,

        /// Path to audit store (default: <data-dir>/audit.db). When present,
        /// canon'd tool names are loaded as the typosquat reference set.
        #[arg(long)]
        audit_db: Option<PathBuf>,
    },
    /// Scan for entities that exist but have no canonicalization receipt (M11 violations)
    Discover {
        /// Directory to scan for tools (default: ~/projects)
        #[arg(long)]
        scan_path: Option<PathBuf>,

        /// Path to audit store (default: <data-dir>/audit.db)
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// P4 (#197) — Issue a standing delegation grant.
    ///
    /// Creates a new `CapabilityGrant` with a lease policy, signs it with
    /// the operator key, and emits a `delegation:granted:{subject}` chain
    /// receipt. The subject node is expected to heartbeat against one of
    /// the listed `--renewal-authorities` before the lease window expires.
    Delegate {
        /// Subject node id (e.g., `artemis`, `sentinel`, `playground`).
        #[arg(long)]
        subject: String,

        /// Comma-separated capability names (e.g., `tool-execution,credential-access`).
        /// Mapped onto `GrantedCapability::Custom { name }` so the brief's
        /// vocabulary survives unchanged on the chain.
        #[arg(long)]
        capabilities: String,

        /// Trust tier ceiling: 0 (T0 read-only) … 4. Maps onto `TrustTier`.
        #[arg(long, default_value = "0")]
        tier_ceiling: u8,

        /// Lease window — accepts `30m`, `2h`, `8h`, `7d`, etc.
        #[arg(long, default_value = "8h")]
        lease_duration: String,

        /// Heartbeat cadence — how often the subject SHOULD renew.
        #[arg(long, default_value = "2h")]
        renewal_interval: String,

        /// Comma-separated authority handles (`genesis`, `sentinel`, …).
        /// Each becomes an `AuthorityRef::genesis(...)` entry in the grant.
        #[arg(long, default_value = "genesis")]
        renewal_authorities: String,

        /// Comma-separated authority handles permitted to revoke the grant.
        #[arg(long, default_value = "genesis")]
        revocable_by: String,

        /// Maximum subtree depth for re-delegation (0 = forbidden).
        #[arg(long, default_value = "0")]
        max_depth: u32,

        /// What the subject does on lease failure: `halt`, `degrade`, `flag`.
        #[arg(long, default_value = "halt")]
        failure_mode: String,

        /// Hex-encoded Ed25519 public key for the subject. Bound onto the
        /// grant; used by the lease renewal endpoint to authenticate
        /// heartbeats from this delegate. When omitted, a fresh keypair
        /// is generated and the secret half is printed for one-time
        /// transcription into the delegate's `lease.toml`.
        #[arg(long)]
        subject_public_key: Option<String>,

        /// Audit DB path. Defaults to <data-dir>/audit.db.
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit JSON instead of human text.
        #[arg(long)]
        json: bool,
    },

    /// P4 (#197) — Revoke a standing delegation grant.
    Revoke {
        /// Target grant id (`grant-...`).
        #[arg(long)]
        grant_id: String,

        /// Cascade policy: `grant-only`, `subtree-halt`, `subtree-reroot`.
        #[arg(long, default_value = "subtree-halt")]
        cascade: String,

        /// Why this is being revoked: `operator-requested`, `compromise-detected`,
        /// `lease-expired`, `policy-violation`, or `superseded:<new-grant-id>`.
        #[arg(long, default_value = "operator-requested")]
        reason: String,

        /// Audit DB path. Defaults to <data-dir>/audit.db.
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit JSON instead of human text.
        #[arg(long)]
        json: bool,
    },

    /// P4 (#197) — List active standing-delegation grants.
    ///
    /// Walks the chain, reconstructs each grant's last-known state from
    /// `delegation:granted:*`, `delegation:renewed:*`, `delegation:revoked:*`,
    /// `delegation:expired:*` receipts, and prints active grants with their
    /// lease status (alive / grace / expired).
    Grants {
        /// Run invariant validation: chain integrity, monotonicity, no
        /// revoked-but-active grants.
        #[arg(long)]
        check: bool,

        /// Audit DB path. Defaults to <data-dir>/audit.db.
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit JSON instead of human text.
        #[arg(long)]
        json: bool,
    },

    /// V6 — Refresh a canon'd tool's bead-zero metadata to current schema.
    ///
    /// Reads the tool's `.zp-configure.toml` and registry/tools/*.json from
    /// disk, runs the F3 content scanner, and emits a lifecycle bead
    /// (`tool:adapted:<name>`) parented to the tool's wire tip. The bead
    /// carries the current `scan_verdict` + `reversibility` so post-F3/F5
    /// doctor checks read the latest values without re-canonicalizing.
    ///
    /// Does NOT rewrite the bead-zero — it appends. Tamper-evident chain
    /// integrity is preserved.
    Adapt {
        /// Tool name (must already have a bead-zero on the chain).
        tool: String,

        /// Directory containing the tool's source. Defaults to
        /// `$HOME/projects/<tool>`.
        #[arg(long)]
        path: Option<PathBuf>,

        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit findings as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum MemoryCmd {
    /// List pending memory promotion reviews
    Review {
        /// Memory ID to filter reviews for
        #[arg(long)]
        memory_id: Option<String>,
    },
    /// Approve a pending promotion review
    Approve {
        /// Review ID to approve
        review_id: String,
        /// Comment (optional)
        #[arg(long)]
        comment: Option<String>,
    },
    /// Reject a pending promotion review
    Reject {
        /// Review ID to reject
        review_id: String,
        /// Reason for rejection
        #[arg(long)]
        reason: String,
        /// Action: keep, quarantine, or demote:<stage>
        #[arg(long, default_value = "keep")]
        action: String,
    },
    /// Defer a pending promotion review
    Defer {
        /// Review ID to defer
        review_id: String,
        /// Reason for deferral
        #[arg(long)]
        reason: String,
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
    /// Show current policy version and transition history (R6-4: downgrade resistance)
    Version,
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
    /// Rotate a key to a new keypair (preserves identity via rotation certificate)
    ///
    /// For operator rotation: `zp keys rotate --target operator`
    /// For agent rotation:    `zp keys rotate --target <agent-name>`
    ///
    /// The old key signs the rotation certificate (proving possession),
    /// and the parent key co-signs for defense-in-depth.
    Rotate {
        /// Key to rotate: "operator" or an agent name
        #[arg(long)]
        target: String,

        /// Reason for rotation (recorded in the certificate for audit)
        #[arg(long)]
        reason: Option<String>,
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

        /// ZP server port for proxy mode (default: 17770)
        #[arg(long, default_value = "17770")]
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
    /// Rotate a provider credential — verify the old key, prompt for the new one,
    /// update the vault, and report which tools are affected.
    Rotate {
        /// Provider name (e.g., "anthropic", "openai")
        #[arg(long)]
        provider: String,

        /// Field to rotate (e.g., "api_key")
        #[arg(long)]
        field: String,
    },
}

#[derive(Subcommand)]
enum CfgCmd {
    /// Show all configuration with provenance (where each value came from)
    Show,
    /// Set a configuration value in ~/ZeroPoint/config.toml
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
                eprintln!("  \x1b[31mNo keyring found at ~/ZeroPoint/keys/\x1b[0m");
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

        let vault_path = zp_core::paths::vault_path()
            .unwrap_or_else(|_| commands::resolve_zp_home().join("vault.json"));

        let exit_code = match cmd {
            ConfigureCmd::Tool {
                path,
                name,
                dry_run,
            } => match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                Ok(mut vault) => configure::run_tool(
                    path,
                    name,
                    *dry_run,
                    &mut vault,
                    configure_policy,
                    Some(&vault_path),
                ),
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
                    Ok(mut vault) => {
                        let exit = configure::run_auto(
                            path,
                            &mut vault,
                            configure_policy,
                            *depth,
                            *dry_run,
                            *overwrite,
                            proxy_opt,
                            Some(&vault_path),
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
            ConfigureCmd::Rotate { provider, field } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(vault) => configure::run_rotate(&vault, provider, field),
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
        let vault_path = zp_core::paths::vault_path()
            .unwrap_or_else(|_| home_zp.join("vault.json"));
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
            KeysCmd::Rotate { target, reason } => {
                commands::keys_rotate(target, reason.as_deref())
            }
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

    // Verify — run the catalog grammar verifier over the audit chain.
    // Strategy: try the running server's API first (no DB lock contention),
    // fall back to direct DB access if the server isn't reachable.
    if let Some(Commands::Verify { audit_db, json, reconstitute, anchors }) = &args.command {
        // Try server API first — works even while the server holds the DB lock
        let port: u16 = 17770; // ZeroPoint default server port
        let server_ok = (|| -> Option<()> {
            use std::io::{Read as _, Write as _};
            let mut conn = std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", port).parse().ok()?,
                std::time::Duration::from_secs(2),
            ).ok()?;
            conn.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
            write!(conn, "GET /api/v1/audit/verify HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", port).ok()?;
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).ok()?;
            let raw = String::from_utf8_lossy(&buf);
            // Extract JSON body after \r\n\r\n
            let body = raw.split("\r\n\r\n").nth(1)?;
            if *json {
                println!("{}", body);
            } else {
                let v: serde_json::Value = serde_json::from_str(body).ok()?;
                let valid = v["valid"].as_bool().unwrap_or(false);
                let entries = v["entries_examined"].as_u64().unwrap_or(0);
                let sigs_total = v["signatures_checked"].as_u64().unwrap_or(0);
                let sigs_pass = v["signatures_valid"].as_u64().unwrap_or(0);
                let issues = v["issues"].as_array();

                println!("\x1b[1mzp verify — Chain Attestation (via server)\x1b[0m");
                println!();
                if valid {
                    println!("  \x1b[32m✓\x1b[0m Chain integrity: {} entries, {}/{} signatures pass, hash-link intact",
                        entries, sigs_pass, sigs_total);
                } else {
                    println!("  \x1b[31m✗\x1b[0m Chain integrity: FAILED ({} entries examined)", entries);
                }
                if let Some(issues) = issues {
                    if !issues.is_empty() {
                        println!();
                        for issue in issues {
                            println!("  \x1b[33m⚠\x1b[0m {}", issue.as_str().unwrap_or("?"));
                        }
                    }
                }
                println!();
            }
            Some(())
        })();

        if server_ok.is_some() {
            std::process::exit(0);
        }

        // Fallback: direct DB access (server not running)
        let db_path = audit_db
            .clone()
            .unwrap_or_else(|| args.data_dir.join("audit.db"));
        let store = match zp_audit::AuditStore::open(&db_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error opening audit store at {}: {}", db_path.display(), e);
                eprintln!("Hint: if the server is running, check that port {} is correct", port);
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

        // F5: count irreversible action receipts. Backward compatible —
        // chains predating F5 simply have zero matches.
        #[cfg(feature = "embedded-server")]
        let irreversible_counts = {
            use std::sync::{Arc, Mutex};
            match zp_audit::AuditStore::open(&db_path) {
                Ok(s) => {
                    let s = Arc::new(Mutex::new(s));
                    Some(zp_server::tool_chain::count_irreversible_actions(&s))
                }
                Err(_) => None,
            }
        };
        #[cfg(not(feature = "embedded-server"))]
        let irreversible_counts: Option<(usize, usize)> = None;
        if *json {
            // Wrap the report so the F5 irreversible counts are surfaced
            // alongside the existing fields without modifying the upstream
            // `VerifyReport` shape.
            let wrapped = serde_json::json!({
                "report": &report,
                "f5_irreversible_actions_total": irreversible_counts.map(|(t, _)| t),
                "f5_irreversible_actions_signed": irreversible_counts.map(|(_, s)| s),
            });
            match serde_json::to_string_pretty(&wrapped) {
                Ok(s) => println!("{}", s),
                Err(e) => {
                    eprintln!("Error serializing report: {}", e);
                    std::process::exit(2);
                }
            }
        } else {
            // ── Trajectory Attestation ──
            println!("\x1b[1mzp verify — Trajectory Attestation\x1b[0m");
            println!("audit_db:         {}", db_path.display());
            println!("rules_checked:    {}", report.rules_checked.join(", "));
            println!("entries_checked:  {}", report.entries_checked);

            if let Some(ts) = report.genesis_timestamp {
                println!(
                    "well-formed since: {}",
                    ts.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
            if let Some(head) = report.chain_head.as_deref() {
                let short = if head.len() >= 16 { &head[..16] } else { head };
                println!("chain_head:       {}…", short);
            }

            // Signature stats
            let sig_summary = if report.signature_checks == 0 {
                "\x1b[33mno signed receipts found\x1b[0m".to_string()
            } else if report.signature_failures == 0 {
                format!(
                    "\x1b[32m{}/{} valid\x1b[0m",
                    report.signature_checks, report.signature_checks
                )
            } else {
                format!(
                    "\x1b[31m{} of {} failed\x1b[0m",
                    report.signature_failures, report.signature_checks
                )
            };
            println!("signatures:       {}", sig_summary);

            // F5 trajectory line.
            match irreversible_counts {
                Some((0, _)) => {
                    println!("irreversible:     \x1b[32mnone\x1b[0m");
                }
                Some((total, signed)) => {
                    let plural = if total == 1 { "" } else { "s" };
                    let sig_note = if signed == total {
                        format!("(all {} signed — tier ≥ 1)", signed)
                    } else if signed == 0 {
                        format!("(\x1b[31mnone signed\x1b[0m — possible tier-0 violation)")
                    } else {
                        format!(
                            "(\x1b[33m{} of {} signed\x1b[0m — review tier provenance)",
                            signed, total
                        )
                    };
                    println!(
                        "irreversible:     \x1b[33m{} irreversible action{} executed\x1b[0m {}",
                        total, plural, sig_note
                    );
                }
                None => {
                    println!("irreversible:     \x1b[33munavailable\x1b[0m (built without embedded-server)");
                }
            }

            let errors = report.error_count();
            let warnings = report.findings.len() - errors;
            if errors == 0 {
                println!(
                    "result:           \x1b[32mACCEPT\x1b[0m — chain attested against {} rule(s){}",
                    report.rules_checked.len(),
                    if warnings > 0 {
                        format!(" ({} warning(s))", warnings)
                    } else {
                        String::new()
                    }
                );
            } else {
                println!(
                    "result:           \x1b[31mREJECT\x1b[0m — {} error(s){}",
                    errors,
                    if warnings > 0 {
                        format!(", {} warning(s)", warnings)
                    } else {
                        String::new()
                    }
                );
            }

            if !report.findings.is_empty() {
                println!();
                println!("findings:");
                for f in &report.findings {
                    let badge = match f.severity {
                        zp_verify::FindingSeverity::Error => "\x1b[31mERROR\x1b[0m",
                        zp_verify::FindingSeverity::Warning => "\x1b[33mWARN \x1b[0m",
                        zp_verify::FindingSeverity::Info => "\x1b[36mINFO \x1b[0m",
                    };
                    let entry_short = if f.entry_id.len() >= 12 {
                        &f.entry_id[..12]
                    } else {
                        &f.entry_id
                    };
                    println!("  {} [{}] entry={}… {}", badge, f.rule, entry_short, f.description);
                }
            }
        }
        // R6-3: Reconstitution — rebuild trust state from chain.
        if *reconstitute {
            eprintln!("\n\x1b[1m── R6-3: Chain Reconstitution ──\x1b[0m\n");
            let chain = match store.export_chain(100_000) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error exporting chain: {}", e);
                    std::process::exit(2);
                }
            };

            let config = zp_audit::ReconstitutionConfig::default();
            let mut engine = zp_audit::ReconstitutionEngine::new(config);

            let mut chain_integrity = true;
            let mut prev_hash = String::new();
            for entry in &chain {
                let chain_entry = zp_audit::ReconstitutionEntry::from_audit_entry(entry);
                if !prev_hash.is_empty() && chain_entry.prev_hash != prev_hash {
                    chain_integrity = false;
                }
                prev_hash = chain_entry.entry_hash.clone();
                engine.process_entry(&chain_entry);
            }

            let state = engine.finalize(chain_integrity);

            eprintln!("entries processed:  {}", state.entries_processed);
            eprintln!("chain integrity:    {}", if state.chain_integrity_verified { "\x1b[32mOK\x1b[0m" } else { "\x1b[31mBROKEN\x1b[0m" });
            eprintln!("valid operator keys: {}", state.valid_operator_keys.len());
            eprintln!("valid agent keys:    {}", state.valid_agent_keys.len());
            eprintln!("revoked keys:        {}", state.revoked_keys.len());
            eprintln!("active capabilities: {}", state.active_capabilities.len());
            eprintln!("memory states:       {}", state.memory_states.len());
            eprintln!("quarantined:         {}", state.quarantined_memories.len());

            if state.anomalies.is_empty() {
                eprintln!("\nanomalies:           \x1b[32mnone\x1b[0m");
            } else {
                eprintln!("\nanomalies:           \x1b[31m{}\x1b[0m", state.anomalies.len());
                for a in &state.anomalies {
                    eprintln!("  [{:?}] entry={} {:?}: {}", a.severity, a.entry_id, a.kind, a.description);
                }
            }
        }

        // #176: --anchors walks `epoch:anchored:N` receipts and recomputes
        // the Merkle root from the entry range each one claims. Mismatches
        // surface as findings; coverage is reported as a percentage of all
        // chain entries that fall inside a sealed epoch.
        let mut anchor_failed = false;
        if *anchors {
            eprintln!("\n\x1b[1m── #176: Merkle Anchor Verification ──\x1b[0m\n");
            match verify_anchors(&store) {
                Ok(report) => {
                    eprintln!("epoch count:        {}", report.epoch_count);
                    eprintln!("chain entries:      {}", report.total_entries);
                    eprintln!(
                        "covered:            {} ({:.1}% of chain)",
                        report.entries_covered, report.coverage_pct
                    );
                    if report.mismatches.is_empty() {
                        eprintln!("merkle integrity:   \x1b[32mOK\x1b[0m");
                    } else {
                        anchor_failed = true;
                        eprintln!(
                            "merkle integrity:   \x1b[31mFAIL\x1b[0m ({} mismatch(es))",
                            report.mismatches.len()
                        );
                        for m in &report.mismatches {
                            eprintln!(
                                "  epoch {}: stored={} computed={} (entries [{}..{}])",
                                m.epoch_number,
                                short_hash(&m.stored_root),
                                short_hash(&m.computed_root),
                                m.first_sequence,
                                m.last_sequence
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("\x1b[31manchor verification failed:\x1b[0m {}", e);
                    anchor_failed = true;
                }
            }
        }

        let chain_failed = !report.violations().is_empty();
        std::process::exit(if chain_failed || anchor_failed { 1 } else { 0 });
    }

    // #176 — manual anchor trigger.
    if let Some(Commands::Anchor { audit_db, reason, json }) = &args.command {
        let exit_code = run_anchor(audit_db.clone(), reason, &args.data_dir, *json);
        std::process::exit(exit_code);
    }

    // P4 (#197) — standing delegation lifecycle.
    if let Some(Commands::Delegate {
        subject,
        capabilities,
        tier_ceiling,
        lease_duration,
        renewal_interval,
        renewal_authorities,
        revocable_by,
        max_depth,
        failure_mode,
        subject_public_key,
        audit_db,
        json,
    }) = &args.command
    {
        let exit_code = run_delegate(
            subject,
            capabilities,
            *tier_ceiling,
            lease_duration,
            renewal_interval,
            renewal_authorities,
            revocable_by,
            *max_depth,
            failure_mode,
            subject_public_key.as_deref(),
            audit_db.clone(),
            &args.data_dir,
            *json,
        );
        std::process::exit(exit_code);
    }
    if let Some(Commands::Revoke {
        grant_id,
        cascade,
        reason,
        audit_db,
        json,
    }) = &args.command
    {
        let exit_code = run_revoke(
            grant_id,
            cascade,
            reason,
            audit_db.clone(),
            &args.data_dir,
            *json,
        );
        std::process::exit(exit_code);
    }
    if let Some(Commands::Grants {
        check,
        audit_db,
        json,
    }) = &args.command
    {
        let exit_code = run_grants(*check, audit_db.clone(), &args.data_dir, *json);
        std::process::exit(exit_code);
    }

    // Discover — scan filesystem and chain for uncanonicalized entities (M11)
    if let Some(Commands::Discover { scan_path, audit_db, json }) = &args.command {
        let exit_code = run_discover(scan_path.clone(), audit_db.clone(), &args.data_dir, *json);
        std::process::exit(exit_code);
    }

    // Scan — F3 content-scan MCP tool definitions before canon.
    // V6 — Adapt: refresh a canon'd tool's bead-zero metadata to current schema.
    if let Some(Commands::Adapt { tool, path, audit_db, json }) = &args.command {
        let exit_code = run_adapt(tool, path.clone(), audit_db.clone(), &args.data_dir, *json);
        std::process::exit(exit_code);
    }

    if let Some(Commands::Scan { path, json, audit_db }) = &args.command {
        let exit_code = run_scan(path, *json, audit_db.clone(), &args.data_dir);
        std::process::exit(exit_code);
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
                    println!("  Written to ~/ZeroPoint/config.toml");
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

    // Memory — review gate for memory promotion (G5-2).
    // Talks to the running server via API, no pipeline needed.
    if let Some(Commands::Memory(cmd)) = &args.command {
        let port: u16 = std::env::var("ZP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(17770);
        let base_url = format!("http://127.0.0.1:{}", port);
        let client = reqwest::Client::new();

        match cmd {
            MemoryCmd::Review { memory_id } => {
                let resp = client
                    .get(format!("{}/api/v1/cognition/reviews", base_url))
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let reviews: Vec<serde_json::Value> = r.json().await.unwrap_or_default();
                        let filtered: Vec<_> = if let Some(mid) = memory_id {
                            reviews
                                .into_iter()
                                .filter(|r| r.get("memory_id").and_then(|v| v.as_str()) == Some(mid.as_str()))
                                .collect()
                        } else {
                            reviews
                        };

                        if filtered.is_empty() {
                            eprintln!("No pending reviews.");
                        } else {
                            eprintln!("\x1b[1mPending Memory Promotion Reviews\x1b[0m\n");
                            for r in &filtered {
                                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                                let mem = r.get("memory_id").and_then(|v| v.as_str()).unwrap_or("?");
                                let from = r.get("current_stage").and_then(|v| v.as_str()).unwrap_or("?");
                                let to = r.get("target_stage").and_then(|v| v.as_str()).unwrap_or("?");
                                let expires = r.get("expires_at").and_then(|v| v.as_str()).unwrap_or("?");
                                let deferrals = r.get("deferral_count").and_then(|v| v.as_u64()).unwrap_or(0);
                                eprintln!(
                                    "  \x1b[36m{}\x1b[0m  {} → {}  (memory: {}, deferrals: {}, expires: {})",
                                    id, from, to, mem, deferrals, expires
                                );
                                if let Some(ev) = r.get("evidence").and_then(|v| v.as_str()) {
                                    eprintln!("    evidence: {}", ev);
                                }
                            }
                            eprintln!("\n  {} pending review(s)", filtered.len());
                        }
                    }
                    Ok(r) => {
                        eprintln!("Server returned {}", r.status());
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Cannot reach ZP server at {}: {}", base_url, e);
                        eprintln!("Is `zp serve` running?");
                        std::process::exit(1);
                    }
                }
            }
            MemoryCmd::Approve { review_id, comment } => {
                let body = serde_json::json!({
                    "decision": "approve",
                    "reviewer": args.data_dir.display().to_string(),
                    "comment": comment,
                });
                let resp = client
                    .post(format!("{}/api/v1/cognition/reviews/{}/decide", base_url, review_id))
                    .json(&body)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let result: serde_json::Value = r.json().await.unwrap_or_default();
                        let outcome = result.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");
                        let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                        eprintln!("\x1b[32m✓\x1b[0m Review {}: {} — {}", review_id, outcome, detail);
                    }
                    Ok(r) => {
                        let status = r.status();
                        let body = r.text().await.unwrap_or_default();
                        eprintln!("\x1b[31m✗\x1b[0m Server returned {}: {}", status, body);
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Cannot reach ZP server: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            MemoryCmd::Reject { review_id, reason, action } => {
                let body = serde_json::json!({
                    "decision": "reject",
                    "reviewer": args.data_dir.display().to_string(),
                    "reason": reason,
                    "action": action,
                });
                let resp = client
                    .post(format!("{}/api/v1/cognition/reviews/{}/decide", base_url, review_id))
                    .json(&body)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let result: serde_json::Value = r.json().await.unwrap_or_default();
                        let outcome = result.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");
                        let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                        eprintln!("\x1b[32m✓\x1b[0m Review {}: {} — {}", review_id, outcome, detail);
                    }
                    Ok(r) => {
                        let status = r.status();
                        let body = r.text().await.unwrap_or_default();
                        eprintln!("\x1b[31m✗\x1b[0m Server returned {}: {}", status, body);
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Cannot reach ZP server: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            MemoryCmd::Defer { review_id, reason } => {
                let body = serde_json::json!({
                    "decision": "defer",
                    "reviewer": args.data_dir.display().to_string(),
                    "reason": reason,
                });
                let resp = client
                    .post(format!("{}/api/v1/cognition/reviews/{}/decide", base_url, review_id))
                    .json(&body)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let result: serde_json::Value = r.json().await.unwrap_or_default();
                        let outcome = result.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");
                        let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                        eprintln!("\x1b[32m✓\x1b[0m Review {}: {} — {}", review_id, outcome, detail);
                    }
                    Ok(r) => {
                        let status = r.status();
                        let body = r.text().await.unwrap_or_default();
                        eprintln!("\x1b[31m✗\x1b[0m Server returned {}: {}", status, body);
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Cannot reach ZP server: {}", e);
                        std::process::exit(1);
                    }
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
            status: &'static str, // "pass", "fail", "warn", "info"
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

        // 2. Genesis key (certificate on disk)
        let genesis_path = home.join("genesis.json");
        if genesis_path.exists() {
            checks.push(Check {
                label: "Genesis certificate".into(),
                status: "pass",
                detail: format!("{}", genesis_path.display()),
                fix: String::new(),
            });
        } else {
            checks.push(Check {
                label: "Genesis certificate".into(),
                status: "fail",
                detail: "genesis.json not found".into(),
                fix: "Run: zp init".into(),
            });
        }

        // 2b. Genesis secret (credential store)
        let keys_dir = home.join("keys");
        let genesis_secret_ok = zp_keys::Keyring::open(&keys_dir)
            .map(|kr| kr.status().has_genesis_secret)
            .unwrap_or(false);
        if genesis_secret_ok {
            checks.push(Check {
                label: "Genesis secret".into(),
                status: "pass",
                detail: "present in credential store".into(),
                fix: String::new(),
            });
        } else if genesis_path.exists() {
            checks.push(Check {
                label: "Genesis secret".into(),
                status: "fail",
                detail: "certificate exists but secret missing from credential store".into(),
                fix: "Run: zp recover (with your 24-word mnemonic)".into(),
            });
        } else {
            checks.push(Check {
                label: "Genesis secret".into(),
                status: "fail",
                detail: "not initialized".into(),
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

        // ── F6 falsifiers — open the audit store once and feed all of them ──
        //
        // Existing check #6 ("Audit chain") gives a coarse pass/fail. F6 (a)
        // adds the richer breakdown the spec asks for (entries / signatures /
        // hash-link / genesis), and (b)–(d) consult the chain's
        // canonicalization metadata. We wrap the store in `Arc<Mutex<...>>`
        // so the F3/F5 query helpers in `zp-server` can take it by reference.
        #[cfg(feature = "embedded-server")]
        {
            use std::sync::{Arc, Mutex};

            // The store may not exist yet on a clean install; in that case
            // every F6 check downgrades to a friendly informational result
            // so doctor doesn't FAIL just because the user hasn't started the
            // server yet.
            if audit_db.exists() {
                let store_for_canon = match zp_audit::AuditStore::open(&audit_db) {
                    Ok(s) => Some(Arc::new(Mutex::new(s))),
                    Err(_) => None,
                };

                // ── (a) F6 CHAIN INTEGRITY ─────────────────────────────────
                // Distilled `zp verify`: total entries, signature pass/fail,
                // hash-link continuity (P1 + M3), and genesis sealed status.
                if let Ok(store) = zp_audit::AuditStore::open(&audit_db) {
                    match store.verify_with_catalog() {
                        Ok(report) => {
                            let errors = report.error_count();
                            let hashlink_ok = report
                                .findings
                                .iter()
                                .all(|f| f.rule != "M3" && f.rule != "P1"
                                    || f.severity != zp_verify::FindingSeverity::Error);
                            let genesis_sealed = report.genesis_timestamp.is_some();
                            let sig_ok = report.signature_failures == 0;

                            let summary = format!(
                                "{} entries, {}/{} signatures pass, hash-link {}, genesis {}",
                                report.entries_checked,
                                report
                                    .signature_checks
                                    .saturating_sub(report.signature_failures),
                                report.signature_checks,
                                if hashlink_ok { "intact" } else { "broken" },
                                if genesis_sealed { "sealed" } else { "missing" },
                            );

                            if errors == 0 {
                                checks.push(Check {
                                    label: "Chain integrity".into(),
                                    status: "pass",
                                    detail: summary,
                                    fix: String::new(),
                                });
                            } else {
                                // Find the first error finding for the operator
                                // to start with — the full list is in `zp verify`.
                                let first_err = report
                                    .findings
                                    .iter()
                                    .find(|f| {
                                        f.severity == zp_verify::FindingSeverity::Error
                                    })
                                    .map(|f| {
                                        format!(
                                            "{} [{}] entry={}: {}",
                                            summary, f.rule, f.entry_id, f.description
                                        )
                                    })
                                    .unwrap_or(summary);
                                checks.push(Check {
                                    label: "Chain integrity".into(),
                                    status: "fail",
                                    detail: first_err,
                                    fix: format!(
                                        "Run: zp verify --audit-db {}",
                                        audit_db.display()
                                    ),
                                });
                            }

                            // Signature failures are a separate failure mode —
                            // a chain can be hash-link-intact but contain a
                            // forged signature. Surface it explicitly.
                            if !sig_ok {
                                checks.push(Check {
                                    label: "Chain signatures".into(),
                                    status: "fail",
                                    detail: format!(
                                        "{} of {} signatures failed verification",
                                        report.signature_failures,
                                        report.signature_checks
                                    ),
                                    fix: "Run: zp verify --audit-db for details".into(),
                                });
                            }
                        }
                        Err(e) => {
                            checks.push(Check {
                                label: "Chain integrity".into(),
                                status: "warn",
                                detail: format!("verification could not run: {e}"),
                                fix: String::new(),
                            });
                        }
                    }
                }

                // ── (b) F6 CANONICALIZATION COMPLETENESS ──────────────────
                if let Some(store) = store_for_canon.as_ref() {
                    let bead_zeros =
                        zp_server::tool_chain::query_bead_zeros(store);
                    // Match `zp discover`'s default scan path so the same set
                    // of tools surfaces in both commands.
                    let scan_path = std::env::var("HOME")
                        .map(|h| PathBuf::from(h).join("projects"))
                        .unwrap_or_else(|_| PathBuf::from("."));
                    let scan = zp_engine::scan::scan_tools(&scan_path);
                    let fs_tools: Vec<&str> =
                        scan.tools.iter().map(|t| t.name.as_str()).collect();

                    let system_canon = bead_zeros.contains_key("system:zeropoint");
                    let canon_tool_count = bead_zeros
                        .keys()
                        .filter(|k| k.starts_with("tool:"))
                        .count();

                    if !system_canon {
                        // System bead-zero missing is a hard failure — every
                        // other wire descends from it.
                        checks.push(Check {
                            label: "Canonicalization".into(),
                            status: "fail",
                            detail: format!(
                                "system:zeropoint has no bead-zero ({} entities canon'd, {} tools on disk)",
                                bead_zeros.len(),
                                fs_tools.len()
                            ),
                            fix: "Start the server once to anchor system bead-zero".into(),
                        });
                    } else {
                        // Tools on disk that lack a bead-zero.
                        let missing: Vec<&str> = fs_tools
                            .iter()
                            .filter(|name| {
                                !bead_zeros.contains_key(&format!("tool:{}", name))
                            })
                            .copied()
                            .collect();

                        if missing.is_empty() {
                            checks.push(Check {
                                label: "Canonicalization".into(),
                                status: "pass",
                                detail: format!(
                                    "{} entities canon'd, {} tools on disk all anchored",
                                    bead_zeros.len(),
                                    fs_tools.len()
                                ),
                                fix: String::new(),
                            });
                        } else {
                            // Show up to 5 names — the rest is a count.
                            let preview: String = missing
                                .iter()
                                .take(5)
                                .copied()
                                .collect::<Vec<&str>>()
                                .join(", ");
                            let suffix = if missing.len() > 5 {
                                format!(", +{} more", missing.len() - 5)
                            } else {
                                String::new()
                            };
                            checks.push(Check {
                                label: "Canonicalization".into(),
                                status: "warn",
                                detail: format!(
                                    "{}/{} tools have bead-zeros — missing: {}{}",
                                    canon_tool_count,
                                    fs_tools.len(),
                                    preview,
                                    suffix
                                ),
                                fix: "Run: zp discover".into(),
                            });
                        }
                    }
                }

                // ── (c) F6 TOOL CONTENT SECURITY (F3 falsifier coverage) ──
                // ── (d) F6 REVERSIBILITY COVERAGE (F5 declaration coverage)
                //
                // Both checks read the same per-tool canonicalization metadata,
                // so we compute it once and feed both.
                if let Some(store) = store_for_canon.as_ref() {
                    let canon_meta =
                        zp_server::tool_chain::query_canonicalization_metadata(store);
                    let tool_meta: Vec<&zp_server::tool_chain::CanonMetadata> =
                        canon_meta.values().filter(|m| m.domain == "tool").collect();

                    // (c) Content security
                    let unscanned: Vec<&str> = tool_meta
                        .iter()
                        .filter(|m| m.scan_verdict.is_none())
                        .map(|m| m.entity_id.as_str())
                        .collect();
                    let flagged: Vec<&str> = tool_meta
                        .iter()
                        .filter(|m| m.scan_verdict.as_deref() == Some("flagged"))
                        .map(|m| m.entity_id.as_str())
                        .collect();
                    let blocked: Vec<&str> = tool_meta
                        .iter()
                        .filter(|m| m.scan_verdict.as_deref() == Some("blocked"))
                        .map(|m| m.entity_id.as_str())
                        .collect();

                    if !blocked.is_empty() {
                        checks.push(Check {
                            label: "Content security".into(),
                            status: "fail",
                            detail: format!(
                                "{} tool(s) canonicalized despite blocked verdict: {}",
                                blocked.len(),
                                blocked.join(", ")
                            ),
                            fix: "Investigate manual override; revoke or re-canon".into(),
                        });
                    } else if !flagged.is_empty() {
                        checks.push(Check {
                            label: "Content security".into(),
                            status: "warn",
                            detail: format!(
                                "{} tool(s) flagged by F3 scanner: {}",
                                flagged.len(),
                                flagged.join(", ")
                            ),
                            fix: "Run: zp scan <tool-path> for findings".into(),
                        });
                    } else if !unscanned.is_empty() && !tool_meta.is_empty() {
                        checks.push(Check {
                            label: "Content security".into(),
                            status: "warn",
                            detail: format!(
                                "{}/{} tools canonicalized without content scan (pre-F3)",
                                unscanned.len(),
                                tool_meta.len()
                            ),
                            fix: "Run: zp scan ~/projects to verify".into(),
                        });
                    } else if tool_meta.is_empty() {
                        checks.push(Check {
                            label: "Content security".into(),
                            status: "pass",
                            detail: "no canonicalized tools yet".into(),
                            fix: String::new(),
                        });
                    } else {
                        checks.push(Check {
                            label: "Content security".into(),
                            status: "pass",
                            detail: format!(
                                "{} tools all scanned clean",
                                tool_meta.len()
                            ),
                            fix: String::new(),
                        });
                    }

                    // (d) Reversibility coverage
                    let total_tools = tool_meta.len();
                    if total_tools == 0 {
                        checks.push(Check {
                            label: "Reversibility".into(),
                            status: "pass",
                            detail: "no canonicalized tools yet".into(),
                            fix: String::new(),
                        });
                    } else {
                        let declared = tool_meta
                            .iter()
                            .filter(|m| {
                                matches!(
                                    m.reversibility.as_deref(),
                                    Some("reversible")
                                        | Some("partial")
                                        | Some("irreversible")
                                )
                            })
                            .count();
                        let unknown = total_tools - declared;
                        let detail = format!(
                            "{}/{} tools have reversibility declared; {} default to unknown (treated as irreversible)",
                            declared, total_tools, unknown
                        );
                        // Spec: WARN when more than half are unknown. Otherwise
                        // a quiet pass — this is an informational nudge, not a
                        // hard requirement.
                        if unknown * 2 > total_tools {
                            checks.push(Check {
                                label: "Reversibility".into(),
                                status: "warn",
                                detail,
                                fix: "Add `[capabilities]` reversibility = ... to each tool's .zp-configure.toml".into(),
                            });
                        } else {
                            checks.push(Check {
                                label: "Reversibility".into(),
                                status: "pass",
                                detail,
                                fix: String::new(),
                            });
                        }
                    }
                }
            } else {
                // No audit DB yet — the F6 falsifiers have nothing to chew on.
                // Don't FAIL the doctor for a clean install; downgrade to info.
                checks.push(Check {
                    label: "Chain integrity".into(),
                    status: "info",
                    detail: "no audit data yet (clean install)".into(),
                    fix: String::new(),
                });
                checks.push(Check {
                    label: "Canonicalization".into(),
                    status: "info",
                    detail: "no canon entries yet".into(),
                    fix: String::new(),
                });
                checks.push(Check {
                    label: "Content security".into(),
                    status: "info",
                    detail: "no canon entries yet".into(),
                    fix: String::new(),
                });
                checks.push(Check {
                    label: "Reversibility".into(),
                    status: "info",
                    detail: "no canon entries yet".into(),
                    fix: String::new(),
                });
            }
        }

        // ── (e) F6 BENCHMARKS HINT ─────────────────────────────────────
        // Always informational. Pulled into the Check vector so it
        // appears in --json output with the rest of the diagnostics.
        checks.push(Check {
            label: "Benchmarks".into(),
            status: "info",
            detail: "cargo bench -p zp-bench | docs/BENCHMARKS.md".into(),
            fix: String::new(),
        });

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
                    "info" => "\x1b[36mℹ\x1b[0m",
                    _ => "?",
                };
                println!("  {icon} {}: {}", c.label, c.detail);
                if !c.fix.is_empty() && c.status != "pass" && c.status != "info" {
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
        // R6-4: `zp policy version` — query downgrade guard via server API.
        if matches!(_cmd, PolicyCmd::Version) {
            let port: u16 = std::env::var("ZP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(17770);
            let url = format!("http://127.0.0.1:{}/api/v1/security/policy-version", port);
            let client = reqwest::Client::new();
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    println!("Policy version: {}", body["current_version"].as_str().unwrap_or("unknown"));
                    if let Some(history) = body["history"].as_array() {
                        if history.is_empty() {
                            println!("No version transitions recorded.");
                        } else {
                            println!("\nVersion history:");
                            for t in history {
                                println!(
                                    "  {} → {}  ({})",
                                    t["from"].as_str().unwrap_or("?"),
                                    t["to"].as_str().unwrap_or("?"),
                                    t["timestamp"].as_str().unwrap_or("?"),
                                );
                            }
                        }
                    }
                }
                Ok(resp) => {
                    eprintln!("Server returned {}", resp.status());
                }
                Err(e) => {
                    eprintln!("Failed to connect to server: {}", e);
                    eprintln!("Is `zp serve` running?");
                }
            }
            std::process::exit(0);
        }

        #[cfg(feature = "policy-wasm")]
        let exit_code = match _cmd {
            PolicyCmd::Load { path } => policy_commands::load(path),
            PolicyCmd::List => policy_commands::list(),
            PolicyCmd::Status => policy_commands::status(),
            PolicyCmd::Verify => policy_commands::verify(),
            PolicyCmd::Remove { identifier } => policy_commands::remove(identifier),
            PolicyCmd::Version => unreachable!(), // handled above
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
        Some(Commands::Anchor { .. }) => unreachable!(), // handled above
        Some(Commands::Delegate { .. }) => unreachable!(), // handled above
        Some(Commands::Revoke { .. }) => unreachable!(), // handled above
        Some(Commands::Grants { .. }) => unreachable!(), // handled above
        Some(Commands::Cfg(_)) => unreachable!(),       // handled above
        Some(Commands::Doctor { .. }) => unreachable!(), // handled above
        Some(Commands::Memory(_)) => unreachable!(),    // handled above
        Some(Commands::Discover { .. }) => unreachable!(), // handled above
        Some(Commands::Adapt { .. }) => unreachable!(),    // handled above
        Some(Commands::Scan { .. }) => unreachable!(),     // handled above
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

// ============================================================================
// zp discover — uncanonicalized entity scanner (M11 invariant)
// ============================================================================

#[derive(serde::Serialize)]
struct DiscoverReport {
    scan_path: String,
    audit_db: String,
    system_canonicalized: bool,
    tools_found: Vec<DiscoveredTool>,
    tools_missing_canon: Vec<String>,
    providers_referenced: Vec<String>,
    providers_missing_canon: Vec<String>,
    canonical_entities: Vec<String>,
}

#[derive(serde::Serialize)]
struct DiscoveredTool {
    name: String,
    path: String,
    has_canon: bool,
    /// F5: reversibility declared in the tool's `.zp-configure.toml`.
    /// One of `"reversible" | "partial" | "irreversible" | "unknown"`.
    reversibility: String,
}

fn run_discover(
    scan_path: Option<PathBuf>,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    // Resolve scan path: explicit flag → ~/projects fallback.
    let scan_path = scan_path.unwrap_or_else(|| {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join("projects"))
            .unwrap_or_else(|_| PathBuf::from("."))
    });

    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));

    // Filesystem scan.
    let scan = zp_engine::scan::scan_tools(&scan_path);

    // Chain query for canonicalized entities.
    #[cfg(feature = "embedded-server")]
    let bead_zeros = {
        use std::sync::{Arc, Mutex};
        match zp_audit::AuditStore::open(&db_path) {
            Ok(store) => {
                let store = Arc::new(Mutex::new(store));
                zp_server::tool_chain::query_bead_zeros(&store)
            }
            Err(e) => {
                eprintln!(
                    "\x1b[31mError\x1b[0m opening audit store at {}: {}",
                    db_path.display(),
                    e
                );
                return 2;
            }
        }
    };
    #[cfg(not(feature = "embedded-server"))]
    let bead_zeros: std::collections::HashMap<String, (String, Option<serde_json::Value>)> = {
        eprintln!(
            "\x1b[33mwarn\x1b[0m: zp-cli built without `embedded-server` — chain queries unavailable; reporting all entities as uncanonicalized."
        );
        std::collections::HashMap::new()
    };

    // Set differences.
    let system_canonicalized = bead_zeros.contains_key("system:zeropoint");

    let mut tools_found: Vec<DiscoveredTool> = scan
        .tools
        .iter()
        .map(|t| {
            let key = format!("tool:{}", t.name);
            // F5: read reversibility from manifest on disk. Falls back to
            // Unknown if the manifest is missing or pre-F5.
            let reversibility =
                zp_engine::capability::reversibility_for_tool_dir(&t.path);
            DiscoveredTool {
                name: t.name.clone(),
                path: t.path.display().to_string(),
                has_canon: bead_zeros.contains_key(&key),
                reversibility: reversibility.as_str().to_string(),
            }
        })
        .collect();
    tools_found.sort_by(|a, b| a.name.cmp(&b.name));

    let tools_missing_canon: Vec<String> = tools_found
        .iter()
        .filter(|t| !t.has_canon)
        .map(|t| t.name.clone())
        .collect();

    let mut providers_referenced: Vec<String> = scan.unique_providers.iter().cloned().collect();
    providers_referenced.sort();

    let providers_missing_canon: Vec<String> = providers_referenced
        .iter()
        .filter(|p| !bead_zeros.contains_key(&format!("provider:{}", p)))
        .cloned()
        .collect();

    let mut canonical_entities: Vec<String> = bead_zeros.keys().cloned().collect();
    canonical_entities.sort();

    let report = DiscoverReport {
        scan_path: scan_path.display().to_string(),
        audit_db: db_path.display().to_string(),
        system_canonicalized,
        tools_found,
        tools_missing_canon,
        providers_referenced,
        providers_missing_canon,
        canonical_entities,
    };

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("Error serializing report: {}", e);
                return 2;
            }
        }
    } else {
        print_discover_text(&report);
    }

    let total_violations =
        report.tools_missing_canon.len() + report.providers_missing_canon.len()
            + if report.system_canonicalized { 0 } else { 1 };
    if total_violations == 0 {
        0
    } else {
        1
    }
}

// ============================================================================
// zp scan — F3 content scanner for MCP tool definitions
// ============================================================================

#[derive(serde::Serialize)]
struct ScanReport {
    scan_path: String,
    known_tools_source: String,
    known_tools: Vec<String>,
    tools: Vec<zp_engine::tool_scan_security::ScannedTool>,
    summary: ScanSummary,
}

#[derive(serde::Serialize)]
struct ScanSummary {
    total: usize,
    clean: usize,
    flagged: usize,
    blocked: usize,
}

// ============================================================================
// V6 — zp adapt: refresh a canon'd tool's metadata to current schema
// ============================================================================
//
// Reads the tool's manifest + registry from disk, runs the F3 content
// scanner, and emits a `tool:adapted:<name>` lifecycle bead carrying the
// current scan_verdict + reversibility. The bead is parented to the
// tool's existing wire tip — bead-zero is NOT rewritten.
//
// Doctor's `query_canonicalization_metadata` overlays adapted-bead
// values on top of the bead-zero claim, so post-adapt the F3/F5 doctor
// counts reflect disk truth. Pre-F3 / pre-F5 tools whose bead-zero
// predates those features now have a remediation primitive.

fn run_adapt(
    tool: &str,
    path: Option<PathBuf>,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    use zp_engine::capability::reversibility_for_tool_dir;
    use zp_engine::tool_scan_security::{scan_path, ScanVerdict};

    let tool_path = path.unwrap_or_else(|| {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join("projects").join(tool))
            .unwrap_or_else(|_| PathBuf::from(tool))
    });

    if !tool_path.exists() {
        eprintln!(
            "\x1b[31merror\x1b[0m: tool path does not exist: {}",
            tool_path.display()
        );
        return 2;
    }

    // ── Read F5 reversibility from manifest ────────────────────────────
    let reversibility = reversibility_for_tool_dir(&tool_path);

    // ── Run F3 content scan, fold into a single tool-level verdict ─────
    let scanned = scan_path(&tool_path, &[]);
    let mut total = 0usize;
    let mut flagged = 0usize;
    let mut blocked = 0usize;
    let mut findings_total = 0usize;
    for s in &scanned {
        total += 1;
        findings_total += s.result.findings.len();
        match s.result.verdict {
            ScanVerdict::Clean => {}
            ScanVerdict::Flagged => flagged += 1,
            ScanVerdict::Blocked => blocked += 1,
        }
    }
    let tool_verdict = if blocked > 0 {
        "blocked"
    } else if flagged > 0 {
        "flagged"
    } else {
        "clean"
    };

    // ── Open audit store, emit lifecycle bead ───────────────────────────
    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));

    #[cfg(feature = "embedded-server")]
    let entry_hash = {
        use std::sync::{Arc, Mutex};
        let store = match zp_audit::AuditStore::open(&db_path) {
            Ok(s) => Arc::new(Mutex::new(s)),
            Err(e) => {
                eprintln!(
                    "\x1b[31merror\x1b[0m: cannot open audit store at {}: {}",
                    db_path.display(),
                    e
                );
                return 2;
            }
        };

        // Refuse to adapt if no bead-zero exists for this tool — the
        // overlay model assumes a base claim is already on the chain.
        let bead_zeros = zp_server::tool_chain::query_bead_zeros(&store);
        if !bead_zeros.contains_key(&format!("tool:{}", tool)) {
            eprintln!(
                "\x1b[31merror\x1b[0m: tool '{}' has no bead-zero on the chain — \
                 run discover/canonicalize first; adapt is for refreshing existing canons",
                tool
            );
            return 2;
        }

        zp_server::tool_chain::emit_adapted_receipt(
            &store,
            tool,
            Some(tool_verdict),
            Some(findings_total as u32),
            Some(reversibility.as_str()),
            None, // No signing key threaded through the CLI yet — F8
                  // makes the bead unsigned at this layer; doctor still
                  // reads its claim metadata correctly.
        )
    };

    #[cfg(not(feature = "embedded-server"))]
    let entry_hash: Option<String> = {
        eprintln!(
            "\x1b[33mwarn\x1b[0m: zp-cli built without `embedded-server` — \
             cannot emit adapted lifecycle bead"
        );
        None
    };

    if json {
        let report = serde_json::json!({
            "tool": tool,
            "path": tool_path.display().to_string(),
            "reversibility": reversibility.as_str(),
            "scan_verdict": tool_verdict,
            "scan_files_total": total,
            "scan_findings_count": findings_total,
            "entry_hash": entry_hash,
        });
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("error serializing report: {}", e);
                return 2;
            }
        }
    } else {
        println!("\x1b[1mzp adapt — F-integration metadata refresh\x1b[0m");
        println!("tool:           {}", tool);
        println!("path:           {}", tool_path.display());
        println!("reversibility:  {}", reversibility.as_str());
        println!(
            "scan verdict:   {} ({} files scanned, {} findings)",
            tool_verdict, total, findings_total
        );
        match entry_hash.as_deref() {
            Some(h) => println!("\x1b[32m✓\x1b[0m emitted tool:adapted:{}  entry_hash={}", tool, h),
            None => println!("\x1b[33m⚠\x1b[0m bead not appended (chain unavailable)"),
        }
    }

    if entry_hash.is_some() {
        0
    } else {
        1
    }
}

// ============================================================================
// V6 helpers end
// ============================================================================

// ============================================================================
// #176 — Merkle anchor verification + manual anchor trigger
// ============================================================================

/// Per-epoch verification result.
struct AnchorMismatch {
    epoch_number: u64,
    stored_root: String,
    computed_root: String,
    first_sequence: i64,
    last_sequence: i64,
}

/// Aggregated anchor-verification report.
struct AnchorReport {
    epoch_count: usize,
    total_entries: usize,
    entries_covered: usize,
    coverage_pct: f64,
    mismatches: Vec<AnchorMismatch>,
}

/// Truncate a hash for display.
fn short_hash(h: &str) -> String {
    if h.len() >= 12 {
        format!("{}…", &h[..12])
    } else {
        h.to_string()
    }
}

/// Walk the chain for `epoch:anchored:N` receipts; for each, recompute the
/// Merkle root from the entry range it claims and compare against the stored
/// root. Returns mismatches and coverage stats.
fn verify_anchors(store: &zp_audit::AuditStore) -> Result<AnchorReport, String> {
    use zp_core::{AuditAction, PolicyDecision};
    use zp_receipt::compute_merkle_root;

    let chain = store
        .export_chain(i32::MAX as usize)
        .map_err(|e| format!("export chain: {}", e))?;
    let total_entries = chain.len();

    let mut epochs: Vec<(u64, String, i64, i64)> = Vec::new(); // (n, root, first, last)
    for entry in &chain {
        if let AuditAction::SystemEvent { event } = &entry.action {
            if let Some(rest) = event.strip_prefix("epoch:anchored:") {
                if let Ok(n) = rest.parse::<u64>() {
                    if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                        if let Some(detail) = conditions.first() {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(detail) {
                                let root = v
                                    .get("merkle_root")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or_default()
                                    .to_string();
                                let first = v
                                    .get("first_sequence")
                                    .and_then(|x| x.as_i64())
                                    .unwrap_or(0);
                                let last = v
                                    .get("last_sequence")
                                    .and_then(|x| x.as_i64())
                                    .unwrap_or(0);
                                epochs.push((n, root, first, last));
                            }
                        }
                    }
                }
            }
        }
    }

    epochs.sort_by_key(|e| e.0);

    let mut mismatches = Vec::new();
    let mut entries_covered: usize = 0;
    for (n, stored_root, first, last) in &epochs {
        let pairs = store
            .export_hashes_in_range(*first, *last)
            .map_err(|e| format!("read range: {}", e))?;
        entries_covered += pairs.len();
        let hashes: Vec<String> = pairs.into_iter().map(|(_, h)| h).collect();
        let computed = compute_merkle_root(&hashes);
        if &computed != stored_root {
            mismatches.push(AnchorMismatch {
                epoch_number: *n,
                stored_root: stored_root.clone(),
                computed_root: computed,
                first_sequence: *first,
                last_sequence: *last,
            });
        }
    }

    let coverage_pct = if total_entries == 0 {
        0.0
    } else {
        (entries_covered as f64) / (total_entries as f64) * 100.0
    };

    Ok(AnchorReport {
        epoch_count: epochs.len(),
        total_entries,
        entries_covered,
        coverage_pct,
        mismatches,
    })
}

/// Manual anchor trigger: collect every chain entry since the last epoch,
/// build a Merkle tree, and append `epoch:anchored:N` directly. Operates
/// without the server runtime — uses NoOpAnchor as the backend.
fn run_anchor(
    audit_db: Option<PathBuf>,
    reason: &str,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    use zp_audit::UnsealedEntry;
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
    use zp_receipt::compute_merkle_root;

    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));
    let mut store = match zp_audit::AuditStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error opening audit store at {}: {}", db_path.display(), e);
            return 2;
        }
    };

    // Discover the prior epoch (if any) so we cover only new entries.
    let chain = match store.export_chain(i32::MAX as usize) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error exporting chain: {}", e);
            return 2;
        }
    };

    let mut last_epoch_seq: i64 = 0;
    let mut next_epoch_n: u64 = 0;
    let mut last_epoch_root: Option<String> = None;
    for entry in &chain {
        if let AuditAction::SystemEvent { event } = &entry.action {
            if let Some(rest) = event.strip_prefix("epoch:anchored:") {
                if let Ok(n) = rest.parse::<u64>() {
                    if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                        if let Some(detail) = conditions.first() {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(detail) {
                                let last_seq = v
                                    .get("last_sequence")
                                    .and_then(|x| x.as_i64())
                                    .unwrap_or(0);
                                if n + 1 > next_epoch_n {
                                    next_epoch_n = n + 1;
                                    last_epoch_seq = last_seq;
                                    last_epoch_root = v
                                        .get("merkle_root")
                                        .and_then(|x| x.as_str())
                                        .map(String::from);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let pairs = match store.export_hashes_after(last_epoch_seq) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error reading chain tail: {}", e);
            return 2;
        }
    };

    if pairs.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "no-op",
                    "reason": "chain has not advanced since last anchor"
                })
            );
        } else {
            println!(
                "\x1b[33m✗\x1b[0m no new entries since epoch {} — nothing to anchor",
                next_epoch_n.saturating_sub(1)
            );
        }
        return 0;
    }

    let first_sequence = pairs.first().map(|(r, _)| *r).unwrap();
    let last_sequence = pairs.last().map(|(r, _)| *r).unwrap();
    let entry_count = pairs.len();
    let hashes: Vec<String> = pairs.into_iter().map(|(_, h)| h).collect();
    let merkle_root = compute_merkle_root(&hashes);

    let detail = serde_json::json!({
        "epoch_number": next_epoch_n,
        "merkle_root": merkle_root,
        "prev_epoch_hash": last_epoch_root.unwrap_or_else(|| "genesis".to_string()),
        "first_sequence": first_sequence,
        "last_sequence": last_sequence,
        "entry_count": entry_count,
        "chain_id": "operator-cli",
        "backend": "none",
        "external_id": serde_json::Value::Null,
        "trigger": { "operator_requested": null, "reason": reason },
    });

    let unsealed = UnsealedEntry::new(
        ActorId::System("zp-anchor-cli".to_string()),
        AuditAction::SystemEvent {
            event: format!("epoch:anchored:{}", next_epoch_n),
        },
        ConversationId(uuid::Uuid::nil()),
        PolicyDecision::Allow {
            conditions: vec![detail.to_string()],
        },
        "anchor-cli",
    );

    let sealed = match store.append(unsealed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error appending epoch receipt: {}", e);
            return 2;
        }
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "epoch_number": next_epoch_n,
                "merkle_root": merkle_root,
                "first_sequence": first_sequence,
                "last_sequence": last_sequence,
                "entry_count": entry_count,
                "entry_hash": sealed.entry_hash,
                "reason": reason,
            })
        );
    } else {
        println!("\x1b[1mzp anchor — manual epoch seal\x1b[0m");
        println!("epoch:        {}", next_epoch_n);
        println!("merkle_root:  {}", short_hash(&merkle_root));
        println!(
            "range:        rowid {}..{} ({} entries)",
            first_sequence, last_sequence, entry_count
        );
        println!("reason:       {}", reason);
        println!("entry_hash:   {}", short_hash(&sealed.entry_hash));
        println!("\x1b[32m✓\x1b[0m sealed");
    }
    0
}

// ============================================================================
// #176 helpers end
// ============================================================================

// ============================================================================
// P4 (#197) — standing delegation: zp delegate / revoke / grants
// ============================================================================

/// Parse a duration like `30m`, `2h`, `8h`, `7d`, `45s`. Returns whole seconds.
fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let unit_char = unit.chars().next().unwrap();
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration number: '{}'", num_str))?;
    let secs = match unit_char {
        's' => n,
        'm' => n * 60,
        'h' => n * 60 * 60,
        'd' => n * 24 * 60 * 60,
        _ => return Err(format!("unknown duration unit: '{}'", unit_char)),
    };
    Ok(secs)
}

fn parse_failure_mode(s: &str) -> Result<zp_core::LeaseFailureMode, String> {
    match s {
        "halt" | "halt-on-expiry" => Ok(zp_core::LeaseFailureMode::HaltOnExpiry),
        "degrade" | "degrade-on-expiry" => Ok(zp_core::LeaseFailureMode::DegradeOnExpiry),
        "flag" | "continue-with-flag" => Ok(zp_core::LeaseFailureMode::ContinueWithFlag),
        other => Err(format!(
            "unknown failure_mode '{}': expected halt|degrade|flag",
            other
        )),
    }
}

fn parse_cascade(s: &str) -> Result<zp_core::CascadePolicy, String> {
    match s {
        "grant-only" | "grant_only" => Ok(zp_core::CascadePolicy::GrantOnly),
        "subtree-halt" | "subtree_halt" => Ok(zp_core::CascadePolicy::SubtreeHalt),
        "subtree-reroot" | "subtree_reroot" => Ok(zp_core::CascadePolicy::SubtreeReroot),
        other => Err(format!(
            "unknown cascade '{}': expected grant-only|subtree-halt|subtree-reroot",
            other
        )),
    }
}

fn parse_revocation_reason(s: &str) -> Result<zp_core::RevocationReason, String> {
    if let Some(rest) = s.strip_prefix("superseded:") {
        return Ok(zp_core::RevocationReason::Superseded {
            new_grant_id: rest.to_string(),
        });
    }
    match s {
        "operator-requested" | "operator_requested" => {
            Ok(zp_core::RevocationReason::OperatorRequested)
        }
        "lease-expired" | "lease_expired" => Ok(zp_core::RevocationReason::LeaseExpired),
        "compromise-detected" | "compromise_detected" => {
            Ok(zp_core::RevocationReason::CompromiseDetected)
        }
        "policy-violation" | "policy_violation" => Ok(zp_core::RevocationReason::PolicyViolation),
        other => Err(format!(
            "unknown revocation reason '{}': expected one of operator-requested|lease-expired|compromise-detected|policy-violation|superseded:<grant-id>",
            other
        )),
    }
}

fn parse_authorities(spec: &str) -> Vec<zp_core::AuthorityRef> {
    spec.split(',')
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .map(|h| {
            // We treat every named authority as a Genesis-rooted reference
            // for now. The CLI takes string handles like `genesis`, `sentinel`,
            // `apollo`; the resolution from handle to actual public key is a
            // P5 deployment concern — not all nodes know each other's keys
            // at issuance time.
            zp_core::AuthorityRef::genesis(format!("authority:{}", h))
        })
        .collect()
}

fn parse_capabilities(spec: &str) -> Vec<zp_core::GrantedCapability> {
    spec.split(',')
        .map(|c| c.trim())
        .filter(|c| !c.is_empty())
        .map(|c| zp_core::GrantedCapability::Custom {
            name: c.to_string(),
            parameters: serde_json::Value::Null,
        })
        .collect()
}

/// Map a `--tier-ceiling` argument to `TrustTier`. Returns the numeric
/// arg back as `Err` when out of the 0..=5 range so the caller can
/// surface "tier 6 unsupported" rather than silently capping.
fn tier_from_u8(t: u8) -> Result<zp_core::TrustTier, u8> {
    zp_core::TrustTier::from_u8(t).ok_or(t)
}

#[allow(clippy::too_many_arguments)]
fn run_delegate(
    subject: &str,
    capabilities: &str,
    tier_ceiling: u8,
    lease_duration: &str,
    renewal_interval: &str,
    renewal_authorities: &str,
    revocable_by: &str,
    max_depth: u32,
    failure_mode: &str,
    subject_public_key: Option<&str>,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    let lease_secs = match parse_duration(lease_duration) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: --lease-duration: {}", e);
            return 2;
        }
    };
    let renewal_secs = match parse_duration(renewal_interval) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: --renewal-interval: {}", e);
            return 2;
        }
    };
    let failure = match parse_failure_mode(failure_mode) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: --failure-mode: {}", e);
            return 2;
        }
    };

    // Resolve --tier-ceiling explicitly so an out-of-range value surfaces
    // as a CLI error rather than silently capping. T5 (Ceremony) is also
    // refused here — issuing a T5 grant from a running process violates
    // the cold-floor invariant; T5 only flows from the genesis ceremony.
    let tier = match tier_from_u8(tier_ceiling) {
        Ok(t) if t.is_ceremony() => {
            eprintln!(
                "error: --tier-ceiling 5 (Ceremony) cannot be issued by a running node. \
                 T5 is exercised only during a genesis ceremony with the operator key offline."
            );
            return 2;
        }
        Ok(t) => t,
        Err(n) => {
            eprintln!(
                "error: --tier-ceiling {} is out of range. Valid range: 0..=5 (5=Ceremony, non-issuable).",
                n
            );
            return 2;
        }
    };

    let caps = parse_capabilities(capabilities);
    if caps.is_empty() {
        eprintln!("error: --capabilities is empty");
        return 2;
    }
    let renewers = parse_authorities(renewal_authorities);
    let revokers = parse_authorities(revocable_by);

    // Resolve the subject's public key. If the caller passed one, validate
    // it. If not, generate a fresh Ed25519 keypair and print both halves
    // so the operator can transcribe the secret into the delegate's
    // lease.toml — the secret never lands on the chain.
    let (subject_pk_hex, generated_secret_hex): (String, Option<String>) = match subject_public_key {
        Some(hex_str) => {
            // Validate length — caller's responsibility for actual validity.
            let trimmed = hex_str.trim();
            if trimmed.len() != 64 {
                eprintln!(
                    "error: --subject-public-key must be 64 hex chars (32 bytes Ed25519); got {} chars",
                    trimmed.len()
                );
                return 2;
            }
            if hex::decode(trimmed).is_err() {
                eprintln!("error: --subject-public-key is not valid hex");
                return 2;
            }
            (trimmed.to_string(), None)
        }
        None => {
            // Generate a fresh keypair.
            use ed25519_dalek::SigningKey;
            use rand::RngCore;
            let mut sk_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut sk_bytes);
            let sk = SigningKey::from_bytes(&sk_bytes);
            let pk_hex = hex::encode(sk.verifying_key().to_bytes());
            let sk_hex = hex::encode(sk.to_bytes());
            (pk_hex, Some(sk_hex))
        }
    };

    // ZP capability grants are single-capability today; if the caller asks
    // for multiple, we issue the FIRST as the grant's main capability and
    // record the rest as constraints. Keeps the existing model intact while
    // surfacing the broader scope on the grant.
    let primary = caps[0].clone();
    let extra_capability_names: Vec<String> = caps.iter().skip(1).map(|c| c.name().into()).collect();

    let lease = zp_core::LeasePolicy {
        lease_duration: std::time::Duration::from_secs(lease_secs),
        grace_period: std::time::Duration::from_secs(lease_secs / 16 + 60), // ~6% + 1min
        renewal_interval: std::time::Duration::from_secs(renewal_secs),
        failure_mode: failure,
        max_consecutive_failures: 3,
    };
    let redelegation = if max_depth == 0 {
        zp_core::RedelegationPolicy::Forbidden
    } else {
        zp_core::RedelegationPolicy::Allowed {
            max_subtree_depth: max_depth,
        }
    };

    // Operator identity: read from the audit chain's genesis if available.
    // For P4 Phase 1 we use `subject` itself as the grantee handle and
    // `genesis` as the grantor handle. The actual public-key fields stay
    // empty until P5 deployment plumbs in the key registry.
    let mut grant = zp_core::CapabilityGrant::new(
        "genesis".to_string(),
        subject.to_string(),
        primary,
        format!("rcpt-delegate-{}", uuid::Uuid::now_v7()),
    )
    .with_trust_tier(tier)
    .with_lease_policy(lease)
    .with_renewal_authorities(renewers)
    .with_revocable_by(revokers)
    .with_redelegation_policy(redelegation)
    .with_subject_public_key(subject_pk_hex.clone())
    .as_standing("genesis");
    for name in &extra_capability_names {
        grant = grant.with_constraint(zp_core::Constraint::Custom {
            name: format!("capability:{}", name),
            value: serde_json::Value::Bool(true),
        });
    }

    // Emit the chain receipt.
    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));
    let store = match zp_audit::AuditStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error opening audit store at {}: {}", db_path.display(), e);
            return 2;
        }
    };
    use std::sync::{Arc, Mutex};
    let store = Arc::new(Mutex::new(store));

    #[cfg(feature = "embedded-server")]
    let entry_hash =
        zp_server::tool_chain::emit_delegation_receipt(&store, "granted", &grant);
    #[cfg(not(feature = "embedded-server"))]
    let entry_hash: Option<String> = {
        eprintln!("error: zp delegate requires the 'embedded-server' feature");
        return 2;
    };

    let entry_hash = match entry_hash {
        Some(h) => h,
        None => {
            eprintln!("error: failed to append delegation receipt");
            return 2;
        }
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "grant_id": grant.id,
                "subject": grant.grantee,
                "capabilities": caps.iter().map(|c| c.name().to_string()).collect::<Vec<_>>(),
                "trust_tier": format!("{:?}", grant.trust_tier),
                "lease_duration_secs": lease_secs,
                "renewal_interval_secs": renewal_secs,
                "expires_at": grant.expires_at,
                "subject_public_key": subject_pk_hex,
                "subject_secret_key": generated_secret_hex,
                "entry_hash": entry_hash,
            })
        );
    } else {
        println!("\x1b[1mzp delegate — standing delegation issued\x1b[0m");
        println!("grant_id:           {}", grant.id);
        println!("subject:            {}", grant.grantee);
        println!(
            "capabilities:       {}",
            caps.iter()
                .map(|c| c.name().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("trust_tier:         {:?}", grant.trust_tier);
        println!("lease_duration:     {}s", lease_secs);
        println!("renewal_interval:   {}s", renewal_secs);
        if let Some(exp) = grant.expires_at {
            println!("expires_at:         {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        println!("subject_pubkey:     {}", subject_pk_hex);
        println!("entry_hash:         {}", short_hash(&entry_hash));
        println!("\x1b[32m✓\x1b[0m granted");

        if let Some(sk_hex) = &generated_secret_hex {
            println!();
            println!("\x1b[33m⚠  SUBJECT SECRET KEY (one-time display)\x1b[0m");
            println!("    {}", sk_hex);
            println!();
            println!("Copy the secret into the delegate's ~/ZeroPoint/lease.toml as");
            println!("`subject_signing_key_hex`. It is NOT stored anywhere on this machine");
            println!("after this command exits. The chain only sees the public half.");
            println!();
            println!("Suggested lease.toml for {}:", grant.grantee);
            println!();
            println!("    grant_id = \"{}\"", grant.id);
            println!("    subject_node_id = \"{}\"", grant.grantee);
            println!("    subject_signing_key_hex = \"{}\"", sk_hex);
            println!("    renewal_authorities = [\"http://<authority-host>:17010\"]");
            println!("    renewal_interval_secs = {}", renewal_secs);
            println!(
                "    max_consecutive_failures = 3"
            );
            let grace_secs = lease_secs / 16 + 60;
            println!("    grace_period_secs = {}", grace_secs);
            println!("    failure_mode = \"{}\"", failure_mode);
        }
    }
    0
}

fn run_revoke(
    grant_id: &str,
    cascade: &str,
    reason: &str,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    let cascade_policy = match parse_cascade(cascade) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: --cascade: {}", e);
            return 2;
        }
    };
    let revocation_reason = match parse_revocation_reason(reason) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: --reason: {}", e);
            return 2;
        }
    };

    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));
    let store = match zp_audit::AuditStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error opening audit store at {}: {}", db_path.display(), e);
            return 2;
        }
    };
    use std::sync::{Arc, Mutex};
    let store = Arc::new(Mutex::new(store));

    // Resolve target subject from chain so the chain entry's event suffix
    // matches the original `delegation:granted:{subject}`.
    let chain = match store.lock().unwrap().export_chain(i32::MAX as usize) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: export chain: {}", e);
            return 2;
        }
    };
    let target_subject = match find_subject_for_grant(&chain, grant_id) {
        Some(s) => s,
        None => {
            eprintln!(
                "error: grant {} not found on chain — cannot revoke",
                grant_id
            );
            return 2;
        }
    };

    let claim = zp_core::RevocationClaim::new(
        grant_id,
        "genesis".to_string(),
        zp_core::AuthorityRef::genesis("revocation_authority"),
        cascade_policy,
        revocation_reason,
    );

    #[cfg(feature = "embedded-server")]
    let entry_hash =
        zp_server::tool_chain::emit_revocation_receipt(&store, &target_subject, &claim);
    #[cfg(not(feature = "embedded-server"))]
    let entry_hash: Option<String> = {
        eprintln!("error: zp revoke requires the 'embedded-server' feature");
        return 2;
    };

    let entry_hash = match entry_hash {
        Some(h) => h,
        None => {
            eprintln!("error: failed to append revocation receipt");
            return 2;
        }
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "revocation_id": claim.revocation_id,
                "target_grant_id": grant_id,
                "subject": target_subject,
                "cascade": format!("{:?}", claim.cascade),
                "reason": format!("{:?}", claim.reason),
                "entry_hash": entry_hash,
            })
        );
    } else {
        println!("\x1b[1mzp revoke — grant revoked\x1b[0m");
        println!("revocation_id:      {}", claim.revocation_id);
        println!("target_grant_id:    {}", grant_id);
        println!("subject:            {}", target_subject);
        println!("cascade:            {:?}", claim.cascade);
        println!("reason:             {:?}", claim.reason);
        println!("entry_hash:         {}", short_hash(&entry_hash));
        println!("\x1b[32m✓\x1b[0m revoked");
    }
    0
}

/// Walk the chain to find the `subject` for which the named grant was issued.
fn find_subject_for_grant(
    chain: &[zp_core::AuditEntry],
    grant_id: &str,
) -> Option<String> {
    for entry in chain {
        if let zp_core::AuditAction::SystemEvent { event } = &entry.action {
            if let Some(rest) = event.strip_prefix("delegation:granted:") {
                if let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision {
                    if let Some(body) = conditions.first() {
                        if let Ok(g) = serde_json::from_str::<zp_core::CapabilityGrant>(body) {
                            if g.id == grant_id {
                                return Some(rest.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
struct GrantSnapshot {
    grant: zp_core::CapabilityGrant,
    revoked: bool,
    revoked_reason: Option<String>,
    last_renewed_at: Option<chrono::DateTime<chrono::Utc>>,
    renewal_count: u32,
}

/// Reconstruct the active-grant table from chain receipts.
fn reconstruct_grants(chain: &[zp_core::AuditEntry]) -> Vec<GrantSnapshot> {
    let mut grants: std::collections::HashMap<String, GrantSnapshot> = Default::default();
    for entry in chain {
        let zp_core::AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision else {
            continue;
        };
        let Some(body) = conditions.first() else {
            continue;
        };

        if event.starts_with("delegation:granted:") {
            if let Ok(g) = serde_json::from_str::<zp_core::CapabilityGrant>(body) {
                grants.insert(
                    g.id.clone(),
                    GrantSnapshot {
                        grant: g,
                        revoked: false,
                        revoked_reason: None,
                        last_renewed_at: None,
                        renewal_count: 0,
                    },
                );
            }
        } else if event.starts_with("delegation:renewed:") {
            if let Ok(g) = serde_json::from_str::<zp_core::CapabilityGrant>(body) {
                if let Some(snap) = grants.get_mut(&g.id) {
                    snap.grant = g.clone();
                    snap.last_renewed_at = g.last_renewed_at.or(Some(entry.timestamp));
                    snap.renewal_count = g.renewal_count;
                }
            }
        } else if event.starts_with("delegation:revoked:") {
            if let Ok(claim) = serde_json::from_str::<zp_core::RevocationClaim>(body) {
                if let Some(snap) = grants.get_mut(&claim.target_grant_id) {
                    snap.revoked = true;
                    snap.revoked_reason = Some(format!("{:?}", claim.reason));
                }
            }
        } else if event.starts_with("delegation:expired:") {
            if let Ok(g) = serde_json::from_str::<zp_core::CapabilityGrant>(body) {
                if let Some(snap) = grants.get_mut(&g.id) {
                    snap.revoked = true;
                    snap.revoked_reason = Some("LeaseExpired".to_string());
                }
            }
        }
    }
    let mut v: Vec<_> = grants.into_values().collect();
    v.sort_by(|a, b| a.grant.created_at.cmp(&b.grant.created_at));
    v
}

fn lease_status(g: &zp_core::CapabilityGrant) -> &'static str {
    if g.is_past_grace() {
        "EXPIRED"
    } else if g.is_in_grace_period() {
        "GRACE"
    } else {
        "ALIVE"
    }
}

fn run_grants(
    check: bool,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));
    let store = match zp_audit::AuditStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error opening audit store at {}: {}", db_path.display(), e);
            return 2;
        }
    };
    let chain = match store.export_chain(i32::MAX as usize) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: export chain: {}", e);
            return 2;
        }
    };

    let snaps = reconstruct_grants(&chain);

    if check {
        let mut violations: Vec<String> = Vec::new();

        // Invariant: revocation is permanent. Once a `delegation:revoked:*`
        // entry has landed for a grant_id, no `delegation:renewed:*` may
        // appear afterwards. We check by walking the chain in rowid order
        // — the snapshot view alone can't tell which receipt came first.
        let mut revoked_at_seq: std::collections::HashMap<String, usize> = Default::default();
        for (idx, entry) in chain.iter().enumerate() {
            let zp_core::AuditAction::SystemEvent { event } = &entry.action else {
                continue;
            };
            let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision else {
                continue;
            };
            let Some(body) = conditions.first() else {
                continue;
            };
            if event.starts_with("delegation:revoked:") {
                if let Ok(claim) = serde_json::from_str::<zp_core::RevocationClaim>(body) {
                    revoked_at_seq.insert(claim.target_grant_id, idx);
                }
            } else if event.starts_with("delegation:renewed:") {
                if let Ok(g) = serde_json::from_str::<zp_core::CapabilityGrant>(body) {
                    if let Some(&revoked_idx) = revoked_at_seq.get(&g.id) {
                        if idx > revoked_idx {
                            violations.push(format!(
                                "grant {} renewed at chain index {} after revocation at index {}",
                                g.id, idx, revoked_idx
                            ));
                        }
                    }
                }
            }
        }

        // Invariant: every grant with a `lease_policy` must list at least
        // one renewal authority — otherwise it can never be renewed and
        // should have been issued without a lease.
        for snap in &snaps {
            if snap.grant.lease_policy.is_some() && snap.grant.renewal_authorities.is_empty() {
                violations.push(format!(
                    "grant {} has a lease_policy but no renewal_authorities",
                    snap.grant.id
                ));
            }
        }

        if json {
            println!(
                "{}",
                serde_json::json!({
                    "grants_checked": snaps.len(),
                    "violations": violations,
                })
            );
        } else {
            println!("\x1b[1mzp grants --check\x1b[0m");
            println!("grants checked: {}", snaps.len());
            if violations.is_empty() {
                println!("invariants:     \x1b[32mOK\x1b[0m");
            } else {
                println!(
                    "invariants:     \x1b[31mFAIL\x1b[0m ({} violation(s))",
                    violations.len()
                );
                for v in &violations {
                    println!("  • {}", v);
                }
            }
        }
        return if violations.is_empty() { 0 } else { 1 };
    }

    if json {
        let entries: Vec<_> = snaps
            .iter()
            .map(|snap| {
                serde_json::json!({
                    "grant_id": snap.grant.id,
                    "subject": snap.grant.grantee,
                    "capability": snap.grant.capability.name(),
                    "trust_tier": format!("{:?}", snap.grant.trust_tier),
                    "expires_at": snap.grant.expires_at,
                    "lease_status": lease_status(&snap.grant),
                    "revoked": snap.revoked,
                    "revoked_reason": snap.revoked_reason,
                    "renewal_count": snap.renewal_count,
                    "last_renewed_at": snap.last_renewed_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({ "grants": entries, "total": snaps.len() })
        );
    } else {
        println!("\x1b[1mzp grants — standing delegations\x1b[0m");
        if snaps.is_empty() {
            println!("(no standing delegations on chain)");
            return 0;
        }
        println!(
            "{:<20} {:<14} {:<18} {:<6} {:<8} {:<6} {}",
            "subject", "grant_id", "capability", "tier", "lease", "renew", "status"
        );
        for snap in &snaps {
            let id_short = if snap.grant.id.len() > 14 {
                format!("{}…", &snap.grant.id[..13])
            } else {
                snap.grant.id.clone()
            };
            let status = if snap.revoked {
                format!(
                    "\x1b[31mREVOKED\x1b[0m ({})",
                    snap.revoked_reason.as_deref().unwrap_or("?")
                )
            } else {
                let s = lease_status(&snap.grant);
                let colour = match s {
                    "ALIVE" => "\x1b[32m",
                    "GRACE" => "\x1b[33m",
                    _ => "\x1b[31m",
                };
                format!("{}{}\x1b[0m", colour, s)
            };
            println!(
                "{:<20} {:<14} {:<18} {:<6} {:<8} {:<6} {}",
                snap.grant.grantee,
                id_short,
                snap.grant.capability.name(),
                format!("{:?}", snap.grant.trust_tier),
                if snap.grant.lease_policy.is_some() {
                    "yes"
                } else {
                    "no"
                },
                snap.renewal_count,
                status
            );
        }
    }
    0
}

// ============================================================================
// P4 helpers end
// ============================================================================

fn run_scan(
    path: &std::path::Path,
    json: bool,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
) -> i32 {
    use zp_engine::tool_scan_security::{ScanVerdict, scan_path};

    if !path.exists() {
        eprintln!(
            "\x1b[31merror\x1b[0m: path does not exist: {}",
            path.display()
        );
        return 2;
    }

    // Resolve the typosquat reference set: canon'd tool names from the chain.
    let (known_tools, source_label) = load_known_tools(audit_db, data_dir);

    let scanned = scan_path(path, &known_tools);

    let mut clean = 0usize;
    let mut flagged = 0usize;
    let mut blocked = 0usize;
    for s in &scanned {
        match s.result.verdict {
            ScanVerdict::Clean => clean += 1,
            ScanVerdict::Flagged => flagged += 1,
            ScanVerdict::Blocked => blocked += 1,
        }
    }

    let report = ScanReport {
        scan_path: path.display().to_string(),
        known_tools_source: source_label,
        known_tools: known_tools.clone(),
        summary: ScanSummary {
            total: scanned.len(),
            clean,
            flagged,
            blocked,
        },
        tools: scanned,
    };

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("error serializing report: {}", e);
                return 2;
            }
        }
    } else {
        print_scan_text(&report);
    }

    if blocked > 0 {
        2
    } else if flagged > 0 {
        1
    } else {
        0
    }
}

fn load_known_tools(
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
) -> (Vec<String>, String) {
    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));

    #[cfg(feature = "embedded-server")]
    {
        use std::sync::{Arc, Mutex};
        if db_path.exists() {
            if let Ok(store) = zp_audit::AuditStore::open(&db_path) {
                let store = Arc::new(Mutex::new(store));
                let bead_zeros = zp_server::tool_chain::query_bead_zeros(&store);
                let mut tools: Vec<String> = bead_zeros
                    .keys()
                    .filter_map(|k| k.strip_prefix("tool:").map(String::from))
                    .collect();
                tools.sort();
                return (tools, format!("audit chain ({})", db_path.display()));
            }
        }
        (Vec::new(), format!("audit chain unavailable ({})", db_path.display()))
    }

    #[cfg(not(feature = "embedded-server"))]
    {
        let _ = db_path;
        (Vec::new(), "no chain (built without embedded-server)".to_string())
    }
}

fn print_scan_text(r: &ScanReport) {
    use zp_engine::tool_scan_security::{ScanSeverity, ScanVerdict};

    println!("\x1b[1mzp scan — F3 MCP tool content falsifier\x1b[0m");
    println!("scan_path:   {}", r.scan_path);
    println!("known_tools: {} ({})", r.known_tools.len(), r.known_tools_source);
    println!();

    if r.tools.is_empty() {
        println!(
            "\x1b[33mwarn\x1b[0m: no tool definitions found at the supplied path"
        );
        println!(
            "       (looked for tool.json, mcp.json, manifest.json, *.tool.json, *.mcp.json,"
        );
        println!("       and *.json under tools/ subdirectories)");
        return;
    }

    for s in &r.tools {
        let mark = match s.result.verdict {
            ScanVerdict::Clean => "\x1b[32m✓\x1b[0m",
            ScanVerdict::Flagged => "\x1b[33m⚠\x1b[0m",
            ScanVerdict::Blocked => "\x1b[31m✗\x1b[0m",
        };
        println!(
            "{} {}  ({})  [{}]",
            mark,
            s.result.tool_name,
            s.source_path.display(),
            s.result.verdict.as_str(),
        );
        for f in &s.result.findings {
            let sev = match f.severity {
                ScanSeverity::Critical => "\x1b[31mcritical\x1b[0m",
                ScanSeverity::Warning => "\x1b[33mwarning\x1b[0m",
            };
            println!(
                "    {} [{:?}] {}: {}",
                sev, f.category, f.location, f.detail
            );
            if !f.evidence.is_empty() {
                println!("      evidence: {}", f.evidence);
            }
        }
        // F5 advisory: surface the reversibility annotation the scanner
        // attached to this result (#194). `Unknown` shows when the
        // manifest didn't declare or no `.zp-configure.toml` was found
        // walking up from this file.
        if let Some(rev) = s.result.reversibility {
            match rev {
                zp_engine::capability::Reversibility::Reversible => {
                    println!("    \x1b[36madvisory\x1b[0m: reversibility=reversible (allowed at any tier)");
                }
                zp_engine::capability::Reversibility::Partial => {
                    println!("    \x1b[33madvisory\x1b[0m: reversibility=partial — gate treats as irreversible (requires tier ≥ 1)");
                }
                zp_engine::capability::Reversibility::Irreversible => {
                    // #194 — note the new escalation rule next to the advisory
                    // so operators see why a Flagged tool became Blocked.
                    println!("    \x1b[33madvisory\x1b[0m: reversibility=irreversible (requires tier ≥ 1; flagged findings escalate to blocked)");
                }
                zp_engine::capability::Reversibility::Unknown => {
                    println!("    \x1b[33madvisory\x1b[0m: reversibility=unknown — gate treats as irreversible (requires tier ≥ 1)");
                }
            }
        }
    }

    println!();
    println!(
        "summary:     {} total — \x1b[32m{} clean\x1b[0m, \x1b[33m{} flagged\x1b[0m, \x1b[31m{} blocked\x1b[0m",
        r.summary.total, r.summary.clean, r.summary.flagged, r.summary.blocked,
    );
    println!();
    if r.summary.blocked > 0 {
        println!(
            "verdict:     \x1b[31mBLOCKED\x1b[0m — {} tool{} cannot earn a canon without operator override",
            r.summary.blocked,
            if r.summary.blocked == 1 { "" } else { "s" }
        );
    } else if r.summary.flagged > 0 {
        println!(
            "verdict:     \x1b[33mFLAGGED\x1b[0m — {} tool{} can canon but findings are recorded on the bead",
            r.summary.flagged,
            if r.summary.flagged == 1 { "" } else { "s" }
        );
    } else {
        println!(
            "verdict:     \x1b[32mCLEAN\x1b[0m — every scanned tool passed every falsifier"
        );
    }
}

fn print_discover_text(r: &DiscoverReport) {
    println!("\x1b[1mzp discover — M11 Canonicalization Audit\x1b[0m");
    println!("scan_path:   {}", r.scan_path);
    println!("audit_db:    {}", r.audit_db);
    println!();

    // System anchor
    print!("system:      ");
    if r.system_canonicalized {
        println!("\x1b[32m✓ canonicalized\x1b[0m (system:zeropoint)");
    } else {
        println!("\x1b[31m✗ uncanonicalized\x1b[0m — no system:zeropoint bead zero in chain");
    }

    // Tools
    println!();
    println!(
        "tools:       {} found on disk, {} missing canon",
        r.tools_found.len(),
        r.tools_missing_canon.len()
    );
    for t in &r.tools_found {
        let mark = if t.has_canon {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        };
        let rev_tag = match t.reversibility.as_str() {
            "reversible" => "\x1b[32m[reversible]\x1b[0m".to_string(),
            "partial" => "\x1b[33m[partial → treated as irreversible]\x1b[0m".to_string(),
            "irreversible" => "\x1b[33m[irreversible]\x1b[0m".to_string(),
            _ => "\x1b[33m[unknown → treated as irreversible]\x1b[0m".to_string(),
        };
        println!("  {} {}  {}  {}", mark, t.name, t.path, rev_tag);
    }

    // Providers
    println!();
    println!(
        "providers:   {} referenced by tools, {} missing canon",
        r.providers_referenced.len(),
        r.providers_missing_canon.len()
    );
    for p in &r.providers_referenced {
        let key = format!("provider:{}", p);
        let mark = if r.canonical_entities.iter().any(|e| e == &key) {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        };
        println!("  {} {}", mark, p);
    }

    // Verdict
    println!();
    let total =
        r.tools_missing_canon.len() + r.providers_missing_canon.len()
            + if r.system_canonicalized { 0 } else { 1 };
    if total == 0 {
        println!("verdict:     \x1b[32mCLEAN\x1b[0m — every discovered entity has a bead zero");
    } else {
        println!(
            "verdict:     \x1b[31mM11 VIOLATIONS\x1b[0m — {} entit{} executing without a canon",
            total,
            if total == 1 { "y" } else { "ies" }
        );
        println!();
        println!("remediation: emit a CanonicalizedClaim receipt for each missing entity");
        println!("             (see crates/zp-server/src/tool_chain.rs append_bead_zero)");
    }
}
