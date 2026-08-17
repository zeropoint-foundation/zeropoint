//! ZeroPoint CLI — terminal interface for developers.

mod chat;
mod commands;
mod keychain;
use zp_configure as configure;
mod emit;
mod guard;
mod init;
mod mesh_commands;
mod onboard;
#[cfg(feature = "policy-wasm")]
mod policy_commands;
mod recover;
mod run;
mod secure;
mod shell;

use anyhow::Context;
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
        /// Bind address (overrides config; default from config or 127.0.0.1)
        #[arg(long)]
        bind: Option<String>,

        /// Port (overrides config; default from config or 17770)
        #[arg(long)]
        port: Option<u16>,

        /// Don't open the dashboard in browser
        #[arg(long)]
        no_open: bool,

        /// Run in the foreground instead of daemonizing (debug use)
        #[arg(long)]
        foreground: bool,
    },
    /// Restart tools or the ZeroPoint server.
    ///
    /// Use --name <tool> to restart a specific ZP-managed tool.
    /// Use --all to restart all registered tools.
    /// Use --self to restart the ZP server itself (escape hatch).
    Restart {
        /// Restart a specific tool by name
        #[arg(long)]
        name: Option<String>,
        /// Restart all ZP-managed tools
        #[arg(long)]
        all: bool,
        /// Restart the ZP server itself (escape hatch — use when chain can't be queried)
        #[arg(long, name = "self")]
        self_: bool,
    },
    /// Port registry operations
    #[command(subcommand)]
    Port(PortCmd),
    /// Interactive chat with the pipeline
    Chat,
    /// System health check
    Health,
    /// Officer cadre diagnostic operations
    ///
    /// Manual trigger for officer sweeps outside the periodic sweep timer.
    /// Composes with OFFICER-ACTION-SURFACES + SUBSTRATE-COORDINATION-DISCIPLINE:
    /// operator (or Regent via equivalent tool) explicitly requests diagnostic
    /// visibility into current officer state.
    #[command(subcommand)]
    Officer(OfficerCmd),
    /// Vault diagnostic and probe operations
    ///
    /// Composes with aligned blindness (KEEL III.24): credential values never
    /// enter cognitive layer; probes return structural pass/fail signals only.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Substrate diagnostic operations — deterministic validation primitives
    ///
    /// Runs canonical substrate validation checks against the running substrate.
    /// Companion to Regent's substrate_validate tool (task #20); provides
    /// operator direct-invocation path independent of Regent's dispatch choice.
    #[command(subcommand)]
    Substrate(SubstrateCmd),
    /// Standing correction operations — chain-anchored operator claims
    /// about Regent's cognitive layer per STANDING-CORRECTION-RECEIPT-SCHEMA.
    /// Persist across cycles; consumed at Tier 1 of Regent's cognitive input.
    #[command(subcommand)]
    Correction(CorrectionCmd),
    /// Approval requests the Regent has raised, and the operator's answers.
    ///
    /// `Intent::RequestApproval` chain-anchors the ask; these verbs
    /// chain-anchor the answer. Per P9 the approval is the operator's act,
    /// not the Regent's reading of a conversation.
    #[command(subcommand)]
    Approval(ApprovalCmd),

    /// The Regent's autonomous envelope — what it may do without asking.
    ///
    /// Precedent is the only thing that widens that envelope, and it widens
    /// permanently until withdrawn. Per KEEL §III.10 the envelope grows
    /// through operator-signed precedent and narrows through revocation, and
    /// both are chain events. These verbs are how an operator sees the first
    /// and performs the second.
    #[command(subcommand)]
    Precedent(PrecedentCmd),
    /// Audit trail operations
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Chain narration and storytelling
    #[command(subcommand)]
    Chain(ChainCmd),
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

    /// Model registry — register, inspect, and update LLM model capabilities.
    /// The audit chain is the registry; no external model database required.
    #[command(subcommand)]
    Model(ModelCmd),

    /// Tool lifecycle management (list, remove)
    #[command(subcommand)]
    Tool(ToolCmd),

    /// Configure tools from vault (Semantic Sed)
    #[command(subcommand)]
    Configure(ConfigureCmd),

    /// Manage OS Keychain entries created by ZeroPoint
    #[command(subcommand)]
    Keychain(KeychainCmd),

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

    /// Workspace operator management — create, register, and manage staff
    #[command(subcommand)]
    Operator(OperatorCmd),

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

        /// Verify against a specific server address (e.g., 192.168.1.199:17770).
        /// Overrides the node.upstream config and localhost default.
        /// Delegate nodes auto-resolve this from zeropoint.toml [node] upstream.
        #[arg(long)]
        server: Option<String>,

        /// Verify the foundation chain at zeropointfoundation.org instead of
        /// the local audit chain. Fetches entries over HTTPS and verifies
        /// hash linkage + Ed25519 signatures. Requires workspace:admin capability.
        #[arg(long)]
        foundation: bool,

        /// Foundation worker URL (default: https://zeropointfoundation.org).
        /// Override for local wrangler dev: --foundation-url http://localhost:8787
        #[arg(long)]
        foundation_url: Option<String>,

        /// Verify foundation-relayed receipts on the LOCAL audit chain.
        /// Filters to AuditAction::SystemEvent entries with event prefix
        /// "foundation_relay:" — receipts forwarded from the Foundation
        /// Edge worker and signed by the operator's audit signer. Distinct
        /// from --foundation, which does remote HTTPS verification against
        /// a worker endpoint.
        #[arg(long)]
        foundation_receipts: bool,

        /// Scope --foundation-receipts to a single operator_id. Defaults
        /// to showing all operators' relayed receipts on this chain.
        #[arg(long, requires = "foundation_receipts")]
        operator: Option<String>,
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

    /// Talk to the Regent — ZeroPoint's apex cognitive entity
    ///
    /// Sends a message to the running Regent and prints the response.
    /// Requires `[regent] enabled = true` in config and a running `zp serve`.
    Regent {
        /// Message to send to the Regent
        message: String,

        /// Show real-time cognitive pipeline events (timing, phases, bottlenecks)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Run post-install diagnostics — check everything and report problems
    Doctor {
        /// Output as JSON (machine-readable)
        #[arg(long)]
        json: bool,
    },

    /// Show all TCP-LISTEN processes with substrate attribution (Part VIII Stage 1)
    ///
    /// Samples the OS for listening ports, attributes each process as
    /// substrate-managed, known-system, or unknown, and prints a table.
    /// Unknown processes are the ones that need operator attention.
    ///
    /// With --tools: also run per-tool health checks — proxy reachability,
    /// port assignment verification, and auth round-trip. This is the
    /// 10-second diagnostic that replaces manual Scooby-Doo debugging.
    Ps {
        /// Output as JSON (machine-readable)
        #[arg(long)]
        json: bool,
        /// Also check governed tool health: proxy reachability, port
        /// assignment, and auth round-trip for each registered tool.
        #[arg(long)]
        tools: bool,
    },

    /// Record a new version for a running tool and optionally relaunch it.
    ///
    /// Captures the current git commit + binary hash for the tool's working
    /// directory, emits a `tool:updated:<name>` chain receipt, then stops the
    /// old process and relaunches with the stored launch command.
    ///
    /// The working directory is taken from the stored `StoredLaunchCommand.working_dir`
    /// (set by `zp configure exec` at spawn time). If no stored command exists,
    /// use `zp configure exec --name <tool> -- <cmd>` first.
    ///
    /// Example:
    ///   zp update --name ember
    #[cfg(feature = "embedded-server")]
    Update {
        /// Tool name (must match `zp port list` output)
        #[arg(long)]
        name: String,

        /// Skip stopping and relaunching the tool — only record the new version.
        #[arg(long)]
        record_only: bool,
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

    /// Emit a bead-zero CanonicalizedClaim receipt for a tool (M11 remediation).
    ///
    /// This is the operator act of recognising a tool as a first-class entity
    /// in the substrate. It must be run once per tool before any `zp adapt`
    /// or chain-grounded reasoning about that tool can proceed.
    ///
    /// Example:
    ///   zp canonicalize --name ember --path ~/projects/ember
    #[cfg(feature = "embedded-server")]
    Canonicalize {
        /// Tool name (must match `zp port list` / `zp discover` output)
        #[arg(long)]
        name: String,

        /// Tool project directory — used to capture the git commit as initial state.
        /// If omitted, initial_state records name and timestamp only.
        #[arg(long)]
        path: Option<PathBuf>,

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

        /// Smooth renewal: look up the most-recent active grant for
        /// --subject and issue a fresh grant with identical capabilities,
        /// trust tier, and lease window. Only --subject is required when
        /// this flag is set; --capabilities, --tier-ceiling, --lease-duration
        /// are filled from the prior grant (--lease-duration can still be
        /// provided to override the prior window).
        ///
        /// The new grant carries `renews: <prior_grant_id>` in its chain
        /// receipt, making renewal a first-class continuity event.
        #[arg(long)]
        renew: bool,

        /// Audit DB path. Defaults to <data-dir>/audit.db.
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit JSON instead of human text.
        #[arg(long)]
        json: bool,
    },

    /// P4 (#197) — Revoke a standing delegation grant.
    ///
    /// Exactly one of `--grant-id` or `--grantee` is required.
    ///
    /// `--grantee` exists because revocation is per-grant-id and cockpit
    /// launch mints a fresh grant every time: an agent in service for a
    /// while holds many live grants, and revoking one leaves the rest
    /// authorised. `--cascade` does not help — it walks the delegation
    /// subtree (children of a grant), not sibling grants of the same
    /// grantee. See docs/design/PERENNIAL-GRANT-2026-08.md §4.
    Revoke {
        /// Target grant id (`grant-...`). Mutually exclusive with `--grantee`.
        #[arg(long, conflicts_with = "grantee", required_unless_present = "grantee")]
        grant_id: Option<String>,

        /// Revoke every live grant held by this grantee. Mutually exclusive
        /// with `--grant-id`.
        #[arg(long)]
        grantee: Option<String>,

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

    /// Emit a signed receipt from a shell script or external process.
    ///
    /// Creates an ObservationClaim receipt with the given label and metadata,
    /// signs it with the operator key, and appends it to the audit chain.
    /// Designed for orchestration hooks (Symphony, CI, custom systems).
    ///
    /// Examples:
    ///   zp emit orchestrator:workspace:created --issue PROJ-347 --agent agent-12
    ///   zp emit orchestrator:run:sealed --issue PROJ-347 --meta exit_code=0
    Emit {
        /// Event label (e.g., orchestrator:workspace:created, agent:turn:3)
        label: String,

        /// Issue or task identifier (groups receipts into a logical chain)
        #[arg(long)]
        issue: Option<String>,

        /// Agent identifier
        #[arg(long)]
        agent: Option<String>,

        /// Parent receipt ID (for chain sequencing)
        #[arg(long)]
        parent: Option<String>,

        /// Upstream genesis reference (for new chain roots)
        #[arg(long)]
        upstream: Option<String>,

        /// Key=value metadata pairs (repeatable)
        #[arg(long = "meta", value_parser = parse_key_val)]
        meta: Vec<(String, String)>,

        /// Path to audit store (default: <data-dir>/audit.db)
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit JSON output instead of just the receipt ID
        #[arg(long)]
        json: bool,
    },

    /// Launch a ZP-governed tool by name using its manifest's [launch] section.
    ///
    /// The tool must have been configured via `zp configure tool` first.
    /// Verifies the manifest hash, emits a receipt, then exec's the child
    /// process with vault-resolved env and a restricted parent env whitelist.
    Run {
        /// Tool name (must have been configured via `zp configure tool` first)
        name: String,
        /// Extra args appended after the manifest's args (after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra_args: Vec<String>,
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

    /// Pricing freshness — fetch live pricing data or manually attest pricing.
    #[command(subcommand)]
    Pricing(PricingCmd),
}

#[derive(Subcommand)]
enum PortCmd {
    /// List all tool port assignments in the registry
    List,
}

#[derive(Subcommand)]
enum SubstrateCmd {
    /// Run canonical substrate validation.
    ///
    /// Walks the chain, checks canonical disciplines (chain integrity, canary,
    /// cognitive discipline sandwich, standing corrections, officer heartbeats,
    /// receipt-type inventory), emits `substrate:validation:regent:<id>`
    /// chain-anchored evidence receipt, returns structured findings.
    ///
    /// Same primitive Regent invokes via `substrate_validate` tool (task #20).
    /// Operator direct-invocation via this verb sidesteps Regent dispatch drift.
    ///
    /// Examples:
    ///   zp substrate validate
    ///   zp substrate validate --json
    Validate {
        /// Emit result as raw JSON instead of formatted text
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// List key names held in the vault. Never prints values.
    ///
    /// Until 2026-08 the vault had no operator surface at all — no way to see
    /// what it held. The one report on it was Steward's `vault_empty` finding,
    /// which says "contains no entries" whether the key is unresolved, the
    /// vault is unreadable, or it is genuinely empty. This distinguishes them.
    List {
        /// Emit result as raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Store a secret. The value is read from stdin, never from an argument.
    ///
    /// Passing a secret on the command line puts it in shell history, the
    /// process table, and any shell-integration log. Piping keeps it out of
    /// all three:
    ///
    ///   printf %s "$SECRET" | zp vault put system/regent/inference/api_key
    Put {
        /// Vault key path, e.g. `system/regent/inference/api_key`.
        /// The leading segment selects the encryption tier.
        key: String,
        /// Emit result as raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Print a secret's value to stdout.
    ///
    /// The only verb that emits secret material, and present on purpose.
    /// Per delegable safety (KEEL §III.18) a restriction with no sanctioned
    /// path gets bypassed — an operator who cannot recover a secret from the
    /// vault keeps their secrets somewhere else, which defeats the discipline
    /// the omission was meant to protect. The read is chain-anchored so it is
    /// auditable; the value never reaches the chain.
    Reveal {
        /// Vault key path.
        key: String,
        /// Emit result as raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove a secret by key name.
    Remove {
        /// Vault key path.
        key: String,
        /// Emit result as raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Probe a vault-stored provider credential for validity.
    ///
    /// Retrieves credential server-side (never in cognitive layer per aligned
    /// blindness) and makes minimal auth-verification request against the
    /// provider's endpoint. Returns pass/fail without echoing credential.
    ///
    /// Supported providers: anthropic, openai, abacus.
    ///
    /// Examples:
    ///   zp vault test anthropic
    ///   zp vault test abacus
    ///   zp vault test openai --json
    Test {
        /// Provider name (anthropic | openai | abacus)
        provider: String,
        /// Emit result as raw JSON instead of formatted text
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PrecedentCmd {
    /// List every call the Regent may now make without asking.
    List {
        /// Emit raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// Withdraw a precedent. Accepts a context-signature prefix.
    Revoke {
        /// Context signature (from `zp precedent list`); a unique prefix is enough.
        context_signature: String,
        /// Optional note recorded with the revocation.
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum ApprovalCmd {
    /// List approval requests awaiting an answer.
    List {
        /// Emit raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// Grant a pending request. Accepts a hash prefix.
    Grant {
        /// Request hash (from `zp approval list`); a unique prefix is enough.
        request_hash: String,
        /// Optional note recorded with the approval.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Deny a pending request. Accepts a hash prefix.
    Deny {
        /// Request hash (from `zp approval list`); a unique prefix is enough.
        request_hash: String,
        /// Optional note recorded with the denial.
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum CorrectionCmd {
    /// Issue a new standing correction.
    ///
    /// Accepts individual field flags OR --json for a full StandingCorrection payload.
    /// Chain-anchors the correction as a cognitive:correction:standing event.
    /// Regent's next perceive() cycle sees this at Tier 1.
    ///
    /// Examples:
    ///   zp correction issue --type factual --domain cognitive.self_reference.model_state \
    ///     --assertion "Regent is running Sonnet 4.6, not GLM 5.2" --priority 90
    ///
    ///   zp correction issue --type prohibition --domain cognitive.narration.tone.day_shape \
    ///     --assertion "Regent may mirror day-shape framing when operator sets it" \
    ///     --negation "Do not open with 'good morning'" --priority 70
    ///
    ///   zp correction issue --type factual --domain cognitive.self_reference.aegis_scope \
    ///     --assertion "..." --supersedes 911ff194606f40f1 --priority 90
    ///
    ///   cat correction.json | zp correction issue --json -
    Issue {
        /// Correction type: factual | boundary | prohibition | preference
        #[arg(long = "type", value_parser = ["factual", "boundary", "prohibition", "preference"])]
        correction_type: Option<String>,
        /// Domain string (hierarchical, e.g. cognitive.narration.tone.day_shape)
        #[arg(long)]
        domain: Option<String>,
        /// The authoritative assertion (what Regent should treat as true / do)
        #[arg(long)]
        assertion: Option<String>,
        /// What Regent should not claim / should not do (optional negation)
        #[arg(long)]
        negation: Option<String>,
        /// Human context for why the correction exists (optional)
        #[arg(long)]
        context: Option<String>,
        /// Priority (0-100). Default scale: 100=existential, 50-99=high, 10-49=moderate, 1-9=soft.
        #[arg(long, default_value = "50")]
        priority: u32,
        /// Correction id this one supersedes. Repeat for several.
        ///
        /// The superseded correction goes inactive from this receipt forward and
        /// stays chain-preserved, per the schema's ordered-evolution lifecycle.
        /// Prefer this over `correction revoke` followed by a fresh issue: revoke
        /// leaves no link between the old claim and its replacement, so the chain
        /// records that something was withdrawn but not what replaced it or why.
        #[arg(long)]
        supersedes: Vec<String>,
        /// Read full StandingCorrection JSON payload from file path (or "-" for stdin)
        #[arg(long)]
        json: Option<String>,
        /// Emit result as raw JSON
        #[arg(long)]
        json_out: bool,
    },
    /// List currently active standing corrections.
    List {
        /// Emit result as raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Revoke a standing correction by id.
    Revoke {
        /// Correction id (from `zp correction list`)
        correction_id: String,
        /// Emit result as raw JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum OfficerCmd {
    /// Trigger an on-demand sweep of one or all officers.
    ///
    /// Without a name, runs the full enabled roster. With a name, runs
    /// only the specified officer. Composes with OFFICER-ACTION-SURFACES —
    /// sweep is an ephemeral action-surface invocation producing
    /// chain-anchored findings.
    ///
    /// Examples:
    ///   zp officer sweep              # all enabled officers
    ///   zp officer sweep steward      # steward only
    ///   zp officer sweep sentinel     # sentinel only
    Sweep {
        /// Officer name (steward | sentinel | forge | cleo). Omit for full roster.
        name: Option<String>,
        /// Emit result as raw JSON instead of formatted text
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ToolCmd {
    /// List registered tools (same as `zp port list`)
    List,
    /// Remove a tool from governance — stops process, revokes delegations,
    /// deallocates port, deletes .env.zp, emits removal receipt.
    Remove {
        /// Tool name (case-insensitive)
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
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
    /// Set a governed policy value on the audit chain
    #[command(subcommand)]
    Set(PolicySetCmd),
    /// Show the current value of a governed policy from the audit chain
    #[command(subcommand)]
    Show(PolicyShowCmd),
}

#[derive(Subcommand)]
enum PolicySetCmd {
    /// Set the LLM inference policy — backend, routing strategy, allowlist, and cost cap.
    ///
    /// Emits a signed `preference:llm:policy:set` receipt to the audit chain.
    /// Governed tools read this receipt at startup; `selected_model` in
    /// config.toml becomes a true fallback only when no receipt exists yet.
    ///
    /// Note: this is the policy for *governed tools*, not for the Regent. Her
    /// inference tier is chosen by the router from the model dossier corpus and
    /// pinned by `regent:config:inference` receipts. As of 2026-08-06 there is
    /// no operator verb for that pin, which is a gap worth closing — the model
    /// serving cognition should be something the operator signs.
    ///
    /// Examples:
    ///   zp policy set inference --backend https://routellm.abacus.ai/v1 --strategy route-llm
    ///   zp policy set inference --backend https://routellm.abacus.ai/v1 --strategy claude-sonnet-4-6
    ///   zp policy set inference --strategy route-llm --allowlist 'claude-*,gpt-*,o1-*'
    Inference {
        /// LLM backend base URL (e.g., "https://routellm.abacus.ai/v1").
        #[arg(long)]
        backend: String,

        /// Routing strategy: "route-llm" for auto-routing, or a named model ID
        /// (e.g. "claude-sonnet-4-6") to pin a specific model. No default —
        /// must be explicit so the operator's intent is always on chain.
        #[arg(long)]
        strategy: String,

        /// Comma-separated model ID patterns that are allowed.
        /// Empty (default) means unrestricted. Example: "claude-*,gpt-*"
        #[arg(long, default_value = "")]
        allowlist: String,

        /// Daily cost ceiling in USD. Gate enforces against accumulated costs.
        /// Omit to set no cap.
        #[arg(long)]
        cost_cap_daily_usd: Option<f64>,

        /// Provider schema constraints the gate pre-validates before dispatch.
        /// Comma-separated provider names (e.g., "gemini").
        #[arg(long, default_value = "")]
        schema_compat: String,

        /// Max consecutive SchemaRejected failures before the gate opens the circuit.
        /// 0 = no circuit-breaker (default).
        #[arg(long, default_value = "0")]
        circuit_breaker_threshold: u32,

        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<std::path::PathBuf>,

        /// Emit JSON instead of formatted text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PolicyShowCmd {
    /// Show the current LLM inference policy from the audit chain.
    Inference {
        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<std::path::PathBuf>,

        /// Emit JSON instead of formatted text.
        #[arg(long)]
        json: bool,
    },
}

// ============================================================================
// Model registry subcommands
// ============================================================================

#[derive(Subcommand)]
enum ModelCmd {
    /// Register an LLM model with its capabilities, pricing, and schema format.
    ///
    /// Emits a signed `model:registered` receipt to the audit chain.
    /// The chain IS the registry — no external model database required.
    ///
    /// Examples:
    ///   zp model register --model-id anthropic/claude-sonnet-4-6 \
    ///       --provider anthropic \
    ///       --provider-url https://api.anthropic.com/v1 \
    ///       --context-window 200000 --supports-tools \
    ///       --schema-format openai \
    ///       --input-cost-per-m 3.0 --output-cost-per-m 15.0 \
    ///       --max-output-tokens 8192
    Register {
        /// Canonical model ID (e.g. "anthropic/claude-sonnet-4-6").
        /// Format: "{provider}/{model_name}" for unambiguous registry lookup.
        #[arg(long)]
        model_id: String,

        /// Provider name (e.g. "anthropic", "google", "openai").
        #[arg(long)]
        provider: String,

        /// Provider API base URL (e.g. "https://api.anthropic.com/v1").
        #[arg(long)]
        provider_url: String,

        /// Maximum context window in tokens.
        #[arg(long)]
        context_window: u32,

        /// Whether this model supports tool/function calling.
        #[arg(long, default_value = "false")]
        supports_tools: bool,

        /// JSON Schema type format: "openai" (lowercase) or "gemini" (uppercase).
        /// "openai" for Anthropic, OpenAI, Mistral. "gemini" for Google Vertex AI.
        #[arg(long, default_value = "openai")]
        schema_format: String,

        /// Input token cost in USD per million tokens.
        #[arg(long)]
        input_cost_per_m: f64,

        /// Output token cost in USD per million tokens.
        #[arg(long)]
        output_cost_per_m: f64,

        /// Maximum output tokens this model supports.
        #[arg(long)]
        max_output_tokens: u32,

        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<std::path::PathBuf>,

        /// Emit JSON instead of formatted text.
        #[arg(long)]
        json: bool,
    },

    /// List all registered models from the audit chain.
    ///
    /// Walks the chain and collects the most recent `model:registered` receipt
    /// for each model ID, then applies any `model:capability:updated` patches
    /// on top. Superseded registrations are excluded.
    List {
        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<std::path::PathBuf>,

        /// Emit JSON instead of formatted text.
        #[arg(long)]
        json: bool,
    },

    /// Update a registered model's capability or pricing data.
    ///
    /// Emits a signed `model:capability:updated` receipt to the audit chain.
    /// The update does not replace the original `model:registered` receipt —
    /// both remain on chain for audit continuity.
    ///
    /// Examples:
    ///   zp model update --model-id anthropic/claude-sonnet-4-6 \
    ///       --field pricing \
    ///       --value '{"input_cost_per_m_usd": 3.0, "output_cost_per_m_usd": 15.0}' \
    ///       --reason "provider price reduction announced 2026-06"
    Update {
        /// The model ID to update (must match a prior model:registered receipt).
        #[arg(long)]
        model_id: String,

        /// Which field to update (e.g. "pricing", "supports_tools",
        /// "context_window", "max_output_tokens", "known_issues").
        #[arg(long)]
        field: String,

        /// The new value as a JSON literal (e.g. "true", "200000", '"openai"').
        #[arg(long)]
        value: String,

        /// Reason for the update (e.g. "provider announcement", "observed behavior").
        #[arg(long)]
        reason: String,

        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<std::path::PathBuf>,

        /// Emit JSON instead of formatted text.
        #[arg(long)]
        json: bool,
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
    /// Compact the chain by archiving old entries
    Compact {
        /// Number of recent entries to retain (default: 10000)
        #[arg(long, default_value = "10000")]
        retain: usize,
    },
}

#[derive(Subcommand)]
enum ChainCmd {
    /// Narrate the chain as a human-readable story
    Story {
        /// Number of entries to narrate (default: 50)
        #[arg(long, default_value = "50")]
        limit: usize,

        /// Filter to a posture domain (governance, integrity, operations, system)
        #[arg(long)]
        domain: Option<String>,

        /// Show compressed arcs instead of individual events
        #[arg(long)]
        summary: bool,

        /// Emit JSON instead of formatted text
        #[arg(long)]
        json: bool,
    },
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
    /// Derive a subkey from the Genesis sovereign root.
    ///
    /// Each subkey serves a distinct trust role (envelope auth, audit signing,
    /// gate signing, vault wrapping) and is derived deterministically via
    /// BLAKE3-keyed hashing with a domain-separation context.
    #[command(subcommand)]
    Derive(DeriveCmd),
}

#[derive(Subcommand)]
enum DeriveCmd {
    /// Derive the Foundation Edge envelope-signing keypair from Genesis
    /// for use by the Cloudflare Worker forwarding receipt-intents.
    ///
    /// One-time ceremony per deployment (idempotent on re-run — same
    /// Genesis derives the same key). Registers the public key in
    /// ~/ZeroPoint/config/foundation-edge-keys.json so the operator's
    /// zp-server can verify envelopes from the worker. Prints the
    /// private key (base64) and pubkey ID for `wrangler secret put`.
    ///
    /// See docs/handoffs/foundation-worker-edge-proxy-2026-05.md.
    FoundationEdge,
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
enum PricingCmd {
    /// Fetch live pricing from provider APIs and update the local catalog.
    ///
    /// For each host ID that has a fetcher, queries the provider's pricing
    /// endpoint and backfills `pricing_verified_at` + `pricing_source` in the
    /// operator's providers.toml override. Emits a signed PricingRefreshClaim
    /// receipt to the audit chain.
    ///
    /// Example:
    ///   zp pricing refresh --host abacus
    ///   zp pricing refresh         (refreshes all hosts with known fetchers)
    Refresh {
        /// Provider host ID to refresh (repeatable; default: all hosts with fetchers).
        #[arg(long = "host")]
        hosts: Vec<String>,

        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit JSON instead of formatted text.
        #[arg(long)]
        json: bool,
    },

    /// Manually attest that pricing data was verified at this moment.
    ///
    /// Use when you have checked pricing by hand (e.g., the provider's pricing
    /// page) and want to reset the staleness clock without a live API fetch.
    /// Emits a signed PricingRefreshClaim receipt with method="manual".
    ///
    /// Example:
    ///   zp pricing attest --host openai --host anthropic
    Attest {
        /// Provider host ID to attest (repeatable; required).
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,

        /// Path to audit store (default: <data-dir>/audit.db).
        #[arg(long)]
        audit_db: Option<PathBuf>,

        /// Emit JSON instead of formatted text.
        #[arg(long)]
        json: bool,
    },
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

        /// Accept a changed manifest — update the stored hash baseline.
        /// Required when the manifest has been intentionally modified since
        /// the last `zp configure tool` run.
        #[arg(long)]
        refresh: bool,
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
    /// Store a tool-specific env var in the vault (e.g. OPENAI_API_KEY for a governed tool).
    /// The cockpit launch handler reads these via tools/{tool}/{VAR} and injects them
    /// into the process env at launch time — no .env files, no key pasting.
    ///
    ///   zp configure vault-set-tool-env --tool ember --var OPENAI_API_KEY
    ///   zp configure vault-set-tool-env --tool ember --var OPENAI_BASE_URL --value https://api.venice.ai/api/v1
    VaultSetToolEnv {
        /// Tool name (e.g., ember, shannon)
        #[arg(long)]
        tool: String,

        /// Environment variable name to inject (e.g., OPENAI_API_KEY)
        #[arg(long)]
        var: String,

        /// Value to store (omit to read securely from stdin)
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
    /// Resolve a tool's vault-backed config into env and exec a command.
    ///
    /// Secrets are injected directly into the child process environment and
    /// never appear in shell history.  The resolved env vars OVERRIDE any
    /// identically-named vars already in the current environment.
    ///
    /// Example:
    ///   zp configure exec --name ember -- bash -c 'echo key_len=${#OPENAI_API_KEY}'
    Exec {
        /// Tool name (matches what was used in `configure tool --name`)
        #[arg(long)]
        name: String,
        /// Command and args to execute (after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeychainCmd {
    /// List orphan Keychain entries and optionally delete them.
    ///
    /// Orphan entries are Keychain items written by old ZeroPoint builds
    /// that are no longer used by current code. The sovereign root
    /// (zeropoint-genesis) is never listed or touched.
    ///
    /// Default: dry-run — shows what would be deleted without doing anything.
    /// Pass --delete to actually remove the entries after reviewing them.
    Cleanup {
        /// Delete the listed orphan entries. Without this flag the command
        /// is a dry-run that shows what would be removed.
        #[arg(long)]
        delete: bool,
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

#[derive(Subcommand)]
enum OperatorCmd {
    /// Create a new operator keypair for a workspace member
    ///
    /// Generates an Ed25519 keypair certified by the genesis key,
    /// stores it in ~/ZeroPoint/keys/operators/<name>.json,
    /// and prints the public key hex for registration.
    ///
    /// Roles:
    ///   founder    — Genesis holder, full workspace:admin
    ///   successor  — Full admin + succession:invoke + genesis recovery
    ///   officer    — Own mailbox + docs + secure channels + succession:co-sign
    Create {
        /// Operator name (e.g., "ken", "kalyn", "lorrie", "katie")
        #[arg(long)]
        name: String,

        /// Operator email (e.g., "ken@zeropoint.global")
        #[arg(long)]
        email: String,

        /// Role: founder, successor, or officer
        #[arg(long)]
        role: String,

        /// Mailbox name for officer role (e.g., "lorrie", "katie")
        /// Required when role is "officer"
        #[arg(long)]
        mailbox: Option<String>,

        /// Expiration in days (default: no expiration for founder/successor, 365 for officer)
        #[arg(long)]
        expires_days: Option<u64>,
    },

    /// Register an operator's public key with the Cloudflare Worker
    ///
    /// Sends the operator's public key, capabilities, and role to the
    /// workspace API (POST /api/operators) for D1 storage.
    Register {
        /// Operator name (must match a key in ~/ZeroPoint/keys/operators/)
        #[arg(long)]
        name: String,

        /// Workspace API base URL
        #[arg(long, default_value = "https://zeropoint.global")]
        api_url: String,

        /// Admin auth token for the API
        #[arg(long, env = "ZP_ADMIN_TOKEN")]
        token: String,
    },

    /// List all operator keys in the keyring
    List,

    /// Deactivate an operator (revoke access without deleting keys)
    Deactivate {
        /// Operator name to deactivate
        #[arg(long)]
        name: String,

        /// Workspace API base URL
        #[arg(long, default_value = "https://zeropoint.global")]
        api_url: String,

        /// Admin auth token for the API
        #[arg(long, env = "ZP_ADMIN_TOKEN")]
        token: String,
    },

    /// Succession ceremony — prepare Kalyn's full authority transfer
    ///
    /// Generates the successor's operator key with workspace:admin +
    /// succession:invoke capabilities, and outputs the genesis recovery
    /// mnemonic for secure offline storage.
    Succession {
        /// Successor name (default: "kalyn")
        #[arg(long, default_value = "kalyn")]
        name: String,

        /// Successor email
        #[arg(long)]
        email: String,
    },
}

/// Parse a key=value pair for the --meta flag.
fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=VALUE: no `=` found in `{s}`"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

/// Spawn a daemonized `zp serve --foreground` child, detached from the terminal.
///
/// Pre-auth must be done by the caller first (Touch ID fires while the terminal
/// is still frontmost). The Keychain credential unlocked by pre-auth persists
/// in the macOS session, so the daemon's AppState::init auth is a cache hit.
///
/// Logs go to `~/ZeroPoint/logs/zp-serve.log`. Returns the log path on success;
/// on spawn failure prints the error and calls `process::exit(1)`.
#[cfg(unix)]
fn spawn_serve_daemon(
    port: &Option<u16>,
    bind: &Option<String>,
    no_open: bool,
) -> std::path::PathBuf {
    use std::os::unix::process::CommandExt;

    let log_dir = commands::resolve_zp_home().join("logs");
    std::fs::create_dir_all(&log_dir).ok();
    let log_path = log_dir.join("zp-serve.log");

    let mut daemon_args = vec!["serve".to_string(), "--foreground".to_string()];
    if let Some(p) = port {
        daemon_args.push("--port".to_string());
        daemon_args.push(p.to_string());
    }
    if let Some(b) = bind {
        daemon_args.push("--bind".to_string());
        daemon_args.push(b.clone());
    }
    if no_open {
        daemon_args.push("--no-open".to_string());
    }

    let exe = std::env::current_exe().unwrap_or_else(|_| "zp".into());
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(&daemon_args);
    cmd.process_group(0); // detach from terminal's process group — no shell job to reap
    cmd.stdin(std::process::Stdio::null());
    // Default to info logging so the log file is useful; operator can override with RUST_LOG.
    if std::env::var("RUST_LOG").is_err() {
        cmd.env("RUST_LOG", "info");
    }

    // Redirect daemon stdio to log file; fall back to /dev/null if open fails.
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);
    match log_file {
        Ok(f) => match f.try_clone() {
            Ok(f2) => {
                cmd.stdout(std::process::Stdio::from(f));
                cmd.stderr(std::process::Stdio::from(f2));
            }
            Err(_) => {
                cmd.stdout(std::process::Stdio::null());
                cmd.stderr(std::process::Stdio::null());
            }
        },
        Err(_) => {
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
        }
    }

    match cmd.spawn() {
        Ok(_) => log_path,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Failed to start zp serve daemon: {}", e);
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();

    // If --data-dir was not explicitly set (still the clap default "./data/zeropoint"),
    // resolve from ZP_HOME / ~/ZeroPoint/data so commands work without flags.
    // Resolution order:  ZP_HOME env var  →  ~/ZeroPoint/data  →  clap default.
    // We only promote when the resolved directory exists, so dev environments that
    // haven't initialized ~/ZeroPoint/ yet keep falling back to the relative path.
    if args.data_dir == std::path::Path::new("./data/zeropoint") {
        if let Ok(zp_home) = zp_core::paths::home() {
            let zp_data = zp_home.join("data");
            if zp_data.exists() {
                args.data_dir = zp_data;
            }
        }
    }

    // ANSI only when a human is watching. Redirected to a file, the escape
    // codes land *between* the message and its field names — so
    // `turns=1` is stored as `turns\x1b[0m=1` and no grep for `turns=` ever
    // matches. Observed 2026-07-31: three separate field-level queries against
    // /tmp/zp-serve.log returned empty against 239k lines that plainly
    // contained the fields, because the terminal renders the escapes
    // invisibly on paste. A log that cannot be queried is not a log.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    // Serve runs the HTTP server with verification surface
    if let Some(Commands::Serve {
        bind,
        port,
        no_open,
        foreground,
    }) = &args.command
    {
        // Resolve config: defaults → system → project → env → CLI flags
        let mut cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        if let Some(b) = bind {
            cfg.bind =
                zp_config::Sourced::new(b.clone(), zp_config::Source::CliFlag("bind".into()));
        }
        if let Some(p) = port {
            cfg.port = zp_config::Sourced::new(*p, zp_config::Source::CliFlag("port".into()));
        }
        if *no_open {
            cfg.open_dashboard =
                zp_config::Sourced::new(false, zp_config::Source::CliFlag("no-open".into()));
        }
        let resolved_bind = cfg.bind.value.clone();
        let resolved_port = cfg.port.value;
        let resolved_open = cfg.open_dashboard.value;

        // Pre-authenticate before server startup so the Touch ID / Keychain
        // dialog appears immediately (terminal still frontmost) rather than
        // 1–2 seconds later inside AppState::init when the operator may have
        // switched focus. Warms the load_genesis_from_credential_store OnceLock;
        // all subsequent Keychain accesses in AppState::init are cache hits.
        // Consistent with singular-sovereign-root (#152): one ceremony here,
        // everything else derived from the in-process cache.
        let genesis_record_path = commands::resolve_zp_home().join("genesis.json");
        if genesis_record_path.exists() {
            if let Err(e) = zp_keys::load_sovereign_root(&genesis_record_path) {
                // An operator declining or mistyping is not a lost Genesis.
                //
                // Both outcomes previously printed "Run `zp recover` with your
                // 24-word mnemonic to restore access." Observed 2026-08-06: a
                // mistyped Trezor PIN produced that line, which is correct
                // guidance for an unrecoverable sovereign root and dangerous
                // guidance for a typo — it invites a recovery ceremony in
                // response to pressing the wrong key, and an operator who
                // follows it is doing something irreversible for no reason.
                //
                // Matching on the message rather than a typed error because the
                // provider surfaces cancellation as a string today. A typed
                // `SovereigntyError::Cancelled` would be better and is a
                // separate change; the message is the part that misleads now.
                let msg = e.to_string();
                let cancelled = msg.contains("cancelled")
                    || msg.contains("canceled")
                    || msg.contains("PIN entry");

                if cancelled {
                    eprintln!("\x1b[33m✗\x1b[0m  Sovereignty ceremony cancelled on device.");
                    eprintln!("  Nothing is wrong and nothing was changed — run the same");
                    eprintln!("  command again and re-enter when the device asks.");
                } else {
                    eprintln!("\x1b[31m✗\x1b[0m  Sovereignty authentication failed: {}", e);
                    eprintln!("  If the device is connected and unlocked, try again first.");
                    eprintln!("  `zp recover` with your 24-word mnemonic is the last resort,");
                    eprintln!("  not the first response — it re-establishes Genesis.");
                }
                std::process::exit(1);
            }
        }

        // Bedrock invariants are evaluated in `AppState::init` and surfaced by
        // `zp-dev.sh`, not here.
        //
        // A version of this block briefly lived at this point, on the reasoning
        // that `zp serve` daemonizes and the child's stderr goes to the logfile,
        // so the operator-facing report belonged in the parent. That reasoning
        // was wrong twice over: `zp-dev.sh` launches with `--foreground` under
        // `nohup … >> "$LOG" 2>&1`, so there is no parent outside the redirect,
        // and *nothing* the binary writes reaches the terminal. The Trezor block
        // letters that appear during boot are printed by the script, which greps
        // the log and renders them — the binary only logs a line the script
        // recognises.
        //
        // So the terminal is the script's to own, and the correct fix was in
        // `zp-dev.sh`, which already solves exactly this for the touch prompt.
        // Its comment states the principle: "The prompt existed — at INFO, in a
        // logfile, where nobody was looking. Put it where the person is."

        // Daemonize by default on Unix so `zp serve` returns the terminal immediately.
        // `--foreground` keeps it attached (debug use, or for callers that manage the
        // process themselves). Pre-auth above runs in the parent so Touch ID fires while
        // the terminal is frontmost; the Keychain unlock persists into the daemon's auth.
        #[cfg(unix)]
        if !foreground {
            let log_path = spawn_serve_daemon(port, bind, *no_open);
            println!(
                "\x1b[32m▶\x1b[0m  zp serve started  (logs: {})",
                log_path.display()
            );
            return Ok(());
        }

        #[cfg(feature = "embedded-server")]
        {
            let config = zp_server::ServerConfig {
                bind_addr: resolved_bind,
                port: resolved_port,
                open_dashboard: resolved_open,
                ..zp_server::ServerConfig::from_zp_config(&cfg)
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
            cmd.env("ZP_BIND", &resolved_bind);
            cmd.env("ZP_PORT", resolved_port.to_string());
            if !resolved_open {
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

    // Restart — tool-targeted restart using the port registry, or server
    // restart as a documented escape hatch (--self).
    if let Some(Commands::Restart { name, all, self_ }) = &args.command {
        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        let port = cfg.port.value;
        let git_hash = env!("ZP_GIT_HASH");

        // --self: escape hatch — restart the ZP server process (original behavior).
        if *self_ {
            let pids = std::process::Command::new("lsof")
                .args(["-ti", &format!(":{}", port)])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        String::from_utf8(o.stdout).ok()
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let mut killed = false;
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    let our_pid = std::process::id() as i32;
                    if pid != our_pid {
                        let _ = std::process::Command::new("kill")
                            .arg(pid_str.trim())
                            .stderr(std::process::Stdio::null())
                            .status();
                        killed = true;
                    }
                }
            }
            if killed {
                println!("\x1b[33m↻\x1b[0m  Stopped server on port {}", port);
                std::thread::sleep(std::time::Duration::from_millis(500));
            } else {
                println!("\x1b[33m⚠\x1b[0m  No server found on port {}", port);
            }
            let exe = std::env::current_exe().unwrap_or_else(|_| "zp".into());
            println!("\x1b[32m▶\x1b[0m  Starting zp serve ({})...", git_hash);
            match std::process::Command::new(&exe).arg("serve").spawn() {
                Ok(_) => {
                    println!("\x1b[32m✓\x1b[0m  Server restarted on port {}", port);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("\x1b[31m✗\x1b[0m  Failed to restart: {}", e);
                    std::process::exit(1);
                }
            }
        }

        // --name <tool>: restart a specific registered tool.
        #[cfg(feature = "embedded-server")]
        if let Some(tool_name) = name {
            let data_dir = cfg.data_dir.value.clone();
            let registry = zp_server::tool_ports::PortRegistry::new(&data_dir);
            match registry.get_assigned(tool_name) {
                Some(binding) => {
                    if let Some(pid) = binding.pid {
                        // SIGTERM first, then wait up to 5s, then SIGKILL.
                        let _ = std::process::Command::new("kill")
                            .args(["-TERM", &pid.to_string()])
                            .status();
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(5);
                        while std::time::Instant::now() < deadline {
                            if !zp_server::tool_ports::is_pid_alive(pid) {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                        if zp_server::tool_ports::is_pid_alive(pid) {
                            let _ = std::process::Command::new("kill")
                                .args(["-KILL", &pid.to_string()])
                                .status();
                        }
                        println!("\x1b[33m↻\x1b[0m  Stopped {} (pid {})", tool_name, pid);
                        registry.release(
                            tool_name,
                            zp_server::tool_ports::ReleaseReason::OperatorKill,
                        );
                    } else {
                        eprintln!(
                            "\x1b[31m✗\x1b[0m  No PID recorded for '{}' — \
                             use zp doctor to inspect the registry",
                            tool_name
                        );
                        std::process::exit(1);
                    }
                    // Re-launch via stored launch command.
                    let lc = match binding.launch_command {
                        Some(lc) => lc,
                        None => {
                            eprintln!(
                                "\x1b[31m✗\x1b[0m  No launch command recorded for '{}'.",
                                tool_name
                            );
                            eprintln!("  Re-launch once manually to register it:");
                            eprintln!(
                                "    zp configure exec --name {} -- <command> [args...]",
                                tool_name
                            );
                            std::process::exit(1);
                        }
                    };
                    println!("\x1b[32m▶\x1b[0m  Re-launching {}...", tool_name);
                    let exe = std::env::current_exe().unwrap_or_else(|_| "zp".into());
                    let mut relaunch = std::process::Command::new(&exe);
                    relaunch.args(["configure", "exec", "--name", tool_name, "--"]);
                    relaunch.arg(&lc.command);
                    relaunch.args(&lc.args);
                    match relaunch.spawn() {
                        Ok(_) => {
                            println!("\x1b[32m✓\x1b[0m  {} re-launched", tool_name);
                            std::process::exit(0);
                        }
                        Err(e) => {
                            eprintln!("\x1b[31m✗\x1b[0m  Re-launch failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                None => {
                    eprintln!(
                        "\x1b[31m✗\x1b[0m  Tool '{}' is not in the port registry — \
                         is it running?",
                        tool_name
                    );
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "embedded-server"))]
        if name.is_some() {
            eprintln!("\x1b[31m✗\x1b[0m  zp restart --name requires the embedded-server feature");
            std::process::exit(1);
        }

        // --all: restart all registered tools serially.
        #[cfg(feature = "embedded-server")]
        if *all {
            let data_dir = cfg.data_dir.value.clone();
            let registry = zp_server::tool_ports::PortRegistry::new(&data_dir);
            let bindings = registry.list();
            if bindings.is_empty() {
                println!("No tools registered in port registry.");
                std::process::exit(0);
            }
            let mut any_failed = false;
            let exe = std::env::current_exe().unwrap_or_else(|_| "zp".into());
            for binding in bindings {
                println!("Restarting {}...", binding.tool);
                match std::process::Command::new(&exe)
                    .args(["restart", "--name", &binding.tool])
                    .status()
                {
                    Ok(s) if s.success() => {}
                    _ => {
                        eprintln!("Failed to restart {}", binding.tool);
                        any_failed = true;
                    }
                }
            }
            std::process::exit(if any_failed { 1 } else { 0 });
        }
        #[cfg(not(feature = "embedded-server"))]
        if *all {
            eprintln!("\x1b[31m✗\x1b[0m  zp restart --all requires the embedded-server feature");
            std::process::exit(1);
        }

        // No recognized flag — print usage hint.
        eprintln!("Specify one of:");
        eprintln!("  zp restart --name <tool>   restart a specific ZP-managed tool");
        eprintln!("  zp restart --all           restart all ZP-managed tools");
        eprintln!("  zp restart --self          restart the ZP server (escape hatch)");
        std::process::exit(1);
    }

    // Port registry operations (read-only, no pipeline needed).
    #[cfg(feature = "embedded-server")]
    if let Some(Commands::Port(PortCmd::List)) = &args.command {
        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        let data_dir = cfg.data_dir.value.clone();
        let registry = zp_server::tool_ports::PortRegistry::new(&data_dir);
        let mut bindings = registry.list();
        if bindings.is_empty() {
            println!("No tool port assignments.");
            std::process::exit(0);
        }
        bindings.sort_by(|a, b| a.tool.cmp(&b.tool));
        println!(
            "{:<20} {:<10} {:<10} {:<10} {:<10}",
            "TOOL", "ALLOCATED", "ACTUAL", "PID", "PROXY"
        );
        println!("{}", "─".repeat(62));
        for b in bindings {
            println!(
                "{:<20} {:<10} {:<10} {:<10} {:<10}",
                b.tool,
                b.port,
                b.actual_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                b.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                b.proxy_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".to_string()),
            );
        }
        std::process::exit(0);
    }
    #[cfg(not(feature = "embedded-server"))]
    if matches!(&args.command, Some(Commands::Port(_))) {
        eprintln!("\x1b[31m✗\x1b[0m  zp port requires the embedded-server feature");
        std::process::exit(1);
    }

    // Tool lifecycle management (list, remove) — no pipeline needed.
    #[cfg(feature = "embedded-server")]
    if let Some(Commands::Tool(cmd)) = &args.command {
        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        let data_dir = cfg.data_dir.value.clone();

        match cmd {
            ToolCmd::List => {
                // Reuse the same listing logic as `zp port list`.
                let registry = zp_server::tool_ports::PortRegistry::new(&data_dir);
                let mut bindings = registry.list();
                if bindings.is_empty() {
                    println!("No registered tools.");
                    std::process::exit(0);
                }
                bindings.sort_by(|a, b| a.tool.cmp(&b.tool));
                println!(
                    "{:<20} {:<10} {:<10} {:<10} {:<10}",
                    "TOOL", "ALLOCATED", "ACTUAL", "PID", "PROXY"
                );
                println!("{}", "─".repeat(62));
                for b in bindings {
                    println!(
                        "{:<20} {:<10} {:<10} {:<10} {:<10}",
                        b.tool,
                        b.port,
                        b.actual_port
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        b.pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        b.proxy_port
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                    );
                }
                std::process::exit(0);
            }
            ToolCmd::Remove { name, force } => {
                let name_lower = name.to_lowercase();
                let registry = zp_server::tool_ports::PortRegistry::new(&data_dir);

                // 1. Resolve
                let binding = match registry.get_assigned(&name_lower) {
                    Some(b) => b,
                    None => {
                        eprintln!("\x1b[31m✗\x1b[0m  Tool '{}' is not registered.", name);
                        std::process::exit(1);
                    }
                };

                let pid_alive = binding.pid.is_some_and(zp_server::tool_ports::is_pid_alive);
                let working_dir = binding
                    .launch_command
                    .as_ref()
                    .and_then(|lc| lc.working_dir.as_deref());
                let env_zp_exists = working_dir
                    .map(|d| std::path::Path::new(d).join(".env.zp").exists())
                    .unwrap_or(false);

                // Confirmation prompt
                if !force {
                    println!("Will remove \x1b[1m{}\x1b[0m:", binding.tool);
                    if pid_alive {
                        println!("  • Stop process (pid {})", binding.pid.unwrap());
                    }
                    println!("  • Deallocate port :{}", binding.port);
                    if env_zp_exists {
                        println!(
                            "  • Delete {}",
                            std::path::Path::new(working_dir.unwrap())
                                .join(".env.zp")
                                .display()
                        );
                    }
                    print!("\nProceed? [y/N] ");
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).unwrap();
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        std::process::exit(0);
                    }
                }

                // Try the server API first — this updates the running server's
                // in-memory PortRegistry so the dashboard reflects the change
                // immediately. Fall back to standalone registry only if the
                // server is unreachable.
                let server_url = zp_net::peer_url_with_path(
                    "127.0.0.1",
                    cfg.port.value,
                    &format!("/api/v1/tools/{}/remove", name_lower),
                );
                let server_result = std::process::Command::new("curl")
                    .args(["-s", "-X", "POST", "-w", "\n%{http_code}", &server_url])
                    .output();

                let used_server = match server_result {
                    Ok(output) if output.status.success() => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let lines: Vec<&str> = stdout.trim().lines().collect();
                        if lines.len() >= 2 {
                            let http_code = lines.last().unwrap_or(&"0");
                            let body = lines[..lines.len() - 1].join("\n");
                            if *http_code == "200" {
                                // Server handled the full removal.
                                if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&body) {
                                    let mut parts: Vec<String> = Vec::new();
                                    if let Some(pid) =
                                        resp.get("pid_killed").and_then(|v| v.as_u64())
                                    {
                                        parts.push(format!("killed pid {}", pid));
                                    }
                                    parts.push(format!("deallocated :{}", binding.port));
                                    if resp
                                        .get("env_zp_deleted")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false)
                                    {
                                        parts.push("deleted .env.zp".to_string());
                                    }
                                    println!(
                                        "\x1b[32m✓\x1b[0m  Removed {}: {}",
                                        binding.tool,
                                        parts.join(", ")
                                    );
                                } else {
                                    println!(
                                        "\x1b[32m✓\x1b[0m  Removed {} via server.",
                                        binding.tool
                                    );
                                }
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                if !used_server {
                    // Server unreachable — fall back to standalone registry.
                    // This path only updates disk; the in-memory state syncs
                    // on next server restart.
                    eprintln!("  (server unreachable — removing from disk registry)");

                    let mut summary_parts: Vec<String> = Vec::new();

                    // Stop process
                    if pid_alive {
                        let pid = binding.pid.unwrap();
                        let _ = std::process::Command::new("kill")
                            .args([&pid.to_string()])
                            .output();
                        for _ in 0..6 {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            if !zp_server::tool_ports::is_pid_alive(pid) {
                                break;
                            }
                        }
                        if zp_server::tool_ports::is_pid_alive(pid) {
                            let _ = std::process::Command::new("kill")
                                .args(["-9", &pid.to_string()])
                                .output();
                        }
                        summary_parts.push(format!("killed pid {}", pid));
                    }

                    // Deallocate port
                    registry.deallocate(&name_lower);
                    summary_parts.push(format!("deallocated :{}", binding.port));

                    // Delete .env.zp
                    if env_zp_exists {
                        let env_zp_path =
                            std::path::Path::new(working_dir.unwrap()).join(".env.zp");
                        if let Err(e) = std::fs::remove_file(&env_zp_path) {
                            eprintln!(
                                "  Warning: could not delete {}: {}",
                                env_zp_path.display(),
                                e
                            );
                        } else {
                            summary_parts.push("deleted .env.zp".to_string());
                        }
                    }

                    println!(
                        "\x1b[32m✓\x1b[0m  Removed {}: {}",
                        binding.tool,
                        summary_parts.join(", ")
                    );
                }

                std::process::exit(0);
            }
        }
    }
    #[cfg(not(feature = "embedded-server"))]
    if matches!(&args.command, Some(Commands::Tool(_))) {
        eprintln!("\x1b[31m✗\x1b[0m  zp tool requires the embedded-server feature");
        std::process::exit(1);
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

    // Keychain — manage OS Keychain entries, no pipeline needed
    if let Some(Commands::Keychain(cmd)) = &args.command {
        let exit_code = match cmd {
            KeychainCmd::Cleanup { delete } => keychain::run_cleanup(*delete),
        };
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
                refresh,
            } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(mut vault) => {
                        let exit = configure::run_tool(
                            path,
                            name,
                            *dry_run,
                            &mut vault,
                            configure_policy,
                            Some(&vault_path),
                        );
                        // Pin manifest hash after successful configure (Security mitigation M3).
                        // Skip on dry-run (nothing was stored).
                        // --refresh unconditionally updates the stored hash.
                        if exit == 0 && !*dry_run {
                            let manifest_file = path.join(".zp-configure.toml");
                            if manifest_file.exists() {
                                match std::fs::read(&manifest_file) {
                                    Ok(manifest_bytes) => {
                                        // Reload vault to pick up changes from run_tool
                                        match zp_trust::vault::CredentialVault::load_or_create(
                                            &padded_key,
                                            &vault_path,
                                        ) {
                                            Ok(mut vault2) => {
                                                match run::pin_manifest_hash(
                                                    &mut vault2,
                                                    name,
                                                    &manifest_file,
                                                    &manifest_bytes,
                                                ) {
                                                    Ok(()) => {
                                                        if let Err(e) = vault2.save(&vault_path) {
                                                            eprintln!("Warning: manifest hash stored but vault persist failed: {}", e);
                                                        } else if *refresh {
                                                            println!("\x1b[32m✓\x1b[0m  Manifest hash refreshed for '{}'", name);
                                                        } else {
                                                            println!("\x1b[32m✓\x1b[0m  Manifest hash pinned for '{}'", name);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("Warning: could not pin manifest hash: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("Warning: could not reload vault for hash pin: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Warning: could not read manifest for hash pin: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        exit
                    }
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
            ConfigureCmd::VaultSetToolEnv { tool, var, value } => {
                match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path) {
                    Ok(mut vault) => {
                        let val = value.clone().unwrap_or_else(|| {
                            eprint!(
                                "Enter value for {}/{} (input hidden by terminal): ",
                                tool, var
                            );
                            // Use rpassword-style stdin read so key bytes don't echo.
                            // Fall back to plain readline if rpassword isn't available.
                            let mut input = String::new();
                            std::io::stdin().read_line(&mut input).unwrap_or(0);
                            input.trim().to_string()
                        });
                        configure::run_vault_set_tool_env(&mut vault, tool, var, &val, &vault_path)
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
            ConfigureCmd::Exec { name, command } => {
                if command.is_empty() {
                    eprintln!();
                    eprintln!("  \x1b[31mNo command specified.\x1b[0m");
                    eprintln!();
                    eprintln!("  Usage: zp configure exec --name <tool> -- <command> [args...]");
                    eprintln!("  Example: zp configure exec --name mytool -- bash -c 'echo hi'");
                    eprintln!();
                    1
                } else {
                    match zp_trust::vault::CredentialVault::load_or_create(&padded_key, &vault_path)
                    {
                        Ok(vault) => {
                            match vault.resolve_tool_env(name) {
                                Ok(env_map) => {
                                    if env_map.is_empty() {
                                        // Check if the tool name is a typo — list what IS configured.
                                        let available: Vec<String> = {
                                            let mut tools: std::collections::BTreeSet<String> =
                                                std::collections::BTreeSet::new();
                                            for key in vault.list() {
                                                if let Some(rest) = key.strip_prefix("tools/") {
                                                    if let Some(slash) = rest.find('/') {
                                                        tools.insert(rest[..slash].to_string());
                                                    }
                                                }
                                            }
                                            tools.into_iter().collect()
                                        };
                                        if available.is_empty() {
                                            eprintln!();
                                            eprintln!(
                                                "  \x1b[31mNo tools are configured in the vault.\x1b[0m"
                                            );
                                            eprintln!();
                                            eprintln!(
                                                "  Run `zp configure tool --name {} --path <dir>` first.",
                                                name
                                            );
                                        } else {
                                            eprintln!();
                                            eprintln!(
                                                "  \x1b[31mTool '{}' has no vault config.\x1b[0m",
                                                name
                                            );
                                            eprintln!();
                                            eprintln!(
                                                "  Configured tools: {}",
                                                available.join(", ")
                                            );
                                            eprintln!(
                                                "  Run `zp configure tool --name {} --path <dir>` to configure it.",
                                                name
                                            );
                                        }
                                        eprintln!();
                                        1
                                    } else {
                                        eprintln!(
                                            "resolved {} env var(s) for tool '{}'",
                                            env_map.len(),
                                            name
                                        );

                                        // Emit launch receipt BEFORE exec (Security mitigation M4).
                                        // collect vault-resolved var names only — never values.
                                        let vault_resolved_names: Vec<String> =
                                            env_map.keys().cloned().collect();
                                        let exec_args: Vec<String> =
                                            command[1..].iter().map(|s| s.to_string()).collect();

                                        let receipt_keyring = crate::commands::open_keyring();
                                        // Architecture II.0: same canonical resolver `zp doctor`
                                        // and `zp status` use. The clap default for `args.data_dir`
                                        // args.data_dir is already resolved from ZP_HOME / ~/ZeroPoint/data
                                        // at startup; no inline fallback needed here.
                                        let db_path = args.data_dir.join("audit.db");
                                        match receipt_keyring {
                                            Ok(kr) => {
                                                // genesis_secret is an OnceLock cache hit —
                                                // resolve_vault_key() already loaded it above.
                                                let genesis_secret =
                                                    crate::commands::load_genesis_secret_composed()
                                                        .ok();
                                                let receipt_fields = run::LaunchReceiptFields {
                                                    tool_name: name,
                                                    manifest_hash:
                                                        "(ad-hoc exec — no manifest hash)",
                                                    command: &command[0],
                                                    args: &exec_args,
                                                    inherited: &[],
                                                    extra_inherited: &[],
                                                    vault_resolved: &vault_resolved_names,
                                                    genesis_secret,
                                                };
                                                if let Err(e) = run::emit_launch_receipt(
                                                    &receipt_fields,
                                                    &db_path,
                                                    &kr,
                                                ) {
                                                    eprintln!();
                                                    eprintln!("  \x1b[31mLaunch blocked: could not emit receipt.\x1b[0m");
                                                    eprintln!("  {}", e);
                                                    eprintln!();
                                                    eprintln!("  ZP-governed tools must be auditable. Fix the audit chain and retry.");
                                                    eprintln!();
                                                    std::process::exit(1);
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!();
                                                eprintln!("  \x1b[31mLaunch blocked: cannot open keyring for receipt signing.\x1b[0m");
                                                eprintln!("  {}", e);
                                                eprintln!();
                                                std::process::exit(1);
                                            }
                                        }

                                        let mut child = std::process::Command::new(&command[0]);
                                        child.args(&command[1..]);
                                        // Inject resolved vars (override inherited env).
                                        for (k, v) in &env_map {
                                            if let Ok(s) = std::str::from_utf8(v) {
                                                child.env(k, s);
                                            }
                                        }
                                        // Inject ZP session token so the gov hook can authenticate.
                                        // session.json is Genesis-derived, file-stored, owner-readable
                                        // — same tier as vault.json (filesystem IPC for a signing-key
                                        // projection). Not a third sovereign reference; the discipline
                                        // pin does not fire. If unification is ever needed, move to
                                        // vault.retrieve("session/*").
                                        //
                                        // Retained during Step 3 of the genesis-signed-gate-requests
                                        // migration; the bearer token is dead code once Step 4
                                        // removes legacy bearer acceptance.
                                        match read_zp_session_token() {
                                            Ok(tok) => {
                                                child.env("ZP_SESSION_TOKEN", tok);
                                            }
                                            Err(_) => {
                                                eprintln!();
                                                eprintln!("  ⚠  ZP session not found at ~/ZeroPoint/session.json");
                                                eprintln!("     Is `zp serve` running? Tool calls through the gov hook will");
                                                eprintln!("     fail with 401 until the session is available.");
                                                eprintln!();
                                            }
                                        }

                                        #[cfg(unix)]
                                        {
                                            // With embedded-server: spawn() so we can capture the
                                            // PID and run post-launch reconciliation (Wires 1+2).
                                            // Without embedded-server: exec() (no registry).
                                            #[cfg(feature = "embedded-server")]
                                            {
                                                use std::os::unix::process::CommandExt;
                                                // New process group: detach from terminal so the
                                                // tool survives configure exec exiting.
                                                child.process_group(0);
                                                match child.spawn() {
                                                    Ok(spawned) => {
                                                        let child_pid = spawned.id();
                                                        eprintln!(
                                                            "spawned {} (pid {})",
                                                            name, child_pid
                                                        );
                                                        // Wire 1: record PID + launch command in port registry.
                                                        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
                                                        let data_dir = cfg.data_dir.value.clone();
                                                        let registry = zp_server::tool_ports::PortRegistry::new(&data_dir);
                                                        if registry
                                                            .update_pid(name, child_pid)
                                                            .is_err()
                                                        {
                                                            // No binding yet — auto-allocate from the resolved
                                                            // env_map. Scan for PORT-like vars; the vault values
                                                            // already carry the operator's intended port numbers,
                                                            // so pass them as preferred hints.
                                                            use zp_server::tool_ports::PreferenceSource;
                                                            let mut port_vars: Vec<(
                                                                String,
                                                                Option<u16>,
                                                            )> = env_map
                                                                .iter()
                                                                .filter(|(k, _)| {
                                                                    *k == "PORT"
                                                                        || k.ends_with("_PORT")
                                                                })
                                                                .map(|(k, v)| {
                                                                    let preferred =
                                                                        std::str::from_utf8(v)
                                                                            .ok()
                                                                            .and_then(|s| {
                                                                                s.trim()
                                                                                    .parse::<u16>()
                                                                                    .ok()
                                                                            });
                                                                    (k.clone(), preferred)
                                                                })
                                                                .collect();
                                                            // Sort deterministically; prefer HTTP_PORT, then PORT.
                                                            port_vars.sort_by_key(|(k, _)| {
                                                                if k == "HTTP_PORT" {
                                                                    0u8
                                                                } else if k == "PORT" {
                                                                    1
                                                                } else {
                                                                    2
                                                                }
                                                            });
                                                            let primary_var = port_vars
                                                                .first()
                                                                .map(|(k, _)| k.as_str())
                                                                .unwrap_or("PORT");
                                                            let preferred_port = port_vars
                                                                .first()
                                                                .and_then(|(_, p)| *p);
                                                            let extra_vars: Vec<String> = port_vars
                                                                .iter()
                                                                .skip(1)
                                                                .map(|(k, _)| k.clone())
                                                                .collect();
                                                            match registry.allocate_or_existing(
                                                                name,
                                                                child_pid,
                                                                primary_var,
                                                                &extra_vars,
                                                                preferred_port,
                                                                PreferenceSource::Manifest,
                                                            ) {
                                                                Ok(binding) => {
                                                                    eprintln!(
                                                                        "  registered {}  port {} ({})",
                                                                        name, binding.port, primary_var
                                                                    );
                                                                }
                                                                Err(e) => {
                                                                    eprintln!(
                                                                        "  \u{26a0}  port registry: could not allocate binding for '{}': {}",
                                                                        name, e
                                                                    );
                                                                }
                                                            }
                                                        }
                                                        // Capture working dir (CWD at spawn time) for
                                                        // version provenance and restart replay.
                                                        let cwd = std::env::current_dir().ok();
                                                        let cwd_str = cwd
                                                            .as_deref()
                                                            .and_then(|p| p.to_str())
                                                            .map(|s| s.to_string());
                                                        let _ = registry.store_launch_command(
                                                            name,
                                                            &command[0],
                                                            &command[1..],
                                                            cwd_str.as_deref(),
                                                        );
                                                        // Wire 1b: auto-canonicalize.
                                                        // If this tool has no bead-zero on the chain,
                                                        // emit one now. This makes the first
                                                        // `configure exec` the canonical registration
                                                        // act — operators don't need a separate
                                                        // `zp canonicalize` step.
                                                        // Best-effort: failures never block launch.
                                                        {
                                                            let db_path = data_dir.join("audit.db");
                                                            let auto_canon: anyhow::Result<()> =
                                                                (|| {
                                                                    use std::sync::{Arc, Mutex};
                                                                    let keyring = crate::commands::open_keyring()
                                                                    .context("open keyring")?;
                                                                    let genesis_secret = crate::commands::load_genesis_secret_composed()
                                                                    .context("genesis secret")?;
                                                                    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
                                                                    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);
                                                                    let store = Arc::new(Mutex::new(
                                                                    zp_audit::AuditStore::open_signed(&db_path, audit_signer)
                                                                        .context("open audit store")?,
                                                                ));
                                                                    // Idempotent: returns None if already canonicalized.
                                                                    let bead_zeros = zp_server::tool_chain::query_bead_zeros(&store);
                                                                    if bead_zeros.contains_key(
                                                                        &format!("tool:{}", name),
                                                                    ) {
                                                                        return Ok(());
                                                                        // already on chain
                                                                    }
                                                                    let operator_secret: [u8; 32] = crate::commands::load_operator_composed(&keyring)
                                                                    .context("operator key")?
                                                                    .secret_key();
                                                                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&operator_secret);
                                                                    let initial_state = serde_json::json!({
                                                                        "tool": name,
                                                                        "path": cwd_str,
                                                                        "canonicalized_at": chrono::Utc::now().to_rfc3339(),
                                                                    });
                                                                    zp_server::tool_chain::emit_signed_canonicalization_receipt(
                                                                    &store,
                                                                    "tool",
                                                                    name,
                                                                    &initial_state,
                                                                    None,
                                                                    "zp-configure-exec",
                                                                    Some(&signing_key),
                                                                );
                                                                    eprintln!("  canon    tool:{} (bead-zero emitted)", name);
                                                                    Ok(())
                                                                })(
                                                                );
                                                            if let Err(e) = auto_canon {
                                                                eprintln!("  \u{26a0}  auto-canonicalize skipped: {}", e);
                                                            }
                                                        }
                                                        // Wire 3: version provenance capture.
                                                        // Resolve git commit + binary hash;
                                                        // best-effort — failures never block launch.
                                                        {
                                                            use zp_server::tool_ports::{
                                                                capture_tool_version,
                                                                resolve_binary_path,
                                                            };
                                                            let bin_path =
                                                                resolve_binary_path(&command[0]);
                                                            let version = capture_tool_version(
                                                                cwd.as_deref(),
                                                                bin_path.as_deref(),
                                                            );
                                                            // Print captured provenance for operator visibility.
                                                            if let Some(ref commit) =
                                                                version.source_commit
                                                            {
                                                                let dirty = version
                                                                    .source_dirty
                                                                    .unwrap_or(false);
                                                                eprintln!(
                                                                    "  version  {} @ {}{}",
                                                                    name,
                                                                    &commit[..commit.len().min(12)],
                                                                    if dirty {
                                                                        " (dirty)"
                                                                    } else {
                                                                        ""
                                                                    }
                                                                );
                                                            }
                                                            if let Some(ref hash) =
                                                                version.binary_hash
                                                            {
                                                                eprintln!(
                                                                    "  binary   {}…",
                                                                    &hash[..hash.len().min(16)]
                                                                );
                                                            }
                                                            let _ = registry.store_tool_version(
                                                                name,
                                                                version.clone(),
                                                            );
                                                            // Emit chain receipt: tool:launched:<name>
                                                            emit::emit_tool_launch_receipt(
                                                                name, &version, &data_dir,
                                                            );
                                                        }
                                                        // Wire 2: post-launch port reconciliation.
                                                        //
                                                        // Query by allocated port, not by launcher
                                                        // PID. When the launch command is a meta-
                                                        // launcher (cargo run, npx, …), the launcher
                                                        // exits after spawning the real binary. Its
                                                        // child owns the listening port but has a
                                                        // different PID. Querying by port is
                                                        // launcher-chain agnostic.
                                                        //
                                                        // Steps:
                                                        //   a) sleep to let the binary bind
                                                        //   b) get allocated port from registry
                                                        //   c) lsof by port → actual PID
                                                        //   d) update registry with actual PID
                                                        //   e) lsof by actual PID → all ports
                                                        //   f) reconcile_ports with full port set
                                                        std::thread::sleep(
                                                            std::time::Duration::from_millis(3500),
                                                        );
                                                        // (b) read allocated port
                                                        let allocated_port = registry
                                                            .get_assigned(name)
                                                            .map(|b| b.port);
                                                        if let Some(port) = allocated_port {
                                                            // (c) discover actual PID via port
                                                            let actual_pid =
                                                                zp_server::tool_ports::lsof_pid_for_port(port)
                                                                    .unwrap_or(child_pid);
                                                            // (d) update registry with real PID
                                                            if actual_pid != child_pid {
                                                                let _ = registry
                                                                    .update_pid(name, actual_pid);
                                                                eprintln!(
                                                                    "  pid      {} launcher={} actual={}",
                                                                    name, child_pid, actual_pid
                                                                );
                                                            }
                                                            // (e) all ports owned by actual process
                                                            let actual_ports =
                                                                zp_server::tool_ports::lsof_tcp_listen_ports(actual_pid);
                                                            // (f) reconcile
                                                            if !actual_ports.is_empty() {
                                                                let n = registry.reconcile_ports(
                                                                    name,
                                                                    actual_pid,
                                                                    &actual_ports,
                                                                );
                                                                if n > 0 {
                                                                    eprintln!(
                                                                        "  reconciled {} receipt(s) for '{}' \u{2192} actual ports {:?}",
                                                                        n, name, actual_ports
                                                                    );
                                                                }
                                                            }
                                                        }
                                                        // Tool runs as detached daemon; dropping
                                                        // Child without wait() reparents it to
                                                        // init/launchd. configure exec exits cleanly.
                                                        drop(spawned);
                                                        0
                                                    }
                                                    Err(e) => {
                                                        eprintln!(
                                                            "\x1b[31m✗\x1b[0m  spawn failed: {}",
                                                            e
                                                        );
                                                        1
                                                    }
                                                }
                                            }
                                            #[cfg(not(feature = "embedded-server"))]
                                            {
                                                use std::os::unix::process::CommandExt;
                                                let err = child.exec();
                                                eprintln!("exec failed: {}", err);
                                                1
                                            }
                                        }
                                        #[cfg(not(unix))]
                                        {
                                            match child.status() {
                                                Ok(status) => status.code().unwrap_or(1),
                                                Err(e) => {
                                                    eprintln!("Failed to run command: {}", e);
                                                    1
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Error resolving vault env for '{}': {}", name, e);
                                    1
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error loading vault: {}", e);
                            1
                        }
                    }
                }
            }
        };
        std::process::exit(exit_code);
    }

    // Run — universal ZP-governed tool launch
    if let Some(Commands::Run { name, extra_args }) = &args.command {
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
            .unwrap_or_else(|_| commands::resolve_zp_home().join("vault.json"));

        let exit_code = run::run(name, extra_args, &padded_key, &vault_path, &args.data_dir);
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
        let vault_path =
            zp_core::paths::vault_path().unwrap_or_else(|_| home_zp.join("vault.json"));
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
            KeysCmd::Rotate { target, reason } => commands::keys_rotate(target, reason.as_deref()),
            KeysCmd::Derive(DeriveCmd::FoundationEdge) => commands::keys_derive_foundation_edge(),
        };
        std::process::exit(exit_code);
    }

    // Operator — workspace staff management, no pipeline needed
    if let Some(Commands::Operator(cmd)) = &args.command {
        let exit_code = match cmd {
            OperatorCmd::Create {
                name,
                email,
                role,
                mailbox,
                expires_days,
            } => commands::operator_create(name, email, role, mailbox.as_deref(), *expires_days),
            OperatorCmd::Register {
                name,
                api_url,
                token,
            } => commands::operator_register(name, api_url, token).await,
            OperatorCmd::List => commands::operator_list(),
            OperatorCmd::Deactivate {
                name,
                api_url,
                token,
            } => commands::operator_deactivate(name, api_url, token).await,
            OperatorCmd::Succession { name, email } => commands::operator_succession(name, email),
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
    // Strategy: resolve the server address from topology, then try API first,
    // fall back to direct DB access if no server is reachable.
    //
    // Topology resolution (priority order):
    //   1. --server CLI flag           (explicit override)
    //   2. [node] upstream from config (delegate nodes)
    //   3. 127.0.0.1:<port>            (genesis default — local server)
    if let Some(Commands::Verify {
        audit_db,
        json,
        reconstitute,
        anchors,
        server,
        foundation,
        foundation_url,
        foundation_receipts,
        operator,
    }) = &args.command
    {
        // ── Foundation chain verification (remote HTTPS path) ──────────────
        if *foundation {
            let exit = verify_foundation_chain(foundation_url.as_deref(), *json).await;
            std::process::exit(exit);
        }
        // ── Foundation-relayed receipts on the LOCAL chain ─────────────────
        if *foundation_receipts {
            let exit =
                verify_foundation_receipts_local(audit_db.as_deref(), operator.as_deref(), *json);
            std::process::exit(exit);
        }
        // Resolve the target server address from topology config.
        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();

        // Derive node role from chain state + config hint.
        // Config hint disambiguates delegate (holding upstream cert) from genesis.
        let derived_role = zp_config::derive_node_role_with_hint(
            &cfg.home_dir.value,
            Some(cfg.node_role.value.as_str()),
            cfg.node_upstream.value.as_deref(),
        );
        let config_hint_role = zp_config::config_hint_role(&cfg.node_role.value);

        // Log mismatch if config disagrees with chain
        if !derived_role.same_variant(&config_hint_role) {
            eprintln!("\x1b[33m⚠\x1b[0m  Config says role=\"{}\" but chain says {:?}. Using chain-derived role.",
                &cfg.node_role.value, derived_role);
        }

        let is_delegate = matches!(&derived_role, zp_config::NodeRole::Delegate { .. });
        let server_addr: Option<String> = if let Some(s) = server {
            // CLI flag takes precedence — always use it.
            Some(s.clone())
        } else if is_delegate {
            // Delegate node: upstream is required.
            match &cfg.node_upstream.value {
                Some(u) => Some(u.clone()),
                None => {
                    eprintln!(
                        "\x1b[31m✗\x1b[0m  Node role is \"delegate\" but no upstream configured."
                    );
                    eprintln!(
                        "    Set [node] upstream in zeropoint.toml or ~/ZeroPoint/config.toml,"
                    );
                    eprintln!("    or pass --server <host:port>.");
                    std::process::exit(2);
                }
            }
        } else {
            // Genesis node: try local server first, fall back to direct DB.
            Some(format!("127.0.0.1:{}", cfg.port.value))
        };

        // Try server API first — works even while the server holds the DB lock.
        let server_ok: bool = 'server: {
            let addr = match &server_addr {
                Some(a) => a.clone(),
                None => break 'server false,
            };

            // Read session token from the canonical ~/ZeroPoint/session.json
            // (Seam 19: route through zp_core::paths so ZP_HOME override and
            // future path-resolution changes are inherited automatically).
            let token = match (|| -> Option<String> {
                let path = zp_core::paths::session_path().ok()?;
                let data = std::fs::read_to_string(path).ok()?;
                let v: serde_json::Value = serde_json::from_str(&data).ok()?;
                v["token"].as_str().map(|s| s.to_string())
            })() {
                Some(t) => t,
                None => {
                    if is_delegate {
                        eprintln!(
                            "\x1b[31m✗\x1b[0m  No session token found at ~/ZeroPoint/session.json"
                        );
                        eprintln!("    Delegate nodes require a session token to authenticate with upstream.");
                        std::process::exit(2);
                    }
                    break 'server false;
                }
            };

            let timeout_secs = if is_delegate { 10 } else { 5 };
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(2))
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build()
                .unwrap();

            let url = format!("http://{}/api/v1/audit/verify", addr);
            let resp = match client.get(&url).bearer_auth(&token).send().await {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    if is_delegate {
                        eprintln!(
                            "\x1b[31m✗\x1b[0m  Upstream server at {} returned HTTP {}",
                            addr,
                            r.status()
                        );
                        std::process::exit(2);
                    }
                    break 'server false;
                }
                Err(e) => {
                    if is_delegate {
                        eprintln!(
                            "\x1b[31m✗\x1b[0m  Cannot reach upstream server at {}: {}",
                            addr, e
                        );
                        eprintln!("    Check that the upstream genesis server is running.");
                        std::process::exit(2);
                    }
                    break 'server false;
                }
            };

            let body = match resp.text().await {
                Ok(b) => b,
                Err(_) => break 'server false,
            };

            if *json {
                println!("{}", body);
            } else {
                let v: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(_) => break 'server false,
                };
                let valid = v["valid"].as_bool().unwrap_or(false);
                let entries = v["entries_examined"].as_u64().unwrap_or(0);
                let chain_links = v["chain_links_valid"].as_u64().unwrap_or(0);
                let issues = v["issues"].as_array();

                let source_label = if is_delegate {
                    format!("via upstream {}", addr)
                } else {
                    "via server".to_string()
                };
                println!(
                    "\x1b[1mzp verify — Chain Attestation ({})\x1b[0m",
                    source_label
                );
                println!();
                if valid {
                    println!(
                        "  \x1b[32m✓\x1b[0m Chain integrity: {} entries, {} chain links valid",
                        entries, chain_links
                    );
                } else {
                    println!(
                        "  \x1b[31m✗\x1b[0m Chain integrity: FAILED ({} entries examined)",
                        entries
                    );
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
            true
        };

        if server_ok {
            std::process::exit(0);
        }

        // Delegate nodes MUST verify via upstream — no local fallback.
        if is_delegate {
            eprintln!("\x1b[31m✗\x1b[0m  Delegate node has no local chain to verify.");
            eprintln!("    Verification requires a running upstream server.");
            std::process::exit(2);
        }

        // Fallback: direct DB access (server not running).
        // args.data_dir is already resolved from ZP_HOME / ~/ZeroPoint/data at startup.
        let db_path = audit_db
            .clone()
            .unwrap_or_else(|| args.data_dir.join("audit.db"));
        let store = match zp_audit::AuditStore::open_readonly(&db_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error opening audit store at {}: {}", db_path.display(), e);
                eprintln!(
                    "Hint: if the server is running, check that port {} is correct",
                    cfg.port.value
                );
                std::process::exit(2);
            }
        };
        // Guard: an empty chain is not ACCEPT — it means we're reading the wrong file.
        if let Ok(entries) = store.export_chain(1) {
            if entries.is_empty() {
                eprintln!(
                    "\x1b[33m⚠\x1b[0m  Audit store at {} is empty — no chain to verify.",
                    db_path.display()
                );
                eprintln!("    This usually means --data-dir points to the wrong location.");
                eprintln!("    Hint: try --data-dir ~/ZeroPoint/data/zeropoint");
                std::process::exit(2);
            }
        }
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
            match zp_audit::AuditStore::open_readonly(&db_path) {
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
                println!("well-formed since: {}", ts.format("%Y-%m-%d %H:%M:%S UTC"));
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
                        "(\x1b[31mnone signed\x1b[0m — possible tier-0 violation)".to_string()
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
                    println!(
                        "  {} [{}] entry={}… {}",
                        badge, f.rule, entry_short, f.description
                    );
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
            eprintln!(
                "chain integrity:    {}",
                if state.chain_integrity_verified {
                    "\x1b[32mOK\x1b[0m"
                } else {
                    "\x1b[31mBROKEN\x1b[0m"
                }
            );
            eprintln!("valid operator keys: {}", state.valid_operator_keys.len());
            eprintln!("valid agent keys:    {}", state.valid_agent_keys.len());
            eprintln!("revoked keys:        {}", state.revoked_keys.len());
            eprintln!("active capabilities: {}", state.active_capabilities.len());
            eprintln!("memory states:       {}", state.memory_states.len());
            eprintln!("quarantined:         {}", state.quarantined_memories.len());

            if state.anomalies.is_empty() {
                eprintln!("\nanomalies:           \x1b[32mnone\x1b[0m");
            } else {
                eprintln!(
                    "\nanomalies:           \x1b[31m{}\x1b[0m",
                    state.anomalies.len()
                );
                for a in &state.anomalies {
                    eprintln!(
                        "  [{:?}] entry={} {:?}: {}",
                        a.severity, a.entry_id, a.kind, a.description
                    );
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
    if let Some(Commands::Anchor {
        audit_db,
        reason,
        json,
    }) = &args.command
    {
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
        renew,
        audit_db,
        json,
    }) = &args.command
    {
        let exit_code = if *renew {
            run_delegate_renew(
                subject,
                // --lease-duration is the only override the operator may
                // supply; everything else is looked up from the prior grant.
                // If the default "8h" came through it means the user didn't
                // explicitly set it; we detect "user explicitly supplied it"
                // by checking whether it differs from the clap default. We
                // pass it through regardless — run_delegate_renew will use
                // the prior grant's lease when this equals the default.
                lease_duration,
                subject_public_key.as_deref(),
                audit_db.clone(),
                &args.data_dir,
                *json,
            )
        } else {
            run_delegate(
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
                None, // renews: initial grant, no prior
                audit_db.clone(),
                &args.data_dir,
                *json,
            )
        };
        std::process::exit(exit_code);
    }
    if let Some(Commands::Revoke {
        grant_id,
        grantee,
        cascade,
        reason,
        audit_db,
        json,
    }) = &args.command
    {
        let target = match (grant_id.as_deref(), grantee.as_deref()) {
            (Some(id), None) => RevokeTarget::Grant(id.to_string()),
            (None, Some(g)) => RevokeTarget::Grantee(g.to_string()),
            // clap's conflicts_with / required_unless_present make both of
            // these unreachable via the CLI; keep them as refusals rather
            // than unreachable!() so a future programmatic caller cannot
            // reach a panic.
            (Some(_), Some(_)) => {
                eprintln!("error: --grant-id and --grantee are mutually exclusive");
                std::process::exit(2);
            }
            (None, None) => {
                eprintln!("error: one of --grant-id or --grantee is required");
                std::process::exit(2);
            }
        };
        let exit_code = run_revoke(
            target,
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
    if let Some(Commands::Discover {
        scan_path,
        audit_db,
        json,
    }) = &args.command
    {
        let exit_code = run_discover(scan_path.clone(), audit_db.clone(), &args.data_dir, *json);
        std::process::exit(exit_code);
    }

    // Canonicalize — emit bead-zero CanonicalizedClaim for a tool (M11 remediation).
    #[cfg(feature = "embedded-server")]
    if let Some(Commands::Canonicalize {
        name,
        path,
        audit_db,
        json,
    }) = &args.command
    {
        let exit_code = run_canonicalize(
            name,
            path.as_deref(),
            audit_db.as_deref(),
            &args.data_dir,
            *json,
        );
        std::process::exit(exit_code);
    }

    // Scan — F3 content-scan MCP tool definitions before canon.
    // V6 — Adapt: refresh a canon'd tool's bead-zero metadata to current schema.
    if let Some(Commands::Adapt {
        tool,
        path,
        audit_db,
        json,
    }) = &args.command
    {
        let exit_code = run_adapt(tool, path.clone(), audit_db.clone(), &args.data_dir, *json);
        std::process::exit(exit_code);
    }

    if let Some(Commands::Pricing(cmd)) = &args.command {
        match run_pricing(cmd, &args.data_dir).await {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m pricing failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(Commands::Policy(PolicyCmd::Set(PolicySetCmd::Inference {
        backend,
        strategy,
        allowlist,
        cost_cap_daily_usd,
        schema_compat,
        circuit_breaker_threshold,
        audit_db,
        json,
    }))) = &args.command
    {
        match run_policy_set_inference(
            backend,
            strategy,
            allowlist,
            *cost_cap_daily_usd,
            schema_compat,
            *circuit_breaker_threshold,
            audit_db.as_deref(),
            *json,
            &args.data_dir,
        )
        .await
        {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m policy set inference failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(Commands::Policy(PolicyCmd::Show(PolicyShowCmd::Inference { audit_db, json }))) =
        &args.command
    {
        match run_policy_show_inference(audit_db.as_deref(), *json, &args.data_dir).await {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m policy show inference failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(Commands::Model(ModelCmd::Register {
        model_id,
        provider,
        provider_url,
        context_window,
        supports_tools,
        schema_format,
        input_cost_per_m,
        output_cost_per_m,
        max_output_tokens,
        audit_db,
        json,
    })) = &args.command
    {
        match run_model_register(
            model_id,
            provider,
            provider_url,
            *context_window,
            *supports_tools,
            schema_format,
            *input_cost_per_m,
            *output_cost_per_m,
            *max_output_tokens,
            audit_db.as_deref(),
            *json,
            &args.data_dir,
        )
        .await
        {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m model register failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(Commands::Model(ModelCmd::List { audit_db, json })) = &args.command {
        match run_model_list(audit_db.as_deref(), *json, &args.data_dir).await {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m model list failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(Commands::Model(ModelCmd::Update {
        model_id,
        field,
        value,
        reason,
        audit_db,
        json,
    })) = &args.command
    {
        match run_model_update(
            model_id,
            field,
            value,
            reason,
            audit_db.as_deref(),
            *json,
            &args.data_dir,
        )
        .await
        {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m model update failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(Commands::Emit {
        label,
        issue,
        agent,
        parent,
        upstream,
        meta,
        audit_db,
        json,
    }) = &args.command
    {
        match emit::run_emit(
            label,
            issue.as_deref(),
            agent.as_deref(),
            parent.as_deref(),
            upstream.as_deref(),
            meta,
            audit_db.as_deref(),
            &args.data_dir,
            *json,
        ) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m emit failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(Commands::Scan {
        path,
        json,
        audit_db,
    }) = &args.command
    {
        let exit_code = run_scan(path, *json, audit_db.clone(), &args.data_dir);
        std::process::exit(exit_code);
    }

    // Ps — Part VIII Stage 1 compute surface snapshot.
    // Samples lsof system-wide, attributes via PortRegistry, prints table.
    if let Some(Commands::Ps { json, tools }) = &args.command {
        use zp_server::tool_ports::{
            lsof_all_listen, PortRegistry, PostureSnapshot, ProcessAttribution,
        };

        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        let data_dir = cfg.data_dir.value.clone();
        let registry = PortRegistry::new(&data_dir);

        let procs = lsof_all_listen();
        let snapshot = PostureSnapshot::from_processes(&registry, procs);

        if *json {
            let to_obj = |ap: &zp_server::tool_ports::AttributedProcess| {
                let (kind, detail) = match &ap.attribution {
                    ProcessAttribution::SubstrateManaged {
                        tool_name,
                        allocated_receipt_id,
                    } => (
                        "substrate_managed",
                        serde_json::json!({
                            "tool_name": tool_name,
                            "allocated_receipt_id": allocated_receipt_id
                        }),
                    ),
                    ProcessAttribution::KnownSystem { category } => {
                        ("known_system", serde_json::json!({ "category": category }))
                    }
                    ProcessAttribution::Unknown => ("unknown", serde_json::json!({})),
                };
                serde_json::json!({
                    "pid": ap.process.pid,
                    "name": ap.process.name,
                    "port": ap.process.port,
                    "attribution": kind,
                    "detail": detail,
                })
            };

            let out = serde_json::json!({
                "total": snapshot.total(),
                "substrate_managed": snapshot.substrate_managed.iter().map(to_obj).collect::<Vec<_>>(),
                "known_system": snapshot.known_system.iter().map(to_obj).collect::<Vec<_>>(),
                "unknown": snapshot.unknown.iter().map(to_obj).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            let total = snapshot.total();
            println!("\x1b[1mCompute Surface Snapshot\x1b[0m  ({total} processes listening)");
            println!();

            // ── Substrate-managed ──────────────────────────────────────────
            if !snapshot.substrate_managed.is_empty() {
                println!("\x1b[32m● Substrate-managed\x1b[0m");
                for ap in &snapshot.substrate_managed {
                    if let ProcessAttribution::SubstrateManaged { tool_name, .. } = &ap.attribution
                    {
                        // Fetch version info from registry binding.
                        let version_str = registry
                            .get_assigned(tool_name)
                            .and_then(|b| b.last_version)
                            .map(|v| {
                                let mut parts = Vec::new();
                                if let Some(ref c) = v.source_commit {
                                    let short = &c[..c.len().min(8)];
                                    let dirty = if v.source_dirty.unwrap_or(false) {
                                        "*"
                                    } else {
                                        ""
                                    };
                                    parts.push(format!("commit:{}{}", short, dirty));
                                }
                                if let Some(ref h) = v.binary_hash {
                                    parts.push(format!("bin:{:.8}…", h));
                                }
                                if parts.is_empty() {
                                    String::from("(no version captured)")
                                } else {
                                    parts.join("  ")
                                }
                            })
                            .unwrap_or_default();
                        if version_str.is_empty() {
                            println!(
                                "  {:5}  {:20}  :{:<6}  → {}",
                                ap.process.pid, ap.process.name, ap.process.port, tool_name
                            );
                        } else {
                            println!(
                                "  {:5}  {:20}  :{:<6}  → {}  \x1b[2m[{}]\x1b[0m",
                                ap.process.pid,
                                ap.process.name,
                                ap.process.port,
                                tool_name,
                                version_str
                            );
                        }
                    }
                }
                println!();
            }

            // ── Known system ───────────────────────────────────────────────
            if !snapshot.known_system.is_empty() {
                println!("\x1b[34m◌ Known system\x1b[0m");
                for ap in &snapshot.known_system {
                    if let ProcessAttribution::KnownSystem { category } = &ap.attribution {
                        println!(
                            "  {:5}  {:20}  :{:<6}  ({})",
                            ap.process.pid, ap.process.name, ap.process.port, category
                        );
                    }
                }
                println!();
            }

            // ── Unknown ────────────────────────────────────────────────────
            if !snapshot.unknown.is_empty() {
                println!("\x1b[33m? Unknown — review required\x1b[0m");
                for ap in &snapshot.unknown {
                    println!(
                        "  {:5}  {:20}  :{}",
                        ap.process.pid, ap.process.name, ap.process.port
                    );
                }
                println!();
                println!(
                    "  \x1b[33m{} unknown process(es)\x1b[0m — run `lsof -p <pid>` to investigate",
                    snapshot.unknown.len()
                );
            } else {
                println!("\x1b[32m✓ All processes attributed\x1b[0m");
            }
        }

        // ── Governed tool health (--tools) ────────────────────────────────
        if *tools {
            let bindings = registry.list();
            if bindings.is_empty() {
                println!();
                println!("No governed tools registered.");
            } else {
                println!();
                println!("\x1b[1mGoverned Tool Health\x1b[0m");
                println!();

                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

                for binding in &bindings {
                    // ── Collect all ports this tool should have bound ──────
                    let mut port_checks: Vec<(String, u16)> =
                        vec![(binding.port_var.clone(), binding.port)];
                    for (var, &port) in &binding.extra_ports {
                        port_checks.push((var.clone(), port));
                    }
                    let proxy_target = binding.proxy_target();

                    // ── lsof: which ports are actually listening ───────────
                    let mut port_status: Vec<(String, u16, Option<u32>)> = Vec::new();
                    for (var, port) in &port_checks {
                        let pid = zp_server::tool_ports::lsof_pid_for_port(*port);
                        port_status.push((var.clone(), *port, pid));
                    }

                    // Also check proxy_target if different from all allocated ports
                    let allocated_ports: Vec<u16> = port_checks.iter().map(|(_, p)| *p).collect();
                    if !allocated_ports.contains(&proxy_target) {
                        let pid = zp_server::tool_ports::lsof_pid_for_port(proxy_target);
                        port_status.push(("proxy_target".to_string(), proxy_target, pid));
                    }

                    // ── HTTP probe: proxy_target with auth ─────────────────
                    let probe_url = zp_net::peer_url_with_path("127.0.0.1", proxy_target, "/");
                    let auth_token = binding.auth_token.clone();
                    let (authed_status, authed_ct, unauthed_status) = rt.block_on(async {
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(3))
                            .build()
                            .unwrap_or_else(|_| reqwest::Client::new());

                        // Authed probe
                        let authed = client
                            .get(&probe_url)
                            .header("Authorization", format!("Bearer {}", &auth_token))
                            .send()
                            .await;
                        let (status, ct) = match authed {
                            Ok(r) => {
                                let s = r.status().as_u16();
                                let c = r
                                    .headers()
                                    .get("content-type")
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());
                                (Some(s), c)
                            }
                            Err(_) => (None, None),
                        };

                        // Unauthed probe (expect 401 or redirect, not 200 — check auth is enforced)
                        let unauthed = client.get(&probe_url).send().await;
                        let unauthed_s = match unauthed {
                            Ok(r) => Some(r.status().as_u16()),
                            Err(_) => None,
                        };

                        (status, ct, unauthed_s)
                    });

                    // ── Classify issues ───────────────────────────────────
                    let mut issues: Vec<String> = Vec::new();

                    // All allocated ports must be listening
                    for (var, port, pid) in &port_status {
                        if pid.is_none() && var != "proxy_target" {
                            issues.push(format!(
                                "\x1b[31m[CRIT]\x1b[0m :{} ({}) not listening — process did not start or failed to bind",
                                port, var
                            ));
                        }
                    }

                    // proxy_target must return 200 with HTML
                    match authed_status {
                        None => issues.push(format!(
                            "\x1b[31m[CRIT]\x1b[0m proxy_target :{} not reachable — connection refused",
                            proxy_target
                        )),
                        Some(404) => issues.push(format!(
                            "\x1b[31m[CRIT]\x1b[0m proxy_target :{} → 404 — wrong port (web UI not here)",
                            proxy_target
                        )),
                        Some(401) | Some(403) => issues.push(format!(
                            "\x1b[33m[WARN]\x1b[0m proxy_target :{} → {} with correct token — auth gate active on static routes",
                            proxy_target, authed_status.unwrap()
                        )),
                        Some(s) if s >= 500 => issues.push(format!(
                            "\x1b[31m[CRIT]\x1b[0m proxy_target :{} → {} — server error",
                            proxy_target, s
                        )),
                        _ => {}
                    }

                    // proxy_port registry divergence
                    if let Some(rp) = binding.proxy_port {
                        if rp != proxy_target {
                            issues.push(format!(
                                "\x1b[33m[WARN]\x1b[0m registry proxy_port={} but proxy_target()={} — stale value",
                                rp, proxy_target
                            ));
                        }
                    }

                    // ── Print ─────────────────────────────────────────────
                    let healthy = issues.is_empty();
                    let status_icon = if healthy {
                        "\x1b[32m✓\x1b[0m"
                    } else {
                        "\x1b[31m✗\x1b[0m"
                    };
                    println!("  {} \x1b[1m{}\x1b[0m", status_icon, binding.tool);

                    // Ports line
                    let ports_str: Vec<String> = port_status
                        .iter()
                        .map(|(var, port, pid)| match pid {
                            Some(p) => format!("  :{} {} pid={}", port, var, p),
                            None if var == "proxy_target" => format!("  :{} proxy_target", port),
                            None => format!("  :{} {} \x1b[31m✗ not listening\x1b[0m", port, var),
                        })
                        .collect();
                    println!("    Ports:{}", ports_str.join("  "));

                    // Probe line
                    let probe_str = match (authed_status, &authed_ct) {
                        (Some(200), Some(ct)) => format!(
                            ":{} GET / → \x1b[32m200 {}\x1b[0m \x1b[32m✓\x1b[0m",
                            proxy_target, ct
                        ),
                        (Some(s), _) => format!(":{} GET / → \x1b[31m{}\x1b[0m", proxy_target, s),
                        (None, _) => {
                            format!(":{} GET / → \x1b[31mno response\x1b[0m", proxy_target)
                        }
                    };
                    let unauthed_str = match unauthed_status {
                        Some(200) => {
                            " \x1b[33m(unauthed also 200 — no auth gate)\x1b[0m".to_string()
                        }
                        Some(s) => format!(" (unauthed→{})", s),
                        None => String::new(),
                    };
                    println!("    Proxy:  {}{}", probe_str, unauthed_str);

                    // Issues
                    if !issues.is_empty() {
                        println!("    Issues ({}):", issues.len());
                        for issue in &issues {
                            println!("      {}", issue);
                        }
                    }
                    println!();
                }
            }
        }

        std::process::exit(0);
    }

    // Update — record new version + optionally relaunch a tool.
    #[cfg(feature = "embedded-server")]
    if let Some(Commands::Update { name, record_only }) = &args.command {
        use zp_server::tool_ports::{capture_tool_version, resolve_binary_path, PortRegistry};

        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        let data_dir = cfg.data_dir.value.clone();
        let registry = PortRegistry::new(&data_dir);

        // Fetch stored binding to get working_dir and pid.
        let binding = match registry.get_assigned(name) {
            Some(b) => b,
            None => {
                eprintln!("\x1b[31m✗\x1b[0m  no binding for '{}' — run `zp configure exec --name {} -- <cmd>` first", name, name);
                std::process::exit(1);
            }
        };

        let working_dir_str = binding
            .launch_command
            .as_ref()
            .and_then(|lc| lc.working_dir.clone());
        let working_dir = working_dir_str.as_deref().map(std::path::Path::new);

        let bin_command = binding.launch_command.as_ref().map(|lc| lc.command.clone());
        let bin_path = bin_command.as_deref().and_then(resolve_binary_path);

        println!("  Capturing version for '{}'…", name);
        let version = capture_tool_version(working_dir, bin_path.as_deref());

        if let Some(ref commit) = version.source_commit {
            let dirty = version.source_dirty.unwrap_or(false);
            println!(
                "  commit   {}{}",
                &commit[..commit.len().min(12)],
                if dirty {
                    " (dirty — uncommitted changes present)"
                } else {
                    ""
                }
            );
        } else {
            println!("  commit   (not a git working directory)");
        }
        if let Some(ref hash) = version.binary_hash {
            println!(
                "  binary   {}…  ({})",
                &hash[..hash.len().min(16)],
                bin_path.as_deref().and_then(|p| p.to_str()).unwrap_or("?")
            );
        }

        // Compare vs. previous recorded version.
        if let Some(prev) = &binding.last_version {
            let prev_commit = prev.source_commit.as_deref().unwrap_or("?");
            let new_commit = version.source_commit.as_deref().unwrap_or("?");
            let prev_hash = prev.binary_hash.as_deref().unwrap_or("?");
            let new_hash = version.binary_hash.as_deref().unwrap_or("?");

            if prev_hash != new_hash {
                println!(
                    "  \x1b[33m⚑ binary changed\x1b[0m  {} → {}",
                    &prev_hash[..prev_hash.len().min(8)],
                    &new_hash[..new_hash.len().min(8)]
                );
            } else if prev_commit != new_commit {
                println!(
                    "  \x1b[33m⚑ commit changed\x1b[0m  {} → {}",
                    &prev_commit[..prev_commit.len().min(8)],
                    &new_commit[..new_commit.len().min(8)]
                );
            } else {
                println!("  \x1b[32m✓ no change detected\x1b[0m");
            }
        } else {
            println!("  (first version record for this tool)");
        }

        // Store new version.
        if let Err(e) = registry.store_tool_version(name, version.clone()) {
            eprintln!("  \x1b[31m✗\x1b[0m  could not store version: {}", e);
            std::process::exit(1);
        }

        // Emit chain receipt.
        emit::emit_tool_launch_receipt(name, &version, &data_dir);
        // Rename the event label for updates vs. initial launches.
        // (The receipt above uses tool:launched:<name>; a future emit variant
        //  for tool:updated:<name> would disambiguate — acceptable for now.)

        if *record_only {
            println!("  \x1b[32m✓ version recorded\x1b[0m (--record-only; tool not relaunched)");
            std::process::exit(0);
        }

        // Relaunch: kill old pid, re-exec via configure exec.
        if let Some(pid) = binding.pid {
            println!("  stopping  {} (pid {})", name, pid);
            // SIGTERM the old process; give it 800ms to exit cleanly, then SIGKILL.
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            std::thread::sleep(std::time::Duration::from_millis(800));
            // Check if still alive (kill -0 = existence probe, no signal sent).
            let still_alive = std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if still_alive {
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
            }
        } else {
            println!("  \x1b[33m⚠\x1b[0m  no recorded pid — cannot stop old process; proceeding with relaunch");
        }

        // Rebuild relaunch args from stored launch command.
        let lc = match binding.launch_command {
            Some(ref lc) => lc,
            None => {
                eprintln!("  \x1b[31m✗\x1b[0m  no stored launch command — run `zp configure exec --name {} -- <cmd>` first", name);
                std::process::exit(1);
            }
        };
        println!(
            "  relaunching  {} via `{} {}`",
            name,
            lc.command,
            lc.args.join(" ")
        );
        let mut relaunch = std::process::Command::new("zp");
        relaunch.args(["configure", "exec", "--name", name, "--"]);
        relaunch.arg(&lc.command);
        relaunch.args(&lc.args);
        if let Some(ref wd) = lc.working_dir {
            relaunch.current_dir(wd);
        }
        match relaunch.status() {
            Ok(s) if s.success() => {
                println!("  \x1b[32m✓ relaunched\x1b[0m");
                std::process::exit(0);
            }
            Ok(s) => {
                eprintln!(
                    "  \x1b[31m✗\x1b[0m  relaunch exited {}",
                    s.code().unwrap_or(-1)
                );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("  \x1b[31m✗\x1b[0m  relaunch failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Config subcommand — unified configuration management
    if let Some(Commands::Cfg(cmd)) = &args.command {
        match cmd {
            CfgCmd::Show => {
                let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
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
                let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
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
        let base_url = zp_net::peer_origin("127.0.0.1", port);
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
                                .filter(|r| {
                                    r.get("memory_id").and_then(|v| v.as_str())
                                        == Some(mid.as_str())
                                })
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
                                let mem =
                                    r.get("memory_id").and_then(|v| v.as_str()).unwrap_or("?");
                                let from = r
                                    .get("current_stage")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let to = r
                                    .get("target_stage")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let expires =
                                    r.get("expires_at").and_then(|v| v.as_str()).unwrap_or("?");
                                let deferrals = r
                                    .get("deferral_count")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);
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
                    .post(format!(
                        "{}/api/v1/cognition/reviews/{}/decide",
                        base_url, review_id
                    ))
                    .json(&body)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let result: serde_json::Value = r.json().await.unwrap_or_default();
                        let outcome = result
                            .get("outcome")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                        eprintln!(
                            "\x1b[32m✓\x1b[0m Review {}: {} — {}",
                            review_id, outcome, detail
                        );
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
            MemoryCmd::Reject {
                review_id,
                reason,
                action,
            } => {
                let body = serde_json::json!({
                    "decision": "reject",
                    "reviewer": args.data_dir.display().to_string(),
                    "reason": reason,
                    "action": action,
                });
                let resp = client
                    .post(format!(
                        "{}/api/v1/cognition/reviews/{}/decide",
                        base_url, review_id
                    ))
                    .json(&body)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let result: serde_json::Value = r.json().await.unwrap_or_default();
                        let outcome = result
                            .get("outcome")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                        eprintln!(
                            "\x1b[32m✓\x1b[0m Review {}: {} — {}",
                            review_id, outcome, detail
                        );
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
                    .post(format!(
                        "{}/api/v1/cognition/reviews/{}/decide",
                        base_url, review_id
                    ))
                    .json(&body)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let result: serde_json::Value = r.json().await.unwrap_or_default();
                        let outcome = result
                            .get("outcome")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                        eprintln!(
                            "\x1b[32m✓\x1b[0m Review {}: {} — {}",
                            review_id, outcome, detail
                        );
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

    // Regent — talk to the cognitive loop via HTTP
    if let Some(Commands::Regent { message, verbose }) = &args.command {
        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        let port = cfg.port.value;
        let bind = &cfg.bind.value;
        let api_url = format!("http://{}:{}/api/v1/regent/input", bind, port);
        let verbose = *verbose;

        // If verbose, start SSE listener before sending the request so we
        // catch all cognitive events including cycle_start.
        let sse_handle = if verbose {
            let sse_url = format!("http://{}:{}/api/v1/events/stream", bind, port);
            let t0 = std::time::Instant::now();
            Some(tokio::spawn(async move {
                let client = reqwest::Client::new();
                let resp = match client.get(&sse_url).send().await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let mut stream = resp.bytes_stream();
                use futures::StreamExt;
                let mut buf = String::new();
                while let Some(Ok(chunk)) = stream.next().await {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    // Process complete SSE messages (terminated by double newline)
                    while let Some(pos) = buf.find("\n\n") {
                        let msg = buf[..pos].to_string();
                        buf = buf[pos + 2..].to_string();

                        // Parse SSE: look for event: and data: lines
                        let mut event_type = String::new();
                        let mut data = String::new();
                        for line in msg.lines() {
                            if let Some(rest) = line.strip_prefix("event:") {
                                event_type = rest.trim().to_string();
                            } else if let Some(rest) = line.strip_prefix("data:") {
                                data = rest.trim().to_string();
                            }
                        }

                        // Only show cognition events
                        if event_type != "cognition" {
                            continue;
                        }

                        if let Ok(item) = serde_json::from_str::<serde_json::Value>(&data) {
                            let elapsed = t0.elapsed().as_millis();
                            let phase = item
                                .get("event_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            let summary =
                                item.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                            eprintln!("\x1b[2m[{:>6}ms] {:<30} {}\x1b[0m", elapsed, phase, summary);
                        }
                    }
                }
            }))
        } else {
            None
        };

        // Small delay to ensure SSE is connected before we send.
        if verbose {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let client = reqwest::Client::new();
        match client
            .post(&api_url)
            .json(&serde_json::json!({"content": message}))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .unwrap_or_else(|_| serde_json::json!({"error": "failed to parse response"}));

                if status.is_success() {
                    if let Some(text) = body.get("response").and_then(|v| v.as_str()) {
                        println!("{}", text);
                    } else {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&body).unwrap_or_default()
                        );
                    }
                } else {
                    let err = body
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown error");
                    eprintln!("regent: {}", err);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("regent: cannot reach zp serve at {} — {}", api_url, e);
                std::process::exit(1);
            }
        }

        // Give the SSE listener a moment to flush remaining events, then drop it.
        if let Some(handle) = sse_handle {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            handle.abort();
        }

        std::process::exit(0);
    }

    // Doctor — post-install diagnostics
    if let Some(Commands::Doctor { json }) = &args.command {
        let cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        let home = &cfg.home_dir.value;
        let data = &cfg.data_dir.value;

        struct Check {
            label: String,
            status: &'static str, // "pass", "fail", "warn", "info"
            detail: String,
            fix: String,
        }

        let mut checks: Vec<Check> = Vec::new();

        // 1. Binary version (with git hash for staleness detection)
        let ver = env!("CARGO_PKG_VERSION");
        let git_hash = env!("ZP_GIT_HASH");
        let git_dirty = env!("ZP_GIT_DIRTY");
        let binary_version = format!("zp {ver} ({git_hash}{git_dirty})");

        // Check if the installed binary matches the repo HEAD.
        // Run git from the ZP repo root — two levels up from the canonical
        // binary path (target/debug/zp → target/ → repo/).
        // This resolves symlinks first so /usr/local/bin/zp → target/debug/zp
        // → ../../ = the ZP repo, regardless of the operator's CWD.
        let repo_dir = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(p).ok())
            .and_then(|p| {
                p.parent() // target/debug/
                    .and_then(|p| p.parent()) // target/
                    .and_then(|p| p.parent()) // repo root
                    .map(|p| p.to_path_buf())
            });
        let head_hash = repo_dir
            .as_deref()
            .and_then(|dir| {
                std::process::Command::new("git")
                    .args([
                        "-C",
                        dir.to_str().unwrap_or("."),
                        "rev-parse",
                        "--short",
                        "HEAD",
                    ])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            String::from_utf8(o.stdout).ok()
                        } else {
                            None
                        }
                    })
            })
            .unwrap_or_default();
        let head_hash = head_hash.trim();

        let (bin_status, bin_fix) = if !head_hash.is_empty() && git_hash != head_hash {
            (
                "warn",
                format!("Binary is {git_hash} but repo HEAD is {head_hash}. Run: just deploy"),
            )
        } else {
            ("pass", String::new())
        };

        checks.push(Check {
            label: "Binary version".into(),
            status: bin_status,
            detail: binary_version,
            fix: bin_fix,
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

        // 2a. Node role coherence check (T1: Chain-Derived Role)
        let derived_role = zp_config::derive_node_role_with_hint(
            home,
            Some(cfg.node_role.value.as_str()),
            cfg.node_upstream.value.as_deref(),
        );
        let config_hint_role = zp_config::config_hint_role(&cfg.node_role.value);

        if derived_role.same_variant(&config_hint_role) {
            let role_str = match &derived_role {
                zp_config::NodeRole::Genesis => "Genesis",
                zp_config::NodeRole::Delegate { .. } => "Delegate",
                zp_config::NodeRole::Standalone => "Standalone",
            };
            checks.push(Check {
                label: "Node role (derived)".into(),
                status: "pass",
                detail: format!("{} (matches config)", role_str),
                fix: String::new(),
            });
        } else {
            let derived_str = match &derived_role {
                zp_config::NodeRole::Genesis => "Genesis (genesis.json present)".to_string(),
                zp_config::NodeRole::Delegate { upstream_addr, .. } => {
                    format!("Delegate (upstream: {})", upstream_addr)
                }
                zp_config::NodeRole::Standalone => {
                    "Standalone (no genesis.json, no delegation receipt)".to_string()
                }
            };
            let config_str = &cfg.node_role.value;
            let (status, fix) = if matches!(derived_role, zp_config::NodeRole::Genesis) {
                ("warn", format!("Config says \"{}\" but chain says Genesis. Update config if you converted this node.", config_str))
            } else if matches!(derived_role, zp_config::NodeRole::Delegate { .. }) {
                ("warn", "Config hint does not match chain state (delegation receipt present). Update config or run 'zp serve' to finalize delegation.".to_string())
            } else {
                ("info", "Config says delegate but chain is Standalone. Run 'zp serve' to initiate delegation handshake.".to_string())
            };
            checks.push(Check {
                label: "Node role (derived)".into(),
                status,
                detail: format!("{} | config says \"{}\"", derived_str, config_str),
                fix,
            });
        }

        // 2b. Upstream binding (delegate nodes only)
        let upstream_status = zp_config::verify_upstream_binding_local(&derived_role);
        match &upstream_status {
            zp_config::UpstreamBindingStatus::Verified { .. } => {
                checks.push(Check {
                    label: "Upstream binding".into(),
                    status: "pass",
                    detail: upstream_status.summary(),
                    fix: String::new(),
                });
            }
            zp_config::UpstreamBindingStatus::NotDelegate => {
                // Not a delegate — skip this check silently
            }
            zp_config::UpstreamBindingStatus::Unbound { .. } => {
                checks.push(Check {
                    label: "Upstream binding".into(),
                    status: "warn",
                    detail: upstream_status.summary(),
                    fix: "Re-delegate to record the upstream's genesis pubkey in the delegation receipt.".into(),
                });
            }
            zp_config::UpstreamBindingStatus::MalformedPubkey { .. } => {
                checks.push(Check {
                    label: "Upstream binding".into(),
                    status: "fail",
                    detail: upstream_status.summary(),
                    fix: "The delegation receipt contains a malformed pubkey. Re-delegate from the upstream node.".into(),
                });
            }
            zp_config::UpstreamBindingStatus::PubkeyMismatch { .. } => {
                checks.push(Check {
                    label: "Upstream binding".into(),
                    status: "fail",
                    detail: upstream_status.summary(),
                    fix: "SECURITY: Upstream identity changed. Verify with your operator and re-delegate if legitimate.".into(),
                });
            }
            zp_config::UpstreamBindingStatus::UpstreamUnreachable { .. } => {
                checks.push(Check {
                    label: "Upstream binding".into(),
                    status: "warn",
                    detail: upstream_status.summary(),
                    fix: "Upstream node is not reachable. Check network connectivity.".into(),
                });
            }
        }

        // 2c. Fleet membership attestation (T4)
        match &derived_role {
            zp_config::NodeRole::Genesis => {
                checks.push(Check {
                    label: "Fleet membership".into(),
                    status: "pass",
                    detail: "Fleet authority (genesis node)".into(),
                    fix: String::new(),
                });
            }
            zp_config::NodeRole::Delegate { upstream_addr, .. } => {
                // TODO: Check chain for FleetMembershipAccepted receipt
                // For now, report that membership attestation is pending
                checks.push(Check {
                    label: "Fleet membership".into(),
                    status: "warn",
                    detail: format!(
                        "Delegate of {} — membership receipt not yet attested (T4 pending)",
                        upstream_addr
                    ),
                    fix: "Fleet membership attestation will be issued during delegation handshake."
                        .into(),
                });
            }
            zp_config::NodeRole::Standalone => {
                // Standalone nodes are not fleet members — skip silently
            }
        }

        // 2d. External anchoring (T7)
        // TODO: Check chain for most recent ExternalAnchor receipt
        // For now, report anchoring status based on configuration
        let anchor_configured = false; // Will be wired to config when HCS client exists
        if anchor_configured {
            checks.push(Check {
                label: "External anchoring".into(),
                status: "pass",
                detail: "Configured (settlement layer connected)".into(),
                fix: String::new(),
            });
        } else {
            checks.push(Check {
                label: "External anchoring".into(),
                status: "info",
                detail: "Not configured — chain is locally verifiable but not externally anchored"
                    .into(),
                fix: "Configure a settlement layer (e.g., Hedera HCS) for external timestamping."
                    .into(),
            });
        }

        // 2e. Financial capability grants (T7 Phase 2)
        // TODO: Scan chain for active FinancialCapabilityGrant receipts
        // For now, report as info — no financial grants exist yet
        checks.push(Check {
            label: "Financial capabilities".into(),
            status: "info",
            detail: "No active financial capability grants — agents have no spending authority".into(),
            fix: "Issue a FinancialCapabilityGrant receipt to bind financial constraints to a delegation.".into(),
        });

        // 2f. Genesis secret (credential store)
        // Delegates hold the upstream's genesis.json for verification — they
        // do NOT need the genesis secret (that's the upstream's private key).
        if matches!(&derived_role, zp_config::NodeRole::Delegate { .. }) {
            if genesis_path.exists() {
                checks.push(Check {
                    label: "Upstream certificate".into(),
                    status: "pass",
                    detail: "upstream genesis.json present (for verification)".into(),
                    fix: String::new(),
                });
            } else {
                checks.push(Check {
                    label: "Upstream certificate".into(),
                    status: "fail",
                    detail: "upstream genesis.json missing — cannot verify upstream identity"
                        .into(),
                    fix: "Copy genesis.json from your upstream genesis node.".into(),
                });
            }
        } else {
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
            if let Ok(store) = zp_audit::AuditStore::open_readonly(&audit_db) {
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
                let store_for_canon = match zp_audit::AuditStore::open_readonly(&audit_db) {
                    Ok(s) => Some(Arc::new(Mutex::new(s))),
                    Err(_) => None,
                };

                // ── (a) F6 CHAIN INTEGRITY ─────────────────────────────────
                // Distilled `zp verify`: total entries, signature pass/fail,
                // hash-link continuity (P1 + M3), and genesis sealed status.
                if let Ok(store) = zp_audit::AuditStore::open_readonly(&audit_db) {
                    match store.verify_with_catalog() {
                        Ok(report) => {
                            let errors = report.error_count();
                            let hashlink_ok = report.findings.iter().all(|f| {
                                f.rule != "M3" && f.rule != "P1"
                                    || f.severity != zp_verify::FindingSeverity::Error
                            });
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
                                    .find(|f| f.severity == zp_verify::FindingSeverity::Error)
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
                                        report.signature_failures, report.signature_checks
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
                    let bead_zeros = zp_server::tool_chain::query_bead_zeros(store);
                    // Match `zp discover`'s default scan path so the same set
                    // of tools surfaces in both commands.
                    let scan_path = zp_core::paths::user_home_or(".").join("projects");
                    let scan = zp_engine::scan::scan_tools(&scan_path);
                    let fs_tools: Vec<&str> = scan.tools.iter().map(|t| t.name.as_str()).collect();

                    let system_canon = bead_zeros.contains_key("system:zeropoint");
                    let canon_tool_count =
                        bead_zeros.keys().filter(|k| k.starts_with("tool:")).count();

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
                            .filter(|name| !bead_zeros.contains_key(&format!("tool:{}", name)))
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
                    let canon_meta = zp_server::tool_chain::query_canonicalization_metadata(store);
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
                            detail: format!("{} tools all scanned clean", tool_meta.len()),
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
                                    Some("reversible") | Some("partial") | Some("irreversible")
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

        // ── Part VIII Stage 1: Compute surface posture ──────────────────
        // Run lsof, attribute against PortRegistry. Warn if unknown
        // processes are listening — the lsof test (heuristic #11).
        {
            let registry = zp_server::tool_ports::PortRegistry::new(data);
            let snapshot = zp_server::tool_ports::PostureSnapshot::build(&registry);
            let unknown_count = snapshot.unknown.len();
            let total = snapshot.total();
            if total == 0 {
                // lsof unavailable or no listeners yet — informational only
                checks.push(Check {
                    label: "Compute surface".into(),
                    status: "info",
                    detail: "No TCP listeners detected (lsof may be unavailable)".into(),
                    fix: String::new(),
                });
            } else if unknown_count == 0 {
                checks.push(Check {
                    label: "Compute surface".into(),
                    status: "pass",
                    detail: format!(
                        "{total} process(es) listening — all attributed (substrate={}, system={})",
                        snapshot.substrate_managed.len(),
                        snapshot.known_system.len()
                    ),
                    fix: String::new(),
                });
            } else {
                let names: Vec<String> = snapshot
                    .unknown
                    .iter()
                    .map(|ap| format!("{}:{}", ap.process.name, ap.process.port))
                    .collect();
                checks.push(Check {
                    label: "Compute surface".into(),
                    status: "warn",
                    detail: format!("{unknown_count} unknown listener(s): {}", names.join(", ")),
                    fix: "Run `zp ps` to review. Investigate with `lsof -p <pid>`.".into(),
                });
            }
        }

        // ── Tool version drift ───────────────────────────────────────────
        // For each substrate-managed tool with a recorded binary_hash,
        // hash the current binary and warn if it has changed since launch.
        // This detects out-of-band binary replacements (manual updates,
        // package managers, etc.) that haven't gone through `zp update`.
        #[cfg(feature = "embedded-server")]
        {
            use zp_server::tool_ports::{resolve_binary_path, PortRegistry};
            let registry = PortRegistry::new(data);
            let bindings = registry.list();
            let mut drifted: Vec<String> = Vec::new();
            let mut no_version: Vec<String> = Vec::new();

            for binding in &bindings {
                match &binding.last_version {
                    None => {
                        // Never had a version captured — prompt operator.
                        no_version.push(binding.tool.clone());
                    }
                    Some(prev) => {
                        if prev.binary_hash.is_none() {
                            continue; // No hash to compare against.
                        }
                        // Resolve current binary and re-hash.
                        let bin_cmd = binding.launch_command.as_ref().map(|lc| lc.command.clone());
                        let current_hash = bin_cmd
                            .as_deref()
                            .and_then(resolve_binary_path)
                            .and_then(|p| std::fs::read(&p).ok())
                            .map(|b| blake3::hash(&b).to_hex().to_string());

                        if let (Some(stored), Some(current)) = (&prev.binary_hash, &current_hash) {
                            if stored != current {
                                drifted.push(format!(
                                    "{} (stored:{:.8}… current:{:.8}…)",
                                    binding.tool, stored, current
                                ));
                            }
                        }
                    }
                }
            }

            if !drifted.is_empty() {
                checks.push(Check {
                    label: "Tool version drift".into(),
                    status: "warn",
                    detail: format!(
                        "{} tool(s) have changed since last `zp configure exec`: {}",
                        drifted.len(),
                        drifted.join(", ")
                    ),
                    fix: "Run `zp update --name <tool>` to record the new version and relaunch."
                        .into(),
                });
            } else if !no_version.is_empty() {
                checks.push(Check {
                    label: "Tool version drift".into(),
                    status: "info",
                    detail: format!(
                        "{} tool(s) have no recorded version: {}",
                        no_version.len(),
                        no_version.join(", ")
                    ),
                    fix: "Re-launch each tool via `zp configure exec` to begin tracking.".into(),
                });
            } else if !bindings.is_empty() {
                checks.push(Check {
                    label: "Tool version drift".into(),
                    status: "pass",
                    detail: format!(
                        "All {} tool binding(s) match recorded binary hashes",
                        bindings.len()
                    ),
                    fix: String::new(),
                });
            }
        }

        // ── Tool governance posture ─────────────────────────────────────
        // Per-tool facet computation from chain evidence + port registry.
        {
            use zp_officers::governance_posture::{
                compute_postures, GovernanceFacet, RegisteredToolInfo, ToolRegistrySnapshot,
                UnregisteredTools,
            };

            let registry = zp_server::tool_ports::PortRegistry::new(data);
            let bindings = registry.list();

            // Build snapshot from port registry.
            let mut snapshot = ToolRegistrySnapshot::default();
            for b in &bindings {
                snapshot.registered_tools.insert(
                    b.tool.clone(),
                    RegisteredToolInfo {
                        port: b.port,
                        pid: b.pid,
                        has_launch_command: b.launch_command.is_some(),
                    },
                );
            }

            let unregistered = UnregisteredTools::new();

            // Open audit store for chain evidence. Fall back to in-memory
            // empty store when the DB doesn't exist or can't open.
            let store = if audit_db.exists() {
                zp_audit::AuditStore::open_readonly(&audit_db).ok()
            } else {
                None
            };
            let fallback = zp_audit::AuditStore::open_readonly(":memory:").unwrap();
            let chain = zp_officers::officer::ChainReader::new(store.as_ref().unwrap_or(&fallback));
            let postures = compute_postures(&chain, &snapshot, &unregistered);

            if postures.is_empty() {
                checks.push(Check {
                    label: "Tool governance".into(),
                    status: "info",
                    detail: "No tools registered or discovered".into(),
                    fix: String::new(),
                });
            } else {
                for p in &postures {
                    let status =
                        if p.has(GovernanceFacet::Hardened) || p.has(GovernanceFacet::Governed) {
                            "pass"
                        } else if p.has(GovernanceFacet::Registered)
                            || p.has(GovernanceFacet::Unregistered)
                        {
                            "warn"
                        } else {
                            "info"
                        };

                    let fix = if p.has(GovernanceFacet::Unregistered) {
                        "Run: zp configure <tool> to register".into()
                    } else if p.has(GovernanceFacet::Registered)
                        && !p.has(GovernanceFacet::Governed)
                    {
                        "Launch via: zp configure exec <tool>".into()
                    } else {
                        String::new()
                    };

                    checks.push(Check {
                        label: format!("Governance: {}", p.tool_name),
                        status,
                        detail: p.summary(),
                        fix,
                    });
                }
            }
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
            let url =
                zp_net::peer_url_with_path("127.0.0.1", port, "/api/v1/security/policy-version");
            let client = reqwest::Client::new();
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    println!(
                        "Policy version: {}",
                        body["current_version"].as_str().unwrap_or("unknown")
                    );
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
            PolicyCmd::Set(_) => unreachable!(),  // handled above (async path)
            PolicyCmd::Show(_) => unreachable!(), // handled above (async path)
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

    // ── Approval surface — handled ahead of pipeline construction ────────
    //
    // Everything below this point unlocks the sovereign root:
    // `load_genesis_secret_composed()` prompts a hardware touch, to derive an
    // audit signer these three commands never use. `zp approval list` reads a
    // token file and issues an HTTP GET. It has no business asking the
    // operator to press a button.
    //
    // Observed 2026-07-31: `zp approval list` printed the Trezor banner, took
    // the touch, and *then* failed `session_stale` — the operator paid a
    // physical confirmation for a command that never reached the network.
    //
    // This is a P9 surface, which is why it matters past the annoyance. The
    // signature is the operator's act, so the queue of things awaiting it is
    // something they must be able to check freely and often. A queue that
    // costs a ceremony to read is a queue that stops being read, and an
    // unread approval queue is indistinguishable from no approval queue at
    // all — which is the exact failure the Regent's confabulated "it needs
    // your signature" was already simulating.
    //
    // `zp regent` sits above for the same reason; this is the second member
    // of a group that will keep growing. The general form — commands declaring
    // whether they need the sovereign root, rather than paying for it by
    // position in main() — is the right fix and is not this one.
    //
    // 2026-08-05: the group grew exactly as forecast. `zp correction` landed
    // after the note above was written, was never added to the early-exit set,
    // and inherited the defect by position — an operator checking or amending
    // the corrections that steer Regent's cognition paid a hardware touch per
    // invocation, for an audit signer none of those three verbs construct.
    //
    // Membership is now declared by `is_session_token_only` rather than by
    // where a block happens to sit in this function, and dispatch runs through
    // one arm instead of one block per command group. That does not reach the
    // full general form — every command declaring its own requirement — but it
    // removes the failure mode that produced this recurrence: a new verb can
    // no longer inherit the touch silently, because adding it to the session
    // surface means naming it in one predicate.
    if let Some(cmd) = &args.command {
        if is_session_token_only(cmd) {
            run_session_token_command(cmd).await?;
            std::process::exit(0);
        }
    }

    let config = PipelineConfig {
        // `OperatorIdentity::default()` sets `name: "ZeroPoint"` — the
        // substrate's own name, not the operator's. Using the default here
        // meant `zp chat` ran with no knowledge of who it served, while the
        // server (lib.rs, AppState::init) populated the same field from
        // `config.operator_name`. Two entry points, two identities, one field.
        //
        // Resolved toward the server's reading: `name` is the operator. See
        // PromptBuilder::system_prompt.
        operator_identity: OperatorIdentity {
            name: zp_config::ConfigResolver::resolve_standard_or_exit()
                .operator_name
                .value,
            base_prompt: OperatorIdentity::default().base_prompt,
        },
        trust_tier,
        data_dir: args.data_dir,
        mesh: mesh_config.clone(),
    };

    // Stage 3 (AUDIT-03): CLI owns the single AuditStore and hands it to
    // the pipeline. No second handle is ever opened for the same process.
    let audit_db = config.data_dir.join("audit.db");
    std::fs::create_dir_all(&config.data_dir).ok();

    // audit.db is created immediately below, under ~/ZeroPoint. Harden the
    // directory first (CROSS-USER-01) — this was previously an unnamed side
    // effect of `open_keyring()`, whose value went unused after the
    // composed-loader refactor.
    crate::commands::harden_zp_home().context("Failed to prepare the ZeroPoint home directory")?;
    // Derive the audit signer from the Genesis secret
    let genesis_secret = crate::commands::load_genesis_secret_composed()
        .context("Failed to load Genesis secret for audit signer")?;
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

    let audit_store = std::sync::Arc::new(std::sync::Mutex::new(
        zp_audit::AuditStore::open_signed(&audit_db, audit_signer)
            .map_err(|e| anyhow::anyhow!("audit store open: {}", e))?,
    ));
    let mut pipeline = Pipeline::new(config, audit_store.clone())?;

    // Populate the provider pool.
    //
    // HARNESS-SEAM-2026-08 S3: both entry points must behave identically. The
    // server wires this at AppState::init; without the same call here the CLI
    // holds a well-formed pipeline that cannot serve, and `zp` fails with
    // NoProvider while the server works — one substrate, two behaviours.
    //
    // Model election is read from zp-config (crossing C1, sole authority).
    // Providers route through the running server's proxy on cfg.port, so CLI
    // completions are receipted on the same terms as server completions.
    //
    // Unlike the server this is NOT boot-fatal, and the difference is principled
    // rather than a concession. The server exists to serve, so its process start
    // IS its point of use. The CLI's point of use is the verb: `zp keys`,
    // `zp verify` and `zp config` do not depend on inference, and killing them
    // over a model tag would be its own incoherence.
    //
    // §4 invariant — *no verb silently degrades*. That is satisfied by the
    // diagnostic living on PipelineError::NoProvider, which fires at the moment
    // a verb actually depends on the crossing. Warning here instead would print
    // noise on every invocation that does not care, and a warning nobody reads
    // is the silent failure wearing a hat.
    //
    // The signer derives from the same `genesis_secret` already loaded above
    // for the audit signer — one sovereign-root load, two domain-separated
    // subkeys, no second ceremony. `derive_gate_signer_seed` is the only
    // derivation permitted (the `no_inline_gate_signer_derivation` pin), and
    // the resulting kid matches the server's `expected_kid` by construction
    // because both sides derive from the same root.
    {
        let llm_cfg = zp_config::ConfigResolver::resolve_standard_or_exit();
        if llm_cfg.llm_enabled.value {
            let gate_seed = zp_keys::derive_gate_signer_seed(&genesis_secret);
            let signer: std::sync::Arc<dyn zp_core::provider::RequestSigner> =
                std::sync::Arc::new(zp_gate_envelope::GateRequestSigner::from_seed(&gate_seed));
            match pipeline
                .init_providers(
                    llm_cfg.port.value,
                    &llm_cfg.llm_provider.value,
                    &llm_cfg.llm_model.value,
                    &llm_cfg.llm_escalation_model.value,
                    llm_cfg.llm_supports_tools.value,
                    signer,
                )
                .await
            {
                Ok(n) => tracing::debug!(providers = n, "CLI provider pool ready"),
                // Deliberately not user-facing. The verb that depends on this
                // will say so, with the full diagnostic, at the point of use.
                Err(e) => tracing::debug!(error = %e, "CLI provider pool unavailable"),
            }
        }
    }

    // Initialize execution engine — governed via HostContext so every sandboxed
    // file write and process spawn passes through the governance gate.
    {
        let exec_gate = std::sync::Arc::new(zp_policy::GovernanceGate::new("cli-exec"));
        let exec_host: std::sync::Arc<dyn zp_host::HostContext> = std::sync::Arc::new(
            zp_host::SystemHostContext::new(exec_gate, audit_store.clone()),
        );
        if let Err(e) = pipeline.init_execution_engine(exec_host).await {
            eprintln!("Warning: execution engine unavailable: {}", e);
        }
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
        // Session-token surface — handled above, before pipeline construction.
        Some(Commands::Officer(OfficerCmd::Sweep { .. })) => unreachable!(),
        Some(Commands::Vault(_)) => unreachable!(), // handled above
        Some(Commands::Substrate(SubstrateCmd::Validate { .. })) => unreachable!(),
        // Session-token surface — dispatched before pipeline construction so
        // it never unlocks the sovereign root. See `is_session_token_only`.
        Some(Commands::Approval(_)) => unreachable!(), // handled above
        Some(Commands::Precedent(_)) => unreachable!(), // handled above
        Some(Commands::Correction(_)) => unreachable!(), // handled above
        Some(Commands::Audit(AuditCmd::Verify)) => commands::audit_verify(&pipeline).await?,
        Some(Commands::Audit(AuditCmd::Log { limit, category })) => {
            commands::audit_log(&pipeline, limit, category.as_deref()).await?
        }
        Some(Commands::Audit(AuditCmd::Compact { retain })) => {
            commands::audit_compact(&pipeline, retain).await?
        }
        Some(Commands::Chain(ChainCmd::Story {
            limit,
            domain,
            summary,
            json,
        })) => commands::chain_story(&pipeline, limit, domain.as_deref(), summary, json).await?,
        Some(Commands::Guard { .. }) => unreachable!(), // handled above
        Some(Commands::Serve { .. }) => unreachable!(), // handled above
        Some(Commands::Restart { .. }) => unreachable!(), // handled above
        Some(Commands::Port(_)) => unreachable!(),      // handled above
        Some(Commands::Tool(_)) => unreachable!(),      // handled above
        Some(Commands::Secure { .. }) => unreachable!(), // handled above
        Some(Commands::Status) => unreachable!(),       // handled above
        Some(Commands::Policy(_)) => unreachable!(),    // handled above
        Some(Commands::Configure(_)) => unreachable!(), // handled above
        Some(Commands::Keychain(_)) => unreachable!(),  // handled above
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
        Some(Commands::Regent { .. }) => unreachable!(), // handled above
        Some(Commands::Doctor { .. }) => unreachable!(), // handled above
        Some(Commands::Ps { .. }) => unreachable!(),    // handled above
        #[cfg(feature = "embedded-server")]
        Some(Commands::Update { .. }) => unreachable!(), // handled above
        Some(Commands::Memory(_)) => unreachable!(),    // handled above
        Some(Commands::Discover { .. }) => unreachable!(), // handled above
        #[cfg(feature = "embedded-server")]
        Some(Commands::Canonicalize { .. }) => unreachable!(), // handled above
        Some(Commands::Adapt { .. }) => unreachable!(), // handled above
        Some(Commands::Pricing(_)) => unreachable!(),   // handled above
        Some(Commands::Scan { .. }) => unreachable!(),  // handled above
        Some(Commands::Operator(_)) => unreachable!(),  // handled above
        Some(Commands::Emit { .. }) => unreachable!(),  // handled above
        Some(Commands::Run { .. }) => unreachable!(),   // handled above
        Some(Commands::Model(_)) => unreachable!(),     // handled above
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
    let scan_path = scan_path.unwrap_or_else(|| zp_core::paths::user_home_or(".").join("projects"));

    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));

    // Filesystem scan.
    let scan = zp_engine::scan::scan_tools(&scan_path);

    // Chain query for canonicalized entities.
    #[cfg(feature = "embedded-server")]
    let bead_zeros = {
        use std::sync::{Arc, Mutex};
        match zp_audit::AuditStore::open_readonly(&db_path) {
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
            let reversibility = zp_engine::capability::reversibility_for_tool_dir(&t.path);
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

    let total_violations = report.tools_missing_canon.len()
        + report.providers_missing_canon.len()
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

// ── zp canonicalize ────────────────────────────────────────────────────────
// Emit a bead-zero CanonicalizedClaim receipt for a tool that has no canon
// (M11 remediation). This is the operator act of recognising a tool as a
// first-class entity. Idempotent: a second call is a no-op if the receipt
// already exists.
#[cfg(feature = "embedded-server")]
fn run_canonicalize(
    name: &str,
    path: Option<&std::path::Path>,
    audit_db: Option<&std::path::Path>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    use std::sync::{Arc, Mutex};

    let db_path = audit_db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));

    // Capture git commit from the tool's working directory (best-effort).
    let source_commit: Option<String> = path.and_then(|dir| {
        std::process::Command::new("git")
            .args([
                "-C",
                dir.to_str().unwrap_or("."),
                "rev-parse",
                "--short",
                "HEAD",
            ])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    });

    let initial_state = serde_json::json!({
        "tool": name,
        "path": path.map(|p| p.display().to_string()),
        "source_commit": source_commit,
        "canonicalized_at": chrono::Utc::now().to_rfc3339(),
    });

    // Open keyring → derive audit signer → open signed store.
    let keyring: zp_keys::Keyring = match crate::commands::open_keyring() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("\x1b[31merror\x1b[0m: keyring: {e}");
            return 1;
        }
    };
    let genesis_secret = match crate::commands::load_genesis_secret_composed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("\x1b[31merror\x1b[0m: genesis secret: {e}");
            return 1;
        }
    };
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

    let store = match zp_audit::AuditStore::open_signed(&db_path, audit_signer) {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => {
            eprintln!(
                "\x1b[31merror\x1b[0m: cannot open audit store at {}: {e}",
                db_path.display()
            );
            return 1;
        }
    };

    // Derive operator signing key for the receipt itself.
    let operator_secret: [u8; 32] = match crate::commands::load_operator_composed(&keyring) {
        Ok(k) => k.secret_key(),
        Err(e) => {
            eprintln!("\x1b[31merror\x1b[0m: operator key: {e}");
            return 1;
        }
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&operator_secret);

    let result = zp_server::tool_chain::emit_signed_canonicalization_receipt(
        &store,
        "tool",
        name,
        &initial_state,
        None, // tools are first-class entities — no parent
        "zp-cli:canonicalize",
        Some(&signing_key),
    );

    if json {
        println!(
            "{}",
            serde_json::json!({
                "tool": name,
                "entry_hash": result,
                "idempotent": result.is_none(),
            })
        );
    } else if let Some(hash) = result {
        println!(
            "✓ canonicalized  tool:{}  ({})",
            name,
            &hash[..hash.len().min(16)]
        );
    } else {
        println!("✓ already canonicalized  tool:{}", name);
    }

    0
}

fn run_adapt(
    tool: &str,
    path: Option<PathBuf>,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    use zp_engine::capability::reversibility_for_tool_dir;
    use zp_engine::tool_scan_security::{scan_path, ScanVerdict};

    let tool_path = path.unwrap_or_else(|| match zp_core::paths::user_home() {
        Ok(home) => home.join("projects").join(tool),
        Err(_) => PathBuf::from(tool),
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

        // audit.db lives under ~/ZeroPoint; harden the directory before
        // creating it (CROSS-USER-01).
        if let Err(e) = crate::commands::harden_zp_home() {
            eprintln!(
                "\x1b[31merror\x1b[0m: failed to prepare the ZeroPoint home directory: {}",
                e
            );
            return 2;
        }
        // Derive the audit signer from the Genesis secret
        let genesis_secret = match crate::commands::load_genesis_secret_composed() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("\x1b[31merror\x1b[0m: failed to load Genesis secret: {}", e);
                return 2;
            }
        };
        let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
        let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

        let store = match zp_audit::AuditStore::open_signed(&db_path, audit_signer) {
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
            Some(h) => println!(
                "\x1b[32m✓\x1b[0m emitted tool:adapted:{}  entry_hash={}",
                tool, h
            ),
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

// ── Foundation-relayed receipts on the local chain ─────────────────────────
//
// `zp verify --foundation-receipts [--operator <id>] [--json]`
//
// Reads the operator's local audit chain, filters to entries emitted by the
// foundation-relay path (AuditAction::SystemEvent with event prefix
// "foundation_relay:"), and cross-references each entry against the per-entry
// results returned by AuditStore::verify_with_report. Surfaces:
//
//   - count of foundation-relayed entries
//   - signature validity per entry (delegated to zp-audit's verifier)
//   - chain-link validity per entry
//   - human-readable details: timestamp, operator, claim, subject, edge pubkey id
//
// Distinct from `--foundation` (remote HTTPS verification against the worker).
// This is the verifier for what Cut B writes and Cut C forwards.

fn verify_foundation_receipts_local(
    audit_db: Option<&std::path::Path>,
    operator_filter: Option<&str>,
    emit_json: bool,
) -> i32 {
    use std::collections::HashMap;

    // Resolve the audit.db path (CLI flag wins; otherwise data_dir/audit.db).
    let db_path: std::path::PathBuf = match audit_db {
        Some(p) => p.to_path_buf(),
        None => match zp_core::paths::data_dir() {
            Ok(d) => d.join("audit.db"),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m  Could not resolve data dir: {}", e);
                return 2;
            }
        },
    };

    if !db_path.exists() {
        eprintln!("\x1b[31m✗\x1b[0m  No audit store at {}", db_path.display());
        eprintln!("    (Foundation-relay receipts land here after the worker forwards an intent.)");
        return 2;
    }

    let store = match zp_audit::AuditStore::open_readonly(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Failed to open audit store: {}", e);
            return 2;
        }
    };

    // Run the chain-wide verifier once; we'll index per-entry results below.
    let report = match store.verify_with_report() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Verification failed: {}", e);
            return 2;
        }
    };
    let entry_results: HashMap<String, &zp_audit::EntryVerification> = report
        .entries
        .iter()
        .map(|e| (e.entry_id.clone(), e))
        .collect();

    // Pull the chain entries themselves. Generous limit; foundation-relay
    // traffic is small in the current single-operator deployment.
    let entries = match store.export_chain(100_000) {
        Ok(es) => es,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Failed to export chain: {}", e);
            return 2;
        }
    };

    // Filter to foundation-relay entries, optionally scoped to an operator.
    let target_actor = operator_filter.map(|id| zp_core::ActorId::User(id.to_string()));
    let relayed: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.action,
                zp_core::AuditAction::SystemEvent { event } if event.starts_with("foundation_relay:")
            )
        })
        .filter(|e| match &target_actor {
            Some(want) => &e.actor == want,
            None => true,
        })
        .collect();

    // Aggregate per-entry verification outcomes.
    let mut sig_valid = 0usize;
    let mut sig_invalid = 0usize;
    let mut sig_missing = 0usize;
    let mut link_invalid = 0usize;
    let mut hash_invalid = 0usize;
    let mut anomalies: Vec<(String, String)> = Vec::new();

    for entry in &relayed {
        let id_str = entry.id.0.to_string();
        match entry_results.get(&id_str) {
            Some(v) => {
                match v.signature_valid {
                    Some(true) => sig_valid += 1,
                    Some(false) => {
                        sig_invalid += 1;
                        anomalies.push((id_str.clone(), "signature failed verification".into()));
                    }
                    None => sig_missing += 1,
                }
                if !v.chain_link_valid {
                    link_invalid += 1;
                    anomalies.push((id_str.clone(), "prev_hash linkage broken".into()));
                }
                if !v.hash_valid {
                    hash_invalid += 1;
                    anomalies.push((id_str.clone(), "entry_hash recomputation mismatch".into()));
                }
                if let Some(issue) = &v.issue {
                    anomalies.push((id_str.clone(), issue.clone()));
                }
            }
            None => {
                anomalies.push((id_str.clone(), "no per-entry verification record".into()));
            }
        }
    }

    if emit_json {
        let payload = serde_json::json!({
            "total": relayed.len(),
            "signatures_valid": sig_valid,
            "signatures_invalid": sig_invalid,
            "signatures_missing": sig_missing,
            "chain_links_invalid": link_invalid,
            "entry_hashes_invalid": hash_invalid,
            "operator_filter": operator_filter,
            "anomalies": anomalies
                .iter()
                .map(|(id, msg)| serde_json::json!({ "entry_id": id, "issue": msg }))
                .collect::<Vec<_>>(),
            "entries": relayed.iter().map(|e| relayed_entry_json(e)).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return if anomalies.is_empty() { 0 } else { 1 };
    }

    // Human-readable output.
    eprintln!();
    eprintln!("  \x1b[1mFoundation-Relay Receipts (local chain)\x1b[0m");
    eprintln!("  \x1b[2m─────────────────────────────────────────\x1b[0m");
    eprintln!("  Audit store:        {}", db_path.display());
    if let Some(op) = operator_filter {
        eprintln!("  Operator filter:    \x1b[36m{}\x1b[0m", op);
    }
    eprintln!("  Total entries:      {}", relayed.len());
    eprintln!(
        "  Signatures valid:   {}{}",
        sig_valid,
        if sig_invalid > 0 || sig_missing > 0 {
            format!(
                "  \x1b[31m(invalid: {}, missing: {})\x1b[0m",
                sig_invalid, sig_missing
            )
        } else {
            String::new()
        }
    );
    eprintln!(
        "  Chain links:        {}{}",
        relayed.len().saturating_sub(link_invalid),
        if link_invalid > 0 {
            format!("  \x1b[31m(broken: {})\x1b[0m", link_invalid)
        } else {
            String::new()
        }
    );

    if !relayed.is_empty() {
        eprintln!();
        eprintln!("  \x1b[1mEntries:\x1b[0m");
        for entry in &relayed {
            let claim = match &entry.action {
                zp_core::AuditAction::SystemEvent { event } => event
                    .strip_prefix("foundation_relay:")
                    .unwrap_or(event.as_str()),
                _ => "(unknown)",
            };
            let operator_str = match &entry.actor {
                zp_core::ActorId::User(s) => s.as_str(),
                zp_core::ActorId::Operator => "Operator",
                zp_core::ActorId::System(s) => s.as_str(),
                zp_core::ActorId::Skill(s) => s.as_str(),
            };
            let id_str = entry.id.0.to_string();
            let sig_indicator = match entry_results.get(&id_str).and_then(|v| v.signature_valid) {
                Some(true) => "\x1b[32m✓\x1b[0m",
                Some(false) => "\x1b[31m✗\x1b[0m",
                None => "\x1b[33m∅\x1b[0m",
            };
            let link_indicator = match entry_results.get(&id_str) {
                Some(v) if v.chain_link_valid => "\x1b[32m✓\x1b[0m",
                Some(_) => "\x1b[31m✗\x1b[0m",
                None => "?",
            };
            eprintln!(
                "    {} {} {} {}  {:.16}  {}",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                sig_indicator,
                link_indicator,
                operator_str,
                id_str,
                claim,
            );
        }
    }

    if !anomalies.is_empty() {
        eprintln!();
        eprintln!("  \x1b[31mAnomalies:\x1b[0m");
        for (id, msg) in &anomalies {
            eprintln!("    ✗ {:.16}  {}", id, msg);
        }
    }

    eprintln!();
    if anomalies.is_empty() {
        if relayed.is_empty() {
            eprintln!("  \x1b[2m(No foundation-relayed receipts on this chain yet.)\x1b[0m");
        } else {
            eprintln!("  \x1b[32m✓\x1b[0m  All foundation-relayed receipts verify cleanly.");
        }
        eprintln!();
        0
    } else {
        eprintln!("  \x1b[31mForeign-edge receipts have integrity issues.\x1b[0m");
        eprintln!("  Investigate the entries listed above before trusting this set.");
        eprintln!();
        1
    }
}

fn relayed_entry_json(entry: &zp_core::AuditEntry) -> serde_json::Value {
    let claim = match &entry.action {
        zp_core::AuditAction::SystemEvent { event } => event
            .strip_prefix("foundation_relay:")
            .unwrap_or(event.as_str()),
        _ => "",
    };
    let operator = match &entry.actor {
        zp_core::ActorId::User(s) => s.clone(),
        zp_core::ActorId::Operator => "Operator".to_string(),
        zp_core::ActorId::System(s) => s.clone(),
        zp_core::ActorId::Skill(s) => s.clone(),
    };
    serde_json::json!({
        "entry_id": entry.id.0.to_string(),
        "timestamp": entry.timestamp.to_rfc3339(),
        "operator": operator,
        "claim": claim,
        "receipt": entry.receipt.as_ref().and_then(|r| serde_json::to_value(r).ok()),
    })
}

// ── Foundation chain verification (zp verify --foundation) ───────────────────

/// Walk the foundation chain at `url` (default: https://zeropointfoundation.org),
/// verify every entry's hash linkage and Ed25519 signature, and print a report.
/// Returns the process exit code: 0 = pass, 1 = verification failure, 2 = error.
async fn verify_foundation_chain(url_override: Option<&str>, emit_json: bool) -> i32 {
    use zp_verify::foundation::{
        verify_foundation_chain as verify_chain, FoundationChainResponse, FoundationPubkeyResponse,
    };

    let base_url = url_override
        .unwrap_or("https://zeropointfoundation.org")
        .trim_end_matches('/');

    // Read the session token for Bearer auth (same path as local verify).
    let token = match (|| -> Option<String> {
        let path = zp_core::paths::session_path().ok()?;
        let data = std::fs::read_to_string(path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&data).ok()?;
        v["token"].as_str().map(|s| s.to_string())
    })() {
        Some(t) => t,
        None => {
            // The session file is written by the server, not by any CLI verb —
            // `SessionAuth::new` mints a token at startup and persists it. There
            // is no login command. This message named `zp session login` until
            // 2026-08-05, sending operators after a verb that has never existed.
            // Per *the chain configures the cockpit*: output must not name
            // affordances absent from the verb set.
            eprintln!("\x1b[31m✗\x1b[0m  No session token at ~/ZeroPoint/session.json");
            eprintln!("    The server mints this file at startup — start it with `zp serve`.");
            eprintln!("    If it is already running, the token has aged out past");
            eprintln!("    ZP_SESSION_MAX_AGE_SECONDS (default 8h); `zp restart` re-mints it.");
            return 2;
        }
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    // 1. Fetch the worker's public key + chain metadata.
    let pubkey_resp: FoundationPubkeyResponse = match client
        .get(format!("{}/api/v1/foundation/pubkey", base_url))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m  Failed to parse pubkey response: {}", e);
                return 2;
            }
        },
        Ok(r) => {
            eprintln!(
                "\x1b[31m✗\x1b[0m  /api/v1/foundation/pubkey returned HTTP {}",
                r.status()
            );
            return 2;
        }
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Cannot reach {}: {}", base_url, e);
            return 2;
        }
    };

    if pubkey_resp.schema_version != "foundation-canonical-v1" {
        eprintln!(
            "\x1b[31m✗\x1b[0m  Unsupported schema_version: {}",
            pubkey_resp.schema_version
        );
        return 2;
    }

    let chain_id = &pubkey_resp.chain_id;
    let pubkey_hex = &pubkey_resp.pubkey_hex;

    // 2. Page through the full chain.
    let mut all_entries = Vec::new();
    let mut from: u64 = 0;
    loop {
        let resp: FoundationChainResponse = match client
            .get(format!(
                "{}/api/v1/foundation/chain?from={}&limit=1000",
                base_url, from
            ))
            .bearer_auth(&token)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => match r.json().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("\x1b[31m✗\x1b[0m  Failed to parse chain response: {}", e);
                    return 2;
                }
            },
            Ok(r) => {
                eprintln!(
                    "\x1b[31m✗\x1b[0m  /api/v1/foundation/chain returned HTTP {}",
                    r.status()
                );
                return 2;
            }
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m  Chain fetch failed: {}", e);
                return 2;
            }
        };

        all_entries.extend(resp.entries);
        match resp.next_from {
            Some(next) => from = next,
            None => break,
        }
    }

    // 3. Run the verifier.
    let report = verify_chain(&all_entries, chain_id, pubkey_hex);

    // 4. Emit report.
    if emit_json {
        let out = serde_json::json!({
            "source": "foundation",
            "chain_id": chain_id,
            "schema_version": pubkey_resp.schema_version,
            "passed": report.passed,
            "entries_checked": report.entries_checked,
            "signature_checks": report.signature_checks,
            "signature_failures": report.signature_failures,
            "chain_head": report.chain_head,
            "findings": report.findings,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("\x1b[1mzp verify --foundation — Foundation Chain Attestation\x1b[0m");
        println!("  chain_id : {}", chain_id);
        println!("  url      : {}", base_url);
        println!();
        if report.passed {
            println!(
                "  \x1b[32m✓\x1b[0m  {} entries verified  |  {} signatures checked",
                report.entries_checked, report.signature_checks
            );
            if let Some(head) = &report.chain_head {
                println!("  head     : {}", head);
            }
        } else {
            println!(
                "  \x1b[31m✗\x1b[0m  VERIFICATION FAILED  ({} entries checked)",
                report.entries_checked
            );
            for f in &report.findings {
                let label = match f.severity {
                    zp_verify::FindingSeverity::Error => "\x1b[31mERROR\x1b[0m",
                    zp_verify::FindingSeverity::Warning => "\x1b[33mWARN \x1b[0m",
                    zp_verify::FindingSeverity::Info => "\x1b[36mINFO \x1b[0m",
                };
                println!(
                    "  [{}] [{}] {} — {}",
                    label, f.rule, f.entry_id, f.description
                );
            }
        }
        println!();
    }

    if report.passed {
        0
    } else {
        1
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// The default-audit-DB-path helper that used to live here (a thin Seam 19
// delegate to `zp_core::paths::audit_db_path`) is gone; only its doc comment
// survived, silently documenting whatever came next. Plain `//` so it cannot
// do that again.

/// Trigger a manual officer sweep via the running substrate's HTTP API.
///
/// Hits `GET /api/v1/officer/sweep?officer=<name>` with session-token auth.
/// Prints a formatted per-officer summary (or raw JSON with --json).
///
/// Composes with SUBSTRATE-COORDINATION-DISCIPLINE (autonomic vs deliberate
/// scope): manual sweep is a deliberate operator (or Regent) diagnostic
/// action outside routine coordination. Findings surface via the same
/// chain-anchored discipline the periodic sweep uses; this verb just fires
/// the sweep off-schedule.
async fn run_officer_sweep(name: Option<&str>, json_out: bool) -> anyhow::Result<()> {
    // Load config to get server port
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;

    // Read session token
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    // Officer names are known-safe (alphanumeric, no URL-special chars).
    // Reject anything else to avoid injection into the query string.
    let mut url = zp_net::peer_url_with_path("127.0.0.1", port, "/api/v1/officer/sweep");
    if let Some(n) = name {
        if !n.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(anyhow::anyhow!(
                "Officer name must be alphanumeric (got: {:?})",
                n
            ));
        }
        url.push_str(&format!("?officer={}", n));
    }

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate at 127.0.0.1:{}: {}", port, e))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

    if !status.is_success() {
        eprintln!("\x1b[31m✗\x1b[0m  Officer sweep failed: HTTP {}", status);
        eprintln!("    {}", body);
        std::process::exit(1);
    }

    if json_out {
        println!("{}", body);
        return Ok(());
    }

    // Formatted output
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response JSON: {}", e))?;

    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        std::process::exit(1);
    }

    println!();
    println!("\x1b[1mOfficer Sweep\x1b[0m");
    println!("\x1b[2m─────────────\x1b[0m");
    println!();

    let officers_run = v["officers_run"].as_array().cloned().unwrap_or_default();
    let officer_list = officers_run
        .iter()
        .filter_map(|o| o.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    println!("  Officers run:     {}", officer_list);
    println!("  Total findings:   {}", v["total_findings"]);
    println!(
        "  Posture:          {:.2}",
        v["posture_composite"].as_f64().unwrap_or(0.0)
    );
    println!(
        "  Completed at:     {}",
        v["completed_at"].as_str().unwrap_or("?")
    );
    println!();

    if let Some(per_officer) = v["per_officer"].as_array() {
        for entry in per_officer {
            let officer = entry["officer"].as_str().unwrap_or("?");
            let duration = entry["sweep_duration_ms"].as_u64().unwrap_or(0);
            let count = entry["finding_count"].as_u64().unwrap_or(0);
            println!(
                "  \x1b[1m{}\x1b[0m ({}ms) — {} finding(s)",
                officer, duration, count
            );

            if let Some(findings) = entry["findings"].as_array() {
                for f in findings {
                    let severity = f["severity"].as_str().unwrap_or("?");
                    let ftype = f["finding_type"].as_str().unwrap_or("?");
                    let summary = f["summary"].as_str().unwrap_or("");
                    let color = match severity {
                        "Critical" => "\x1b[31m",
                        "Error" => "\x1b[31m",
                        "Warning" => "\x1b[33m",
                        "Info" => "\x1b[2m",
                        _ => "\x1b[0m",
                    };
                    println!("    {}[{}]\x1b[0m {} — {}", color, severity, ftype, summary);
                }
            }
            println!();
        }
    }

    Ok(())
}

/// Probe a vault-stored provider credential via the running substrate.
///
/// Hits `POST /api/v1/vault/test/<provider>` with session-token auth. Prints
/// formatted result (or raw JSON with --json). Composes with aligned blindness:
/// credential value never appears in CLI output or logs — only structural
/// pass/fail indicators.
async fn run_vault_test(provider: &str, json_out: bool) -> anyhow::Result<()> {
    // Validate provider name (mirrors server-side validation)
    if !provider.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(anyhow::anyhow!(
            "Provider name must be alphanumeric (got: {:?})",
            provider
        ));
    }

    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;

    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path(
        "127.0.0.1",
        port,
        &format!("/api/v1/vault/test/{}", provider),
    );

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate at 127.0.0.1:{}: {}", port, e))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

    if json_out {
        println!("{}", body);
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response JSON: {} (body: {})", e, body))?;

    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        if let Some(known) = v.get("known_providers").and_then(|k| k.as_array()) {
            let names: Vec<&str> = known.iter().filter_map(|n| n.as_str()).collect();
            eprintln!("    Known providers: {}", names.join(", "));
        }
        std::process::exit(1);
    }

    let provider_display = v["provider"].as_str().unwrap_or(provider);
    let probe_status = v["probe_status"].as_str().unwrap_or("unknown");
    let http_status = v["http_status"].as_u64().unwrap_or(0);
    let latency = v["latency_ms"].as_u64().unwrap_or(0);

    let (icon, color) = match probe_status {
        "credential_valid" => ("✓", "\x1b[32m"),     // green
        "credential_rejected" => ("✗", "\x1b[31m"),  // red
        "credential_not_found" => ("?", "\x1b[33m"), // yellow
        "rate_limited" => ("~", "\x1b[33m"),         // yellow
        "provider_error" => ("!", "\x1b[33m"),       // yellow
        "network_error" => ("~", "\x1b[33m"),        // yellow
        _ => ("?", "\x1b[0m"),
    };

    println!();
    println!("\x1b[1mVault Probe\x1b[0m");
    println!("\x1b[2m───────────\x1b[0m");
    println!();
    println!("  Provider:      {}", provider_display);
    println!("  Probe status:  {}{} {}\x1b[0m", color, icon, probe_status);
    if http_status > 0 {
        println!("  HTTP status:   {}", http_status);
    }
    if latency > 0 {
        println!("  Latency:       {}ms", latency);
    }
    if let Some(detail) = v.get("detail").and_then(|d| d.as_str()) {
        println!("  Detail:        {}", detail);
    }
    if let Some(url) = v.get("probe_url").and_then(|u| u.as_str()) {
        println!("  Probe URL:     {}", url);
    }
    println!();

    // Exit non-zero when probe fails so scripts can react.
    if !matches!(probe_status, "credential_valid") || !status.is_success() {
        std::process::exit(2);
    }

    Ok(())
}

// ── Substrate validate verb (task #21, companion to task #20) ──────────────

/// Run substrate validation via server API and print structured results.
///
/// Hits `GET /api/v1/substrate/validate` with session-token auth. Server runs
/// the same `substrate_validate::run_substrate_validation` primitive Regent
/// invokes via her `substrate_validate` tool. Emits chain-anchored evidence
/// receipt server-side. Prints formatted result (or raw JSON with --json).
///
/// Operator direct-invocation path independent of Regent's dispatch — useful
/// when Regent drifts from the directive or when the operator wants a fresh
/// validation without initiating a Regent cycle.
async fn run_substrate_validate(json_out: bool) -> anyhow::Result<()> {
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;

    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path("127.0.0.1", port, "/api/v1/substrate/validate");

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate at 127.0.0.1:{}: {}", port, e))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

    if json_out {
        println!("{}", body);
        if !status.is_success() {
            std::process::exit(1);
        }
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response JSON: {} (body: {})", e, body))?;

    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  Substrate validation failed: {}", err);
        std::process::exit(1);
    }

    let posture = v["posture"].as_str().unwrap_or("unknown");
    let (posture_icon, posture_color) = match posture {
        "healthy" => ("✓", "\x1b[32m"),
        "degraded" => ("⚠", "\x1b[33m"),
        "critical" => ("✗", "\x1b[31m"),
        _ => ("?", "\x1b[0m"),
    };

    let validation_id = v["validation_id"].as_str().unwrap_or("?");
    let validated_at = v["validated_at"].as_str().unwrap_or("?");
    let evidence_hash = v["evidence_receipt"]["entry_hash"]
        .as_str()
        .unwrap_or("(none)");

    println!();
    println!("\x1b[1mSubstrate Validation\x1b[0m");
    println!("\x1b[2m────────────────────\x1b[0m");
    println!();
    println!(
        "  Posture:        {}{} {}\x1b[0m",
        posture_color, posture_icon, posture
    );
    println!("  Validation ID:  {}", validation_id);
    println!("  Timestamp:      {}", validated_at);
    if let Some(short) = evidence_hash.get(..evidence_hash.len().min(16)) {
        println!("  Evidence hash:  {}", short);
    }
    println!();

    // Per-check summary.
    if let Some(checks) = v["checks"].as_object() {
        println!("  \x1b[1mChecks:\x1b[0m");
        for (name, check) in checks {
            let check_status = check["status"].as_str().unwrap_or("unknown");
            let (icon, color) = match check_status {
                "ok" | "self_healed" => ("✓", "\x1b[32m"),
                "degraded" | "imbalanced" | "violations_present" | "unrecognized_present" => {
                    ("⚠", "\x1b[33m")
                }
                "critical" | "failed" | "inactive" | "missing" => ("✗", "\x1b[31m"),
                _ => ("?", "\x1b[0m"),
            };
            println!(
                "    {}{} {}\x1b[0m  {} — {}",
                color, icon, check_status, name, check_status
            );
        }
        println!();
    }

    // Notable gaps.
    if let Some(gaps) = v["notable_gaps"].as_array() {
        if !gaps.is_empty() {
            println!("  \x1b[1mNotable gaps:\x1b[0m");
            for gap in gaps {
                if let Some(s) = gap.as_str() {
                    println!("    • {}", s);
                }
            }
            println!();
        }
    }

    // Exit non-zero on critical posture so scripts can react.
    if posture == "critical" {
        std::process::exit(2);
    }

    Ok(())
}

// ── Standing correction verbs (P2.1) ─────────────────────────────────────────

/// Issue a standing correction — chain-anchored operator claim about Regent's
/// cognitive layer. Chain-anchors as `cognitive:correction:standing` event so
/// Regent's next perceive() cycle picks it up at Tier 1.
#[allow(clippy::too_many_arguments)]
async fn run_correction_issue(
    correction_type: Option<&str>,
    domain: Option<&str>,
    assertion: Option<&str>,
    negation: Option<&str>,
    context: Option<&str>,
    priority: u32,
    supersedes: &[String],
    json_source: Option<&str>,
    json_out: bool,
) -> anyhow::Result<()> {
    // Assemble the payload from either --json input or individual flags.
    let payload: serde_json::Value = if let Some(source) = json_source {
        let raw = if source == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(source)
                .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", source, e))?
        };
        serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("Failed to parse JSON payload: {}", e))?
    } else {
        let ct = correction_type.ok_or_else(|| {
            anyhow::anyhow!("--type is required (or use --json for full payload)")
        })?;
        let dom = domain.ok_or_else(|| anyhow::anyhow!("--domain is required (or use --json)"))?;
        let ass =
            assertion.ok_or_else(|| anyhow::anyhow!("--assertion is required (or use --json)"))?;

        let mut content = serde_json::json!({ "assertion": ass });
        if let Some(n) = negation {
            content["negation"] = serde_json::json!(n);
        }
        if let Some(c) = context {
            content["context"] = serde_json::json!(c);
        }

        let mut body = serde_json::json!({
            "correction_type": ct,
            "domain": dom,
            "content": content,
            "priority": priority,
        });
        // Omit when empty rather than sending `[]` — `supersedes` is
        // `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, and an
        // absent field round-trips identically to an empty one.
        if !supersedes.is_empty() {
            body["supersedes"] = serde_json::json!(supersedes);
        }
        body
    };

    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path("127.0.0.1", port, "/api/v1/correction/issue");
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate at 127.0.0.1:{}: {}", port, e))?;
    let status = resp.status();
    let body = resp.text().await?;

    if json_out {
        println!("{}", body);
        if !status.is_success() {
            std::process::exit(1);
        }
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {} (body: {})", e, body))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        if let Some(hint) = v.get("hint").and_then(|h| h.as_str()) {
            eprintln!("    {}", hint);
        }
        std::process::exit(1);
    }

    let cid = v["correction_id"].as_str().unwrap_or("?");
    let dom_out = v["domain"].as_str().unwrap_or("?");
    let pri = v["priority"].as_u64().unwrap_or(0);
    let hash = v["entry_hash"].as_str().unwrap_or("");
    println!();
    println!("\x1b[1;32m✓\x1b[0m  Standing correction issued");
    println!("    correction_id: {}", cid);
    println!("    domain:        {}", dom_out);
    println!("    priority:      {}", pri);
    if !hash.is_empty() {
        println!("    entry_hash:    {}", &hash[..hash.len().min(16)]);
    }
    println!();
    Ok(())
}

/// List all currently active standing corrections (priority-sorted descending).
/// Show the Regent's autonomous envelope.
///
/// Prints the whole call, never a summary of it — the same discipline the
/// approval queue follows. A precedent is standing permission for a specific
/// call, and an operator reviewing what they have permitted needs to read it
/// as precisely as they read it when they granted it.
async fn run_precedent_list(json_out: bool) -> anyhow::Result<()> {
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;
    let url = zp_net::peer_url_with_path("127.0.0.1", cfg.port.value, "/api/v1/regent/precedents");

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let body = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate: {}", e))?
        .text()
        .await?;

    if json_out {
        println!("{body}");
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {err}");
        std::process::exit(1);
    }

    let count = v["count"].as_u64().unwrap_or(0);
    println!();
    println!("\x1b[1mCalls the Regent may make without asking: {count}\x1b[0m");
    println!("\x1b[2m──────────────────────────────────────\x1b[0m");
    if count == 0 {
        println!("\x1b[2mNone. Every act requiring a signature will be proposed.\x1b[0m");
        println!();
        return Ok(());
    }
    if let Some(list) = v["precedents"].as_array() {
        for p in list {
            let sig = p["context_signature"].as_str().unwrap_or("?");
            let tool = p["tool"].as_str().unwrap_or("?");
            let granted_at = p["granted_at"].as_str().unwrap_or("?");
            let req = p["granted_request"].as_str().unwrap_or("?");
            println!("  \x1b[1m{sig}\x1b[0m");
            println!("    {tool}");
            println!(
                "    \x1b[2mfrom your signature on {} at {}\x1b[0m",
                &req[..12.min(req.len())],
                granted_at
            );
            println!();
        }
    }
    println!("\x1b[2mzp precedent revoke <signature> --reason \"...\"\x1b[0m");
    println!();
    Ok(())
}

/// Withdraw a precedent, narrowing the autonomous envelope.
async fn run_precedent_revoke(context_signature: &str, reason: Option<&str>) -> anyhow::Result<()> {
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;
    let url = zp_net::peer_url_with_path(
        "127.0.0.1",
        cfg.port.value,
        &format!("/api/v1/regent/precedents/{context_signature}/revoke"),
    );

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let body = client
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "reason": reason.unwrap_or("") }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate: {}", e))?
        .text()
        .await?;

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {err}");
        std::process::exit(1);
    }

    println!();
    println!(
        "\x1b[32m✓\x1b[0m  revoked — {} may no longer run unasked",
        v["tool"].as_str().unwrap_or("?")
    );
    println!(
        "    \x1b[2msignature {}\x1b[0m",
        v["context_signature"].as_str().unwrap_or("?")
    );
    println!(
        "    \x1b[2manchored {}\x1b[0m",
        v["anchored"].as_str().unwrap_or("?")
    );
    println!();
    Ok(())
}

/// List approval requests awaiting an operator answer.
async fn run_approval_list(json_out: bool) -> anyhow::Result<()> {
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path("127.0.0.1", port, "/api/v1/regent/approvals");
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate: {}", e))?;
    let body = resp.text().await?;

    if json_out {
        println!("{}", body);
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        std::process::exit(1);
    }

    let count = v["pending_count"].as_u64().unwrap_or(0);
    println!();
    println!(
        "\x1b[1mApproval requests awaiting an answer: {}\x1b[0m",
        count
    );
    println!("\x1b[2m──────────────────────────────────────\x1b[0m");
    if count == 0 {
        println!("\x1b[2mNothing pending.\x1b[0m");
        println!();
        return Ok(());
    }
    if let Some(list) = v["pending"].as_array() {
        for item in list {
            let hash = item["request_hash"].as_str().unwrap_or("?");
            let action = item["action"].as_str().unwrap_or("?");
            let at = item["requested_at"].as_str().unwrap_or("?");
            println!("  \x1b[1m{}\x1b[0m", &hash[..hash.len().min(12)]);
            println!("    {}", action);
            // What granting this actually runs. Never summarised — the
            // operator signs a call, and a summary of a call is not the call.
            match item.get("enactment") {
                Some(e) if !e.is_null() => {
                    let tool = e["tool"].as_str().unwrap_or("?");
                    let params = e
                        .get("params")
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "{}".to_string());
                    println!("    \x1b[1mwould run:\x1b[0m {} {}", tool, params);
                }
                _ => {
                    println!(
                        "    \x1b[2mno automatic action — approving records \
                         consent only\x1b[0m"
                    );
                }
            }
            println!("    \x1b[2masked {}\x1b[0m", at);
            println!();
        }
    }
    println!(
        "\x1b[2mzp approval grant <hash>   |   zp approval deny <hash> --reason \"...\"\x1b[0m"
    );
    println!();
    Ok(())
}

/// Record the operator's answer. `decision` is "granted" or "denied".
async fn run_approval_resolve(
    request_hash: &str,
    decision: &str,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path(
        "127.0.0.1",
        port,
        &format!("/api/v1/regent/approvals/{}/resolve", request_hash),
    );
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "decision": decision,
            "reason": reason.unwrap_or(""),
        }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate: {}", e))?;
    let body = resp.text().await?;

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        std::process::exit(1);
    }

    let mark = if decision == "granted" { "✓" } else { "•" };
    println!();
    println!(
        "\x1b[32m{}\x1b[0m  {} — {}",
        mark,
        decision,
        v["action"].as_str().unwrap_or("(request)")
    );
    println!(
        "    \x1b[2mrequest {}\x1b[0m",
        v["request_hash"].as_str().unwrap_or("?")
    );
    println!(
        "    \x1b[2manchored {}\x1b[0m",
        v["entry_hash"].as_str().unwrap_or("?")
    );
    println!();
    Ok(())
}

/// True when a command reaches the substrate over HTTP carrying the session
/// token, and signs nothing locally.
///
/// # Why this predicate exists
///
/// Pipeline construction in `main()` calls `load_genesis_secret_composed()` to
/// derive an audit signer. On a hardware-Genesis substrate that prompts a
/// physical touch. Commands listed here never construct that signer — they read
/// `~/ZeroPoint/session.json` and issue an HTTP request — so paying a ceremony
/// for them buys nothing.
///
/// It matters past the annoyance because these are P9 surfaces. The signature is
/// the operator's act, so the queue of things awaiting it, the precedents that
/// authorise autonomous action, and the corrections that steer Regent's
/// cognition must all be freely inspectable and freely amendable. A queue that
/// costs a ceremony to read is a queue that stops being read; a correction that
/// costs a ceremony to issue is a correction that does not get issued. And a
/// ceremony spent on a command that cannot complete — observed twice, 2026-07-31
/// and 2026-08-05, both times ending in `session_stale` or a connection failure
/// *after* the touch — teaches the operator that touches are cheap, which is the
/// opposite of what a signing ceremony exists to establish.
///
/// # Adding a command
///
/// Name it here. Membership is deliberately a declaration rather than a
/// consequence of where a block sits in `main()`: `zp correction` inherited the
/// touch for months precisely because it landed below pipeline construction and
/// nobody had to say otherwise.
///
/// The full general form — every command declaring its own sovereign-root
/// requirement, checked exhaustively so the compiler forces the decision — is
/// still the right destination. This is the narrower step that closes the
/// silent-inheritance path.
/// Membership was derived 2026-08-06 by scanning every caller of
/// `read_zp_session_token()` — the marker for "talks to the substrate over
/// HTTP" — rather than by noticing verbs one complaint at a time. Three
/// families beyond the original set turned up: substrate validation, officer
/// sweeps, and vault provider tests.
///
/// Note the granularity difference. `Precedent`, `Approval` and `Correction`
/// match whole-group because every subcommand in each is an HTTP call.
/// `Substrate`, `Officer` and `Vault` match per-subcommand: their siblings
/// (`vault list`, `vault revoke`, `officer list`) were not audited and may
/// legitimately need the root, so they keep the default path.
fn is_session_token_only(cmd: &Commands) -> bool {
    matches!(
        cmd,
        Commands::Precedent(_)
            | Commands::Approval(_)
            | Commands::Correction(_)
            | Commands::Substrate(SubstrateCmd::Validate { .. })
            | Commands::Officer(OfficerCmd::Sweep { .. })
            | Commands::Vault(VaultCmd::Test { .. })
            // The vault verbs proxy to the server, which already holds the
            // master key from the boot ceremony. Unlocking the sovereign root
            // again here would be a second root — see `singular_sovereign_root`.
            | Commands::Vault(VaultCmd::List { .. })
            | Commands::Vault(VaultCmd::Put { .. })
            | Commands::Vault(VaultCmd::Reveal { .. })
            | Commands::Vault(VaultCmd::Remove { .. })
    )
}

/// Dispatch a session-token-only command.
///
/// Callers must gate on [`is_session_token_only`] first. The two are a pair:
/// the predicate decides membership, this decides behaviour, and a command in
/// one but not the other is a bug the `unreachable!` arm will surface loudly
/// rather than silently falling through to a hardware prompt.
async fn run_session_token_command(cmd: &Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Precedent(PrecedentCmd::List { json }) => run_precedent_list(*json).await,
        Commands::Precedent(PrecedentCmd::Revoke {
            context_signature,
            reason,
        }) => run_precedent_revoke(context_signature, reason.as_deref()).await,

        Commands::Approval(ApprovalCmd::List { json }) => run_approval_list(*json).await,
        Commands::Approval(ApprovalCmd::Grant {
            request_hash,
            reason,
        }) => run_approval_resolve(request_hash, "granted", reason.as_deref()).await,
        Commands::Approval(ApprovalCmd::Deny {
            request_hash,
            reason,
        }) => run_approval_resolve(request_hash, "denied", reason.as_deref()).await,

        Commands::Correction(CorrectionCmd::Issue {
            correction_type,
            domain,
            assertion,
            negation,
            context,
            priority,
            supersedes,
            json,
            json_out,
        }) => {
            run_correction_issue(
                correction_type.as_deref(),
                domain.as_deref(),
                assertion.as_deref(),
                negation.as_deref(),
                context.as_deref(),
                *priority,
                supersedes,
                json.as_deref(),
                *json_out,
            )
            .await
        }
        Commands::Correction(CorrectionCmd::List { json }) => run_correction_list(*json).await,
        Commands::Correction(CorrectionCmd::Revoke {
            correction_id,
            json,
        }) => run_correction_revoke(correction_id, *json).await,

        Commands::Substrate(SubstrateCmd::Validate { json }) => run_substrate_validate(*json).await,
        Commands::Officer(OfficerCmd::Sweep { name, json }) => {
            run_officer_sweep(name.as_deref(), *json).await
        }
        Commands::Vault(VaultCmd::Test { provider, json }) => run_vault_test(provider, *json).await,
        Commands::Vault(VaultCmd::List { json }) => run_vault_list(*json).await,
        Commands::Vault(VaultCmd::Put { key, json }) => run_vault_put(key, *json).await,
        Commands::Vault(VaultCmd::Reveal { key, json }) => run_vault_reveal(key, *json).await,
        Commands::Vault(VaultCmd::Remove { key, json }) => run_vault_remove(key, *json).await,

        _ => unreachable!(
            "run_session_token_command reached for a command \
             is_session_token_only does not claim"
        ),
    }
}

/// Shared plumbing for the vault verbs: config, session token, HTTP client.
///
/// All four talk to the running server rather than opening the vault directly.
/// The server already holds the vault master key, derived once from the boot
/// ceremony; unlocking the sovereign root again in the CLI would be a second
/// root in all but name, which `singular_sovereign_root` forbids.
async fn vault_request(
    path: &str,
    method: reqwest::Method,
    body: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path("127.0.0.1", port, path);
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let mut req = client.request(method, &url).bearer_auth(&token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate at 127.0.0.1:{}: {}", port, e))?;
    let body = resp.text().await?;
    serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {} (body: {})", e, body))
}

/// Print `{"error": ..., "detail": ...}` if present. Returns true when handled.
fn vault_report_error(v: &serde_json::Value) -> bool {
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        if let Some(d) = v.get("detail").and_then(|d| d.as_str()) {
            eprintln!("    {}", d);
        }
        return true;
    }
    false
}

async fn run_vault_list(json_out: bool) -> anyhow::Result<()> {
    let v = vault_request("/api/v1/vault/list", reqwest::Method::GET, None).await?;
    if json_out {
        println!("{}", v);
        return Ok(());
    }
    if vault_report_error(&v) {
        std::process::exit(1);
    }
    let keys: Vec<&str> = v["keys"]
        .as_array()
        .map(|a| a.iter().filter_map(|k| k.as_str()).collect())
        .unwrap_or_default();
    let exists = v["exists"].as_bool().unwrap_or(false);
    let path = v["vault_path"].as_str().unwrap_or("?");

    println!();
    if keys.is_empty() {
        println!("Vault holds no secrets.");
        println!("─────────────────────────");
        // The distinction Steward's finding cannot make.
        if exists {
            println!("  The vault file exists and is empty.");
        } else {
            println!("  No vault file yet at {}", path);
            println!("  It is created the first time a secret is stored, not at startup.");
        }
    } else {
        println!("Vault secrets: {}", keys.len());
        println!("─────────────────────────");
        for k in &keys {
            println!("  {}", k);
        }
        println!();
        println!("  Key names only — values are never listed.");
    }
    println!();
    Ok(())
}

async fn run_vault_put(key: &str, json_out: bool) -> anyhow::Result<()> {
    use std::io::Read;
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    // Trailing newline from `echo` or a heredoc is almost never part of the
    // secret, and a stray one produces an auth failure that is very hard to
    // see. Strip it; a caller who needs the newline can use `--json` input.
    let value = value.trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() {
        anyhow::bail!(
            "No value on stdin. Pipe the secret in:\n    \
             printf %s \"$SECRET\" | zp vault put {}",
            key
        );
    }

    let v = vault_request(
        "/api/v1/vault/put",
        reqwest::Method::POST,
        Some(serde_json::json!({ "key": key, "value": value })),
    )
    .await?;
    if json_out {
        println!("{}", v);
        return Ok(());
    }
    if vault_report_error(&v) {
        std::process::exit(1);
    }
    println!("\x1b[32m✓\x1b[0m  Stored {} ({} bytes)", key, value.len());
    Ok(())
}

async fn run_vault_reveal(key: &str, json_out: bool) -> anyhow::Result<()> {
    let v = vault_request(
        "/api/v1/vault/reveal",
        reqwest::Method::POST,
        Some(serde_json::json!({ "key": key })),
    )
    .await?;
    if json_out {
        println!("{}", v);
        return Ok(());
    }
    if vault_report_error(&v) {
        std::process::exit(1);
    }
    // Bare value on stdout, no decoration — so it composes with a pipe without
    // the caller having to strip a banner.
    if let Some(s) = v["value"].as_str() {
        println!("{}", s);
    }
    Ok(())
}

async fn run_vault_remove(key: &str, json_out: bool) -> anyhow::Result<()> {
    let v = vault_request(
        "/api/v1/vault/remove",
        reqwest::Method::POST,
        Some(serde_json::json!({ "key": key })),
    )
    .await?;
    if json_out {
        println!("{}", v);
        return Ok(());
    }
    if vault_report_error(&v) {
        std::process::exit(1);
    }
    println!("\x1b[32m✓\x1b[0m  Removed {}", key);
    Ok(())
}

async fn run_correction_list(json_out: bool) -> anyhow::Result<()> {
    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path("127.0.0.1", port, "/api/v1/correction/list");
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate: {}", e))?;
    let body = resp.text().await?;

    if json_out {
        println!("{}", body);
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        std::process::exit(1);
    }

    let count = v["active_count"].as_u64().unwrap_or(0);
    println!();
    println!("\x1b[1mActive standing corrections: {}\x1b[0m", count);
    println!("\x1b[2m─────────────────────────────\x1b[0m");
    if let Some(list) = v["corrections"].as_array() {
        for item in list {
            let c = &item["correction"];
            let cid = c["correction_id"].as_str().unwrap_or("?");
            let dom = c["domain"].as_str().unwrap_or("?");
            let pri = c["priority"].as_u64().unwrap_or(0);
            let ct = c["correction_type"].as_str().unwrap_or("?");
            let ass = c["content"]["assertion"].as_str().unwrap_or("");
            println!();
            println!("  \x1b[36m{}\x1b[0m  [{}] pri={}", cid, ct, pri);
            println!("    domain: {}", dom);
            println!("    {}", ass);
            if let Some(neg) = c["content"]["negation"].as_str() {
                println!("    \x1b[33mnot:\x1b[0m {}", neg);
            }
        }
    }
    println!();
    Ok(())
}

/// Revoke a standing correction by id.
async fn run_correction_revoke(correction_id: &str, json_out: bool) -> anyhow::Result<()> {
    if correction_id.is_empty() {
        return Err(anyhow::anyhow!("correction_id must not be empty"));
    }

    let cfg = zp_config::resolve::ConfigResolver::resolve_standard()
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let port = cfg.port.value;
    let token = read_zp_session_token().map_err(|e| {
        anyhow::anyhow!("Cannot read session token (is the server running?): {}", e)
    })?;

    let url = zp_net::peer_url_with_path(
        "127.0.0.1",
        port,
        &format!("/api/v1/correction/revoke/{}", correction_id),
    );
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reach substrate: {}", e))?;
    let body = resp.text().await?;

    if json_out {
        println!("{}", body);
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        eprintln!("\x1b[31m✗\x1b[0m  {}", err);
        std::process::exit(1);
    }

    let cid = v["correction_id"].as_str().unwrap_or(correction_id);
    let revoked_at = v["revoked_at"].as_str().unwrap_or("");
    println!();
    println!("\x1b[1;33m✓\x1b[0m  Standing correction revoked");
    println!("    correction_id: {}", cid);
    if !revoked_at.is_empty() {
        println!("    revoked_at:    {}", revoked_at);
    }
    println!();
    Ok(())
}

/// Read the ZP session token from `~/ZeroPoint/session.json`.
///
/// Delegates to `read_zp_session_token_from` with the canonical path so the
/// path-resolution logic can be tested independently without touching the real
/// `~/ZeroPoint` directory.
fn read_zp_session_token() -> Result<String, Box<dyn std::error::Error>> {
    let path = zp_core::paths::session_path()?;
    read_zp_session_token_from(&path)
}

/// Extract the `token` field from a persisted session file at `path`.
///
/// Non-fatal by design: callers degrade gracefully when this returns `Err`
/// (server not running, file absent, stale schema). The file is written by
/// `zp serve` at startup and is Genesis-derived: its contents are a
/// signing-key projection, not a separate sovereign credential.
fn read_zp_session_token_from(
    path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let s = std::fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&s)?;
    v["token"]
        .as_str()
        .map(|t| t.to_string())
        .ok_or_else(|| "no token field in session.json".into())
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
                                let last =
                                    v.get("last_sequence").and_then(|x| x.as_i64()).unwrap_or(0);
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

    // audit.db lives under ~/ZeroPoint; harden the directory before creating it
    // (CROSS-USER-01). The Genesis secret itself comes from the sovereignty
    // provider, not the keyring.
    if let Err(e) = crate::commands::harden_zp_home() {
        eprintln!(
            "error: failed to prepare the ZeroPoint home directory: {}",
            e
        );
        return 2;
    }
    // Derive the audit signer from the Genesis secret
    let genesis_secret = match crate::commands::load_genesis_secret_composed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to load Genesis secret: {}", e);
            return 2;
        }
    };
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

    let mut store = match zp_audit::AuditStore::open_signed(&db_path, audit_signer) {
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
                                let last_seq =
                                    v.get("last_sequence").and_then(|x| x.as_i64()).unwrap_or(0);
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

/// Parse capability specs from a comma-separated string.
///
/// Supports two forms:
/// - `name` — Custom capability with Null parameters
/// - `name{json}` — Custom capability with parsed JSON parameters
///
/// Example: `governance:propose{"mutations":["restart_tool","set_port"]},tool:exec`
fn parse_capabilities(spec: &str) -> Vec<zp_core::GrantedCapability> {
    let mut caps = Vec::new();
    let mut remaining = spec;

    while !remaining.is_empty() {
        let remaining_trimmed = remaining.trim_start_matches(',').trim();
        if remaining_trimmed.is_empty() {
            break;
        }
        remaining = remaining_trimmed;

        // Find the capability name (up to '{' or ',' or end).
        if let Some(brace_pos) = remaining.find('{') {
            let comma_pos = remaining.find(',').unwrap_or(remaining.len());
            if brace_pos < comma_pos {
                // Has JSON parameters: name{...}
                let name = remaining[..brace_pos].trim().to_string();
                let rest = &remaining[brace_pos..];

                // Find matching closing brace (handle nested braces).
                let mut depth = 0i32;
                let mut end = 0;
                for (i, ch) in rest.char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if end > 0 {
                    let json_str = &rest[..end];
                    let parameters = serde_json::from_str(json_str).unwrap_or_else(|_| {
                        eprintln!(
                            "warning: invalid JSON in capability '{}': {}, using Null",
                            name, json_str
                        );
                        serde_json::Value::Null
                    });
                    caps.push(zp_core::GrantedCapability::Custom { name, parameters });
                    remaining = &rest[end..];
                } else {
                    // Unmatched brace — treat rest as name
                    let name = remaining.trim().to_string();
                    caps.push(zp_core::GrantedCapability::Custom {
                        name,
                        parameters: serde_json::Value::Null,
                    });
                    break;
                }
            } else {
                // Comma comes before brace — plain name
                let name = remaining[..comma_pos].trim().to_string();
                if !name.is_empty() {
                    caps.push(zp_core::GrantedCapability::Custom {
                        name,
                        parameters: serde_json::Value::Null,
                    });
                }
                remaining = &remaining[comma_pos..];
            }
        } else if let Some(comma_pos) = remaining.find(',') {
            let name = remaining[..comma_pos].trim().to_string();
            if !name.is_empty() {
                caps.push(zp_core::GrantedCapability::Custom {
                    name,
                    parameters: serde_json::Value::Null,
                });
            }
            remaining = &remaining[comma_pos..];
        } else {
            // Last capability, no comma
            let name = remaining.trim().to_string();
            if !name.is_empty() {
                caps.push(zp_core::GrantedCapability::Custom {
                    name,
                    parameters: serde_json::Value::Null,
                });
            }
            break;
        }
    }

    caps
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
    // When Some, the new grant's `renews` field is set to this prior grant id,
    // making smooth renewal a first-class continuity relation in the chain.
    renews_id: Option<String>,
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
    let (subject_pk_hex, generated_secret_hex): (String, Option<String>) = match subject_public_key
    {
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
    let extra_capability_names: Vec<String> =
        caps.iter().skip(1).map(|c| c.name().into()).collect();

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
    // Attach the prior-grant back-reference for smooth renewals. When
    // `renews_id` is Some, this is a renewal; the chain receipt will carry
    // `renews: <prior_grant_id>` so the continuity is structurally visible.
    if let Some(ref prior_id) = renews_id {
        grant.renews = Some(prior_id.clone());
    }

    // M4-3 issuance validation on the CLI path.
    //
    // Until now `zp delegate` built a standing grant and wrote it straight to
    // the chain with no issuance validation at all, so the SSRF self-grant
    // protection `grant_handler` applies (`zp-server/src/lib.rs`, "M4-3:
    // Validate issuance") did not cover this path. The hole was not that the
    // CLI is externally reachable — it is not — but that `validate_issuance`
    // is also where the non-delegable reserved set is refused, and that refusal
    // is capability-intrinsic: it must fire regardless of who is asking.
    //
    // Provenance is `UserAction`, which is the honest description of an
    // operator at a terminal and matches `EventOrigin::UserAction`'s own
    // documentation ("CLI, API with authenticated session"). That keeps
    // internal-only capabilities (ConfigChange, CredentialAccess) grantable
    // here, which is correct — the external-request restriction exists to stop
    // a fetch from granting itself credentials, not to stop the operator.
    grant = grant.with_issued_via(zp_core::EventProvenance::user_action("zp-cli-delegate"));
    if let Err(e) = grant.validate_issuance() {
        eprintln!("error: grant issuance rejected: {}", e);
        return 2;
    }

    // Emit the chain receipt.
    let db_path = audit_db.unwrap_or_else(|| data_dir.join("audit.db"));

    // audit.db lives under ~/ZeroPoint; harden the directory before creating it
    // (CROSS-USER-01). The Genesis secret itself comes from the sovereignty
    // provider, not the keyring.
    if let Err(e) = crate::commands::harden_zp_home() {
        eprintln!(
            "error: failed to prepare the ZeroPoint home directory: {}",
            e
        );
        return 2;
    }
    // Derive the audit signer from the Genesis secret
    let genesis_secret = match crate::commands::load_genesis_secret_composed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to load Genesis secret: {}", e);
            return 2;
        }
    };
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

    let store = match zp_audit::AuditStore::open_signed(&db_path, audit_signer) {
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
        zp_server::tool_chain::emit_delegation_receipt(&store, "granted", &grant, None);
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
                "renews": grant.renews,
                "entry_hash": entry_hash,
            })
        );
    } else {
        let title = if grant.renews.is_some() {
            "\x1b[1mzp delegate --renew — smooth renewal issued\x1b[0m"
        } else {
            "\x1b[1mzp delegate — standing delegation issued\x1b[0m"
        };
        println!("{}", title);
        println!("grant_id:           {}", grant.id);
        if let Some(ref prior) = grant.renews {
            println!("renews:             {}", prior);
        }
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
            println!(
                "expires_at:         {}",
                exp.format("%Y-%m-%d %H:%M:%S UTC")
            );
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
            println!("    max_consecutive_failures = 3");
            let grace_secs = lease_secs / 16 + 60;
            println!("    grace_period_secs = {}", grace_secs);
            println!("    failure_mode = \"{}\"", failure_mode);
        }
    }
    0
}

// ── Smooth renewal ────────────────────────────────────────────────────────────

/// Walk the reconstructed grant table and return the most-recent non-revoked,
/// non-expired active grant for `subject`. "Most-recent" is by `created_at`
/// descending; `reconstruct_grants` returns grants in ascending created_at
/// order, so we take the last non-revoked entry for this grantee.
fn find_most_recent_active_grant_for_subject(
    chain: &[zp_core::AuditEntry],
    subject: &str,
) -> Option<zp_core::CapabilityGrant> {
    let snaps = reconstruct_grants(chain);
    // `reconstruct_grants` returns sorted ascending by created_at; iterate
    // in reverse to find the most-recent non-revoked grant for this subject.
    snaps
        .into_iter()
        .rev()
        .find(|s| !s.revoked && s.grant.grantee == subject)
        .map(|s| s.grant)
}

/// `zp delegate --renew --subject <id> [--lease-duration <window>]`
///
/// Looks up the most-recent active grant for `subject`, copies its
/// capabilities and trust tier, and issues a fresh grant.  The caller may
/// supply `lease_duration_override` to use a different window; if it equals
/// the CLI default ("8h") and the prior grant had a lease policy, we use
/// the prior grant's lease duration instead so an unspecified flag does the
/// intuitive thing (copy the prior window).
fn run_delegate_renew(
    subject: &str,
    lease_duration_override: &str,
    subject_public_key: Option<&str>,
    audit_db: Option<PathBuf>,
    data_dir: &std::path::Path,
    json: bool,
) -> i32 {
    let db_path = audit_db
        .clone()
        .unwrap_or_else(|| data_dir.join("audit.db"));

    // Open the store read-only to look up the prior grant. We'll re-open
    // it (signed) inside run_delegate for the write.
    let ro_store = match zp_audit::AuditStore::open_readonly(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error opening audit store at {}: {}", db_path.display(), e);
            return 2;
        }
    };
    let chain = match ro_store.export_chain(i32::MAX as usize) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: export chain: {}", e);
            return 2;
        }
    };

    let prior = match find_most_recent_active_grant_for_subject(&chain, subject) {
        Some(g) => g,
        None => {
            eprintln!(
                "error: no active grant found for subject '{}'. \
                 Use `zp delegate --subject {} --capabilities <list>` to issue an initial grant.",
                subject, subject
            );
            return 2;
        }
    };

    // Extract capabilities from the prior grant. The primary capability is
    // the grant's main capability; extra ones are stored as `capability:*`
    // constraints.
    let mut all_caps: Vec<String> = vec![prior.capability.name().to_string()];
    for c in &prior.constraints {
        if let zp_core::Constraint::Custom { name, .. } = c {
            if let Some(rest) = name.strip_prefix("capability:") {
                all_caps.push(rest.to_string());
            }
        }
    }
    let capabilities_str = all_caps.join(",");

    // Trust tier from prior grant.
    let tier_ceiling = prior.trust_tier.as_u8();

    // Lease duration: use override unless it's the CLI default ("8h") AND
    // the prior grant has an explicit lease policy — in that case inherit
    // the prior window so an unspecified `--lease-duration` doesn't
    // silently change the window.
    let effective_lease: String = if let Some(ref policy) = prior.lease_policy {
        if lease_duration_override == "8h" {
            // Operator did not override; copy the prior lease duration.
            let prior_secs = policy.lease_duration.as_secs();
            format!("{}s", prior_secs)
        } else {
            lease_duration_override.to_string()
        }
    } else {
        lease_duration_override.to_string()
    };

    // Renewal interval: copy from prior grant if available.
    let renewal_interval: String = prior
        .lease_policy
        .as_ref()
        .map(|p| format!("{}s", p.renewal_interval.as_secs()))
        .unwrap_or_else(|| "2h".to_string());

    // Renewal authorities: reconstruct from prior grant's list.
    // `parse_authorities` encoded each handle as
    // `AuthorityRef::genesis("authority:<handle>")`, so we strip that prefix.
    let authority_handle = |a: &zp_core::AuthorityRef| -> String {
        let raw = a.capability_required.name();
        raw.strip_prefix("authority:").unwrap_or(raw).to_string()
    };
    let renewal_authorities: String = if prior.renewal_authorities.is_empty() {
        "genesis".to_string()
    } else {
        prior
            .renewal_authorities
            .iter()
            .map(&authority_handle)
            .collect::<Vec<_>>()
            .join(",")
    };

    // Revocable-by: copy from prior grant.
    let revocable_by: String = if prior.revocable_by.is_empty() {
        "genesis".to_string()
    } else {
        prior
            .revocable_by
            .iter()
            .map(&authority_handle)
            .collect::<Vec<_>>()
            .join(",")
    };

    // Redelegation depth: copy from prior grant.
    let max_depth: u32 = match &prior.redelegation {
        zp_core::RedelegationPolicy::Forbidden => 0,
        zp_core::RedelegationPolicy::Allowed { max_subtree_depth } => *max_subtree_depth,
        // RequiresApproval: sub-delegation is permitted but subject to operator
        // approval.  Use depth 1 as a conservative default; the operator can
        // override when they approve the grant.
        zp_core::RedelegationPolicy::RequiresApproval => 1,
    };

    // Failure mode: copy from prior grant.
    let failure_mode: String = prior
        .lease_policy
        .as_ref()
        .map(|p| match &p.failure_mode {
            zp_core::LeaseFailureMode::HaltOnExpiry => "halt".to_string(),
            zp_core::LeaseFailureMode::DegradeOnExpiry => "degrade".to_string(),
            zp_core::LeaseFailureMode::ContinueWithFlag => "flag".to_string(),
        })
        .unwrap_or_else(|| "halt".to_string());

    run_delegate(
        subject,
        &capabilities_str,
        tier_ceiling,
        &effective_lease,
        &renewal_interval,
        &renewal_authorities,
        &revocable_by,
        max_depth,
        &failure_mode,
        subject_public_key,
        Some(prior.id.clone()), // renews: this is the prior grant's id
        audit_db,
        data_dir,
        json,
    )
}

/// What `zp revoke` was pointed at.
///
/// `Grantee` is not sugar for "look up one id". An agent accumulates a live
/// grant per cockpit launch, so revoking it means revoking all of them; a
/// partial sweep leaves the agent authorised, which is the failure this
/// variant exists to make unreachable.
enum RevokeTarget {
    Grant(String),
    Grantee(String),
}

fn run_revoke(
    target: RevokeTarget,
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

    // audit.db lives under ~/ZeroPoint; harden the directory before creating it
    // (CROSS-USER-01). The Genesis secret itself comes from the sovereignty
    // provider, not the keyring.
    if let Err(e) = crate::commands::harden_zp_home() {
        eprintln!(
            "error: failed to prepare the ZeroPoint home directory: {}",
            e
        );
        return 2;
    }
    // Derive the audit signer from the Genesis secret
    let genesis_secret = match crate::commands::load_genesis_secret_composed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to load Genesis secret: {}", e);
            return 2;
        }
    };
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

    let store = match zp_audit::AuditStore::open_signed(&db_path, audit_signer) {
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
    // Resolve the target to (grant_id, subject) pairs. One for --grant-id;
    // every live grant for --grantee.
    let targets: Vec<(String, String)> = match &target {
        RevokeTarget::Grant(grant_id) => match find_subject_for_grant(&chain, grant_id) {
            Some(s) => vec![(grant_id.clone(), s)],
            None => {
                eprintln!(
                    "error: grant {} not found on chain — cannot revoke",
                    grant_id
                );
                return 2;
            }
        },
        RevokeTarget::Grantee(grantee) => {
            // Already-revoked grants are skipped rather than re-revoked: the
            // chain records revocation as permanent, and a second claim
            // against the same id would be a second irreversible act with no
            // effect. Skipping keeps the sweep idempotent.
            let live: Vec<(String, String)> = reconstruct_grants(&chain)
                .into_iter()
                .filter(|s| !s.revoked && s.grant.grantee == *grantee)
                .map(|s| (s.grant.id.clone(), s.grant.grantee.clone()))
                .collect();
            if live.is_empty() {
                eprintln!(
                    "error: no live grants for grantee {} — nothing to revoke",
                    grantee
                );
                return 2;
            }
            live
        }
    };

    // Revoke every resolved grant. A failure part-way through leaves earlier
    // revocations standing — they are chain entries and cannot be rolled
    // back — so the count of what succeeded is reported, not just the failure.
    let mut revoked: Vec<(String, String, String)> = Vec::new();
    for (grant_id, target_subject) in &targets {
        let claim = zp_core::RevocationClaim::new(
            grant_id,
            "genesis".to_string(),
            zp_core::AuthorityRef::genesis("revocation_authority"),
            cascade_policy,
            revocation_reason.clone(),
        );

        #[cfg(feature = "embedded-server")]
        let entry_hash =
            zp_server::tool_chain::emit_revocation_receipt(&store, target_subject, &claim);
        #[cfg(not(feature = "embedded-server"))]
        let entry_hash: Option<String> = {
            eprintln!("error: zp revoke requires the 'embedded-server' feature");
            return 2;
        };

        match entry_hash {
            Some(h) => revoked.push((claim.revocation_id.clone(), grant_id.clone(), h)),
            None => {
                eprintln!(
                    "error: failed to append revocation receipt for {} ({} of {} succeeded)",
                    grant_id,
                    revoked.len(),
                    targets.len()
                );
                return 2;
            }
        }
    }

    let target_subject = targets[0].1.clone();
    let (claim_id, grant_id, entry_hash) = revoked[0].clone();
    let claim_cascade = format!("{:?}", cascade_policy);
    let claim_reason = format!("{:?}", revocation_reason);

    if json {
        // `revocations` is always present, including for the single-grant
        // case, so a consumer never has to branch on which flag was used.
        // The flat fields describe the first revocation and are kept for
        // compatibility with callers written against the one-grant shape.
        println!(
            "{}",
            serde_json::json!({
                "revocation_id": claim_id,
                "target_grant_id": grant_id,
                "subject": target_subject,
                "cascade": claim_cascade,
                "reason": claim_reason,
                "entry_hash": entry_hash,
                "revoked_count": revoked.len(),
                "revocations": revoked
                    .iter()
                    .map(|(rid, gid, hash)| serde_json::json!({
                        "revocation_id": rid,
                        "target_grant_id": gid,
                        "entry_hash": hash,
                    }))
                    .collect::<Vec<_>>(),
            })
        );
    } else if revoked.len() == 1 {
        println!("\x1b[1mzp revoke — grant revoked\x1b[0m");
        println!("revocation_id:      {}", claim_id);
        println!("target_grant_id:    {}", grant_id);
        println!("subject:            {}", target_subject);
        println!("cascade:            {}", claim_cascade);
        println!("reason:             {}", claim_reason);
        println!("entry_hash:         {}", short_hash(&entry_hash));
        println!("\x1b[32m✓\x1b[0m revoked");
    } else {
        println!("\x1b[1mzp revoke — {} grants revoked\x1b[0m", revoked.len());
        println!("subject:            {}", target_subject);
        println!("cascade:            {}", claim_cascade);
        println!("reason:             {}", claim_reason);
        println!();
        for (rid, gid, hash) in &revoked {
            println!("  {}  {}  {}", gid, short_hash(hash), rid);
        }
        println!();
        println!(
            "\x1b[32m✓\x1b[0m {} grants revoked — the grantee holds none",
            revoked.len()
        );
    }
    0
}

/// Walk the chain to find the `subject` for which the named grant was issued.
fn find_subject_for_grant(chain: &[zp_core::AuditEntry], grant_id: &str) -> Option<String> {
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
    let store = match zp_audit::AuditStore::open_readonly(&db_path) {
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
            "{:<20} {:<14} {:<18} {:<6} {:<8} {:<6} status",
            "subject", "grant_id", "capability", "tier", "lease", "renew"
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
    use zp_engine::tool_scan_security::{scan_path, ScanVerdict};

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
            if let Ok(store) = zp_audit::AuditStore::open_readonly(&db_path) {
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
        (
            Vec::new(),
            format!("audit chain unavailable ({})", db_path.display()),
        )
    }

    #[cfg(not(feature = "embedded-server"))]
    {
        let _ = db_path;
        (
            Vec::new(),
            "no chain (built without embedded-server)".to_string(),
        )
    }
}

fn print_scan_text(r: &ScanReport) {
    use zp_engine::tool_scan_security::{ScanSeverity, ScanVerdict};

    println!("\x1b[1mzp scan — F3 MCP tool content falsifier\x1b[0m");
    println!("scan_path:   {}", r.scan_path);
    println!(
        "known_tools: {} ({})",
        r.known_tools.len(),
        r.known_tools_source
    );
    println!();

    if r.tools.is_empty() {
        println!("\x1b[33mwarn\x1b[0m: no tool definitions found at the supplied path");
        println!("       (looked for tool.json, mcp.json, manifest.json, *.tool.json, *.mcp.json,");
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
        println!("verdict:     \x1b[32mCLEAN\x1b[0m — every scanned tool passed every falsifier");
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
    let total = r.tools_missing_canon.len()
        + r.providers_missing_canon.len()
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

// ============================================================================
// zp pricing — freshness refresh and manual attestation
// ============================================================================

async fn run_pricing(cmd: &PricingCmd, data_dir: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context;
    use zp_audit::chain::UnsealedEntry;
    use zp_audit::AuditStore;
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
    use zp_engine::pricing::{refresh_hosts, PricingRefreshResult};
    use zp_engine::providers::{load_catalog, PricingSource};
    use zp_receipt::{ClaimMetadata, ReceiptBuilder, ReceiptType, Signer, Status};

    let (host_ids, audit_db, json, method) = match cmd {
        PricingCmd::Refresh {
            hosts,
            audit_db,
            json,
        } => {
            let ids = if hosts.is_empty() {
                vec!["abacus".to_string()]
            } else {
                hosts.clone()
            };
            (ids, audit_db, *json, "fetch")
        }
        PricingCmd::Attest {
            hosts,
            audit_db,
            json,
        } => (hosts.clone(), audit_db, *json, "manual"),
    };

    let db_path = audit_db
        .as_deref()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));

    let keyring = crate::commands::open_keyring().context("Failed to open keyring")?;
    let secret = crate::commands::load_operator_composed(&keyring)
        .context("No operator key available — run `zp init` first")?
        .secret_key();
    let signer = Signer::from_secret(&secret);

    let catalog = load_catalog();
    let result: PricingRefreshResult = if method == "fetch" {
        refresh_hosts(&catalog, &host_ids, |provider_id| {
            // Resolve API key from environment (e.g. ABACUS_API_KEY)
            let env_key = format!("{}_API_KEY", provider_id.to_uppercase());
            std::env::var(&env_key).unwrap_or_default()
        })
        .await
    } else {
        // Manual attestation: backfill timestamps, no API call
        let now = chrono::Utc::now().to_rfc3339();
        let mut updated = catalog.clone();
        for p in &mut updated {
            if host_ids.contains(&p.id) {
                p.pricing_verified_at = Some(now.clone());
                p.pricing_source = PricingSource::Manual;
            }
        }
        PricingRefreshResult {
            host_ids: host_ids.clone(),
            method: "manual".to_string(),
            source_urls: vec![],
            changed_count: 0,
            unchanged_count: host_ids.len() as u32,
            delta_lines: vec![],
            updated_profiles: updated,
        }
    };

    // Emit PricingRefreshClaim receipt
    let mut receipt = ReceiptBuilder::new(ReceiptType::PricingRefreshClaim, "zp-cli")
        .status(Status::Success)
        .claim_metadata(ClaimMetadata::PricingRefresh {
            host_ids: result.host_ids.clone(),
            method: result.method.clone(),
            source_urls: result.source_urls.clone(),
            changed_count: result.changed_count,
            unchanged_count: result.unchanged_count,
            delta_lines: result.delta_lines.clone(),
        })
        .finalize();
    signer.sign(&mut receipt);
    let receipt_id = receipt.id.clone();

    let genesis_secret = crate::commands::load_genesis_secret_composed()
        .context("Failed to load Genesis secret for audit signer")?;
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);
    let mut store =
        AuditStore::open_signed(&db_path, audit_signer).context("Failed to open audit store")?;
    let entry = UnsealedEntry::new(
        ActorId::System("zp-pricing".to_string()),
        AuditAction::SystemEvent {
            event: format!("pricing:refresh:{}", result.method),
        },
        ConversationId::new(),
        PolicyDecision::Allow { conditions: vec![] },
        "zp-pricing",
    )
    .with_receipt(receipt);
    store.append(entry).context("Failed to append to chain")?;

    // Persist refreshed entries to operator's providers.toml override
    persist_pricing_overrides(&host_ids, &result.updated_profiles);

    if json {
        println!(
            "{}",
            serde_json::json!({
                "receipt_id": receipt_id,
                "method": result.method,
                "host_ids": result.host_ids,
                "changed_count": result.changed_count,
                "unchanged_count": result.unchanged_count,
                "delta_lines": result.delta_lines,
                "source_urls": result.source_urls,
            })
        );
    } else {
        println!("\x1b[32m✓\x1b[0m  Pricing {} complete", result.method);
        println!("  Receipt: {}", receipt_id);
        println!(
            "  {} changed, {} unchanged",
            result.changed_count, result.unchanged_count
        );
        for line in &result.delta_lines {
            println!("  Δ {}", line);
        }
    }

    Ok(())
}

/// Write the refreshed provider entries into ~/ZeroPoint/config/providers.toml.
///
/// Merges with any existing override file: entries with matching IDs are
/// replaced; new entries are appended. Unknown existing entries are preserved.
fn persist_pricing_overrides(
    host_ids: &[String],
    updated_profiles: &[zp_engine::providers::ProviderProfile],
) {
    use zp_engine::providers::ProviderProfile;

    let Ok(zp_home) = zp_core::paths::home() else {
        return;
    };
    let override_path = zp_home.join("config").join("providers.toml");

    // Load existing override file, or start with an empty list
    let mut existing: Vec<ProviderProfile> = if override_path.exists() {
        #[derive(serde::Deserialize, Default)]
        struct Catalog {
            #[serde(default)]
            providers: Vec<ProviderProfile>,
        }
        std::fs::read_to_string(&override_path)
            .ok()
            .and_then(|s| toml::from_str::<Catalog>(&s).ok())
            .map(|c| c.providers)
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Merge: replace matching IDs, append new ones
    for updated in updated_profiles.iter().filter(|p| host_ids.contains(&p.id)) {
        if let Some(pos) = existing.iter().position(|p| p.id == updated.id) {
            existing[pos] = updated.clone();
        } else {
            existing.push(updated.clone());
        }
    }

    #[derive(serde::Serialize)]
    struct Catalog {
        providers: Vec<ProviderProfile>,
    }
    if let Ok(content) = toml::to_string_pretty(&Catalog {
        providers: existing,
    }) {
        std::fs::create_dir_all(override_path.parent().unwrap_or(std::path::Path::new("."))).ok();
        std::fs::write(&override_path, content).ok();
    }
}

// ============================================================================
// Tests
// ============================================================================

// ============================================================================
// zp policy set inference / zp policy show inference
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn run_policy_set_inference(
    backend: &str,
    strategy: &str,
    allowlist: &str,
    cost_cap_daily_usd: Option<f64>,
    schema_compat: &str,
    circuit_breaker_threshold: u32,
    audit_db: Option<&std::path::Path>,
    json: bool,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use zp_audit::chain::UnsealedEntry;
    use zp_audit::AuditStore;
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
    use zp_receipt::{ClaimMetadata, ClaimSemantics, ReceiptBuilder, ReceiptType, Signer, Status};

    // Parse comma-separated allowlist / schema_compat, stripping blanks
    let model_allowlist: Vec<String> = allowlist
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let schema_compat_vec: Vec<String> = schema_compat
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let circuit_breaker = if circuit_breaker_threshold == 0 {
        None
    } else {
        Some(circuit_breaker_threshold)
    };

    // Signing keys
    let keyring = crate::commands::open_keyring().context("Failed to open keyring")?;
    let secret = crate::commands::load_operator_composed(&keyring)
        .context("No operator key available — run `zp init` first")?
        .secret_key();
    let signer = Signer::from_secret(&secret);

    // Build and sign the receipt
    let mut receipt = ReceiptBuilder::new(ReceiptType::PreferenceLlmPolicySet, "zp-cli")
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorizationGrant)
        .claim_metadata(ClaimMetadata::PreferenceLlmPolicySet {
            backend_url: backend.to_string(),
            routing_strategy: strategy.to_string(),
            model_allowlist: model_allowlist.clone(),
            cost_cap_daily_usd,
            schema_compat: schema_compat_vec.clone(),
            circuit_breaker_threshold: circuit_breaker,
        })
        .finalize();
    signer.sign(&mut receipt);
    let receipt_id = receipt.id.clone();

    // Append to audit chain
    let db_path = audit_db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));

    let genesis_secret = crate::commands::load_genesis_secret_composed()
        .context("Failed to load Genesis secret for audit signer")?;
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);
    let mut store =
        AuditStore::open_signed(&db_path, audit_signer).context("Failed to open audit store")?;
    let entry = UnsealedEntry::new(
        ActorId::System("zp-policy".to_string()),
        AuditAction::SystemEvent {
            event: "preference:llm:policy:set".to_string(),
        },
        ConversationId::new(),
        PolicyDecision::Allow { conditions: vec![] },
        "zp-policy",
    )
    .with_receipt(receipt);
    store.append(entry).context("Failed to append to chain")?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "receipt_id": receipt_id,
                "backend_url": backend,
                "routing_strategy": strategy,
                "model_allowlist": model_allowlist,
                "cost_cap_daily_usd": cost_cap_daily_usd,
                "schema_compat": schema_compat_vec,
                "circuit_breaker_threshold": circuit_breaker,
            })
        );
    } else {
        println!("\x1b[32m✓\x1b[0m  Inference policy set");
        println!("  Receipt:  {}", receipt_id);
        println!("  Backend:  {}", backend);
        println!("  Strategy: {}", strategy);
        if model_allowlist.is_empty() {
            println!("  Allowlist: (unrestricted)");
        } else {
            println!("  Allowlist: {}", model_allowlist.join(", "));
        }
        if let Some(cap) = cost_cap_daily_usd {
            println!("  Cost cap: ${:.2}/day", cap);
        }
        if !schema_compat_vec.is_empty() {
            println!("  Schema compat: {}", schema_compat_vec.join(", "));
        }
        if let Some(threshold) = circuit_breaker {
            println!("  Circuit breaker: {} consecutive failures", threshold);
        }
        println!();
        println!("  Restart any governed tool reading this policy for it to take effect.");
    }

    Ok(())
}

async fn run_policy_show_inference(
    audit_db: Option<&std::path::Path>,
    json: bool,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use zp_audit::AuditStore;
    use zp_receipt::{ClaimMetadata, ReceiptType};

    let db_path = audit_db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));

    if !db_path.exists() {
        if json {
            println!("{{\"error\": \"no audit chain found\"}}");
        } else {
            eprintln!("No audit chain found. Run `zp policy set inference` first.");
        }
        return Ok(());
    }

    let store = AuditStore::open_readonly(&db_path).context("Failed to open audit store")?;
    let entries = store.export_chain(10_000).context("Failed to read chain")?;

    // Walk chain in reverse to find the most recent PreferenceLlmPolicySet
    let policy = entries.iter().rev().find_map(|e| {
        e.receipt.as_ref().and_then(|r| {
            if r.receipt_type == ReceiptType::PreferenceLlmPolicySet {
                r.claim_metadata.as_ref()
            } else {
                None
            }
        })
    });

    match policy {
        None => {
            if json {
                println!("{{\"error\": \"no preference:llm:policy:set receipt on chain\"}}");
            } else {
                eprintln!(
                    "No inference policy receipt on chain. Run `zp policy set inference` to set one."
                );
            }
        }
        Some(ClaimMetadata::PreferenceLlmPolicySet {
            backend_url,
            routing_strategy,
            model_allowlist,
            cost_cap_daily_usd,
            schema_compat,
            circuit_breaker_threshold,
        }) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "backend_url": backend_url,
                        "routing_strategy": routing_strategy,
                        "model_allowlist": model_allowlist,
                        "cost_cap_daily_usd": cost_cap_daily_usd,
                        "schema_compat": schema_compat,
                        "circuit_breaker_threshold": circuit_breaker_threshold,
                    })
                );
            } else {
                println!("\x1b[1mCurrent inference policy\x1b[0m");
                println!("  Backend:   {}", backend_url);
                println!("  Strategy:  {}", routing_strategy);
                if model_allowlist.is_empty() {
                    println!("  Allowlist: (unrestricted)");
                } else {
                    println!("  Allowlist: {}", model_allowlist.join(", "));
                }
                if let Some(cap) = cost_cap_daily_usd {
                    println!("  Cost cap:  ${:.2}/day", cap);
                } else {
                    println!("  Cost cap:  (none)");
                }
                if schema_compat.is_empty() {
                    println!("  Schema compat: (none)");
                } else {
                    println!("  Schema compat: {}", schema_compat.join(", "));
                }
                if let Some(t) = circuit_breaker_threshold {
                    println!("  Circuit breaker: {} failures", t);
                }
            }
        }
        Some(_) => unreachable!("receipt_type filter guarantees PreferenceLlmPolicySet"),
    }

    Ok(())
}

// ============================================================================
// Model registry helpers
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn run_model_register(
    model_id: &str,
    provider: &str,
    provider_url: &str,
    context_window: u32,
    supports_tools: bool,
    schema_format_str: &str,
    input_cost_per_m: f64,
    output_cost_per_m: f64,
    max_output_tokens: u32,
    audit_db: Option<&std::path::Path>,
    json: bool,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use zp_audit::chain::UnsealedEntry;
    use zp_audit::AuditStore;
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
    use zp_receipt::{
        ClaimMetadata, ClaimSemantics, ReceiptBuilder, ReceiptType, SchemaFormat, Signer, Status,
    };

    let schema_format = match schema_format_str.to_lowercase().as_str() {
        "gemini" => SchemaFormat::Gemini,
        "other" => SchemaFormat::Other,
        _ => SchemaFormat::OpenAi,
    };

    let keyring = crate::commands::open_keyring().context("Failed to open keyring")?;
    let secret = crate::commands::load_operator_composed(&keyring)
        .context("No operator key available — run `zp init` first")?
        .secret_key();
    let signer = Signer::from_secret(&secret);

    let mut receipt = ReceiptBuilder::new(ReceiptType::ModelRegistered, "zp-model")
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::ModelRegistered {
            model_id: model_id.to_string(),
            provider: provider.to_string(),
            provider_url: provider_url.to_string(),
            context_window,
            supports_tools,
            schema_format,
            input_cost_per_m_usd: input_cost_per_m,
            output_cost_per_m_usd: output_cost_per_m,
            max_output_tokens,
        })
        .finalize();
    signer.sign(&mut receipt);
    let receipt_id = receipt.id.clone();

    let db_path = audit_db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));
    let genesis_secret = crate::commands::load_genesis_secret_composed()
        .context("Failed to load Genesis secret for audit signer")?;
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);
    let mut store =
        AuditStore::open_signed(&db_path, audit_signer).context("Failed to open audit store")?;
    let entry = UnsealedEntry::new(
        ActorId::System("zp-model".to_string()),
        AuditAction::SystemEvent {
            event: "model:registered".to_string(),
        },
        ConversationId::new(),
        PolicyDecision::Allow { conditions: vec![] },
        "zp-model",
    )
    .with_receipt(receipt);
    store.append(entry).context("Failed to append to chain")?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "receipt_id": receipt_id,
                "model_id": model_id,
                "provider": provider,
                "schema_format": schema_format_str,
            })
        );
    } else {
        println!("\x1b[32m✓\x1b[0m Model registered: \x1b[1m{model_id}\x1b[0m");
        println!("  Provider:       {provider}");
        println!("  Endpoint:       {provider_url}");
        println!("  Context window: {} tokens", context_window);
        println!("  Tool support:   {supports_tools}");
        println!("  Schema format:  {schema_format_str}");
        println!("  Pricing:        ${input_cost_per_m}/M in · ${output_cost_per_m}/M out");
        println!("  Max output:     {} tokens", max_output_tokens);
        println!("  Receipt:        {receipt_id}");
    }

    Ok(())
}

async fn run_model_list(
    audit_db: Option<&std::path::Path>,
    json: bool,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::collections::HashMap;
    use zp_audit::AuditStore;
    use zp_receipt::{ClaimMetadata, ReceiptType};

    let db_path = audit_db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));

    if !db_path.exists() {
        if json {
            println!("[]");
        } else {
            eprintln!("No audit chain found. Run `zp model register` to add models.");
        }
        return Ok(());
    }

    let store = AuditStore::open_readonly(&db_path).context("Failed to open audit store")?;
    let entries = store
        .export_chain(100_000)
        .context("Failed to read chain")?;

    // Collect the latest model:registered receipt per model_id
    let mut models: HashMap<String, serde_json::Value> = HashMap::new();

    for entry in &entries {
        let Some(receipt) = entry.receipt.as_ref() else {
            continue;
        };
        let Some(meta) = receipt.claim_metadata.as_ref() else {
            continue;
        };

        match (receipt.receipt_type, meta) {
            (
                ReceiptType::ModelRegistered,
                ClaimMetadata::ModelRegistered {
                    model_id,
                    provider,
                    provider_url,
                    context_window,
                    supports_tools,
                    schema_format,
                    input_cost_per_m_usd,
                    output_cost_per_m_usd,
                    max_output_tokens,
                },
            ) => {
                models.insert(
                    model_id.clone(),
                    serde_json::json!({
                        "model_id": model_id,
                        "provider": provider,
                        "provider_url": provider_url,
                        "context_window": context_window,
                        "supports_tools": supports_tools,
                        "schema_format": schema_format,
                        "input_cost_per_m_usd": input_cost_per_m_usd,
                        "output_cost_per_m_usd": output_cost_per_m_usd,
                        "max_output_tokens": max_output_tokens,
                        "receipt_id": receipt.id,
                    }),
                );
            }
            (
                ReceiptType::ModelCapabilityUpdated,
                ClaimMetadata::ModelCapabilityUpdated {
                    model_id,
                    field_updated,
                    new_value,
                    ..
                },
            ) => {
                if let Some(entry) = models.get_mut(model_id) {
                    // Patch the registered entry in-place so `list` always shows current state
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert(field_updated.clone(), new_value.clone());
                    }
                }
            }
            _ => {}
        }
    }

    if json {
        let list: Vec<_> = models.values().collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
    } else if models.is_empty() {
        println!("No models registered. Run `zp model register` to add one.");
    } else {
        println!("\x1b[1mRegistered models ({}):\x1b[0m\n", models.len());
        let mut sorted: Vec<_> = models.values().collect();
        sorted.sort_by(|a, b| {
            a["model_id"]
                .as_str()
                .unwrap_or("")
                .cmp(b["model_id"].as_str().unwrap_or(""))
        });
        for m in sorted {
            println!("  \x1b[1m{}\x1b[0m", m["model_id"].as_str().unwrap_or("?"));
            println!(
                "    Provider:  {} · {}",
                m["provider"].as_str().unwrap_or("?"),
                m["provider_url"].as_str().unwrap_or("?")
            );
            println!(
                "    Context:   {} tokens  max_out: {}",
                m["context_window"], m["max_output_tokens"]
            );
            println!(
                "    Tools:     {}  schema: {}",
                m["supports_tools"], m["schema_format"]
            );
            println!(
                "    Pricing:   ${}/M in · ${}/M out",
                m["input_cost_per_m_usd"], m["output_cost_per_m_usd"]
            );
            println!();
        }
    }

    Ok(())
}

async fn run_model_update(
    model_id: &str,
    field: &str,
    value_str: &str,
    reason: &str,
    audit_db: Option<&std::path::Path>,
    json: bool,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use zp_audit::chain::UnsealedEntry;
    use zp_audit::AuditStore;
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
    use zp_receipt::{ClaimMetadata, ClaimSemantics, ReceiptBuilder, ReceiptType, Signer, Status};

    let new_value: serde_json::Value =
        serde_json::from_str(value_str).context("--value must be valid JSON")?;

    let keyring = crate::commands::open_keyring().context("Failed to open keyring")?;
    let secret = crate::commands::load_operator_composed(&keyring)
        .context("No operator key available — run `zp init` first")?
        .secret_key();
    let signer = Signer::from_secret(&secret);

    let mut receipt = ReceiptBuilder::new(ReceiptType::ModelCapabilityUpdated, "zp-model")
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::ModelCapabilityUpdated {
            model_id: model_id.to_string(),
            field_updated: field.to_string(),
            new_value: new_value.clone(),
            reason: reason.to_string(),
        })
        .finalize();
    signer.sign(&mut receipt);
    let receipt_id = receipt.id.clone();

    let db_path = audit_db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));
    let genesis_secret = crate::commands::load_genesis_secret_composed()
        .context("Failed to load Genesis secret for audit signer")?;
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);
    let mut store =
        AuditStore::open_signed(&db_path, audit_signer).context("Failed to open audit store")?;
    let entry = UnsealedEntry::new(
        ActorId::System("zp-model".to_string()),
        AuditAction::SystemEvent {
            event: "model:capability:updated".to_string(),
        },
        ConversationId::new(),
        PolicyDecision::Allow { conditions: vec![] },
        "zp-model",
    )
    .with_receipt(receipt);
    store.append(entry).context("Failed to append to chain")?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "receipt_id": receipt_id,
                "model_id": model_id,
                "field_updated": field,
                "new_value": new_value,
                "reason": reason,
            })
        );
    } else {
        println!("\x1b[32m✓\x1b[0m Model updated: \x1b[1m{model_id}\x1b[0m");
        println!("  Field:   {field}");
        println!("  Value:   {new_value}");
        println!("  Reason:  {reason}");
        println!("  Receipt: {receipt_id}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read_zp_session_token_from;

    /// Verify that `resolve_tool_env` returns the expected env vars for `zp configure exec`.
    ///
    /// Sets up a vault with:
    ///   - a provider credential: openai/api_key = "sk-test-12345"
    ///   - a tool ref:           tools/test-tool/OPENAI_API_KEY → openai/api_key
    ///
    /// Then resolves the tool env and asserts OPENAI_API_KEY = "sk-test-12345".
    /// This is the same resolution path the Exec dispatch handler calls.
    #[test]
    fn test_configure_exec_env_resolution() {
        let master_key = [0x5a_u8; 32];
        let mut vault = zp_trust::vault::CredentialVault::new(&master_key);

        // Store the provider credential at the canonical providers/ path.
        vault
            .store("providers/openai/api_key", b"sk-test-12345")
            .unwrap();

        // Store a ref from the tool's env var to the provider credential.
        // store_tool_ref(tool, var, provider, field) writes
        //   tools/test-tool/OPENAI_API_KEY → providers/openai/api_key
        vault
            .store_tool_ref("test-tool", "OPENAI_API_KEY", "openai", "api_key")
            .unwrap();

        // Resolve — same call the Exec handler makes.
        let env_map = vault.resolve_tool_env("test-tool").unwrap();

        assert!(
            !env_map.is_empty(),
            "env map should not be empty for test-tool"
        );

        let raw = env_map
            .get("OPENAI_API_KEY")
            .expect("OPENAI_API_KEY must be present in resolved env");
        assert_eq!(
            std::str::from_utf8(raw).unwrap(),
            "sk-test-12345",
            "resolved value must match the vault credential"
        );

        // Confirm the resolved map can be converted to String for injection.
        let as_str = std::str::from_utf8(raw).unwrap();
        assert_eq!(as_str.len(), 13, "key should be 13 chars");

        // Confirm unknown tool returns an empty map (not an error).
        let empty = vault.resolve_tool_env("no-such-tool").unwrap();
        assert!(empty.is_empty(), "unknown tool should yield empty map");
    }

    /// read_zp_session_token_from returns the token from a well-formed session file.
    #[test]
    fn test_read_zp_session_token_from_valid() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("session.json");
        let token = "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890";
        std::fs::write(
            &path,
            format!(
                r#"{{"token":"{}","created_at":1747234800,"key_fp":"deadbeef01020304","version":1}}"#,
                token
            ),
        )
        .unwrap();
        assert_eq!(read_zp_session_token_from(&path).unwrap(), token);
    }

    /// read_zp_session_token_from returns Err when the file does not exist.
    #[test]
    fn test_read_zp_session_token_from_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("no_such_session.json");
        assert!(
            read_zp_session_token_from(&path).is_err(),
            "absent file must return Err"
        );
    }

    /// read_zp_session_token_from returns Err when the token field is missing.
    #[test]
    fn test_read_zp_session_token_from_missing_field() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("session.json");
        std::fs::write(&path, r#"{"created_at":1747234800,"version":1}"#).unwrap();
        assert!(
            read_zp_session_token_from(&path).is_err(),
            "missing token field must return Err"
        );
    }

    /// read_zp_session_token_from returns Err on malformed JSON.
    #[test]
    fn test_read_zp_session_token_from_malformed() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("session.json");
        std::fs::write(&path, b"not json at all").unwrap();
        assert!(
            read_zp_session_token_from(&path).is_err(),
            "malformed JSON must return Err"
        );
    }

    #[test]
    fn parse_capabilities_plain_names() {
        let caps = super::parse_capabilities("tool:exec,tool:read");
        assert_eq!(caps.len(), 2);
        match &caps[0] {
            zp_core::GrantedCapability::Custom { name, parameters } => {
                assert_eq!(name, "tool:exec");
                assert!(parameters.is_null());
            }
            _ => panic!("expected Custom"),
        }
    }

    #[test]
    fn parse_capabilities_with_json_params() {
        let caps = super::parse_capabilities(
            r#"governance:propose{"mutations":["restart_tool","set_port"]}"#,
        );
        assert_eq!(caps.len(), 1);
        match &caps[0] {
            zp_core::GrantedCapability::Custom { name, parameters } => {
                assert_eq!(name, "governance:propose");
                let mutations = parameters.get("mutations").unwrap().as_array().unwrap();
                assert_eq!(mutations.len(), 2);
                assert_eq!(mutations[0].as_str().unwrap(), "restart_tool");
            }
            _ => panic!("expected Custom"),
        }
    }

    #[test]
    fn parse_capabilities_mixed() {
        let caps = super::parse_capabilities(r#"governance:propose{"mutations":["*"]},tool:exec"#);
        assert_eq!(caps.len(), 2);
        match &caps[0] {
            zp_core::GrantedCapability::Custom { name, parameters } => {
                assert_eq!(name, "governance:propose");
                assert!(!parameters.is_null());
            }
            _ => panic!("expected Custom"),
        }
        match &caps[1] {
            zp_core::GrantedCapability::Custom { name, parameters } => {
                assert_eq!(name, "tool:exec");
                assert!(parameters.is_null());
            }
            _ => panic!("expected Custom"),
        }
    }

    #[test]
    fn parse_capabilities_empty() {
        let caps = super::parse_capabilities("");
        assert!(caps.is_empty());
    }
}
