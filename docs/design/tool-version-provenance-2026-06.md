# Tool Version Provenance
**Date:** 2026-06-10  
**Status:** Shipped (this session)  
**Tier:** Sonnet — focused implementation, no architectural change

---

## What this is

Every tool launched via `zp configure exec` now has its version captured on the chain.
Before this session, ZeroPoint had no mechanism to record which version of a cockpit
tool (IronClaw, etc.) was running, no update ceremony, and no pre-launch integrity check.
The gap was identified during the IronClaw walkthrough: if a tool binary is replaced
out-of-band, the chain has no record of it.

This brief covers the full provenance arc: capture at launch, chain receipt, drift
detection, and operator-initiated update ceremony.

---

## What was built

### New types in `crates/zp-server/src/tool_ports.rs`

**`StoredLaunchCommand`** — extended with:
```rust
pub working_dir: Option<String>,  // CWD at spawn time (git + restart context)
```

**`ToolVersionInfo`** — new struct on `ToolBinding`:
```rust
pub struct ToolVersionInfo {
    pub source_commit: Option<String>,  // git rev-parse HEAD
    pub source_dirty: Option<bool>,     // git status --porcelain non-empty?
    pub binary_hash: Option<String>,    // blake3 hex of resolved binary
    pub binary_path: Option<String>,    // absolute path of binary launched
    pub captured_at: String,            // RFC3339 timestamp
}
```

All fields `Option` — capture is best-effort. A non-git tool yields `source_commit: None`;
a PATH-only binary that can't be resolved yields `binary_hash: None`. `captured_at` always set.

**`ToolBinding`** — extended with:
```rust
pub last_version: Option<ToolVersionInfo>,  // updated at each launch/update
```

### New functions in `tool_ports.rs`

| Function | What |
|----------|------|
| `capture_tool_version(working_dir, binary_path) -> ToolVersionInfo` | Runs git rev-parse + git status + blake3-hashes binary. Non-fatal on all errors. |
| `resolve_binary_path(command: &str) -> Option<PathBuf>` | Resolves a command name to an absolute path via PATH search (like `which`). |
| `PortRegistry::store_tool_version(tool, version)` | Persists `ToolVersionInfo` into the binding JSON. |
| `PortRegistry::store_launch_command(...)` | Signature extended — now also accepts `working_dir: Option<&str>`. |

### Chain receipt in `crates/zp-cli/src/emit.rs`

**`emit_tool_launch_receipt(tool_name, version, data_dir)`** — gated `#[cfg(feature = "embedded-server")]`.

Emits a `tool:launched:<name>` chain receipt with version payload in the `conditions`
slot of the `PolicyDecision`. Tries signed write first (derives audit key from keyring);
falls back to unsigned on keyring error. Never blocks the spawn path.

This is the chain entry that makes tool versioning governance rather than metadata —
every launch is a signed, chain-anchored event.

### `configure exec` spawn path (`crates/zp-cli/src/main.rs`)

After `child.spawn()` (Wire 1 and Wire 2 already existed):

**Wire 3 (new):** Captures CWD as `working_dir`, resolves `command[0]` to a binary
path via `resolve_binary_path`, calls `capture_tool_version`, prints a one-line
version summary for operator visibility, stores via `store_tool_version`, and emits
the chain receipt. All under `#[cfg(feature = "embedded-server")]`, consistent with
the existing wire 1 and wire 2.

Operator sees at launch:
```
spawned ironclaw (pid 12345)
  version  ironclaw @ abc123def012
  binary   deadbeef01234567…
  receipt  tool:launched:ironclaw
```

### `zp ps` version display

Substrate-managed section now shows `[commit:abc123*  bin:deadbeef…]` per tool
when `last_version` is present in the binding. Dim-gray rendering so it doesn't
compete with the primary attribution info.

### `zp update --name <tool>` — new subcommand

Gated `#[cfg(feature = "embedded-server")]`.

Workflow:
1. Fetch stored binding (working_dir, binary path, current pid, launch command).
2. Run `capture_tool_version` to get current state.
3. Compare vs. `last_version` — print diff if binary hash or commit changed.
4. Store new version via `store_tool_version`.
5. Emit `tool:launched:<name>` chain receipt (reuses launch receipt for now).
6. Unless `--record-only`: SIGTERM old pid, wait 800ms, SIGKILL if still alive, then
   re-exec `zp configure exec --name <tool> -- <stored_command>` from stored `working_dir`.

`--record-only` skips the stop+relaunch — useful when the binary was already replaced
by an external process (e.g., `cargo install`).

### `zp doctor` version drift check

After the Part VIII compute surface posture check, a new block:

- Lists all bindings with `last_version.binary_hash` set.
- Re-hashes the current binary at the stored path.
- Reports `warn` if any tool's current binary hash differs from the stored hash.
- Reports `info` if any tool has no recorded version yet.
- Reports `pass` if all recorded hashes match.

The drift check catches out-of-band binary replacements: a `cargo install --path .`
or a package manager update that replaced the binary without going through `zp update`.

---

## Design decisions

**Capture is best-effort, governance is chain-anchored.**  
The version fields are all `Option` — a missing binary or non-git directory doesn't fail
the spawn. But the chain receipt is always attempted. If genesis is on the chain, the
receipt is signed. If not (bootstrap mode), it falls back to unsigned. The chain record
is what gives the system governance character; the metadata is secondary.

**`working_dir` from CWD, not a flag.**  
At spawn time, `configure exec` captures `std::env::current_dir()`. Operators running
`zp configure exec` from the tool's source directory get git provenance automatically.
A future `--working-dir` flag would make this explicit; the current shape works for
the common case (cargo-based tools launched from their repo root).

**`zp update` relaunches via `zp configure exec`.**  
This means the relaunch goes through the full Wire 1+2+3 path: PID registered,
port reconciled, version re-captured, chain receipt emitted. The old process is stopped
first. This produces a clean chain record: one `tool:launched` receipt per launch,
with the updated commit and hash.

**Binary hash, not just commit.**  
A git commit tells you what source went in; a binary hash tells you what's actually
running. They can diverge: a `cargo build` with dirty flags, a cross-compiled binary
dropped in-place, or a package manager install that happened to match a commit.
Both are captured. The drift check compares binary hash first (most reliable for
detecting silent replacements), commit second.

**`zp update` receipt label reuses `tool:launched`.**  
A future `tool:updated:<name>` variant would cleanly distinguish initial launch from
operator-initiated update. Acceptable for now — the chain payload already contains
`captured_at`, so the distinction is available via timestamp delta.

---

## Files changed

- `crates/zp-server/src/tool_ports.rs` — `StoredLaunchCommand` + `ToolVersionInfo` +
  `ToolBinding.last_version` + `capture_tool_version` + `resolve_binary_path` +
  `store_tool_version` + signature update on `store_launch_command`
- `crates/zp-cli/src/emit.rs` — `emit_tool_launch_receipt` (cf-embedded-server)
- `crates/zp-cli/src/main.rs` — Wire 3 in spawn path, `zp ps` version display,
  `zp update` subcommand + handler + unreachable arm, `zp doctor` drift check

---

## Connections

- **Heuristic §9 (singular sovereign root)** — every signed launch receipt traces to one
  operator authentication ceremony (genesis key → audit signer → signed receipt).
- **Heuristic §12 (chain configures the cockpit)** — `zp ps` and `zp doctor` read version
  state from the chain-anchored binding, not from a separate config file.
- **Part VIII Stage 1 (compute surface)** — `zp ps` already shows what's running;
  now it also shows what version is running. Stage 3 (posture receipts on chain) will
  compose with this.
- **Architecture Principle 4 (every bit counts)** — no separate "version store"; version
  lives in `ToolBinding` alongside the port allocation, the PID, and the launch command.
  One structure, one persist path.
- **Docker displacement** (`docs/design/docker-displacement-2026-06.md`) — chain-anchored
  version provenance is one more piece that makes ZP the primary governance layer,
  reducing dependence on infrastructure-level controls.

---

## What is NOT built (follow-up work)

| Item | Notes |
|------|-------|
| `tool:updated:<name>` distinct receipt label | Distinguishes initial launch from operator update in the chain view |
| `--working-dir` flag on `configure exec` | Explicit working dir instead of CWD default |
| Pre-launch integrity check | Hash binary before spawn; block if mismatch vs. last authorized hash (requires operator-signed authorization) |
| Stage 3 posture receipts | `posture:surface:sampled` chain entries (Part VIII arc) |
| Cockpit projection of version state | `zp ps` shows version, but no chain receipt anchors the "current posture" — Stage 3 closes this |
