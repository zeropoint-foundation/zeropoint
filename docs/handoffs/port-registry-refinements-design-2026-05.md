# Design — Port registry refinements (allocation/binding split, launch command, reconciliation)

*2026-05-20. Covers three findings from 2026-05-19 live verification.
No code ships in this round. Three focused commits follow.*

---

## Confirmed facts (investigated before designing)

| Question | Answer |
|----------|--------|
| Does `release()` remove the entry? | Yes — `map.remove(tool)` wipes the entire entry |
| `PortBindingCleared` receipt type? | Does not exist. Only `PortAllocated` + `PortReleased` |
| `rebuild_from_chain`? | Does not exist. Registry is index-backed; chain is append-only witness |
| `[launch]` section in manifest? | Yes — `LaunchSpec { command, args, working_dir, inherit_env }`. Optional; already parsed and validated |
| Manifest path in vault? | Yes — `zp_meta/tools/<name>/_manifest_path` (stored at configure time) |
| Does restart access the vault? | No — restart handler runs before the configure block; no vault open |
| Launch command in receipt? | Yes — `emit_launch_receipt` records `zp.launch.command` + `zp.launch.args` in the chain |
| Launch command in `ToolBinding`? | No — not stored in the registry |
| Exact lsof invocation | `lsof -p <pid> -i -n -P` — missing `-a` flag (AND) and `-sTCP:LISTEN` state filter |
| macOS lsof ORs criteria? | Yes — without `-a`, `-p` and `-i` are ORed, returning ALL internet connections |

---

## Finding 1 — Receipt taxonomy: allocation vs binding

### Root cause

`release()` collapses two distinct concepts into one operation:

```rust
// current code — removes the entire entry
pub fn release(&self, tool: &str, reason: ReleaseReason) {
    let mut map = self.bindings.lock().unwrap();
    if let Some(binding) = map.remove(tool) { // <-- wipes config + runtime state
        ...
        self.emit_release_receipt(tool, binding.port, binding.pid, reason);
        self.persist();
    }
}
```

A process death (kill, crash, sweeper) is a **runtime event** — it should clear the
binding's PID and observed port but leave the tool's allocation (port preference,
auth_token, port_var, extra_ports) intact for the next launch.

### Receipt taxonomy

Two receipt types cover the full lifecycle:

| Receipt | Trigger | Effect on registry | `PortReleased` sub-type |
|---------|---------|-------------------|------------------------|
| `PortAllocated` | `allocate_or_existing()` | Entry created / PID updated | — |
| `PortReleased` (binding_cleared) | process exit, crash, sweeper, kill | PID + actual_port cleared; allocation preserved | `"binding_cleared"` |
| `PortReleased` (allocation_removed) | explicit `deallocate()` — future verb | Entry removed entirely | `"allocation_removed"` |

Using a sub-type field in `zp.port.lifecycle.event_type` avoids adding new
`ReceiptType` variants (no changes to `zp-receipt`). The existing `PortReleased`
receipt carries a new extension field:

```json
"zp.port.lifecycle": {
  "tool": "ironclaw",
  "port": 9100,
  "pid": 60758,
  "reason": "operator_kill",
  "event_type": "binding_cleared"   // NEW — distinguishes from full deallocation
}
```

Legacy receipts without `event_type` are interpreted as `"binding_cleared"` for
backwards compatibility.

### Behavioral changes

**New method `clear_binding(tool, reason)`** on `PortRegistry`:
- Locks bindings map
- Finds entry; if absent, no-op
- Sets `binding.pid = None`
- Sets `binding.actual_port = None` (see §schema below)
- Emits `PortReleased` with `event_type = "binding_cleared"`
- Persists
- Does NOT call `map.remove()`

**Rename / repurpose `release()`:**

Keep `release()` as a public method but change its implementation to call
`clear_binding()`. This preserves the existing call signature at all call sites
without breakage:
- `zp restart --name`: calls `release(tool, OperatorKill)` → routes to `clear_binding()`
- `sweep_dead_pids()`: calls `release(tool, PidDead)` → routes to `clear_binding()`

**New `deallocate(tool)`** (for explicit deallocation — out of scope for this
work, but the method and receipt sub-type belong here):
- Calls `map.remove(tool)` (current `release` behavior)
- Emits `PortReleased` with `event_type = "allocation_removed"`
- Invoked by future `zp port deallocate <tool>` verb

### `ToolBinding` schema additions

Add two fields to separate allocation config from runtime observation:

```rust
pub struct ToolBinding {
    // ── Allocation (configuration — persists across restarts) ───────────
    pub tool: String,
    pub port: u16,              // allocated preference — ZP-managed, unchanged after reconcile
    pub port_var: String,
    pub auth_token: String,
    pub extra_ports: HashMap<String, u16>,  // allocated extras
    pub allocated_receipt_id: String,
    pub preference_source: PreferenceSource,

    // ── Runtime state (cleared on binding_cleared event) ────────────────
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub actual_port: Option<u16>,          // NEW: post-reconciliation observed port
    #[serde(default)]
    pub launch_command: Option<StoredLaunchCommand>, // NEW: see §Finding 2

    // ── Proxy ───────────────────────────────────────────────────────────
    #[serde(default)]
    pub proxy_port: Option<u16>,
}
```

`actual_port` replaces the current behavior where `reconcile_ports()` overwrites
`port` with the observed value. After this change:
- `port` = the ZP-managed preference (9100 for ironclaw) — stable
- `actual_port` = what the tool actually bound (3000) — transient
- `clear_binding()` zeroes `pid` + `actual_port`; `port` and config stay

`proxy_target()` updated:
```rust
pub fn proxy_target(&self) -> u16 {
    self.proxy_port
        .or(self.actual_port)   // reconciled actual beats allocation
        .unwrap_or(self.port)   // fall back to allocated if process not yet started
}
```

### `zp port list` output after changes

```
TOOL          ALLOCATED  ACTUAL    PID       PROXY
────────────────────────────────────────────────────────────
ironclaw      9100       3000      60758     —
hermes        9104       —         —         —   ← dead, allocation preserved
ember         9103       9103      77012     —   ← port match, no reconcile needed
```

- ALLOCATED = `binding.port` (always shown; preference even when dead)
- ACTUAL = `binding.actual_port` (shown only when process bound)
- PID = `binding.pid` (shown only when alive)

---

## Finding 2 — Launch command storage

### Root cause

`zp restart --name ironclaw` calls:
```rust
std::process::Command::new(&exe)
    .args(["configure", "exec", "--name", tool_name])
    .spawn()
```

No `-- <command>` trailer. The `ConfigureCmd::Exec` handler requires
`command` to be non-empty. Result: "No command specified."

The registry knows the tool's name and port but not its launch command.

### Design decision: store in ToolBinding

Three options evaluated:

| Option | Mechanism | Vault access needed at restart? | Freshness |
|--------|-----------|--------------------------------|-----------|
| A: receipt-anchored | chain query for last `tool:launch:<name>` event | No | Chain is truth |
| B: manifest-anchored | read `[launch]` from manifest via vault | Yes | Manifest is truth |
| C: registry-stored | add `launch_command` to `ToolBinding` | No | Stored at launch |

**Option C is chosen** for the restart path. Rationale:
- The restart handler runs before any vault open; adding vault access to restart
  requires non-trivial refactoring
- `ToolBinding` already holds the other restart-critical fields (PID, port, tool name)
- The chain receipt already records the launch command independently for audit

Option B (manifest-first) is the preferred *operator-intent* channel when the
manifest has a `[launch]` section. It becomes the **secondary source** in a
manifest-first / registry-fallback lookup (see below).

### `StoredLaunchCommand` schema

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLaunchCommand {
    pub command: String,
    pub args: Vec<String>,
}
```

Added to `ToolBinding` with `#[serde(default)]`:
```rust
#[serde(default)]
pub launch_command: Option<StoredLaunchCommand>,
```

### Write path: `configure exec`

After `child.spawn()` succeeds in the `configure exec` handler, call:
```rust
let _ = registry.store_launch_command(name, &command[0], &command[1..]);
```

New method on `PortRegistry`:
```rust
pub fn store_launch_command(&self, tool: &str, command: &str, args: &[String]) -> Result<(), RegistryError> {
    let mut map = self.bindings.lock().unwrap();
    match map.get_mut(tool) {
        Some(binding) => {
            binding.launch_command = Some(StoredLaunchCommand {
                command: command.to_string(),
                args: args.to_vec(),
            });
            drop(map);
            self.persist();
            Ok(())
        }
        None => Err(RegistryError::NotAssigned(tool.to_string())),
    }
}
```

This is called from the embedded-server spawn path, alongside `update_pid`.

### Read path: `zp restart --name`

The restart handler replaces its current static `configure exec --name <tool>`
invocation with a lookup:

```
1. Check binding.launch_command — if Some, use it
2. Fallback error: operator-actionable message
```

```rust
let launch_cmd = match &binding.launch_command {
    Some(lc) => lc.clone(),
    None => {
        eprintln!("\x1b[31m✗\x1b[0m  No launch command for '{}'.", tool_name);
        eprintln!("  Re-launch once with:");
        eprintln!("    zp configure exec --name {} -- <command> [args...]", tool_name);
        eprintln!("  The registry will capture the command for future restarts.");
        std::process::exit(1);
    }
};

// Re-launch via stored command
println!("\x1b[32m▶\x1b[0m  Re-launching {}...", tool_name);
let exe = std::env::current_exe().unwrap_or_else(|_| "zp".into());
let mut relaunch = std::process::Command::new(&exe);
relaunch.args(["configure", "exec", "--name", tool_name, "--"]);
relaunch.arg(&launch_cmd.command);
relaunch.args(&launch_cmd.args);
match relaunch.spawn() { ... }
```

**Manifest-first as a future enhancement:** If the manifest path is available via
vault lookup, the restart handler can check `[launch]` first and use the manifest's
declared command (operator's current intent). The registry-stored command then
becomes a fallback for tools without a manifest `[launch]` section. This is
deferred to a follow-up — it requires vault access at restart time.

---

## Finding 3 — lsof filter correctness

### Root cause

macOS `lsof` ORs selection criteria by default. Without the `-a` (AND) flag:

```sh
lsof -p <pid> -i -n -P
# Interpreted as: (all files for <pid>) OR (all internet connections from any process)
# Result: returns rapportd's LISTEN sockets, other processes' connections, etc.
```

This explains why port 49197 (rapportd's socket) appeared in ironclaw's results.

### Fix: add `-a` and restrict to TCP LISTEN state

```rust
std::process::Command::new("lsof")
    .args(["-a", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN", "-n", "-P"])
    .output()
```

Flags:
- `-a` — AND all conditions (not OR)
- `-iTCP` — TCP internet connections only (eliminates UDP noise)
- `-sTCP:LISTEN` — LISTEN state only (eliminates ESTABLISHED, TIME_WAIT, etc.)
- `-n` — no hostname resolution (faster, deterministic)
- `-P` — no port name resolution (get numeric ports, not "hbci" for 3000)

With these flags, lsof returns exactly the set of TCP ports the process is
actively listening on. No outbound connections, no other processes.

### Multi-port reconciliation

IronClaw binds three ports: 3000 (gateway/HTTP), 8090 (webhook), 50051 (gRPC).
The current `reconcile_ports(tool, pid, actual_ports: &[u16])` only reconciles
the primary port.

**Design for multi-port:**

The binding carries port_var assignments:
- Primary: `HTTP_PORT → 9100` (allocated)
- Extra: `GATEWAY_PORT → 9101` (allocated)

After launch, actual ports observed: `[3000, 8090, 50051]`.

Reconciliation must map each actual port to its env var role. Strategy:

1. Sort actual ports by magnitude (ascending) to get a stable ordering
2. Try to match each actual port to a declared port_var by position:
   - Primary actual (first = 3000) → `binding.port_var` (`HTTP_PORT`)
   - Secondary actual (8090) → `extra_ports.keys()[0]` (`GATEWAY_PORT`)
   - Unmatched actual (50051) → captured as `extra_ports["PORT_3"]` or logged as
     unmatched with a WARN

This positional matching is a heuristic — tools that bind ports in a different
order than declared will get mismatched labels. For IronClaw's specific case
(config-file ports that ignore env vars entirely), every actual port is unmatched
by value. The reconciliation captures them by position and warns.

**Revised `reconcile_ports` signature:**

```rust
/// Returns number of reconciliation receipt pairs emitted.
pub fn reconcile_ports(&self, tool: &str, pid: u32, actual_ports: &[u16]) -> usize
```

(Signature unchanged, implementation extended for multi-port.)

**Revised logic:**

```
For each (port_var, allocated_port) in [(primary_var, port), ...extra_ports]:
    if actual_ports contains allocated_port:
        // match — no receipt needed for this var
    else if actual_ports has an unmatched port at same position:
        // mismatch — emit release(allocated) + allocate(actual) for this var
        // update actual_port (primary) or actual_extra_ports[var] (secondary)
    else:
        // no actual port for this var (tool didn't bind it)
        // leave allocated; warn
```

**Schema addition for multi-port actuals:**

```rust
pub struct ToolBinding {
    // ... existing ...
    #[serde(default)]
    pub actual_port: Option<u16>,              // actual primary (post-reconcile)
    #[serde(default)]
    pub actual_extra_ports: HashMap<String, u16>, // actual extras (post-reconcile)
    // proxy_port stays separate (discovered via HTTP probe, not lsof)
}
```

`clear_binding()` zeroes both `actual_port` and `actual_extra_ports`.

**Receipt pair per mismatch:**

For IronClaw where HTTP_PORT=9100 (allocated) but actual=3000, and
GATEWAY_PORT=9101 (allocated) but actual=8090:

```
port:release  { tool: ironclaw, port: 9100, var: HTTP_PORT, event_type: binding_cleared }
port:allocate { tool: ironclaw, port: 3000, var: HTTP_PORT, preference_source: post_launch }

port:release  { tool: ironclaw, port: 9101, var: GATEWAY_PORT, event_type: binding_cleared }
port:allocate { tool: ironclaw, port: 8090, var: GATEWAY_PORT, preference_source: post_launch }

WARN: ironclaw bound port 50051 but no port_var maps to it. Recording in actual_extra_ports.
```

Return value from `reconcile_ports`: number of receipt PAIRS (each pair = release +
allocate). IronClaw returns 2 (2 mismatched vars). A tool that bound exactly
its allocated ports returns 0.

### Parser correctness (no change needed)

The existing `parse_lsof_listen_ports` correctly handles the `(LISTEN)` token:
```rust
if *tok == "(LISTEN)" && i > 0 {
    // take tokens[i-1] as address:port
```

With `-sTCP:LISTEN` in the lsof command, only LISTEN entries appear in the
output — the parser's `(LISTEN)` check becomes redundant but harmless. Keep
it as a belt-and-suspenders guard.

---

## Per-finding commit plan

### Commit 1 — allocation/binding split

**Scope:** `crates/zp-server/src/tool_ports.rs` only.

**Changes:**
1. Add `actual_port: Option<u16>` and `actual_extra_ports: HashMap<String, u16>` to `ToolBinding` (with `#[serde(default)]`)
2. Add `event_type` extension field to `emit_release_receipt` (new param or a wrapper method)
3. Add `clear_binding(tool, reason)` method: zeroes pid + actual fields, emits PortReleased(binding_cleared), persists, does NOT remove entry
4. Change `release()` to call `clear_binding()` internally — same call signature, changed behavior
5. Update `reconcile_ports()` to write `actual_port` / `actual_extra_ports` instead of overwriting `port`
6. Update `proxy_target()` to prefer `proxy_port` → `actual_port` → `port`
7. Add `deallocate(tool)` stub with `// TODO: zp port deallocate` comment — emits PortReleased(allocation_removed) and removes entry

**Tests:**
- `clear_binding_preserves_allocation` — allocate, clear_binding, assert entry still present with port/auth_token intact
- `clear_binding_zeroes_pid_and_actual` — allocate + set pid + set actual_port, clear_binding, assert pid=None + actual_port=None
- `release_now_preserves_allocation` — call release(), assert entry still present (changed behavior)
- `actual_port_reflected_in_proxy_target` — set actual_port=3000 on allocated=9100, assert proxy_target()=3000
- `proxy_target_falls_back_to_allocated` — no actual_port, no proxy_port, assert proxy_target()=allocated

**`zp port list` update:** Add ALLOCATED and ACTUAL columns (replace single PORT column).

**Verification:** `zp restart --name ironclaw` → entry still in `zp port list` after stop.

---

### Commit 2 — launch command storage

**Scope:** `crates/zp-server/src/tool_ports.rs` + `crates/zp-cli/src/main.rs`.

**Changes:**
1. Add `StoredLaunchCommand { command: String, args: Vec<String> }` to tool_ports.rs
2. Add `launch_command: Option<StoredLaunchCommand>` to `ToolBinding` (with `#[serde(default)]`)
3. Add `store_launch_command(tool, command, args)` method on `PortRegistry`
4. In `configure exec` spawn path (main.rs), call `registry.store_launch_command()` after `update_pid()`
5. In `zp restart --name` handler, replace the static `configure exec --name <tool>` call with a lookup that reads `binding.launch_command` and constructs the full command + error message when absent

**Tests (tool_ports.rs):**
- `store_launch_command_round_trips` — store, retrieve, assert command + args correct
- `store_launch_command_missing_tool_err` — tool not in registry → NotAssigned error
- `launch_command_survives_clear_binding` — store command, clear_binding, assert launch_command still present (it's allocation-side, not runtime-side)

**Tests (main.rs integration):**
- `test_restart_replays_stored_command` — doctest / manual verification step

**Verification:** after `zp configure exec --name ironclaw -- ironclaw`,
`zp restart --name ironclaw` succeeds end-to-end.

---

### Commit 3 — lsof filter correctness + multi-port reconciliation

**Scope:** `crates/zp-server/src/tool_ports.rs`.

**Changes:**
1. Fix `lsof_tcp_listen_ports` invocation: `lsof -a -p <pid> -iTCP -sTCP:LISTEN -n -P`
2. Update `reconcile_ports` for multi-port: iterate over all port_var/allocated pairs, emit per-var receipt pairs, write `actual_port` + `actual_extra_ports`, warn on unmatched actuals
3. Detect and log unmatched actual ports (bound by tool but not declared in any port_var)

**Tests:**
- `lsof_cmd_uses_and_flag` — (documentation test) verify the exact command constructed
- `reconcile_multi_port_all_mismatch` — 2 allocated vars, 2 different actuals, assert 4 receipts (2 pairs), both actual vars updated
- `reconcile_multi_port_partial_match` — 1 var matches, 1 doesn't, assert 2 receipts (1 pair)
- `reconcile_unmatched_actual_port` — tool binds port with no declared var, assert entry in actual_extra_ports + no receipt
- `parse_lsof_listen_ports_handles_ipv6` — ensure IPv6 address format `[::]:3000` is parsed correctly

**Verification:** launch IronClaw, run `zp port list` — ACTUAL column shows 3000 (not 49197).

---

## Edge cases

| Edge case | Treatment |
|-----------|-----------|
| Tool crashes before binding — lsof returns empty | `reconcile_ports` returns 0; pid already recorded; sweeper will call `clear_binding` on next tick |
| `clear_binding` called on tool with no entry | No-op, no error |
| Legacy `tool-ports.json` without `actual_port` / `launch_command` | `#[serde(default)]` handles transparently |
| `zp restart` when `launch_command` is None | Operator-actionable error with exact command to run once |
| Multi-port tool binds more ports than declared | Extra actuals go into `actual_extra_ports`; WARN logged; no receipt emitted |
| Multi-port tool binds fewer ports than declared | Missing vars stay with allocated port in the binding; no release receipt |
| Tool manifest has `[launch]` section — manifest-first lookup | Deferred. Current commit uses registry-stored command. Future: read manifest via vault at restart time |
| Old-format receipts without `event_type` field | Backwards-compatible: absent field treated as `"binding_cleared"` |
| `deallocate()` called on running tool | Warning logged; binding removed; PID liveness sweeper may emit stale events. Operator should kill first. |

---

## Out of scope (this work)

- `zp port deallocate <tool>` CLI verb (receipt type and `deallocate()` method designed here; verb deferred)
- Manifest-first launch command lookup (vault access at restart)
- Cross-machine port coordination
- Port preference editing without re-launch (`zp port reassign`)
- `zp doctor --repair-port-registry` (manual reconciliation verb)

---

## Connection to principles

- **Every bit counts** — `port` and `actual_port` are distinct concepts; collapsing them (current code) is the duplicate data path this principle flags
- **Signing is gravity** — the new receipt pair per reconciled port makes each reconciliation event individually auditable; the chain reflects what actually happened, not just that something changed
- **Store-and-forward is primary** — an allocation persists through process death; the registry's state survives outages and restarts; only explicit deallocation removes it

---

## Refs

- `crates/zp-server/src/tool_ports.rs` — PortRegistry implementation (current)
- `crates/zp-cli/src/main.rs` lines 1165–1233 — `zp restart --name` handler
- `crates/zp-cli/src/main.rs` lines 1658–1748 — `configure exec` spawn path
- `crates/zp-engine/src/capability.rs` lines 386–412 — `LaunchSpec` schema
- `crates/zp-receipt/src/types.rs` lines 576–609 — `PortAllocated`, `PortReleased` receipt types
- Parent design: `docs/handoffs/port-registry-canonical-path-design-2026-05.md`
- Launch wires: `docs/handoffs/port-registry-launch-wires-investigation-2026-05.md`
