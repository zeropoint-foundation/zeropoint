# ADR: Transition Fragility Patterns

**Status:** Living document — updated as new patterns are discovered
**Created:** 2026-04-22
**Context:** Phase 0 greenfield exercise exposed that security mechanisms
designed for steady-state operation can lock out the operator during
legitimate lifecycle transitions (restart, migration, greenfield).

## The core insight

ZeroPoint's security surface was hardened during the ARTEMIS pentest
cycle (April 2026) to defend against external attackers. Those defenses
assumed the system was in a *running* state with valid auth, a live
chain, and an established genesis. But the operator regularly passes
through *transition* states — greenfield, restart, migration, key
rotation — where those same defenses become self-inflicted wounds.

**Every security mechanism must be tested against all lifecycle
transitions, not just steady-state operation.**

## Pattern catalog

### P1: Self-Inflicted Rate Limiting

**Discovered:** 2026-04-22, greenfield exercise
**Root cause:** Dashboard polling loop carries stale `zp_session` cookie
after server restart. Auth middleware treats stale cookies as
brute-force attempts, calling `record_failure()`. Eight parallel
endpoint polls × 12-second refresh interval exhausts the 10/min
rate-limit budget in seconds, returning 429 on every request.

**The pattern:** A security mechanism (rate limiting) designed to stop
attackers instead stops the operator because a legitimate client
artifact (its own cookie) looks like an attack under the mechanism's
threat model.

**Detection heuristic:** For every `record_failure()` / rate-limit call
site, ask: "Can the system's own client (dashboard, CLI, WebSocket)
trigger this path during a normal lifecycle transition?" If yes, the
mechanism needs a carve-out.

**Fix applied:**
- Server: stale cookie path no longer calls `record_failure()`;
  response clears the stale cookie via `Set-Cookie: Max-Age=0`
- Dashboard: `showStaleSessionBanner()` kills the polling loop
  (`stopAutoRefresh()`) and clears the cookie client-side

**Files:** `auth.rs` (stale-token branch), `dashboard.js`
(`showStaleSessionBanner`)

---

### P2: Concurrent State Fork

**Discovered:** 2026-04-06, Shannon pentest (AUDIT-01)
**Root cause:** Two `AuditStore` instances (AppState handle + Pipeline
handle) each held their own `Mutex`, allowing concurrent `append()`
calls to read the same `prev_hash` tip before either wrote. Result:
two entries claiming the same parent — a chain fork.

**The pattern:** A resource that must be single-writer (the audit chain
tip) is accessed through multiple handles, each with its own lock. The
lock protects the handle, not the resource.

**Detection heuristic:** For every `Arc<Mutex<T>>` or shared-state
wrapper, ask: "Is there exactly one instance of this in the process, or
could a second handle exist?" If the resource has an ordering invariant
(chain, sequence, counter), a second handle is a fork vector.

**Fix applied:**
- Single `Arc<Mutex<AuditStore>>` owned by `AppState`, shared via
  `Arc::clone`
- `BEGIN IMMEDIATE` SQLite transaction enclosing tip-read + entry-write
- Partial `UNIQUE(prev_hash)` index as backstop
- `UnsealedEntry` API — callers no longer compute hashes

**Files:** `store.rs`, `chain.rs`, `lib.rs` (AppState construction)

---

### P3: Serialization Drift

**Discovered:** 2026-04-07, first `zp verify` run (AUDIT-02)
**Root cause:** Actor identity was serialized via `Debug` format
(`Actor(...)`) in the hash computation but via `Display` or
`serde_json` elsewhere. The content hash computed at write time didn't
match the hash recomputed at verification time because the same data
produced different byte sequences through different format traits.

**The pattern:** A value participates in a cryptographic hash but can
be serialized through more than one code path. If the paths produce
different byte sequences for the same logical value, the hash becomes
non-reproducible.

**Detection heuristic:** For every field that enters a `blake3` (or
any hash) computation, ask: "Is there exactly one serialization path
between the in-memory value and the bytes that get hashed?" If `Debug`,
`Display`, and `serde::Serialize` all exist for the type, which one is
canonical? Is it documented and enforced?

**Fix applied:**
- Actor serialization pinned to `serde_json::to_string(&actor)`
- Round-trip test: serialize → hash → deserialize → re-hash → compare
- `seal_entry()` is the single canonical serialization path

**Files:** `chain.rs` (seal_entry, recompute_entry_hash), actor types

---

### P4: Pre-Genesis UX Incoherence

**Discovered:** 2026-04-22, greenfield exercise
**Root cause:** Dashboard renders "No Genesis established" when API
returns 401-missing (no auth, no genesis yet), but also renders the
same message when API returns 401-stale (old cookie, genesis may
exist). The operator can't distinguish "I need to onboard" from "I
need to reload."

**The pattern:** A UI interprets the absence of data as a specific
system state, when in reality the absence might be caused by an auth
failure, a network error, or a timing issue. The UI lies about what's
wrong.

**Detection heuristic:** For every "no data" / "unavailable" UI state,
ask: "Am I showing this because the resource doesn't exist, or because
I failed to fetch it?" If the answer is "I don't know," the UI needs
to distinguish the cases.

**Fix applied:**
- Server emits `X-Auth-Reason: stale|missing` header on 401
- Dashboard shows "Session expired — reload" for stale, "No Genesis"
  for missing
- Stale banner stops polling to prevent cascading 429s

**Files:** `auth.rs` (build_auth_response), `dashboard.js`
(fetchEndpoint, renderIdentity)

---

### P5: Provider Discovery Omission

**Discovered:** 2026-04-22, greenfield onboarding
**Status:** OPEN — under investigation
**Symptom:** Onboarding flow does not prompt for Anthropic API key
despite Anthropic being a primary provider.

**The pattern:** A discovery/enumeration mechanism silently omits an
expected member. No error, no warning — just absence. The operator
doesn't notice until much later.

**Detection heuristic:** For every enumeration (provider list, tool
scan, capability set), ask: "Is there a known-good expected set I can
diff against?" If the result is smaller than expected, emit a warning.

**Fix applied:** TBD — needs investigation of onboarding provider
enumeration logic.

**Files:** `onboard/mod.rs`, vault provider configuration

---

### P6: Stale WAL/SHM Files

**Discovered:** 2026-04-22, greenfield exercise
**Root cause:** Operator archived `audit.db` via `mv` but left behind
`audit.db-shm` (32KB) and `audit.db-wal` from the previous server's
WAL-mode connection. When the new server created a fresh `audit.db`,
SQLite attempted to reconcile the orphaned SHM file with the new
database, producing `SqliteFailure(SystemIoFailure, "disk I/O error")`
and crashing the server on startup.

**The pattern:** A file-level operation (archive, backup, migrate)
targets the primary file but leaves behind auxiliary files that the
subsystem treats as part of the same logical unit. The auxiliary files
become poison for the replacement.

**Detection heuristic:** For every file that is part of a multi-file
logical unit (SQLite WAL/SHM, RocksDB SST/MANIFEST, write-ahead logs),
ask: "If the primary file is replaced or removed, do the auxiliaries
get cleaned up too?" If the answer is "only if the operator remembers,"
the cleanup should be automated or documented.

**Fix applied:** Manual cleanup (`rm audit.db-shm audit.db-wal`).
Future work: `AuditStore::open` could detect orphaned WAL/SHM files
when creating a new database and remove them, or the greenfield
procedure should be a single CLI command (`zp audit reset`) that
handles all three files atomically.

**Files:** `store.rs` (AuditStore::open), operator runbook

---

### P7: Uninterruptible Shutdown

**Discovered:** 2026-04-23, operator couldn't kill `zp serve`
**Root cause:** The graceful shutdown handler consumes
`tokio::signal::ctrl_c()` once, then runs blocking tool cleanup
(synchronous `docker compose down`, `std::thread::sleep`, `kill -0`
loops) inside the async future. If any of those block — hung Docker
daemon, unresponsive process, stale PID — subsequent Ctrl+C signals
are swallowed because the Tokio signal handler was already consumed.
The operator has no escape hatch except `kill -9` from another terminal.

**The pattern:** A shutdown handler that consumes the interrupt signal
then performs blocking work without a fallback signal or timeout. The
operator loses control of the process at the moment they most need it.

**Detection heuristic:** For every shutdown/cleanup handler, ask:
"If this handler blocks forever, can the operator still force-exit?"
If the answer is no, the handler needs either a second signal watcher,
a timeout, or both.

**Fix applied:**
- Second `tokio::signal::ctrl_c()` watcher spawned after first signal;
  calls `std::process::exit(130)` on second Ctrl+C
- Entire cleanup loop wrapped in `tokio::time::timeout(10s, ...)`
- Cleanup runs on `spawn_blocking` instead of the async runtime
- Operator feedback: "Shutting down gracefully (Ctrl+C again to
  force-quit)..."

**Files:** `lib.rs` (shutdown handler near `with_graceful_shutdown`)

---

### P8: Orphaned Tool Processes After Hard Exit

**Discovered:** 2026-04-23, Docker container holding port 8080
**Root cause:** If the server dies hard (`kill -9`, panic, power loss),
the graceful shutdown handler never runs. Tool processes launched via
`docker compose up -d` or `cargo run --release` continue running as
orphans. On the next `zp serve`, the server starts fresh but the
orphaned tools hold ports, database locks, and PID files — causing
silent launch failures and port conflicts.

**The pattern:** A system that manages child processes only cleans them
up on graceful exit. Any non-graceful exit (crash, OOM kill, power
loss) leaves the children orphaned with no recovery mechanism.

**Detection heuristic:** For every process/container the system
spawns, ask: "If the parent crashes right now, what reconciles the
child on next startup?" If the answer is "nothing," the startup path
needs a reconciliation sweep.

**Fix applied:**
- On `zp serve` startup, before binding the listener port:
  1. Walk `~/ZeroPoint/pids/` — any tool PID file whose process is
     still alive gets killed via `kill_tool_process()` (SIGTERM →
     wait → SIGKILL). Stale PID files are removed regardless.
  2. Walk `~/projects/` — any tool directory with a compose file and
     running containers gets `docker compose down --remove-orphans`.
- This guarantees the server always starts from a clean slate,
  regardless of how the previous session ended.

**Files:** `lib.rs` (startup reconciliation block before listener bind)

---

### P9: Conventional Port Gravity

**Transition:** Tool launch after port allocation migration

**What happens:** The orchestrator allocates a high-range port (e.g.,
9100) and injects it via `.env.zp`, shell preamble, and `cmd.env()`.
But the tool's `.env.example` ships with conventional defaults (8080,
3000) and the tool's compiled-in fallback constants use those same
values. When any link in the three-layer injection chain fails — stale
binary, missing `.env.zp`, manual `cargo run` outside the orchestrator —
the tool silently falls back to conventional ports. It binds to 8080
(colliding with whatever was already there) and 3000 (colliding with the
orchestrator itself pre-migration).

**Detection heuristic:** A governed tool's default port constant matches
a conventional port number (80, 443, 3000, 5000, 8080, 8443, 9090).
The tool will work in isolation but collide under orchestration. This
pattern is invisible during development and only surfaces in production
multi-tool setups.

**Fix applied:**
- Updated IronClaw's compiled-in defaults from 8080/3000 to
  17772/17771 (`DEFAULT_GATEWAY_PORT`, HTTP fallback, `.env.example`)
- Updated all documentation references (NETWORK_SECURITY.md, setup
  wizard, channel config prompts)
- The principle: **a tool's standalone defaults should already be in the
  orchestrator's port range**, so falling through every env injection
  layer still lands on a non-colliding port.

**Files:** IronClaw `src/config/channels.rs`, `.env.example`,
`src/NETWORK_SECURITY.md`, `src/setup/wizard.rs`,
`src/setup/channels.rs`

---

## Scan checklist

When adding a new security mechanism or modifying an existing one, walk
through these transitions and verify the mechanism doesn't block the
operator:

1. **Greenfield** — No genesis, no vault, no audit chain, no session
   cookie. Can the operator reach the onboarding flow?

2. **Server restart** — Stale cookies, stale WebSocket connections,
   possibly stale CLI tokens. Does the dashboard recover gracefully?

3. **Key rotation** — Old signing key replaced. Do in-flight requests
   with the old key get rejected gracefully or do they trigger
   brute-force detection?

4. **Chain migration** — Old audit.db archived, fresh chain created.
   Do any subsystems cache chain state that would become stale?

5. **Vault re-keying** — Master key rotated. Do provider credentials
   and tool environments re-resolve, or does the system wedge?

6. **Network partition** — Fleet node loses contact with primary. Does
   the rate limiter on the primary block the node when it reconnects
   and replays buffered requests?

7. **Clock skew** — NTP correction jumps the system clock backward.
   Does M4 (timestamp monotonicity) flag legitimate entries as
   violations?

## Principles

These patterns share a common shape. Each one is a case where:

- A mechanism designed to protect against **external threats** fires
  against **internal operations**
- The mechanism has **no awareness of lifecycle state** — it doesn't
  know if the system is starting up, shutting down, or running
- The **failure mode is silent or misleading** — the operator sees
  symptoms (429, empty UI, missing data) but not causes

The fix is always the same: **make the mechanism lifecycle-aware**, or
at minimum, make the failure mode obvious and self-healing.
