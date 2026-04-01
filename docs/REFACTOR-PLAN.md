# ZeroPoint Architecture Refactor

## Problem Statement

The current dev cycle is broken. Every change — even a CSS tweak — requires a
full `cargo install` (~30–60s). The server shells out to the CLI binary for
configure, then parses stdout with regex. Two separate discovery engines exist
with different definitions of "ready." Stale binaries silently serve old code.
Zombie processes accumulate. The result: hours burned chasing phantom bugs that
are actually just stale builds.

## Current State (What's Wrong)

```
crates/zp-server/
  src/
    lib.rs           (1,543 lines — router + ALL handlers + asset resolution)
    onboard.rs       (2,263 lines — WebSocket + 11 action handlers)
    proxy.rs         (449 lines — fine, leave it)
    handlers.rs      (2 lines — unused stub)
    ...
  assets/
    onboard.html     (2,619 lines — CSS + HTML + JS, compiled via include_str!)
    dashboard.html   (519 lines)

crates/zp-cli/
  src/
    configure.rs     (2,139 lines — duplicate discovery + configure engine)
    main.rs          (677 lines)
    ...
```

Problems:
1. `include_str!` bakes HTML into binary — no hot reload without override dance
2. Server shells out to `zp configure auto` — parses stdout, loses type safety
3. Scan logic duplicated between onboard.rs and configure.rs
4. onboard.rs is a 2,263-line god file
5. onboard.html is a 2,619-line monolith (CSS + HTML + JS)
6. No process management (zombies, stale PIDs)

## Target State (What We Want)

```
crates/zp-engine/                    ← NEW shared library
  src/
    lib.rs                           (re-exports)
    scan.rs                          (tool discovery — single source of truth)
    configure.rs                     (configure engine — called as Rust fn)
    vault.rs                         (vault read/write/encrypt)
    providers.rs                     (provider catalog + detection)
    genesis.rs                       (genesis ceremony logic)

crates/zp-server/
  src/
    lib.rs                           (router only — thin)
    onboard/
      mod.rs                         (WebSocket handler + dispatcher)
      detect.rs                      (handle_detect, handle_detect_local_inference)
      genesis.rs                     (handle_genesis, handle_vault_check)
      inference.rs                   (handle_set_inference_posture, guidance)
      scan.rs                        (handle_scan — delegates to zp-engine)
      credentials.rs                 (handle_vault_store, handle_vault_import_all)
      configure.rs                   (handle_configure — calls engine directly)
      state.rs                       (OnboardState, from_filesystem)
    handlers.rs                      (non-onboard HTTP handlers)
    proxy.rs                         (unchanged)
  assets/
    onboard/
      onboard.html                   (HTML structure only)
      onboard.css                    (styles)
      onboard.js                     (all JS logic)
    dashboard.html

crates/zp-cli/
  src/
    main.rs                          (thin — delegates to zp-engine)
    configure.rs                     (CLI wrapper around zp-engine::configure)
```

## Phased Execution

### Phase 0: Dev Tooling (do first, unblocks everything)

**Goal:** Make the edit → test cycle instant for HTML and < 5s for Rust.

1. ✅ Replace `zp-dev.sh` with multi-mode script (done)
   - `./zp-dev.sh full` — cargo build + restart
   - `./zp-dev.sh html` — copy HTML override + restart (instant)
   - `./zp-dev.sh kill` — kill by port, no zombies
   - `./zp-dev.sh status` — show what's running

2. Add `cargo build` (dev profile) instead of `cargo install` (release)
   - Dev builds are ~5x faster (no LTO, no strip)
   - Only use `cargo install` for "ship it" builds
   - Update zp-dev.sh `full` mode to use `cargo build -p zp-server`
     then symlink/copy from `target/debug/zp`

3. Add a file watcher option (`./zp-dev.sh watch`)
   - Uses `cargo-watch` or `watchexec` to auto-rebuild on .rs changes
   - Uses `fswatch` to auto-copy HTML on .html/.css/.js changes

### Phase 1: Extract zp-engine (shared library)

**Goal:** Single source of truth for scan, configure, vault, providers.

1. Create `crates/zp-engine/` with:
   - `scan.rs` — extracted from onboard.rs `handle_scan` + configure.rs
     `discover_tools_in` / `analyze_tool`. One `scan_tools(path)` function.
   - `configure.rs` — extracted from zp-cli's `configure.rs`. The
     `ConfigEngine`, `builtin_patterns()`, `process_env_file()`, `run_auto()`.
     Now callable as `zp_engine::configure::run_auto(path, opts)`.
   - `vault.rs` — vault read/write/encrypt/decrypt. Currently scattered
     across onboard.rs (handle_vault_store) and configure.rs.
   - `providers.rs` — provider catalog, `detect_provider()`,
     `infer_provider_from_var()`. Currently in onboard.rs.
   - `genesis.rs` — genesis ceremony logic. Currently embedded in
     onboard.rs handle_genesis.

2. Make zp-server depend on zp-engine:
   - `handle_scan` calls `zp_engine::scan::scan_tools()`
   - `handle_configure` calls `zp_engine::configure::run_auto()` directly
     (no more shelling out to `zp configure auto`)
   - Remove stdout parsing, fragile string matching

3. Make zp-cli depend on zp-engine:
   - CLI becomes a thin wrapper: parse args → call engine → format output
   - `zp configure auto` calls same function as onboard WebSocket

**Key benefit:** Server and CLI always agree on tool status because they
use the same code. No more "scan says configured, configure says missing."

### Phase 2: Split onboard.rs into modules ✅

**Goal:** No single file > 500 lines.

**Status:** Complete. Run `python3 scripts/phase2-split-onboard.py` to apply.
Script creates the full module directory with real function bodies (not stubs).

1. Create `crates/zp-server/src/onboard/` module directory
2. Extract by responsibility:
   - `mod.rs` — WebSocket handler, dispatcher, OnboardEvent
   - `state.rs` — OnboardState, from_filesystem()
   - `detect.rs` — handle_detect, handle_detect_local_inference
   - `genesis.rs` — handle_genesis, handle_vault_check
   - `inference.rs` — handle_set_inference_posture, guidance, model pull
   - `scan.rs` — handle_scan (thin wrapper around zp-engine)
   - `credentials.rs` — handle_vault_store, handle_vault_import_all,
     handle_get_provider_catalog
   - `configure.rs` — handle_configure (calls zp-engine directly)

3. Each handler file follows the same pattern:
   ```rust
   use super::{OnboardEvent, OnboardState};
   pub async fn handle_X(action, state) -> Vec<OnboardEvent> { ... }
   ```

### Phase 3: Split onboard.html ✅

**Goal:** Separate CSS, HTML structure, and JS. Enable hot reload of any layer.

**Status:** Complete. Run `python3 scripts/phase3-split-onboard-html.py` to apply.

1. Split into three files:
   - `assets/onboard.css` (~900 lines)
   - `assets/onboard.html` (~490 lines, `<link>` to CSS, `<script src>` to JS)
   - `assets/onboard.js` (~1,650 lines)

2. Asset serving updated:
   - `/assets` ServeDir now chains: `~/.zeropoint/assets/` → dev source tree
   - `resolve_html_asset()` still works for HTML with compiled-in fallback
   - `zp-dev.sh html` copies all three files to `~/.zeropoint/assets/`
   - `zp-dev.sh clean` removes all three overrides

3. Eventually: split onboard.js into modules per step
   - `step-0-welcome.js`, `step-5-scan.js`, `step-7-configure.js`, etc.
   - Bundle with a simple concatenation script (no webpack needed)

### Phase 4: Process management

**Goal:** No zombies ever.

1. Write PID file to `~/.zeropoint/server.pid` on startup
2. Check PID file on start — kill stale process if needed
3. Add signal handler for clean shutdown (SIGTERM, SIGINT)
4. `zp-dev.sh` reads PID file instead of grepping process list
5. Add `zp serve --foreground` option for dev (no backgrounding)

## Execution Order

Phase 0 → immediate (already started with zp-dev.sh)
Phase 1 → next (biggest impact — eliminates CLI shelling, scan/configure mismatch)
Phase 2 → after Phase 1 (mechanical extraction, low risk)
Phase 3 → after Phase 2 (HTML splitting, enables faster frontend iteration)
Phase 4 → anytime (independent of other phases)

## What NOT to Do

- Don't add webpack/vite/npm to the frontend — concatenation is fine
- Don't introduce a separate frontend framework — vanilla JS is appropriate
  for a single-page onboarding flow
- Don't refactor the proxy (it's 449 lines, clean, works)
- Don't split the workspace Cargo.toml — current structure is fine
- Don't add hot module replacement — `./zp-dev.sh html` is fast enough
