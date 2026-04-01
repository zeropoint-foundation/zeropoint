#!/usr/bin/env python3
"""
Patch: State persistence via filesystem reconstruction.

Instead of persisting UI state to disk, we reconstruct OnboardState
from what actually exists on the filesystem when a WebSocket connects:
  - ~/.zeropoint/genesis.json → genesis_complete, operator_name, public_key, sovereignty_mode
  - ~/.zeropoint/vault.json → credentials_stored count
  - ~/projects/*/.env → tools_configured count (those with ZP_PROXY entries)
  - ~/.zeropoint/config/inference.toml → inference_posture

This replaces OnboardState::default() with OnboardState::from_filesystem().
"""

import re

rs_path = "crates/zp-server/src/onboard.rs"
with open(rs_path) as f:
    rs = f.read()

# ── 1. Add from_filesystem() method to OnboardState ──

# Find the end of the struct definition
old_struct_end = """    /// Number of tools configured
    tools_configured: usize,
}"""

new_struct_end = """    /// Number of tools configured
    tools_configured: usize,
}

impl OnboardState {
    /// Reconstruct state from filesystem reality.
    ///
    /// Probes ~/.zeropoint/ for genesis, vault, configured tools,
    /// and inference posture. Returns the furthest step the user
    /// has actually completed.
    fn from_filesystem() -> Self {
        let mut state = Self::default();
        let home = match dirs::home_dir() {
            Some(h) => h.join(".zeropoint"),
            None => return state,
        };

        // ── Genesis ──
        let genesis_path = home.join("genesis.json");
        if genesis_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&genesis_path) {
                if let Ok(record) = serde_json::from_str::<serde_json::Value>(&content) {
                    state.genesis_complete = true;
                    state.platform_detected = true;
                    state.genesis_public_key = record.get("genesis_public_key")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.operator_name = record.get("operator")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.sovereignty_mode = record.get("sovereignty_mode")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.step = 3; // Past genesis
                }
            }
        }

        // ── Vault ──
        let vault_path = home.join("vault.json");
        if vault_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&vault_path) {
                if let Ok(vault) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = vault.as_object() {
                        state.credentials_stored = obj.len();
                        if state.credentials_stored > 0 {
                            state.step = state.step.max(6);
                        }
                    }
                }
            }
        }

        // ── Inference posture ──
        let inference_path = home.join("config").join("inference.toml");
        if inference_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&inference_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("posture") {
                        if let Some(val) = line.split('=').nth(1) {
                            let val = val.trim().trim_matches('"').trim_matches('\'');
                            state.inference_posture = Some(val.to_string());
                            state.step = state.step.max(4);
                        }
                    }
                }
            }
        } else if state.genesis_complete {
            // If genesis exists but no inference config, default to mixed
            state.inference_posture = Some("mixed".to_string());
        }

        // ── Scan path + tools discovery ──
        // Check default scan path for tools
        let scan_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("projects");

        if scan_path.exists() && state.genesis_complete {
            let mut tool_count = 0;
            let mut configured_count = 0;

            if let Ok(entries) = std::fs::read_dir(&scan_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() { continue; }

                    // A "tool" is any dir with .env.example
                    let has_env_example = path.join(".env.example").exists();
                    if !has_env_example { continue; }

                    tool_count += 1;

                    // A "configured" tool has a .env with ZP_ or GOVERNANCE_ entries
                    let env_file = path.join(".env");
                    if env_file.exists() {
                        if let Ok(content) = std::fs::read_to_string(&env_file) {
                            let has_zp = content.lines().any(|l| {
                                let l = l.trim();
                                l.starts_with("ZP_") || l.starts_with("GOVERNANCE_") || l.contains("localhost:3000")
                            });
                            if has_zp {
                                configured_count += 1;
                            }
                        }
                    }
                }
            }

            if tool_count > 0 {
                state.scan_path = Some("~/projects".to_string());
                state.tools_discovered = tool_count;
                state.step = state.step.max(5);

                if configured_count > 0 {
                    state.tools_configured = configured_count;
                    state.step = state.step.max(7);
                }
            }
        }

        // Detect local inference availability
        state.local_inference_available = which::which("ollama").is_ok();

        state
    }
}"""

if 'from_filesystem' not in rs:
    rs = rs.replace(old_struct_end, new_struct_end)
    print("✓ Added OnboardState::from_filesystem()")
else:
    print("· from_filesystem() already present")

# ── 2. Replace OnboardState::default() with from_filesystem() in WS handler ──

old_ws_init = """async fn handle_onboard_ws(socket: WebSocket, app_state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut onboard = OnboardState::default();

    // Send initial state
    let init_event = OnboardEvent::new("state", serde_json::to_value(&onboard).unwrap_or_default());
    let _ = sender.send(WsMessage::Text(init_event.to_json())).await;"""

new_ws_init = """async fn handle_onboard_ws(socket: WebSocket, app_state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut onboard = OnboardState::from_filesystem();

    tracing::info!(
        "onboard ws: reconstructed state — step={}, genesis={}, vault={}, tools={}/{}",
        onboard.step, onboard.genesis_complete, onboard.credentials_stored,
        onboard.tools_configured, onboard.tools_discovered
    );

    // Send initial state so frontend can resume at the right step
    let init_event = OnboardEvent::new("state", serde_json::to_value(&onboard).unwrap_or_default());
    let _ = sender.send(WsMessage::Text(init_event.to_json())).await;"""

if 'OnboardState::default()' in rs:
    rs = rs.replace(old_ws_init, new_ws_init)
    print("✓ Replaced default() with from_filesystem() in WS handler")
elif 'from_filesystem()' in rs:
    print("· from_filesystem() already in WS handler")
else:
    print("✗ Could not find WS init block")

with open(rs_path, "w") as f:
    f.write(rs)
print("✓ Wrote onboard.rs")


# ── 3. Patch frontend to resume at reconstructed step ──

html_path = "crates/zp-server/assets/onboard.html"
with open(html_path) as f:
    html = f.read()

# Find the existing handler for the initial 'state' event
# The WS onopen or onmessage handler should use the state to jump to the right step

# Look for where 'state' event is handled
state_handler_search = re.search(r"case\s+'state':", html)
if state_handler_search:
    print(f"· Found 'state' case handler at position {state_handler_search.start()}")

# Let's find how the WS connects and handles initial state
ws_connect_match = re.search(r"ws\.onmessage|socket\.onmessage|\.onmessage", html)
if ws_connect_match:
    print(f"· Found onmessage handler at position {ws_connect_match.start()}")

# Find the state event in the switch and enhance it
old_state_case = "        case 'state':\n"
state_idx = html.find(old_state_case)
if state_idx > 0:
    # Read what's after it
    after = html[state_idx + len(old_state_case):state_idx + len(old_state_case) + 300]
    print(f"· Current state handler: {after[:100]}...")

# We need to add state resumption logic. Let's find the existing state handler
# and replace it with one that also resumes the UI step.

# Search for the full state case block
state_block = re.search(
    r"case 'state':\s*\n(.*?)break;",
    html,
    re.DOTALL
)

if state_block:
    old_state_block = state_block.group(0)
    print(f"· Found state block: {old_state_block[:80]}...")

    new_state_block = """case 'state':
        // Reconstruct UI from server state (filesystem-backed)
        if (data.step && data.step > 0) {
          console.log('[ZP] Resuming from step', data.step, data);

          // Restore known state into JS globals
          if (data.genesis_public_key) {
            genesisData = {
              genesis_public_key: data.genesis_public_key,
              operator: data.operator_name,
              sovereignty_mode: data.sovereignty_mode,
            };
          }
          if (data.credentials_stored) {
            credentialsStored = data.credentials_stored;
          }
          if (data.operator_name) {
            platformInfo = platformInfo || {};
            platformInfo.operator_name = data.operator_name;
          }
          if (data.inference_posture) {
            // Store for later use in summary
            window._resumedPosture = data.inference_posture;
          }
          if (data.tools_discovered) {
            window._resumedToolCount = data.tools_discovered;
          }

          // Jump to the reconstructed step
          // Give the WS a moment to finish setup before navigating
          setTimeout(() => {
            goStep(data.step);
            appendTerminal('genesisTerm', '✓ Resumed from filesystem state — step ' + data.step, 'success');
          }, 300);
        }
        break;"""

    if 'Resuming from step' not in html:
        html = html.replace(old_state_block, new_state_block)
        print("✓ Replaced state event handler with resumption logic")
    else:
        print("· State resumption already present")
else:
    print("✗ Could not find state case block")

with open(html_path, "w") as f:
    f.write(html)
print("✓ Wrote onboard.html")

print("\n═══════════════════════════════════════════")
print("Done. Rebuild:")
print("  cargo install --path crates/zp-server")
print("  cp ~/.cargo/bin/zp ~/.local/bin/zp")
print("  cp crates/zp-server/assets/onboard.html ~/.zeropoint/assets/onboard.html")
print("═══════════════════════════════════════════")
