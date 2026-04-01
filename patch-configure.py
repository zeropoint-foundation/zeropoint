#!/usr/bin/env python3
"""Patch onboard.rs to wire real tool configuration into Step 7."""

FILE = "crates/zp-server/src/onboard.rs"

with open(FILE, "r") as f:
    src = f.read()

# ── Edit 1: Add scan_path to OnboardState ──
if "scan_path: Option<String>," not in src:
    src = src.replace(
        "    /// Number of tools discovered\n"
        "    tools_discovered: usize,",
        "    /// Path used in Step 5 scan (retained for configure)\n"
        "    scan_path: Option<String>,\n"
        "    /// Number of tools discovered\n"
        "    tools_discovered: usize,",
    )
    print("✓ Edit 1: Added scan_path to OnboardState")
else:
    print("· Edit 1: scan_path already present")

# ── Edit 2: Store scan_path during handle_scan ──
if "state.scan_path = Some(scan_path.to_string())" not in src:
    src = src.replace(
        '    state.tools_discovered = tool_count;',
        '    state.scan_path = Some(scan_path.to_string());\n'
        '    state.tools_discovered = tool_count;',
    )
    print("✓ Edit 2: Store scan_path during scan")
else:
    print("· Edit 2: scan_path storage already present")

# ── Edit 3: Replace stub configure handler with real shell-out ──
STUB = '''/// Configure discovered tools.
async fn handle_configure(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let use_proxy = action.params.get("proxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let proxy_port = action.params.get("proxy_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(3000) as u16;

    events.push(OnboardEvent::terminal("Configuring tools..."));

    if use_proxy {
        events.push(OnboardEvent::terminal(&format!(
            "Governance proxy enabled on port {}", proxy_port
        )));
    }

    // In v0.1, we report that configuration should be done via CLI
    // since the configure engine is in zp-cli, not zp-server.
    // The browser will show the recommended CLI commands.
    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal("Run from your terminal:"));
    let proxy_flag = if use_proxy { format!(" --proxy-port {}", proxy_port) } else { String::new() };
    events.push(OnboardEvent::terminal(&format!(
        "  zp configure auto{}", proxy_flag
    )));

    state.step = 7;
    state.tools_configured = state.tools_discovered; // optimistic

    events.push(OnboardEvent::new(
        "configure_complete",
        serde_json::json!({
            "proxy_enabled": use_proxy,
            "proxy_port": proxy_port,
            "cli_command": format!("zp configure auto{}", if use_proxy { format!(" --proxy-port {}", proxy_port) } else { String::new() }),
        }),
    ));

    events
}'''

REAL = '''/// Configure discovered tools by invoking `zp configure auto`.
///
/// Shells out to the CLI configure engine so we get identical behavior
/// to running it from the terminal. Output is captured and streamed
/// back as terminal events through the WebSocket.
async fn handle_configure(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let use_proxy = action.params.get("proxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let proxy_port = action.params.get("proxy_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(3000) as u16;

    // Determine scan path — prefer what the user set in Step 5,
    // fall back to ~/projects, then accept an override from the action.
    let scan_path = action.params.get("scan_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| state.scan_path.clone())
        .unwrap_or_else(|| "~/projects".to_string());

    // Expand ~ for the shell command
    let expanded_path = if scan_path.starts_with("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(&scan_path[2..])
            .display()
            .to_string()
    } else {
        scan_path.clone()
    };

    events.push(OnboardEvent::terminal("Configuring discovered tools..."));

    // Build the CLI command
    let mut cmd_args = vec![
        "configure".to_string(),
        "auto".to_string(),
        expanded_path.clone(),
        "--overwrite".to_string(),
    ];
    if use_proxy {
        cmd_args.push("--proxy".to_string());
        cmd_args.push("--proxy-port".to_string());
        cmd_args.push(proxy_port.to_string());
    }

    events.push(OnboardEvent::terminal(&format!(
        "$ zp {}", cmd_args.join(" ")
    )));

    // Resolve the zp binary path
    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));

    // Run the configure engine
    match std::process::Command::new(&zp_bin)
        .args(&cmd_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Stream each line of output as a terminal event
            for line in stdout.lines() {
                if !line.trim().is_empty() {
                    events.push(OnboardEvent::terminal(line));
                }
            }
            for line in stderr.lines() {
                if !line.trim().is_empty() {
                    events.push(OnboardEvent::terminal(line));
                }
            }

            if output.status.success() {
                events.push(OnboardEvent::terminal(""));
                events.push(OnboardEvent::terminal("✓ Tools configured with vault credentials"));

                // Count configured tools from output (lines starting with "  CONFIG")
                let configured_count = stdout.lines()
                    .filter(|l| l.trim_start().starts_with("CONFIG"))
                    .count();
                state.tools_configured = if configured_count > 0 {
                    configured_count
                } else {
                    state.tools_discovered
                };
            } else {
                events.push(OnboardEvent::terminal(&format!(
                    "Configure exited with code {}", output.status.code().unwrap_or(-1)
                )));
            }
        }
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Failed to run zp configure: {}", e
            )));
            events.push(OnboardEvent::terminal(
                "Fallback: run from your terminal:"
            ));
            let proxy_flag = if use_proxy { format!(" --proxy --proxy-port {}", proxy_port) } else { String::new() };
            events.push(OnboardEvent::terminal(&format!(
                "  zp configure auto {}{}", expanded_path, proxy_flag
            )));
        }
    }

    state.step = 7;

    events.push(OnboardEvent::new(
        "configure_complete",
        serde_json::json!({
            "proxy_enabled": use_proxy,
            "proxy_port": proxy_port,
            "scan_path": scan_path,
            "tools_configured": state.tools_configured,
        }),
    ));

    events
}'''

if "In v0.1, we report that configuration should be done via CLI" in src:
    src = src.replace(STUB, REAL)
    print("✓ Edit 3: Replaced stub configure handler with real shell-out")
elif "zp configure auto" in src and "Command::new" in src:
    print("· Edit 3: Real configure handler already present")
else:
    print("✗ Edit 3: Could not find stub handler — manual edit needed")
    import sys; sys.exit(1)

# ── Edit 4: Add which crate dependency check ──
# (just a reminder — the user needs to add `which` to Cargo.toml)
if "which::which" in src:
    print("\n⚠ Note: Add `which = \"7\"` to crates/zp-server/Cargo.toml [dependencies]")

with open(FILE, "w") as f:
    f.write(src)

print("\nDone. Before rebuilding, add `which` dependency:")
print('  echo \'which = "7"\' >> crates/zp-server/Cargo.toml')
print("\nThen rebuild:")
print("  cargo clean -p zp-server --release && cargo install --path crates/zp-cli --force --target-dir /tmp/zp-fresh-build && cp ~/.cargo/bin/zp ~/.local/bin/zp")
