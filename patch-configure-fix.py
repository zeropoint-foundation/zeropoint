#!/usr/bin/env python3
"""Fix handle_configure: use tokio::process::Command instead of blocking std::process::Command."""

import re

path = "crates/zp-server/src/onboard.rs"
with open(path, "r") as f:
    src = f.read()

# --- 1. Replace the blocking Command call with tokio async ---
old_configure = '''    // Resolve the zp binary path
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
    }'''

new_configure = '''    // Resolve the zp binary path
    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));

    events.push(OnboardEvent::terminal(&format!("Binary: {}", zp_bin.display())));

    // Run the configure engine (async — avoids blocking the tokio runtime)
    match tokio::process::Command::new(&zp_bin)
        .args(&cmd_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
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

            if stdout.is_empty() && stderr.is_empty() {
                events.push(OnboardEvent::terminal("(no output from zp configure)"));
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
    }'''

if old_configure in src:
    src = src.replace(old_configure, new_configure)
    with open(path, "w") as f:
        f.write(src)
    print("✓ Patched handle_configure: std::process::Command → tokio::process::Command")
    print("✓ Added binary path debug line")
    print("✓ Added empty-output detection")
else:
    print("✗ Could not find the expected old_configure block.")
    print("  Checking if already patched...")
    if "tokio::process::Command" in src and "handle_configure" in src:
        print("  → Looks like it's already using tokio::process::Command")
    else:
        print("  → Manual edit needed")
