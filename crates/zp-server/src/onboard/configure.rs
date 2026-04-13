//! Configure engine dispatch — shells out to `zp configure auto`.

use super::{OnboardAction, OnboardEvent, OnboardState};

/// Configure discovered tools by invoking `zp configure auto`.
///
/// Shells out to the CLI configure engine so we get identical behavior
/// to running it from the terminal. Output is captured and streamed
/// back as terminal events through the WebSocket.
pub async fn handle_configure(
    action: &OnboardAction,
    state: &mut OnboardState,
) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let use_proxy = action
        .params
        .get("proxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let proxy_port = action
        .params
        .get("proxy_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(3000) as u16;

    // Determine scan path — prefer what the user set in Step 5,
    // fall back to ~/projects, then accept an override from the action.
    let scan_path = action
        .params
        .get("scan_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| state.scan_path.clone())
        .unwrap_or_else(|| "~/projects".to_string());

    // Expand ~ for the shell command
    let expanded_path = if let Some(suffix) = scan_path.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(suffix)
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
        "--path".to_string(),
        expanded_path.clone(),
        "--overwrite".to_string(),
    ];
    if use_proxy {
        cmd_args.push("--proxy".to_string());
        cmd_args.push("--proxy-port".to_string());
        cmd_args.push(proxy_port.to_string());
    }

    events.push(OnboardEvent::terminal(&format!(
        "$ zp {}",
        cmd_args.join(" ")
    )));

    // Resolve the zp binary path
    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));

    events.push(OnboardEvent::terminal(&format!(
        "Binary: {}",
        zp_bin.display()
    )));

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
                events.push(OnboardEvent::terminal(
                    "✓ Tools configured with vault credentials",
                ));

                // Count configured tools from output (lines starting with "  CONFIG")
                let configured_count = stdout
                    .lines()
                    .filter(|l| l.trim_start().starts_with("CONFIG"))
                    .count();
                // Only count actually configured tools — never inflate
                state.tools_configured = configured_count;

                // Emit per-tool events so the UI can animate each card
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("CONFIG") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "governed",
                                }),
                            ));
                        }
                    } else if trimmed.starts_with("SKIP") {
                        // Parse: "SKIP  toolname — missing N credential(s)"
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            let missing = trimmed
                                .split("missing ")
                                .nth(1)
                                .and_then(|s| s.split_whitespace().next())
                                .and_then(|n| n.parse::<usize>().ok())
                                .unwrap_or(0);
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "skipped",
                                    "missing": missing,
                                }),
                            ));
                        }
                    }
                }
            } else {
                events.push(OnboardEvent::terminal(&format!(
                    "Configure exited with code {}",
                    output.status.code().unwrap_or(-1)
                )));
            }
        }
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Failed to run zp configure: {}",
                e
            )));
            events.push(OnboardEvent::terminal("Fallback: run from your terminal:"));
            let proxy_flag = if use_proxy {
                format!(" --proxy --proxy-port {}", proxy_port)
            } else {
                String::new()
            };
            events.push(OnboardEvent::terminal(&format!(
                "  zp configure auto {}{}",
                expanded_path, proxy_flag
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
}
