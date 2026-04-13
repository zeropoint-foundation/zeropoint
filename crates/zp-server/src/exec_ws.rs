//! Governed execution surface — WebSocket-based command runner.
//!
//! The cockpit diagnostic panel can execute commands server-side and
//! stream stdout/stderr back in real time. Every command execution
//! is recorded as a receipt in the audit chain.
//!
//! Protocol (JSON over WebSocket):
//!
//!   Client → Server:
//!     { "action": "exec", "cmd": "docker compose up -d", "cwd": "/path/to/tool" }
//!     { "action": "input", "data": "y\n" }    // stdin for interactive prompts
//!     { "action": "kill" }                      // send SIGTERM
//!     { "action": "resize", "cols": 120, "rows": 30 }
//!
//!   Server → Client:
//!     { "type": "stdout", "data": "..." }
//!     { "type": "stderr", "data": "..." }
//!     { "type": "exit", "code": 0, "receipt_hash": "abc..." }
//!     { "type": "error", "message": "..." }

use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::{auth, tool_chain, AppState};

/// Axum handler: upgrade HTTP → WebSocket for governed exec.
pub async fn exec_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Limit inbound WebSocket frame size to 64 KB — exec commands should
    // never be larger than a few hundred bytes. This prevents memory
    // exhaustion from malicious oversized frames.
    ws.max_frame_size(64 * 1024)
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| handle_exec_ws(socket, state))
}

/// Handle a governed execution WebSocket session.
async fn handle_exec_ws(socket: WebSocket, app_state: AppState) {
    let (mut tx, mut rx) = socket.split();

    // Wait for the first message: the exec request
    while let Some(msg) = rx.next().await {
        let text = match msg {
            Ok(WsMessage::Text(t)) => t,
            Ok(WsMessage::Close(_)) => break,
            Err(_) => break,
            _ => continue,
        };

        let req: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.send(WsMessage::Text(
                    serde_json::json!({ "type": "error", "message": format!("Invalid JSON: {}", e) }).to_string()
                )).await;
                continue;
            }
        };

        let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");

        match action {
            "exec" => {
                let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let cwd = req.get("cwd").and_then(|v| v.as_str()).unwrap_or(".").to_string();

                if cmd.is_empty() {
                    let _ = tx.send(WsMessage::Text(
                        serde_json::json!({ "type": "error", "message": "No command provided" }).to_string()
                    )).await;
                    continue;
                }

                // Execute and stream output
                let receipt_hash = execute_and_stream(&mut tx, &mut rx, &cmd, &cwd, &app_state).await;

                // Send exit with receipt
                let _ = tx.send(WsMessage::Text(
                    serde_json::json!({
                        "type": "exec_complete",
                        "receipt_hash": receipt_hash.unwrap_or_default(),
                    }).to_string()
                )).await;
            }
            _ => {
                let _ = tx.send(WsMessage::Text(
                    serde_json::json!({ "type": "error", "message": format!("Unknown action: {}", action) }).to_string()
                )).await;
            }
        }
    }
}

/// Spawn a command, stream stdout/stderr back over WebSocket.
/// Returns the receipt entry_hash on completion.
async fn execute_and_stream(
    tx: &mut futures::stream::SplitSink<WebSocket, WsMessage>,
    _rx: &mut futures::stream::SplitStream<WebSocket>,
    cmd: &str,
    cwd: &str,
    app_state: &AppState,
) -> Option<String> {
    // Expand leading `~` or `~/` — Rust's Command::current_dir() takes paths
    // literally and does not perform shell-style tilde expansion.
    let resolved_cwd = if cwd.starts_with("~/") || cwd == "~" {
        match dirs::home_dir() {
            Some(home) => home.join(cwd.strip_prefix("~/").unwrap_or("")).to_string_lossy().to_string(),
            None => cwd.to_string(),
        }
    } else {
        cwd.to_string()
    };

    // ── CWD governance (INJ-VULN-02, INJ-VULN-03) ──────────────────────
    // Canonicalize the path and reject anything outside the operator's
    // home directory. This prevents path traversal and execution in
    // attacker-controlled directories.
    let resolved_path = std::path::Path::new(&resolved_cwd);

    // Reject path traversal sequences BEFORE canonicalization.
    if cwd.contains("..") {
        let msg = "🛡 Path traversal (..) not permitted in cwd";
        tracing::warn!("exec_ws: BLOCKED cwd '{}' — path traversal", cwd);
        let _ = tx.send(WsMessage::Text(
            serde_json::json!({ "type": "error", "message": msg }).to_string()
        )).await;
        tool_chain::emit_tool_receipt(
            &app_state.0.audit_store,
            "tool:cmd:blocked",
            Some(&format!("reason=cwd_traversal, cwd={}", cwd)),
        );
        return None;
    }

    // Canonicalize and validate the path is within allowed boundaries.
    let canonical_cwd = match resolved_path.canonicalize() {
        Ok(p) => p,
        Err(_) if !resolved_path.exists() => {
            let msg = format!("🛡 Working directory does not exist: {}", resolved_cwd);
            tracing::warn!("exec_ws: BLOCKED — cwd does not exist: {}", resolved_cwd);
            let _ = tx.send(WsMessage::Text(
                serde_json::json!({ "type": "error", "message": msg }).to_string()
            )).await;
            return None;
        }
        Err(e) => {
            let msg = format!("🛡 Cannot resolve working directory: {}", e);
            let _ = tx.send(WsMessage::Text(
                serde_json::json!({ "type": "error", "message": msg }).to_string()
            )).await;
            return None;
        }
    };

    // The cwd must be under the operator's home directory.
    // System paths (/etc, /var, /usr, /tmp, /root, etc.) are never permitted.
    let home_dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/nonexistent"));
    let canonical_str = canonical_cwd.to_string_lossy();
    let is_under_home = canonical_cwd.starts_with(&home_dir);
    let is_system_path = canonical_str.starts_with("/etc")
        || canonical_str.starts_with("/var")
        || canonical_str.starts_with("/usr")
        || canonical_str.starts_with("/bin")
        || canonical_str.starts_with("/sbin")
        || canonical_str.starts_with("/root")
        || canonical_str.starts_with("/boot")
        || canonical_str.starts_with("/dev")
        || canonical_str.starts_with("/proc")
        || canonical_str.starts_with("/sys")
        || canonical_str.starts_with("/tmp")
        || canonical_str.starts_with("/private/etc")
        || canonical_str.starts_with("/private/var")
        || canonical_str.starts_with("/private/tmp");

    if is_system_path || (!is_under_home && canonical_str != ".") {
        let msg = format!(
            "🛡 Working directory '{}' is outside the permitted area. \
             Commands may only execute within your home directory.",
            canonical_str
        );
        tracing::warn!("exec_ws: BLOCKED cwd '{}' — outside home", canonical_str);
        let _ = tx.send(WsMessage::Text(
            serde_json::json!({ "type": "error", "message": msg }).to_string()
        )).await;
        tool_chain::emit_tool_receipt(
            &app_state.0.audit_store,
            "tool:cmd:blocked",
            Some(&format!("reason=cwd_outside_home, cwd={}", canonical_str)),
        );
        return None;
    }

    // ── Command governance: check allowlist before spawning ──────────
    if let Err(reason) = auth::check_command(cmd) {
        tracing::warn!("exec_ws: BLOCKED '{}' — {}", cmd, reason);
        let _ = tx.send(WsMessage::Text(
            serde_json::json!({
                "type": "error",
                "message": format!("🛡 {}", reason)
            }).to_string()
        )).await;

        // Emit a blocked-command receipt for the audit chain
        tool_chain::emit_tool_receipt(
            &app_state.0.audit_store,
            "tool:cmd:blocked",
            Some(&format!("cmd_prefix={}, reason={}", cmd.split_whitespace().next().unwrap_or("?"), reason)),
        );

        return None;
    }

    // ── EXEC-01 fix: NO SHELL. ────────────────────────────────────────
    // The previous implementation passed `cmd` to `sh -c`, which made
    // every metacharacter an injection vector and made command
    // governance fundamentally unsound (auth::check_command saw the
    // string but the shell saw a different parse tree). The new path:
    //
    //   1. Reject any string containing shell metacharacters outright,
    //      even if some downstream tool would have wanted them. This is
    //      defense in depth — we cannot represent these meanings in a
    //      structured argv anyway.
    //   2. Tokenize with shlex (POSIX shell-quoting rules without any
    //      execution semantics) so quoted strings still work.
    //   3. exec the resulting argv directly via `Command::new(argv[0])`
    //      with no shell anywhere in the chain.
    //
    // Catalog mapping: this is a P3 (the gate) hardening — closing the
    // gap where the gate's view of the action and the executor's view
    // of the action could differ. See INVARIANT-CATALOG-v0.md §M1.
    const SHELL_METACHARS: &[char] = &[
        '|', '&', ';', '<', '>', '$', '`', '\\', '\n', '\r', '(', ')', '{', '}',
    ];
    if let Some(c) = cmd.chars().find(|c| SHELL_METACHARS.contains(c)) {
        let msg = format!(
            "🛡 Command rejected: shell metacharacter '{}' is not permitted in structured exec. \
             Compound commands, redirections, and substitutions must be expressed as separate exec calls.",
            c
        );
        tracing::warn!("exec_ws: BLOCKED metachar '{}' in cmd '{}'", c, cmd);
        let _ = tx.send(WsMessage::Text(
            serde_json::json!({ "type": "error", "message": msg }).to_string()
        )).await;
        tool_chain::emit_tool_receipt(
            &app_state.0.audit_store,
            "tool:cmd:blocked",
            Some(&format!("reason=metachar, char={}", c)),
        );
        return None;
    }

    let argv: Vec<String> = match shlex::split(cmd) {
        Some(v) if !v.is_empty() => v.into_iter().map(String::from).collect(),
        Some(_) => {
            let _ = tx.send(WsMessage::Text(
                serde_json::json!({ "type": "error", "message": "🛡 Empty command after tokenization" }).to_string()
            )).await;
            return None;
        }
        None => {
            let _ = tx.send(WsMessage::Text(
                serde_json::json!({ "type": "error", "message": "🛡 Command failed to parse (unbalanced quotes?)" }).to_string()
            )).await;
            tool_chain::emit_tool_receipt(
                &app_state.0.audit_store,
                "tool:cmd:blocked",
                Some("reason=tokenize_failed"),
            );
            return None;
        }
    };

    tracing::info!("exec_ws: running argv {:?} in '{}'", argv, resolved_cwd);

    let program = &argv[0];
    let args = &argv[1..];

    let mut child = match Command::new(program)
        .args(args)
        .current_dir(&resolved_cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(WsMessage::Text(
                serde_json::json!({ "type": "error", "message": format!("Spawn failed: {}", e) }).to_string()
            )).await;
            return None;
        }
    };

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    // Stream both stdout and stderr concurrently
    let mut output_lines: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            line = stdout_reader.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        output_lines.push(l.clone());
                        let _ = tx.send(WsMessage::Text(
                            serde_json::json!({ "type": "stdout", "data": format!("{}\n", l) }).to_string()
                        )).await;
                    }
                    Ok(None) => {
                        // stdout closed — wait for stderr to finish too
                        while let Ok(Some(l)) = stderr_reader.next_line().await {
                            output_lines.push(l.clone());
                            let _ = tx.send(WsMessage::Text(
                                serde_json::json!({ "type": "stderr", "data": format!("{}\n", l) }).to_string()
                            )).await;
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
            line = stderr_reader.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        output_lines.push(l.clone());
                        let _ = tx.send(WsMessage::Text(
                            serde_json::json!({ "type": "stderr", "data": format!("{}\n", l) }).to_string()
                        )).await;
                    }
                    Ok(None) => {} // stderr closed, keep reading stdout
                    Err(_) => {}
                }
            }
        }
    }

    // Wait for the process to exit
    let exit_code = match child.wait().await {
        Ok(status) => status.code().unwrap_or(-1),
        Err(_) => -1,
    };

    // Send exit event
    let _ = tx.send(WsMessage::Text(
        serde_json::json!({ "type": "exit", "code": exit_code }).to_string()
    )).await;

    // Emit a receipt into the audit chain
    let output_hash = blake3::hash(output_lines.join("\n").as_bytes()).to_hex().to_string();
    let cmd_hash = blake3::hash(cmd.as_bytes()).to_hex().to_string();
    let event = format!("tool:cmd:executed");
    let detail = format!(
        "cmd_hash={}, exit_code={}, output_hash={}, cwd={}",
        &cmd_hash[..12], exit_code, &output_hash[..12], cwd
    );

    let receipt_hash = tool_chain::emit_tool_receipt(
        &app_state.0.audit_store,
        &event,
        Some(&detail),
    );

    tracing::info!("exec_ws: exit_code={}, receipt={:?}", exit_code, receipt_hash);
    receipt_hash
}
