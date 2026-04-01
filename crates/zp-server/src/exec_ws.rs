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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::{tool_chain, AppState};

/// Axum handler: upgrade HTTP → WebSocket for governed exec.
pub async fn exec_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_exec_ws(socket, state))
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
    tracing::info!("exec_ws: running '{}' in '{}'", cmd, cwd);

    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(cwd)
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
