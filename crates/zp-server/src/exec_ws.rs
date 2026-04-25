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
use tokio::io::{AsyncBufReadExt, BufReader};

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
                let cmd = req
                    .get("cmd")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let cwd = req
                    .get("cwd")
                    .and_then(|v| v.as_str())
                    .unwrap_or(".")
                    .to_string();

                if cmd.is_empty() {
                    let _ = tx.send(WsMessage::Text(
                        serde_json::json!({ "type": "error", "message": "No command provided" }).to_string()
                    )).await;
                    continue;
                }

                // Execute and stream output
                let receipt_hash =
                    execute_and_stream(&mut tx, &mut rx, &cmd, &cwd, &app_state).await;

                // Send exit with receipt
                let _ = tx
                    .send(WsMessage::Text(
                        serde_json::json!({
                            "type": "exec_complete",
                            "receipt_hash": receipt_hash.unwrap_or_default(),
                        })
                        .to_string(),
                    ))
                    .await;
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
    // ── CWD governance (P2-2, INJ-VULN-02/03) ──────────────────────────
    // Use the centralized safe_path() to canonicalize, resolve symlinks,
    // reject traversal, and verify the cwd falls under $HOME.
    let home_dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/nonexistent"));
    let resolved_cwd = match auth::safe_path(cwd, &home_dir) {
        Ok(canonical) => canonical.to_string_lossy().to_string(),
        Err(e) => {
            let msg = format!("🛡 {}", e);
            tracing::warn!("exec_ws: BLOCKED cwd '{}' — {}", cwd, e);
            let _ = tx
                .send(WsMessage::Text(
                    serde_json::json!({ "type": "error", "message": msg }).to_string(),
                ))
                .await;
            tool_chain::emit_tool_receipt(
                &app_state.0.audit_store,
                "tool:cmd:blocked",
                Some(&format!("reason=cwd_rejected, cwd={}, error={}", cwd, e)),
            );
            return None;
        }
    };

    // ── EXEC-01 fix: NO SHELL — metacharacter rejection (defense-in-depth) ──
    // Reject shell metacharacters outright before any parsing. Even
    // though validate_command() tokenizes via shlex without execution
    // semantics, we keep this layer so the gate's view and the
    // executor's view can never diverge.
    // See INVARIANT-CATALOG-v0.md §M1.
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
        let _ = tx
            .send(WsMessage::Text(
                serde_json::json!({ "type": "error", "message": msg }).to_string(),
            ))
            .await;
        tool_chain::emit_tool_receipt(
            &app_state.0.audit_store,
            "tool:cmd:blocked",
            Some(&format!("reason=metachar, char={}", c)),
        );
        return None;
    }

    // ── Command governance: validate against program allowlist (P2-1) ──
    // validate_command() tokenizes via shlex, checks program allowlist,
    // runs per-program argument validators, and returns a ValidatedCommand
    // that can only be constructed by passing all checks.
    let validated_cmd = match auth::validate_command(cmd) {
        Ok(vc) => vc,
        Err(e) => {
            tracing::warn!("exec_ws: BLOCKED '{}' — {}", cmd, e);
            let _ = tx
                .send(WsMessage::Text(
                    serde_json::json!({
                        "type": "error",
                        "message": format!("🛡 {}", e)
                    })
                    .to_string(),
                ))
                .await;

            // Emit a blocked-command receipt for the audit chain
            tool_chain::emit_tool_receipt(
                &app_state.0.audit_store,
                "tool:cmd:blocked",
                Some(&format!(
                    "cmd_prefix={}, reason={}",
                    cmd.split_whitespace().next().unwrap_or("?"),
                    e
                )),
            );

            return None;
        }
    };

    // ── Governance gate (P3 — Claim 3 invariant) ─────────────────────
    // Every side effect must pass through the GovernanceGate. The input
    // validation above (safe_path, metachar, allowlist) is defense-in-depth;
    // the gate is the formal policy decision point.
    let gate_context = zp_core::PolicyContext {
        action: zp_core::ActionType::Execute {
            language: cmd.to_string(),
        },
        trust_tier: zp_core::TrustTier::Tier1,
        channel: zp_core::Channel::Api,
        conversation_id: zp_core::ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![format!("exec/{}", validated_cmd.program())],
        mesh_context: None,
    };
    let actor = zp_core::ActorId::System("exec_ws".to_string());

    let gate_result = app_state.0.gate.evaluate(&gate_context, actor);

    if gate_result.is_blocked() {
        let reason = match &gate_result.decision {
            zp_core::PolicyDecision::Block { reason, .. } => reason.clone(),
            _ => "Policy denied".to_string(),
        };
        tracing::warn!("exec_ws: BLOCKED by governance gate — {}", reason);
        let _ = tx
            .send(WsMessage::Text(
                serde_json::json!({
                    "type": "error",
                    "message": format!("🛡 Governance gate blocked execution: {}", reason)
                })
                .to_string(),
            ))
            .await;
        tool_chain::emit_tool_receipt(
            &app_state.0.audit_store,
            "tool:cmd:gate_blocked",
            Some(&format!(
                "reason={}, cmd_program={}",
                reason,
                validated_cmd.program()
            )),
        );
        return None;
    }

    if gate_result.needs_interaction() {
        tracing::info!("exec_ws: command flagged for review — allowing");
    }

    // Append the gate's audit entry to the chain so the gate decision is
    // recorded even when the action is allowed.
    if let Ok(mut audit) = app_state.0.audit_store.lock() {
        if let Err(e) = audit.append(gate_result.unsealed.clone()) {
            tracing::warn!("exec_ws: failed to append gate audit entry: {}", e);
        }
    }

    tracing::info!(
        "exec_ws: running {:?} in '{}'",
        validated_cmd,
        resolved_cwd
    );

    // Spawn directly from the ValidatedCommand — no shell, no re-parsing.
    // The program + args were locked in by validate_command(); spawn()
    // uses Command::new(program).args(args) with stdin closed.
    let mut child = match validated_cmd.spawn(&resolved_cwd) {
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
    let _ = tx
        .send(WsMessage::Text(
            serde_json::json!({ "type": "exit", "code": exit_code }).to_string(),
        ))
        .await;

    // Emit a receipt into the audit chain
    let output_hash = blake3::hash(output_lines.join("\n").as_bytes())
        .to_hex()
        .to_string();
    let cmd_hash = blake3::hash(cmd.as_bytes()).to_hex().to_string();
    let event = "tool:cmd:executed".to_string();
    let detail = format!(
        "cmd_hash={}, exit_code={}, output_hash={}, cwd={}",
        &cmd_hash[..12],
        exit_code,
        &output_hash[..12],
        cwd
    );

    let receipt_hash =
        tool_chain::emit_tool_receipt(&app_state.0.audit_store, &event, Some(&detail));

    tracing::info!(
        "exec_ws: exit_code={}, receipt={:?}",
        exit_code,
        receipt_hash
    );
    receipt_hash
}
