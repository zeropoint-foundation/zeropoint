# Regent Phase 0–1: Hands and First Deliverable

**Status:** Design  
**Scope:** Two phases only. No background workflows, no cloud registry, no artifact library.

**Multi-device operation note (per Decision C, July 2026):** Phase 0-1 as specified here runs on a single device (APOLLO in the initial testbed). Full multi-device behavior — Regent state replicated across authorized devices, single active presence, explicit chain-anchored handoff between devices — is a Phase 2+ concern per REGENT-ORCHESTRATION-ARCHITECTURE. The Phase 0-1 loop implementation should be structured so that state migration and handoff can be layered on later without redesigning the core loop.

---

## Phase 0: Giving the Regent Hands

The Regent currently reasons and produces `Intent` variants, but `ServerIntentExecutor::execute()` only emits receipts — it never actually calls tools or evaluates the gate. Phase 0 makes `Intent::Execute` do real work.

### 0.1 What exists today

The loop runner (`zp-regent/src/loop_runner.rs`) is a skeleton. The `OperatorInput` branch at line 149 builds context but then discards everything (`let _ = operator_input; continue;`). The `IntentExecutor::execute()` signature returns `Result<(), RegentError>` — it can say "I did something" but can't return what happened.

The `reason()` method (line 146 of `regent.rs`) always returns `Intent::Respond`. It never produces `Intent::Execute` because the system prompt doesn't tell the model it has tools.

### 0.2 Changes to `IntentExecutor`

The executor needs to return what happened so the Regent can reason about it.

```rust
// zp-regent/src/loop_runner.rs

/// What happened when an intent was executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentOutcome {
    /// Tool ran successfully. Contains the tool output.
    ToolCompleted {
        tool: String,
        output: serde_json::Value,
    },
    /// Gate denied the tool call.
    ToolDenied {
        tool: String,
        reason: String,
    },
    /// Response was delivered to a cockpit surface.
    Delivered,
    /// Observation recorded (no visible effect).
    Observed,
    /// Approval request sent to operator.
    ApprovalRequested,
}

#[async_trait::async_trait]
pub trait IntentExecutor: Send + Sync {
    async fn execute(&self, intent: &Intent) -> Result<IntentOutcome, RegentError>;
}
```

### 0.3 Changes to `ServerIntentExecutor`

The `Intent::Execute` arm currently emits a receipt and returns. It needs to actually call the gate and dispatch the tool.

```rust
// zp-server/src/regent.rs — new fields on ServerIntentExecutor

pub struct ServerIntentExecutor {
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
    gate: Arc<GovernanceGate>,
    event_tx: tokio::sync::broadcast::Sender<crate::events::EventStreamItem>,
}
```

The `Intent::Execute` arm becomes:

```rust
Intent::Execute { tool, params } => {
    // 1. Build PolicyContext for gate evaluation
    let context = PolicyContext {
        action: ActionType::ToolCall,
        tool_name: Some(tool.clone()),
        input_content: Some(serde_json::to_string(params).unwrap_or_default()),
        ..PolicyContext::default()
    };
    let actor = ActorId::System("regent".to_string());

    // 2. Evaluate gate
    let gate_result = self.gate.evaluate(&context, actor);

    // 3. Append gate decision to chain
    {
        let mut store = self.audit_store.lock().unwrap();
        if let Err(e) = store.append(gate_result.unsealed.clone()) {
            warn!("gate receipt append failed: {}", e);
        }
    }

    // 4. If blocked, return denial
    if gate_result.is_blocked() {
        let reason = match &gate_result.decision {
            PolicyDecision::Block { reason, .. } => reason.clone(),
            _ => "policy denied".to_string(),
        };
        return Ok(IntentOutcome::ToolDenied {
            tool: tool.clone(),
            reason,
        });
    }

    // 5. Dispatch tool
    let output = self.dispatch_tool(tool, params).await?;

    // 6. Emit completion receipt
    self.emit_receipt(
        &format!("regent:tool:completed:{}", tool),
        Some(&format!("success=true")),
    );

    Ok(IntentOutcome::ToolCompleted {
        tool: tool.clone(),
        output,
    })
}
```

### 0.4 Tool dispatch — Phase 0 tools only

Phase 0 tools are transparent substrate queries. No external calls, no opaque effects.

```rust
// zp-server/src/regent.rs

impl ServerIntentExecutor {
    async fn dispatch_tool(
        &self,
        tool: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RegentError> {
        match tool {
            "chain_query" => {
                let limit = params.get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;
                let store = self.audit_store.lock()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                let entries = store.recent(limit)
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                let summaries: Vec<_> = entries.iter().map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "event": e.action_summary(),
                        "actor": format!("{}", e.actor),
                        "timestamp": e.timestamp.to_rfc3339(),
                    })
                }).collect();
                Ok(serde_json::json!({ "entries": summaries, "count": summaries.len() }))
            }

            "governance_posture" => {
                let store = self.audit_store.lock()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                let count = store.entry_count()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                Ok(serde_json::json!({
                    "chain_length": count,
                    "gate_active": true,
                }))
            }

            _ => Err(RegentError::Execution(format!("unknown tool: {}", tool))),
        }
    }
}
```

Add the missing error variant:

```rust
// zp-regent/src/error.rs — add:
#[error("tool execution error: {0}")]
Execution(String),
```

### 0.5 Wiring the loop runner

The loop runner's `OperatorInput` branch (line 149) currently discards context. It needs to actually run the cycle. The key constraint: `perceive()` needs a `ChainReader` which requires a lock on `AuditStore`. The executor also needs `AuditStore` for gate evaluation and receipt emission. These are both `std::sync::Mutex`, so we must not hold the chain lock while executing.

The fix is to pass `audit_store` into `start_loop` and construct the `ChainReader` inside the cycle, dropping it before execution:

```rust
// zp-regent/src/loop_runner.rs — change start_loop signature

pub fn start_loop(
    regent: Arc<Mutex<Regent>>,
    executor: Arc<dyn IntentExecutor>,
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
    interval_secs: u64,
) -> RegentHandle {
```

The `OperatorInput` branch becomes:

```rust
RegentMessage::OperatorInput { content, source } => {
    let operator_input = if content.is_empty() {
        None
    } else {
        Some(OperatorInput {
            content,
            received_at: chrono::Utc::now(),
            source,
        })
    };

    // TODO: read delegations from chain state
    let delegations: Vec<DelegationSummary> = Vec::new();

    // Run cognitive cycle.
    // Lock audit_store briefly to construct ChainReader, then drop.
    let intent = {
        let store = audit_store.lock().unwrap();
        let chain_reader = ChainReader::new(&*store);
        let mut regent = regent.lock().await;
        regent.cycle(
            &chain_reader,
            &latest_findings,
            operator_input,
            &delegations,
        ).await
    };
    // audit_store lock is dropped here — executor can safely lock for gate eval.

    match intent {
        Ok(intent) => {
            if let Err(e) = executor.execute(&intent).await {
                warn!("intent execution failed: {}", e);
            }
        }
        Err(e) => {
            warn!("regent cycle failed: {}", e);
        }
    }
}
```

**Lock ordering is load-bearing.** `perceive()` holds the `AuditStore` lock via `ChainReader`. `execute()` needs the same lock for gate evaluation and receipt emission. The block scope above ensures perceive's lock is released before execute runs. This is not an optimization — it prevents deadlock.

### 0.6 Teaching the model to use tools

`reason()` currently returns `Intent::Respond` for everything (line 189 of `regent.rs`). To produce `Intent::Execute`, the system prompt must enumerate available tools and specify the output format.

Add to `build_system_prompt()`:

```
You can call tools by responding with JSON:
{"intent": "execute", "tool": "<name>", "params": {<params>}}

Available tools:
- chain_query: Read recent audit chain entries. Params: { "limit": <number> }
- governance_posture: Get current governance state. Params: {}

When you can answer directly without tools:
{"intent": "respond", "content": "<your response>"}

Always respond with exactly one JSON object. No markdown wrapping, no preamble.
```

Replace the hardcoded `Intent::Respond` at line 189 with intent parsing:

```rust
async fn reason(&self, context: &CognitiveContext) -> Result<Intent, RegentError> {
    // ... existing early-return for no input + no urgency (unchanged) ...

    let response = self.inference.chat(&request).await?;

    // Parse structured intent from model output.
    match self.parse_intent(&response) {
        Some(intent) => Ok(intent),
        None => {
            // Model didn't produce valid JSON — treat as plain response.
            // Emit parse-failure receipt for observability.
            Ok(Intent::Respond {
                content: response,
                target_surface: None,
            })
        }
    }
}

fn parse_intent(&self, response: &str) -> Option<Intent> {
    // Strip markdown code fences if present.
    let json_str = response
        .trim()
        .strip_prefix("```json").or_else(|| response.trim().strip_prefix("```"))
        .and_then(|s| s.strip_suffix("```"))
        .unwrap_or(response)
        .trim();

    let v: serde_json::Value = serde_json::from_str(json_str).ok()?;

    match v.get("intent")?.as_str()? {
        "execute" => {
            let tool = v.get("tool")?.as_str()?.to_string();
            let params = v.get("params").cloned().unwrap_or(serde_json::json!({}));
            Some(Intent::Execute { tool, params })
        }
        "respond" => {
            let content = v.get("content")?.as_str()?.to_string();
            Some(Intent::Respond { content, target_surface: None })
        }
        _ => None,
    }
}
```

### 0.7 Regent delegation at startup

The gate will deny the Regent's tool calls unless it has a delegation. At spawn time, grant it:

```rust
// zp-server/src/regent.rs — in spawn_regent(), after constructing the Regent

// Grant the Regent delegation for Phase 0 tools.
{
    let mut grants = /* access to AppStateInner.grants */;
    grants.push(CapabilityGrant::new(
        ActorId::System("regent".to_string()),
        vec!["chain_query".to_string(), "governance_posture".to_string()],
        None, // no expiry
    ));
}
```

The exact `CapabilityGrant` construction depends on the current `zp-core` API. If the gate uses `grants` to check delegation, this is where the Regent gets its authority. If the gate doesn't check grants yet (it evaluates policy only), this step is deferred until the gate wires capability-grant checking.

### 0.8 Multi-turn tool cycle

A single `cycle()` may produce `Intent::Execute`. After the tool runs, the Regent needs to see the result and reason again to produce a final `Intent::Respond`. This is a multi-turn loop in the loop runner, capped at 3 turns for Phase 0.

No new method on `Regent` — the loop runner drives it:

```rust
// After getting the initial intent from cycle():
let mut current_intent = intent;

for _turn in 0..3 {
    match current_intent {
        Ok(Intent::Execute { ref tool, ref params }) => {
            let outcome = executor.execute(&Intent::Execute {
                tool: tool.clone(),
                params: params.clone(),
            }).await;

            // Feed result back as synthetic input for next cycle
            let feedback = match &outcome {
                Ok(IntentOutcome::ToolCompleted { tool, output }) => {
                    format!("Tool {} returned: {}", tool,
                        serde_json::to_string_pretty(output).unwrap_or_default())
                }
                Ok(IntentOutcome::ToolDenied { tool, reason }) => {
                    format!("Tool {} denied: {}", tool, reason)
                }
                Err(e) => format!("Tool execution error: {}", e),
                _ => break,
            };

            // Re-run cycle with tool result
            let store = audit_store.lock().unwrap();
            let chain_reader = ChainReader::new(&*store);
            let mut regent_guard = regent.lock().await;
            current_intent = regent_guard.cycle(
                &chain_reader,
                &latest_findings,
                Some(OperatorInput {
                    content: feedback,
                    received_at: chrono::Utc::now(),
                    source: CockpitSource::Autonomous,
                }),
                &delegations,
            ).await;
            // Lock drops here
        }
        Ok(ref intent) => {
            // Terminal intent — execute and break
            let _ = executor.execute(intent).await;
            break;
        }
        Err(e) => {
            warn!("regent cycle failed: {}", e);
            break;
        }
    }
}
```

### 0.9 Receipt chain for Phase 0

Operator asks: "How many entries are on the chain?"

```
regent:intent:execute                tool=chain_query, params={"limit":1}
gate:allowed:chain_query             actor=regent
regent:tool:completed:chain_query    count=147
regent:intent:respond                "There are 147 entries on the audit chain."
```

If the gate denies:

```
regent:intent:execute                tool=chain_query
gate:denied:chain_query              actor=regent, reason="no delegation"
regent:intent:respond                "I don't have permission to query the chain."
```

### 0.10 Success criteria

Phase 0 is done when:

1. `./zp-dev.sh release` compiles clean
2. The Regent loop starts, emits `regent:intent:observe` on autonomous cycles
3. Operator sends "How many entries are on the chain?" via cockpit
4. The Regent produces `Intent::Execute { tool: "chain_query" }`, the gate allows it, `chain_query` returns a count, the Regent produces `Intent::Respond` with the answer
5. `zp chain tail` shows the full receipt sequence
6. Removing the Regent's delegation causes `gate:denied` and the Regent reports the denial

### 0.11 Files changed

| File | Change |
|------|--------|
| `crates/zp-regent/src/loop_runner.rs` | Add `IntentOutcome` enum, change `IntentExecutor::execute` return type, add `audit_store` param to `start_loop`, wire actual cycle call with multi-turn loop |
| `crates/zp-regent/src/regent.rs` | Add `parse_intent()`, modify `reason()` to parse structured output, add tool enumeration to `build_system_prompt()` |
| `crates/zp-regent/src/error.rs` | Add `Execution(String)` variant |
| `crates/zp-server/src/regent.rs` | Add `gate` field to `ServerIntentExecutor`, implement `dispatch_tool()`, wire gate evaluation in `Intent::Execute` arm, emit Regent delegation at startup, pass `audit_store` to `start_loop` |

---

## Phase 1: Competitive Analysis Report

**Task:** Operator says: "Create a competitive analysis report for Acme Corp that includes key findings, 2-3 generated images, and at least one interactive graph."

This tests multi-step reasoning, opaque tool calls, and deliverable assembly. The Regent decomposes the goal into sequential tool calls using the same multi-turn loop from Phase 0 — no plan engine, no DAG executor, no new Intent variants.

### 1.1 How decomposition works (no new types)

Phase 1 does **not** add `Intent::Plan`. The local model decomposes the task by emitting one `Intent::Execute` at a time. After each tool completes, the result is fed back as context and the model decides what to do next. The system prompt tells it to work step-by-step:

```
When a task requires multiple steps, work through them one tool call at a time.
After each tool result, decide your next action. When you have everything needed,
respond with the final deliverable.
```

This is the same multi-turn loop from Phase 0 §0.8, just running for more turns. The `max_turns` cap goes from 3 to 12 for Phase 1 tasks.

Why no `Intent::Plan`: a formal plan type with DAG dependencies is a later concern. For Phase 1, the model holds its plan in its context window. The receipts record every step — you can reconstruct the plan from the chain. The chain is the plan.

### 1.2 New tools

Phase 1 adds five tools to `dispatch_tool()`:

| Tool | Transparency | What it does |
|------|-------------|-------------|
| `web_search` | Opaque | Calls a search API, returns structured results |
| `web_fetch` | Opaque | Fetches a URL, returns extracted text |
| `image_generate` | Opaque | Calls image generation API (local Ollama or cloud) |
| `chart_generate` | Transparent | Produces self-contained HTML/SVG chart from structured data |
| `report_assemble` | Transparent | Combines text sections, images, and charts into HTML report |

```rust
// zp-server/src/regent.rs — extend dispatch_tool()

"web_search" => {
    let query = params.get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RegentError::Execution("missing 'query'".into()))?;
    let results = self.search_provider.search(query).await
        .map_err(|e| RegentError::Execution(e.to_string()))?;
    Ok(serde_json::json!({ "results": results }))
}

"web_fetch" => {
    let url = params.get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RegentError::Execution("missing 'url'".into()))?;
    let body = reqwest::get(url).await
        .map_err(|e| RegentError::Execution(e.to_string()))?
        .text().await
        .map_err(|e| RegentError::Execution(e.to_string()))?;
    let text = strip_html(&body);
    let truncated = &text[..text.len().min(8000)];
    Ok(serde_json::json!({ "url": url, "text": truncated }))
}

"image_generate" => {
    let prompt = params.get("prompt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RegentError::Execution("missing 'prompt'".into()))?;
    let width = params.get("width").and_then(|v| v.as_u64()).unwrap_or(1024);
    let height = params.get("height").and_then(|v| v.as_u64()).unwrap_or(768);
    let result = self.image_provider.generate(prompt, width, height).await
        .map_err(|e| RegentError::Execution(e.to_string()))?;
    Ok(serde_json::json!({ "path": result.path, "width": width, "height": height }))
}

"chart_generate" => {
    let chart_type = params.get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("bar");
    let data = params.get("data")
        .ok_or_else(|| RegentError::Execution("missing 'data'".into()))?;
    let title = params.get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Chart");
    let html = generate_chart_html(chart_type, data, title);
    let path = save_to_artifacts(&html, "chart.html")?;
    Ok(serde_json::json!({ "path": path, "type": chart_type }))
}

"report_assemble" => {
    let sections = params.get("sections")
        .ok_or_else(|| RegentError::Execution("missing 'sections'".into()))?;
    let images = params.get("images").and_then(|v| v.as_array());
    let charts = params.get("charts").and_then(|v| v.as_array());
    let html = assemble_report_html(sections, images, charts);
    let hash = blake3::hash(html.as_bytes()).to_hex().to_string();
    let path = save_to_artifacts(&html, "competitive-analysis.html")?;
    Ok(serde_json::json!({ "path": path, "hash": hash, "format": "html" }))
}
```

`generate_chart_html` and `assemble_report_html` live in a new file `crates/zp-server/src/regent_tools.rs` (not yet written; neither function exists in the tree as of 2026-07-27). Both produce self-contained HTML. The chart embeds Chart.js from a vendored copy. The report inlines images as base64 and embeds chart HTML via iframe.

### 1.3 Expected execution trace

The model, working one tool at a time through the multi-turn loop:

```
Turn 1:  Execute(web_search, "Acme Corp competitors market position 2026")
Turn 2:  Execute(web_search, "Acme Corp financial performance revenue")
Turn 3:  Execute(web_search, "Acme Corp product comparison vs competitors")
Turn 4:  Execute(web_fetch, <top result URL from turn 1>)
Turn 5:  Execute(web_fetch, <top result URL from turn 2>)
Turn 6:  Execute(image_generate, "market positioning map showing Acme Corp...")
Turn 7:  Execute(image_generate, "competitive landscape infographic...")
Turn 8:  Execute(chart_generate, {type: "bar", data: <revenue comparison>})
Turn 9:  Execute(report_assemble, {sections: <synthesized findings>, images: [...], charts: [...]})
Turn 10: Respond("Report ready at artifacts/competitive-analysis.html")
```

10 turns, each producing 2–3 receipts (intent + gate + completion), totaling ~25 receipts. The model does synthesis in its context window during turn 9, not via a separate Escalate step. If local model quality is insufficient, that's data for Phase 2 scoping.

### 1.4 System prompt for Phase 1

Extend the tool enumeration from Phase 0:

```
Available tools:
- chain_query: Read recent audit chain entries. Params: { "limit": <number> }
- governance_posture: Get current governance state. Params: {}
- web_search: Search the web. Params: { "query": <string> }
- web_fetch: Fetch a URL and extract text. Params: { "url": <string> }
- image_generate: Generate an image from a description. Params: { "prompt": <string>, "width": <number>, "height": <number> }
- chart_generate: Generate an interactive chart. Params: { "type": "bar"|"line"|"pie", "data": <object>, "title": <string> }
- report_assemble: Assemble a report from sections, images, and charts. Params: { "sections": <object>, "images": <array of paths>, "charts": <array of paths> }

Work through complex tasks one tool call at a time. After each result, decide your next step.
When you have all the pieces, assemble the final deliverable.
```

### 1.5 Delegation grant

Expand the startup delegation:

```rust
vec![
    "chain_query", "governance_posture",       // Phase 0
    "web_search", "web_fetch",                 // Phase 1: research
    "image_generate",                           // Phase 1: visuals
    "chart_generate", "report_assemble",        // Phase 1: assembly
]
```

The operator can revoke any of these at any time. `zp delegate revoke regent web_search` removes web access; the Regent's next `web_search` call hits `gate:denied` and it adapts.

### 1.6 What the report looks like

`report_assemble` produces a single self-contained HTML file at `~/ZeroPoint/artifacts/competitive-analysis.html`:

- Dark theme matching ZP design system (`--bg: #0a0a0c`, accent `#7eb8da`, Inter + JetBrains Mono)
- Text sections with findings, organized by topic
- Images inlined as base64 `<img>` tags
- Charts embedded as `<iframe srcdoc="...">` elements (self-contained, interactive)
- Footer: "Generated by ZeroPoint Regent · chain-anchored · content hash: abc123..."

The content hash is on chain via the `report_assemble` completion receipt. `zp verify` can hash the file and compare against the chain to detect post-generation tampering. This is not artifact signing (later phase) — it's content-address anchoring.

### 1.7 What is NOT in Phase 1

- **No `Intent::Plan` type.** The model holds its plan in context. The chain records what happened.
- **No DAG executor.** Sequential tool calls via the existing multi-turn loop.
- **No cloud escalation.** The local model does everything including synthesis.
- **No artifact signing.** The report is a file with a content hash on chain, not a signed artifact.
- **No concurrent tool execution.** One tool at a time, sequentially.
- **No streaming.** The operator sees the final result, not intermediate progress.
- **No report template system.** One hardcoded HTML template.

### 1.8 Success criteria

Phase 1 is done when:

1. Operator sends "Create a competitive analysis report for Acme Corp" via cockpit
2. The Regent issues 3+ `web_search` calls, 1+ `web_fetch` calls, 2 `image_generate` calls, 1 `chart_generate` call, and 1 `report_assemble` call — all gated, all receipted
3. `~/ZeroPoint/artifacts/competitive-analysis.html` exists and renders correctly
4. `zp chain tail` shows the full execution trace (~25 receipts)
5. The content hash on chain matches `blake3(file contents)`
6. Revoking `web_search` delegation mid-task causes the Regent to adapt

### 1.9 Files changed (beyond Phase 0)

| File | Change |
|------|--------|
| `crates/zp-server/src/regent.rs` | Add `web_search`, `web_fetch`, `image_generate`, `chart_generate`, `report_assemble` arms to `dispatch_tool()`. Expand startup delegation. Increase max turns to 12. |
| `crates/zp-server/src/regent_tools.rs` (not yet written) | **New.** `generate_chart_html()`, `assemble_report_html()`, `strip_html()`, `save_to_artifacts()` |
| `crates/zp-regent/src/regent.rs` | Extend tool enumeration in `build_system_prompt()` |

### 1.10 Risk: model reliability

The riskiest assumption is that qwen3:8b reliably produces structured JSON intent output and decomposes multi-step tasks coherently. Mitigations:

- **Parse failures** fall through to `Intent::Respond` — safe but invisible. Add a `regent:intent:parse_failed` receipt in `reason()` so the chain records when parsing fails. This gives empirical data on model reliability without blocking progress.
- **Bad decomposition** (skipping steps, wrong tool, nonsensical params) produces a bad report. The chain records every step, so the failure is auditable. The fix is model selection, not architecture — try `mistral-small3.2` or `qwen3:14b` if `8b` can't handle it.
- **Infinite loops** (model keeps calling the same tool) are capped by `max_turns`. After 12 turns, the loop stops and the Regent reports what it has.

---

## Implementation order

1. `RegentError::Execution` variant
2. `IntentOutcome` enum in `loop_runner.rs`
3. Change `IntentExecutor::execute` return type → fix `ServerIntentExecutor` to match
4. Add `gate` field to `ServerIntentExecutor`, wire in `spawn_regent`
5. Gate evaluation + `dispatch_tool` in `Intent::Execute` arm (`chain_query` only)
6. Wire the loop runner's `OperatorInput` branch to actually call `cycle()`
7. Add `parse_intent()` and tool enumeration to `reason()` / `build_system_prompt()`
8. Regent delegation at startup
9. `./zp-dev.sh release` — test Phase 0 end-to-end
10. Add Phase 1 tools to `dispatch_tool()`, create `regent_tools.rs`
11. Expand delegation and system prompt
12. Test Phase 1 end-to-end

---

## Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture; the Regent as apex cognitive entity (Part II §6) and the substrate layers this implementation lands within.
- `docs/COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` — the eleven cognitive principles shaping what the Regent reasons about (three context flows, apex-is-slow, peer windows, context assembly as attention).
- `docs/EXECUTION-AUTHORITY-MODEL-2026-07.md` — the two-authority model this implementation slots into; the Regent as cognitive authority whose directives shape officer and sensor cadence.
- `docs/design/REGENT-ORCHESTRATION-ARCHITECTURE-2026-07.md` — the full seven-layer orchestration target this implementation begins to realize; this doc's Phase 1 = the orchestration doc's Phase 2 without formal TaskGraph.
- `docs/design/TOOL-OPACITY-AND-CAPABILITY-CLASSES-2026-07.md` — the capability class model the Regent's delegation grants project into.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — the trajectory-drift check the planner should observe before decomposing.
