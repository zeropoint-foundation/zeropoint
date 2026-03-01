# ZeroPoint Server Architecture

## Overview

The `zp-server` crate is a thin HTTP adapter that exposes the ZeroPoint Pipeline over REST APIs. It follows the adapter pattern: HTTP requests are deserialized, passed to the pipeline, and responses are serialized back to JSON.

## Module Structure

### `src/main.rs` — Server Entry Point

**Responsibilities:**
- Tracing initialization (structured logging with EnvFilter)
- Environment variable configuration loading
- Pipeline initialization with subsystems
- Router construction with all endpoints
- HTTP server binding and startup

**Key Components:**
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize tracing subscriber
    // 2. Load environment configuration
    //    - ZP_OPERATOR_NAME, ZP_OPERATOR_PROMPT
    //    - ZP_TRUST_TIER (tier0/tier1/tier2)
    //    - ZP_DATA_DIR
    //    - ZP_PORT
    // 3. Create PipelineConfig
    // 4. Initialize Pipeline (which initializes all subsystems)
    // 5. Wrap Pipeline in Arc as shared state
    // 6. Build axum Router with routes
    // 7. Add CORS middleware (permissive for dev)
    // 8. Start server on 0.0.0.0:<port>
}
```

**Routes:**
- `POST /api/v1/chat` → `chat_handler`
- `GET /api/v1/conversations` → `list_conversations`
- `POST /api/v1/conversations` → `create_conversation`
- `GET /api/v1/skills` → `list_skills`
- `GET /api/v1/health` → `health_check`
- `GET /api/v1/audit/:conversation_id` → `get_audit`

### `src/state.rs` — Application State

**Simple type alias:**
```rust
pub type AppState = Arc<Pipeline>;
```

**Purpose:**
- Single source of truth for shared state across all handlers
- Wrapped in Arc for thread-safe reference counting
- Passed to handlers via axum's State extractor

**Usage:**
```rust
pub async fn some_handler(
    State(pipeline): State<AppState>,
) -> Json<Response> {
    // pipeline is Arc<Pipeline>
    let conv_id = pipeline.new_conversation();
    // ...
}
```

### `src/handlers.rs` — HTTP Handlers

**Provides:**

1. **Request/Response DTOs:**
   - `ChatRequest` / `ChatResponse`
   - `ConversationResponse`
   - `SkillListResponse`
   - `HealthResponse`
   - `AuditResponse`
   - `ErrorResponse`

2. **Handler Functions:**
   - `chat_handler(POST /api/v1/chat)` — Core message handling
   - `create_conversation(POST /api/v1/conversations)` — Create new conv
   - `list_conversations(GET /api/v1/conversations)` — List active convs
   - `list_skills(GET /api/v1/skills)` — Get registered skills
   - `health_check(GET /api/v1/health)` — Health status
   - `get_audit(GET /api/v1/audit/:id)` — Retrieve audit trail

**Design Pattern:**
```
HTTP Request
    ↓
Handler (deserialize JSON)
    ↓
Call Pipeline method
    ↓
Handle result/errors
    ↓
Serialize response
    ↓
HTTP Response (JSON)
```

## Request Flow

### Chat Request Flow

```
1. POST /api/v1/chat
   {
     "conversation_id": "uuid (optional)",
     "message": "user message"
   }

2. chat_handler receives request
   ├─ Parse/validate conversation_id (create if needed)
   ├─ Create Request object (zp_core::Request)
   └─ Call pipeline.handle(request)

3. Pipeline processes request (in zp-pipeline)
   ├─ Policy evaluation
   ├─ Skill matching
   ├─ LLM provider selection
   ├─ Prompt building
   ├─ LLM invocation
   ├─ Audit logging
   ├─ Learning episode recording
   └─ Return Response

4. Handler receives Response
   ├─ Extract response content
   ├─ Extract model used
   └─ Return ChatResponse JSON

5. Response sent to client
   {
     "conversation_id": "uuid",
     "response": "assistant message",
     "model_used": "gpt-4"
   }
```

## Error Handling

Handlers return `Result<Json<T>, (StatusCode, Json<ErrorResponse>)>`

**Status Codes:**
- `200 OK` — Success
- `400 Bad Request` — Invalid input (bad UUID format, etc)
- `500 Internal Server Error` — Pipeline errors, DB errors, etc

**Error Response Format:**
```json
{
  "error": "Human-readable error message"
}
```

## Configuration

Environment variables are loaded in this precedence:
1. Actual environment variable
2. Default value (hardcoded in main.rs)

| Env Var | Default | Type | Purpose |
|---------|---------|------|---------|
| `ZP_PORT` | `3000` | u16 | Server listen port |
| `ZP_OPERATOR_NAME` | `"ZeroPoint"` | String | Operator identity |
| `ZP_OPERATOR_PROMPT` | (long default) | String | Base system prompt |
| `ZP_TRUST_TIER` | `"tier0"` | String | Trust tier: tier0/tier1/tier2 |
| `ZP_DATA_DIR` | `"./data/zeropoint"` | String | Persistent data directory |
| `RUST_LOG` | (not set) | String | Tracing filter (e.g., "debug") |

Example startup with custom config:
```bash
RUST_LOG=debug \
ZP_PORT=3000 \
ZP_TRUST_TIER=tier1 \
ZP_OPERATOR_NAME="MyOperator" \
cargo run --bin zp-server
```

## Concurrency Model

- **Async Runtime**: Tokio full runtime
- **Shared State**: Pipeline is Arc-wrapped (thread-safe)
- **Per-Request**: Handlers are spawned as separate async tasks
- **No Locking**: Pipeline methods handle their own synchronization
- **Message Store**: Pipeline maintains in-memory HashMap<ConversationId, Vec<Message>>

## Dependencies

**Workspace Dependencies:**
- `axum 0.7` — HTTP server framework, routing
- `tower-http 0.5` — CORS middleware, HTTP utilities
- `tokio 1.35` — Async runtime (with full features)
- `serde 1.0` — Serialization framework
- `serde_json 1.0` — JSON serialization
- `tracing 0.1` — Structured logging
- `tracing-subscriber 0.3` — Logging subscriber with env-filter
- `uuid 1.10` — UUID type and generation
- `chrono 0.4` — Date/time handling

**Path Dependencies:**
- `zp-core` — Core types (Request, Response, ConversationId, etc)
- `zp-pipeline` — Central pipeline orchestrator

## Key Design Decisions

1. **Thin Adapter**: Server is minimal; core logic is in pipeline
2. **Stateless Handlers**: Handlers are pure functions over AppState
3. **Env Configuration**: Flexible deployment without config files
4. **Async Throughout**: Full async/await for scalability
5. **Error Mapping**: HTTP errors properly mapped to status codes
6. **Structured Logging**: All operations traced for debugging
7. **Arc Sharing**: Single pipeline instance shared across all requests
8. **Permissive CORS**: For development; tighten in production

## Future Considerations

- **WebSocket Support**: Real-time streaming responses
- **Request Validation**: Middleware for input validation
- **Authentication**: OAuth2/API key middleware
- **Rate Limiting**: Per-client rate limiting
- **Conversation Persistence**: Load conversations from DB
- **Response Streaming**: Chunk-encoded LLM responses
- **Metrics**: Prometheus metrics export
- **Request Tracing**: Distributed tracing (e.g., Jaeger)
- **API Versioning**: Support multiple API versions
- **Graceful Shutdown**: Signal handling for clean server shutdown

## Testing

Current code is ready for:
- Unit tests in `#[cfg(test)]` modules
- Integration tests with HTTP client
- Load testing with cargo-flamegraph or similar
- Property-based testing with proptest

## Performance Characteristics

- **Startup**: ~1-2 seconds (policy engine, skill registry, DB init)
- **Request Latency**: Dominated by LLM provider latency (usually 500ms-30s)
- **Memory**: Pipeline holds conversation history in RAM (configurable)
- **Scalability**: Can handle hundreds of concurrent requests with tokio

## Operational Notes

- Server does NOT implement graceful shutdown signals yet
- Conversation history is lost on restart (in-memory storage)
- Audit trail persists in SQLite
- Policy modules are loaded from disk on startup
- Skills are registered at runtime (extensible)
