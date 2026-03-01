# ZeroPoint HTTP Server (zp-server)

A thin HTTP/WebSocket server that exposes the ZeroPoint Pipeline as REST APIs.

## Architecture

The server follows a thin adapter pattern:
- **HTTP Layer**: Axum-based router that handles HTTP requests/responses
- **Pipeline Delegation**: All business logic is delegated to `zp-pipeline`
- **Shared State**: The Pipeline is wrapped in `Arc` and shared across all handlers
- **Configuration**: Environment variable-based configuration for operator identity, trust tier, and port

## API Endpoints

All endpoints are under `/api/v1/`.

### Chat (Message Handling)
```
POST /api/v1/chat
Content-Type: application/json

{
  "conversation_id": "optional-uuid",
  "message": "User message text"
}

Response:
{
  "conversation_id": "uuid",
  "response": "Assistant response text",
  "model_used": "model-name"
}
```

### Conversations

**Create a new conversation:**
```
POST /api/v1/conversations

Response:
{
  "id": "new-conversation-uuid"
}
```

**List active conversations:**
```
GET /api/v1/conversations

Response:
{
  "conversations": []
}
```

### Skills

**List registered skills:**
```
GET /api/v1/skills

Response:
{
  "skills": ["skill1", "skill2", ...]
}
```

### Health Check

```
GET /api/v1/health

Response:
{
  "status": "ok",
  "version": "0.1.0"
}
```

### Audit Trail

**Get audit entries for a conversation:**
```
GET /api/v1/audit/:conversation_id

Response:
{
  "conversation_id": "uuid",
  "entry_count": 5,
  "entries": [
    { /* audit entry as JSON */ },
    ...
  ]
}
```

## Configuration

Configuration is loaded from environment variables with sensible defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `ZP_PORT` | `3000` | Server port |
| `ZP_OPERATOR_NAME` | `ZeroPoint` | Operator name for prompts |
| `ZP_OPERATOR_PROMPT` | (default prompt) | Custom base prompt for the operator |
| `ZP_TRUST_TIER` | `tier0` | Trust tier: `tier0`, `tier1`, or `tier2` |
| `ZP_DATA_DIR` | `./data/zeropoint` | Directory for persistent data |
| `RUST_LOG` | `info` | Tracing subscriber log level |

## Server Startup

The server:

1. Initializes the tracing subscriber (logs to stdout)
2. Loads configuration from environment or defaults
3. Creates a Pipeline instance with the configuration
4. Initializes all pipeline subsystems (policy, skills, audit, LLM, learning)
5. Sets up the HTTP router with all endpoints
6. Adds CORS middleware (permissive for development)
7. Binds to `0.0.0.0:<port>` and starts serving

Example startup:

```bash
RUST_LOG=debug ZP_PORT=3001 ZP_TRUST_TIER=tier1 cargo run --bin zp-server
```

## Code Structure

- **`src/main.rs`** — Server entry point
  - Tracing initialization
  - Environment configuration loading
  - Pipeline creation and initialization
  - Router setup with routes and middleware
  - HTTP server binding and startup

- **`src/state.rs`** — Application state
  - Type alias: `AppState = Arc<Pipeline>`
  - Used by axum's State extractor in handlers

- **`src/handlers.rs`** — Route handler functions
  - Request/response DTOs
  - Handler implementations for each endpoint
  - Error handling and HTTP status codes
  - Logging and instrumentation

## Design Principles

1. **Thin Adapter Pattern**: The server is just a thin HTTP adapter over the pipeline. All core logic lives in `zp-pipeline`.

2. **Minimal State**: The only shared state is the Arc-wrapped Pipeline instance.

3. **Synchronous Pipeline**: The Pipeline.handle() method is async, but individual subsystem calls are often synchronous (e.g., AuditStore.get_entries()).

4. **Error Handling**: HTTP errors are properly mapped to status codes and JSON error responses.

5. **Instrumentation**: All handlers use structured logging (tracing) for visibility.

6. **Configuration**: Environment-based configuration for deployment flexibility.

## Dependencies

From workspace:
- `axum` — HTTP server framework
- `tower-http` — Tower HTTP middleware (CORS)
- `tokio` — Async runtime
- `serde`/`serde_json` — Serialization
- `tracing`/`tracing-subscriber` — Structured logging

From path:
- `zp-core` — Core types (Request, Response, etc.)
- `zp-pipeline` — The central pipeline orchestrator

## Future Enhancements

- WebSocket support for real-time chat
- Request validation middleware
- Authentication/authorization middleware
- Rate limiting
- Conversation history storage in persistent backend
- Streaming response support
