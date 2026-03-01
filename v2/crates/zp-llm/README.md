# zp-llm — LLM Provider Pool with Risk-Based Routing

The LLM provider pool for ZeroPoint v2, managing multiple language model providers with intelligent routing based on risk assessment, model capabilities, and health status.

## Architecture

### Core Components

- **provider.rs** — `LlmProvider` trait and request/response types
  - `ChatMessage`, `ChatRole` — conversation structure
  - `CompletionRequest`, `CompletionResponse` — API contracts
  - `Usage` — token accounting
  - `ToolCall` — function invocation data

- **pool.rs** — `ProviderPool` for multi-provider management
  - Provider registration and health checking
  - Risk-based provider selection matching `ModelClass` preferences
  - Async health status aggregation

- **prompt.rs** — `PromptBuilder` for clean prompt construction
  - Builds requests from operator identity and conversation history
  - Tools injected from capabilities
  - No governance or policy details in prompts (clean separation)

- **validator.rs** — Request/response validation
  - Validates temperature, max_tokens, content
  - Ensures API contract compliance

- **providers/** — LLM provider implementations
  - **anthropic.rs** — Anthropic API (Claude)
    - Real HTTP implementation using reqwest
    - Full tool support and token counting
    - Health checks via test API calls
  - **ollama.rs** — Ollama local models
    - Calls `/api/chat` endpoint
    - Local-only routing (is_local=true)
    - No tool support (most local models don't support it well)

## Provider Selection Logic

The `ProviderPool::select()` method implements risk-aware routing:

```rust
pub fn select(&self, preference: &ModelPreference) -> Result<&dyn LlmProvider, ZpError>
```

Routing decisions by `ModelClass`:

- **Any** — Returns first available provider (low-risk requests)
- **Strong** — Selects provider with highest strength rating (medium-risk)
- **RequireStrong** — Enforces strength > 0.7 (critical-risk, policy-required)
- **LocalOnly** — Selects first local provider only (data-sensitive actions)
- **Specific(name)** — Routes to specific provider by ID or model name (user override)

## Provider Capabilities

Each provider exposes:

```rust
pub struct ProviderCapabilities {
    pub is_local: bool,           // Local execution (privacy-sensitive)
    pub max_context: usize,        // Context window size
    pub supports_tools: bool,      // Function calling support
    pub strength: f64,             // Capability rating (0.0-1.0)
    pub model_name: String,        // Provider's model identifier
}
```

## Health Checking

Asynchronous health monitoring:

```rust
pub async fn health_check(&self) -> Vec<(ProviderId, ProviderHealth)>
```

Returns status for all providers:

- **Healthy { latency_ms }** — Responding normally
- **Degraded { reason }** — Slow or partially working
- **Unavailable { reason }** — Cannot reach service

## Prompt Building

The `PromptBuilder` creates clean prompts with only essential context:

```rust
pub fn build(
    identity: &OperatorIdentity,
    capabilities: &[Capability],
    history: &[Message],
    user_message: &str,
) -> CompletionRequest
```

Includes only:
- System prompt (operator identity)
- Tool definitions (from active capabilities)
- Conversation history
- Current user message

**Explicitly excludes:**
- Policy decisions
- Verification status
- Governance information
- Audit trails

This keeps the LLM focused on task completion without governance noise.

## Error Handling

All operations use `ZpError` for consistent error reporting:

- `ZpError::NoProvider` — No provider available for preference
- `ZpError::ProviderError { provider, message }` — Provider-specific failure
- Standard validation errors via `ZpError::Config`

## Dependencies

- **zp-core** — Type definitions and traits
- **async-trait** — Async trait support
- **reqwest** — HTTP client (with TLS and streaming)
- **serde/serde_json** — Serialization
- **tokio** — Async runtime
- **tracing** — Structured logging
- **thiserror** — Error handling
