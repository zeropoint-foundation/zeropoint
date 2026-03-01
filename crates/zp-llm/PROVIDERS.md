# LLM Provider Implementations

## Anthropic Provider

Real-world implementation for Claude models via the Anthropic API.

### Features

- Full support for Claude 3.5 Sonnet, Claude 3 Opus, and other Claude models
- Tool use (function calling) support
- Streaming response support ready (non-streaming implemented)
- Token counting via API response
- Health checks via test API calls
- High strength rating (0.95) — strong models suitable for complex reasoning

### Configuration

```rust
use zp_llm::AnthropicProvider;

let provider = AnthropicProvider::new(
    "sk-ant-...".to_string(),  // API key from ANTHROPIC_API_KEY
    "claude-3-5-sonnet-20241022".to_string(),
);
```

### Capabilities

| Property | Value |
|----------|-------|
| is_local | false |
| max_context | 200,000 tokens |
| supports_tools | true |
| strength | 0.95 |
| model_name | claude-3-5-sonnet-20241022 |

### API Integration Details

- **Endpoint:** `https://api.anthropic.com/v1/messages`
- **Headers:** `x-api-key`, `anthropic-version: 2023-06-01`
- **Request Format:** Converts `CompletionRequest` to Anthropic message format
- **Response Format:** Parses Anthropic response with text and tool_use content blocks
- **Error Handling:** Maps API errors to `ZpError::ProviderError`

### Health Checking

Sends a test message ("test") to the API. Reports:
- **Healthy** if API responds with 2xx status
- **Degraded** if API returns non-2xx but is reachable
- **Unavailable** if connection fails

---

## Ollama Provider

Local LLM execution via Ollama API.

### Features

- Run open-source models locally (Mistral, Llama, Phi, etc.)
- No external API calls — full privacy and data residency
- Configurable base URL for remote Ollama instances
- Health checks via `/api/tags` endpoint
- Appropriate strength rating (0.6) for local models

### Configuration

```rust
use zp_llm::OllamaProvider;

// Default (localhost:11434)
let provider = OllamaProvider::new("mistral".to_string());

// Custom host/port
let provider = OllamaProvider::with_base_url(
    "http://192.168.1.100:11434".to_string(),
    "llama2".to_string(),
);
```

### Capabilities

| Property | Value |
|----------|-------|
| is_local | true |
| max_context | 4,096 tokens |
| supports_tools | false |
| strength | 0.6 |
| model_name | (from constructor) |

### API Integration Details

- **Endpoint:** `{base_url}/api/chat` (non-streaming)
- **Health Endpoint:** `{base_url}/api/tags`
- **Request Format:** Converts to Ollama chat format with system message
- **Response Format:** Parses Ollama chat response
- **Token Counting:** Uses approximate counts from API response

### Health Checking

Calls `/api/tags` endpoint to check if Ollama is running. Reports:
- **Healthy** if endpoint responds with 2xx
- **Degraded** if endpoint returns non-2xx
- **Unavailable** if Ollama is not reachable

---

## Usage Example

```rust
use zp_llm::{ProviderPool, PromptBuilder, CompletionRequest};
use zp_core::ModelClass;

// Set up providers
let mut pool = ProviderPool::new();

// Add Anthropic provider
pool.add_provider(Box::new(AnthropicProvider::new(
    std::env::var("ANTHROPIC_API_KEY").unwrap(),
    "claude-3-5-sonnet-20241022".to_string(),
)));

// Add local Ollama provider
pool.add_provider(Box::new(OllamaProvider::new(
    "mistral".to_string(),
)));

// Build request
let request = PromptBuilder::build(
    &operator_identity,
    &active_capabilities,
    &conversation_history,
    "What's the capital of France?",
);

// Select provider based on risk
let preference = ModelPreference {
    preference: ModelClass::Strong,  // Use strong model
    reason: "Medium-risk task".to_string(),
    overridable: true,
};

let provider = pool.select(&preference)?;

// Execute completion
let response = provider.complete(&request).await?;
println!("Response: {}", response.content);
println!("Model used: {}", response.model);
```

---

## Adding New Providers

To implement a new LLM provider:

1. **Create a struct** implementing `LlmProvider`:

```rust
pub struct MyProvider {
    id: ProviderId,
    capabilities: ProviderCapabilities,
    // ... provider-specific fields
}
```

2. **Implement the trait**:

```rust
#[async_trait]
impl LlmProvider for MyProvider {
    fn id(&self) -> &ProviderId { /* ... */ }
    fn capabilities(&self) -> &ProviderCapabilities { /* ... */ }
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, ZpError> {
        // Convert CompletionRequest to provider format
        // Make HTTP/RPC call
        // Convert response back to CompletionResponse
    }
    async fn health(&self) -> ProviderHealth { /* ... */ }
}
```

3. **Add module** in `src/providers/mod.rs`

4. **Test** with mock implementations if needed

---

## Provider Selection Strategy

The pool's `select()` method implements risk-aware routing:

```
Request comes in with ModelClass preference
    ↓
Pool evaluates all providers
    ↓
For ModelClass::Any → First available (low risk)
For ModelClass::Strong → Highest strength (medium risk)
For ModelClass::RequireStrong → Strength > 0.7 only (high risk)
For ModelClass::LocalOnly → Local providers only (data sensitive)
For ModelClass::Specific(name) → Exact match (user override)
    ↓
Return selected provider or ZpError::NoProvider
```

This ensures the right model is used for the right risk level.
