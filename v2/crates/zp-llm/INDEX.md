# zp-llm Crate Index

## Quick Navigation

### Source Code

#### Core Module Files

- **`src/lib.rs`** (20 lines)
  - Package root and module declarations
  - Public API exports

- **`src/provider.rs`** (198 lines)
  - `LlmProvider` trait — core interface all providers implement
  - `ChatRole` enum — System, User, Assistant, Tool
  - `ChatMessage` struct — single conversation message
  - `CompletionRequest` — what we send to providers
  - `CompletionResponse` — what providers return
  - `Usage` — token counting
  - `ToolCall` — function invocation data
  - Tests for all types

- **`src/pool.rs`** (256 lines)
  - `ProviderPool` struct — manages multiple providers
  - `add_provider()` — register new providers
  - `select()` — risk-based provider selection (Any, Strong, RequireStrong, LocalOnly, Specific)
  - `health_check()` — async health monitoring
  - `provider_ids()`, `len()`, `is_empty()` — utility methods
  - Tests with MockProvider

- **`src/prompt.rs`** (111 lines)
  - `PromptBuilder` struct and implementation
  - `build()` — constructs clean completion requests
  - Merges operator identity + capabilities + conversation history
  - Explicitly excludes policy/governance info
  - Tests with/without conversation history

- **`src/validator.rs`** (163 lines)
  - `RequestValidator` struct
  - `validate_request()` — checks system_prompt, messages, temperature, max_tokens
  - `validate_response()` — checks content, model name, token counts
  - Tests for all validation scenarios

#### Provider Implementations

- **`src/providers/mod.rs`** (7 lines)
  - Module declarations for anthropic and ollama
  - Re-exports for public API

- **`src/providers/anthropic.rs`** (298 lines)
  - `AnthropicProvider` struct
  - Real HTTP implementation using reqwest
  - Calls `https://api.anthropic.com/v1/messages`
  - Handles message conversion to Anthropic format
  - Parses Anthropic response (text + tool_use blocks)
  - Token counting from API response
  - Health checks via test API calls
  - Tests for provider creation

- **`src/providers/ollama.rs`** (224 lines)
  - `OllamaProvider` struct
  - Real HTTP implementation using reqwest
  - Calls `{base_url}/api/chat` for completions
  - Calls `{base_url}/api/tags` for health checks
  - Configurable base URL (default localhost:11434)
  - Message conversion to Ollama format
  - Approximate token counting
  - Tests for provider creation and custom URLs

#### Package Configuration

- **`Cargo.toml`** (35 lines)
  - Package metadata
  - Dependencies from workspace (async-trait, reqwest, serde, tokio, etc.)
  - zp-core path dependency

### Documentation

- **`README.md`** (126 lines)
  - High-level architecture overview
  - Component descriptions
  - Provider selection logic
  - Provider capabilities structure
  - Health checking system
  - Prompt building explanation
  - Error handling approach
  - Dependency list

- **`PROVIDERS.md`** (207 lines)
  - Anthropic provider details and configuration
  - Ollama provider details and configuration
  - Capabilities tables for each provider
  - API integration specifics
  - Health checking behavior
  - Usage example
  - How to add new providers

- **`EXAMPLES.md`** (319 lines)
  - Complete provider pool setup
  - Risk-based routing examples (Any, Strong, RequireStrong, LocalOnly, Specific)
  - Prompt building examples
  - Full completion workflow
  - Custom provider implementation
  - Error handling patterns
  - Unit test examples

- **`BUILD_SUMMARY.md`** (this document's reference)
  - Build overview and statistics
  - Architecture diagram
  - Key design decisions
  - Dependency documentation
  - Integration points
  - Building and testing commands
  - Security considerations
  - Future enhancement ideas

- **`INDEX.md`** (this file)
  - Navigation guide
  - File descriptions and sizes

## Type Hierarchy

```
zp_core::ZpError
  ↑
  └─ zp_llm::CompletionRequest
  └─ zp_llm::CompletionResponse
  └─ zp_llm::ChatMessage
  └─ zp_llm::ToolCall
  └─ zp_llm::Usage

zp_core::ProviderId
  ↑
  └─ AnthropicProvider
  └─ OllamaProvider
  └─ (any custom provider)

zp_core::ProviderCapabilities
  ↑
  └─ LlmProvider::capabilities()

zp_core::ProviderHealth
  ↑
  └─ LlmProvider::health()

zp_core::ModelClass
  ↑
  └─ ProviderPool::select()

zp_core::ModelPreference
  ↑
  └─ ProviderPool::select()
```

## Public API

### Main Exports (from lib.rs)

```rust
pub use provider::{
    LlmProvider, CompletionRequest, CompletionResponse, ChatMessage, ChatRole,
    ToolCall, Usage,
};
pub use pool::ProviderPool;
pub use prompt::PromptBuilder;
pub use zp_core::{ProviderId, ProviderCapabilities, ProviderHealth, ZpError};
```

### Key Structs & Traits

| Name | Module | Type | Purpose |
|------|--------|------|---------|
| `LlmProvider` | provider | Trait | Core provider interface |
| `ProviderPool` | pool | Struct | Multi-provider management |
| `PromptBuilder` | prompt | Struct | Request builder |
| `RequestValidator` | validator | Struct | Request/response validation |
| `AnthropicProvider` | providers::anthropic | Struct | Claude API implementation |
| `OllamaProvider` | providers::ollama | Struct | Local model implementation |
| `CompletionRequest` | provider | Struct | API request payload |
| `CompletionResponse` | provider | Struct | API response payload |
| `ChatMessage` | provider | Struct | Single message |
| `ChatRole` | provider | Enum | Message role (System, User, Assistant, Tool) |
| `Usage` | provider | Struct | Token usage stats |
| `ToolCall` | provider | Struct | Function invocation |

## Testing Strategy

- **Unit tests** in each module test core functionality
- **Mock providers** used for pool testing (avoid external API calls)
- **Validation tests** cover all error paths
- Tests organized with `#[cfg(test)]` modules

Run tests:
```bash
cargo test -p zp-llm
cargo test -p zp-llm -- --nocapture  # with output
```

## Code Statistics

| Category | Count |
|----------|-------|
| Rust source files | 7 |
| Documentation files | 4 |
| Total lines of Rust code | ~1,445 |
| Total lines of documentation | ~751 |
| Number of public types | 12+ |
| Number of traits | 1 |
| Number of test modules | 5 |
| Number of provider implementations | 2 |

## Integration Checklist

When using zp-llm in other crates:

- [ ] Add `zp-llm` to dependencies in `Cargo.toml`
- [ ] Import `ProviderPool` and specific providers
- [ ] Initialize pool in system startup
- [ ] Configure providers with API keys/URLs
- [ ] Pass `ModelPreference` from policy decisions to `pool.select()`
- [ ] Use `PromptBuilder` to construct requests
- [ ] Execute `provider.complete()` and handle `CompletionResponse`
- [ ] Add error handling for `ZpError`

## Module Dependencies

```
lib.rs
  ├── provider.rs (core types, LlmProvider trait)
  ├── pool.rs (depends on provider.rs)
  ├── prompt.rs (depends on provider.rs, zp-core)
  ├── validator.rs (depends on provider.rs)
  └── providers/
      ├── anthropic.rs (depends on provider.rs, external: reqwest, serde)
      └── ollama.rs (depends on provider.rs, external: reqwest, serde)
```

## Quick Start

1. **Create pool**:
   ```rust
   let mut pool = ProviderPool::new();
   ```

2. **Add providers**:
   ```rust
   pool.add_provider(Box::new(AnthropicProvider::new(api_key, model)));
   pool.add_provider(Box::new(OllamaProvider::new(model)));
   ```

3. **Build request**:
   ```rust
   let request = PromptBuilder::build(&identity, &capabilities, &history, user_msg);
   ```

4. **Select provider**:
   ```rust
   let provider = pool.select(&preference)?;
   ```

5. **Execute**:
   ```rust
   let response = provider.complete(&request).await?;
   ```

---

**See EXAMPLES.md for comprehensive usage examples.**
