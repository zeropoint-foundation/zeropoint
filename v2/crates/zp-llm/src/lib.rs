//! ZeroPoint v2 LLM Provider Pool — risk-based routing for language model completions.
//!
//! This crate manages a pool of LLM providers (Anthropic, Ollama, etc.) and routes
//! completion requests based on risk assessment, model preferences, and provider health.
//! The pool is responsible for selecting the best available provider for a given request.

pub mod pool;
pub mod prompt;
pub mod provider;
pub mod providers;
pub mod validator;

// Re-exports
pub use pool::ProviderPool;
pub use prompt::PromptBuilder;
pub use provider::{
    ChatMessage, ChatRole, CompletionRequest, CompletionResponse, LlmProvider, ToolCall, Usage,
};
pub use zp_core::{ProviderCapabilities, ProviderHealth, ProviderId, ZpError};
