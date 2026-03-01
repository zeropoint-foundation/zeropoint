//! Core LLM provider trait and request/response types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zp_core::{ProviderCapabilities, ProviderHealth, ProviderId, ToolDefinition, ZpError};

/// Core trait that all LLM providers must implement.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Return this provider's unique identifier.
    fn id(&self) -> &ProviderId;

    /// Return the provider's capabilities (local, context window, tool support, etc.).
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Execute a completion request.
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, ZpError>;

    /// Check provider health status.
    async fn health(&self) -> ProviderHealth;
}

/// Chat message role.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    /// System instruction message
    System,
    /// User message
    User,
    /// Assistant response
    Assistant,
    /// Tool execution result
    Tool,
}

/// A single message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// The role of the message sender
    pub role: ChatRole,
    /// The message content
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: String) -> Self {
        Self {
            role: ChatRole::System,
            content,
        }
    }

    pub fn user(content: String) -> Self {
        Self {
            role: ChatRole::User,
            content,
        }
    }

    pub fn assistant(content: String) -> Self {
        Self {
            role: ChatRole::Assistant,
            content,
        }
    }

    pub fn tool(content: String) -> Self {
        Self {
            role: ChatRole::Tool,
            content,
        }
    }
}

/// Token usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// Number of tokens in the prompt
    pub prompt_tokens: u32,
    /// Number of tokens in the completion
    pub completion_tokens: u32,
}

impl Usage {
    pub fn total(&self) -> u32 {
        self.prompt_tokens + self.completion_tokens
    }
}

/// Tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// The name of the tool being called
    pub tool_name: String,
    /// The arguments to pass (as a JSON value)
    pub arguments: serde_json::Value,
}

/// Request to complete a prompt with an LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// System prompt (operator identity instructions)
    pub system_prompt: String,
    /// Conversation history
    pub messages: Vec<ChatMessage>,
    /// Available tools
    pub tools: Vec<ToolDefinition>,
    /// Specific model name to use (if set by user)
    pub model: Option<String>,
    /// Maximum tokens to generate
    pub max_tokens: Option<u32>,
    /// Sampling temperature (0.0 to 2.0)
    pub temperature: Option<f32>,
}

impl CompletionRequest {
    pub fn new(
        system_prompt: String,
        messages: Vec<ChatMessage>,
        tools: Vec<ToolDefinition>,
    ) -> Self {
        Self {
            system_prompt,
            messages,
            tools,
            model: None,
            max_tokens: None,
            temperature: None,
        }
    }

    pub fn with_model(mut self, model: String) -> Self {
        self.model = Some(model);
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }
}

/// Response from an LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// The generated text content
    pub content: String,
    /// Tool calls made by the model
    pub tool_calls: Vec<ToolCall>,
    /// Which model was actually used
    pub model: String,
    /// Token usage statistics
    pub usage: Usage,
}

impl CompletionResponse {
    pub fn new(content: String, model: String, usage: Usage) -> Self {
        Self {
            content,
            tool_calls: vec![],
            model,
            usage,
        }
    }

    pub fn with_tool_calls(mut self, tool_calls: Vec<ToolCall>) -> Self {
        self.tool_calls = tool_calls;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_message_constructors() {
        let system = ChatMessage::system("Be helpful".to_string());
        assert_eq!(system.role, ChatRole::System);

        let user = ChatMessage::user("Hello".to_string());
        assert_eq!(user.role, ChatRole::User);

        let assistant = ChatMessage::assistant("Hi there".to_string());
        assert_eq!(assistant.role, ChatRole::Assistant);
    }

    #[test]
    fn test_usage_total() {
        let usage = Usage {
            prompt_tokens: 10,
            completion_tokens: 20,
        };
        assert_eq!(usage.total(), 30);
    }
}
