//! Anthropic API provider implementation.

use crate::provider::{
    ChatRole, CompletionRequest, CompletionResponse, LlmProvider, ToolCall, Usage,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error, warn};
use zp_core::{ProviderCapabilities, ProviderHealth, ProviderId, ZpError};

/// Anthropic API provider.
pub struct AnthropicProvider {
    id: ProviderId,
    api_key: String,
    model_name: String,
    capabilities: ProviderCapabilities,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<AnthropicTool>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: Vec<AnthropicContent>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum AnthropicContent {
    Text {
        #[serde(rename = "type")]
        type_: String,
        text: String,
    },
    ToolUse {
        #[serde(rename = "type")]
        type_: String,
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

#[derive(Debug, Serialize)]
struct AnthropicTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicResponseContent>,
    model: String,
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum AnthropicResponseContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider.
    pub fn new(api_key: String, model_name: String) -> Self {
        let id = ProviderId::new(&format!("anthropic-{}", model_name));
        Self {
            id: id.clone(),
            api_key,
            model_name: model_name.clone(),
            capabilities: ProviderCapabilities {
                is_local: false,
                max_context: 200_000, // Claude 3.5 Sonnet context window
                supports_tools: true,
                strength: 0.95, // Very strong model
                model_name,
            },
        }
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, ZpError> {
        debug!("Anthropic: Starting completion request");

        // Convert messages to Anthropic format
        let mut messages = Vec::new();
        for msg in &request.messages {
            let content = match msg.role {
                ChatRole::System => {
                    // System messages are handled separately in Anthropic API
                    continue;
                }
                ChatRole::User => vec![AnthropicContent::Text {
                    type_: "text".to_string(),
                    text: msg.content.clone(),
                }],
                ChatRole::Assistant => vec![AnthropicContent::Text {
                    type_: "text".to_string(),
                    text: msg.content.clone(),
                }],
                ChatRole::Tool => vec![AnthropicContent::Text {
                    type_: "text".to_string(),
                    text: msg.content.clone(),
                }],
            };

            messages.push(AnthropicMessage {
                role: match msg.role {
                    ChatRole::System => continue,
                    ChatRole::User | ChatRole::Tool => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                },
                content,
            });
        }

        // Convert tools
        let tools: Vec<AnthropicTool> = request
            .tools
            .iter()
            .map(|tool| AnthropicTool {
                name: tool.name.clone(),
                description: tool.description.clone(),
                input_schema: tool.parameters.clone(),
            })
            .collect();

        let anthropic_request = AnthropicRequest {
            model: request
                .model
                .clone()
                .unwrap_or_else(|| self.model_name.clone()),
            max_tokens: request.max_tokens.unwrap_or(4096),
            system: request.system_prompt.clone(),
            messages,
            temperature: request.temperature,
            tools,
        };

        debug!("Anthropic: Sending request to API");
        let client = reqwest::Client::new();
        let start = Instant::now();

        let response = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&anthropic_request)
            .send()
            .await
            .map_err(|e| {
                error!("Anthropic API request failed: {}", e);
                ZpError::ProviderError {
                    provider: self.id.0.clone(),
                    message: format!("API request failed: {}", e),
                }
            })?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            error!("Failed to read Anthropic response body: {}", e);
            ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: format!("Failed to read response: {}", e),
            }
        })?;

        if !status.is_success() {
            error!("Anthropic API error: {} {}", status, response_text);
            return Err(ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: format!("API returned {}: {}", status, response_text),
            });
        }

        let anthropic_response: AnthropicResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                error!("Failed to parse Anthropic response: {}", e);
                ZpError::ProviderError {
                    provider: self.id.0.clone(),
                    message: format!("Failed to parse response: {}", e),
                }
            })?;

        let elapsed = start.elapsed().as_millis() as u64;
        debug!("Anthropic: Request completed in {}ms", elapsed);

        // Extract content and tool calls
        let mut content = String::new();
        let mut tool_calls = Vec::new();

        for item in anthropic_response.content {
            match item {
                AnthropicResponseContent::Text { text } => {
                    content.push_str(&text);
                }
                AnthropicResponseContent::ToolUse {
                    id: _id,
                    name,
                    input,
                } => {
                    tool_calls.push(ToolCall {
                        tool_name: name,
                        arguments: input,
                    });
                }
            }
        }

        Ok(CompletionResponse {
            content,
            tool_calls,
            model: anthropic_response.model,
            usage: Usage {
                prompt_tokens: anthropic_response.usage.input_tokens,
                completion_tokens: anthropic_response.usage.output_tokens,
            },
        })
    }

    async fn health(&self) -> ProviderHealth {
        debug!("Anthropic: Checking health");
        let client = reqwest::Client::new();
        let start = Instant::now();

        // Make a simple API call to check health
        let request = AnthropicRequest {
            model: self.model_name.clone(),
            max_tokens: 10,
            system: "You are a test.".to_string(),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: vec![AnthropicContent::Text {
                    type_: "text".to_string(),
                    text: "test".to_string(),
                }],
            }],
            temperature: None,
            tools: vec![],
        };

        match client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send()
            .await
        {
            Ok(response) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                if response.status().is_success() {
                    ProviderHealth::Healthy { latency_ms }
                } else {
                    warn!(
                        "Anthropic health check returned status: {}",
                        response.status()
                    );
                    ProviderHealth::Degraded {
                        reason: format!("API returned {}", response.status()),
                    }
                }
            }
            Err(e) => {
                warn!("Anthropic health check failed: {}", e);
                ProviderHealth::Unavailable {
                    reason: format!("API unreachable: {}", e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_creation() {
        let provider = AnthropicProvider::new(
            "test-key".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );
        assert_eq!(provider.id().0, "anthropic-claude-3-5-sonnet-20241022");
        assert_eq!(provider.capabilities().strength, 0.95);
        assert!(!provider.capabilities().is_local);
    }
}
