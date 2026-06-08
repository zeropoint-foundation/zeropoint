//! Ollama API provider implementation (local models).
//!
//! Tool calling is supported for models that implement it (llama3.1+,
//! qwen2.5, mistral-nemo, command-r, etc.) via the OpenAI-compatible
//! tools field on `/api/chat`. Pass `supports_tools: true` to
//! `OllamaProvider::with_options` for those models.

use crate::provider::{ChatRole, CompletionRequest, CompletionResponse, LlmProvider, ToolCall, Usage};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error, warn};
use zp_core::{ProviderCapabilities, ProviderHealth, ProviderId, ToolDefinition, ZpError};

/// Ollama API provider for local models.
pub struct OllamaProvider {
    id: ProviderId,
    base_url: String,
    model_name: String,
    capabilities: ProviderCapabilities,
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
    /// Tool definitions. Only sent when non-empty; Ollama ignores the field
    /// for models that don't support tools, but sending it to an incapable
    /// model produces a confusing error, so callers should set
    /// `supports_tools: true` only for models known to handle it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OllamaTool>,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
    /// Present in responses when the model wants to invoke a tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tool_calls: Vec<OllamaToolCall>,
}

/// OpenAI-compatible tool definition format accepted by Ollama.
#[derive(Debug, Serialize, Deserialize)]
struct OllamaTool {
    #[serde(rename = "type")]
    tool_type: String, // always "function"
    function: OllamaFunction,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaToolCall {
    function: OllamaToolCallFunction,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaToolCallFunction {
    name: String,
    arguments: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    model: String,
    message: OllamaMessage,
    #[allow(dead_code)]
    done: bool,
    eval_count: Option<u32>,
    prompt_eval_count: Option<u32>,
}

// ── Constructor ───────────────────────────────────────────────────────────────

impl OllamaProvider {
    /// Create a new Ollama provider at `localhost:11434`.
    ///
    /// `supports_tools: false`, `max_context: 4096` — safe defaults for any
    /// model. Use `with_options` for models that support tool calling or
    /// have larger context windows.
    pub fn new(model_name: String) -> Self {
        Self::with_options(
            "http://localhost:11434".to_string(),
            model_name,
            false,
            4096,
        )
    }

    /// Create a new Ollama provider with a custom base URL.
    ///
    /// Same conservative defaults as `new`. Use `with_options` to enable
    /// tool calling for capable models.
    pub fn with_base_url(base_url: String, model_name: String) -> Self {
        Self::with_options(base_url, model_name, false, 4096)
    }

    /// Full constructor — configure tool support and context window explicitly.
    ///
    /// `supports_tools`: set `true` for llama3.1+, qwen2.5, mistral-nemo,
    /// command-r and other models that implement the OpenAI tool-call format.
    ///
    /// `max_context`: set to the model's actual context window (e.g. 32768
    /// for llama3.1:8b, 131072 for qwen2.5:72b).
    pub fn with_options(
        base_url: String,
        model_name: String,
        supports_tools: bool,
        max_context: usize,
    ) -> Self {
        let id = ProviderId::new(&format!("ollama-{}", model_name));
        Self {
            id,
            base_url,
            model_name: model_name.clone(),
            capabilities: ProviderCapabilities {
                is_local: true,
                max_context,
                supports_tools,
                strength: 0.6,
                model_name,
            },
        }
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, ZpError> {
        debug!("Ollama: Starting completion request");

        // Build message list: system prompt first, then conversation history.
        let mut messages = vec![OllamaMessage {
            role: "system".to_string(),
            content: request.system_prompt.clone(),
            tool_calls: vec![],
        }];
        for msg in &request.messages {
            messages.push(OllamaMessage {
                role: match msg.role {
                    ChatRole::System => "system".to_string(),
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                    // Ollama uses "tool" for tool result messages in newer builds;
                    // fall back to "user" for older versions.
                    ChatRole::Tool => "tool".to_string(),
                },
                content: msg.content.clone(),
                tool_calls: vec![],
            });
        }

        // Convert tool definitions to Ollama's OpenAI-compatible format.
        // Only sent when the provider was constructed with `supports_tools: true`
        // AND the request actually carries tools — avoids confusing errors from
        // models that don't implement the tool protocol.
        let tools: Vec<OllamaTool> = if self.capabilities.supports_tools {
            request
                .tools
                .iter()
                .map(tool_definition_to_ollama)
                .collect()
        } else {
            vec![]
        };

        let ollama_request = OllamaRequest {
            model: request.model.clone().unwrap_or_else(|| self.model_name.clone()),
            messages,
            temperature: request.temperature,
            num_predict: request.max_tokens,
            tools,
            stream: false,
        };

        debug!("Ollama: Sending request to {}/api/chat", self.base_url);
        let client = reqwest::Client::new();
        let start = Instant::now();
        let url = format!("{}/api/chat", self.base_url);

        let response = client
            .post(&url)
            .json(&ollama_request)
            .send()
            .await
            .map_err(|e| {
                error!("Ollama API request failed: {}", e);
                ZpError::ProviderError {
                    provider: self.id.0.clone(),
                    message: format!("API request failed: {}", e),
                }
            })?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            error!("Failed to read Ollama response body: {}", e);
            ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: format!("Failed to read response: {}", e),
            }
        })?;

        if !status.is_success() {
            error!("Ollama API error: {} {}", status, response_text);
            return Err(ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: format!("API returned {}: {}", status, response_text),
            });
        }

        let ollama_response: OllamaResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                error!("Failed to parse Ollama response: {}", e);
                ZpError::ProviderError {
                    provider: self.id.0.clone(),
                    message: format!("Failed to parse response: {}", e),
                }
            })?;

        let elapsed = start.elapsed().as_millis() as u64;
        debug!("Ollama: Request completed in {}ms", elapsed);

        // Map Ollama tool_calls → ZP ToolCall.
        let tool_calls = ollama_response
            .message
            .tool_calls
            .into_iter()
            .map(|tc| ToolCall {
                tool_name: tc.function.name,
                arguments: tc.function.arguments,
            })
            .collect();

        let prompt_tokens = ollama_response.prompt_eval_count.unwrap_or(0);
        let completion_tokens = ollama_response.eval_count.unwrap_or(0);

        Ok(CompletionResponse {
            content: ollama_response.message.content,
            tool_calls,
            model: ollama_response.model,
            usage: Usage {
                prompt_tokens,
                completion_tokens,
            },
            cost_usd: None,
        })
    }

    async fn health(&self) -> ProviderHealth {
        debug!("Ollama: Checking health");
        let client = reqwest::Client::new();
        let start = Instant::now();
        let url = format!("{}/api/tags", self.base_url);

        match client.get(&url).send().await {
            Ok(response) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                if response.status().is_success() {
                    debug!("Ollama: Health check passed ({}ms)", latency_ms);
                    ProviderHealth::Healthy { latency_ms }
                } else {
                    warn!("Ollama health check returned status: {}", response.status());
                    ProviderHealth::Degraded {
                        reason: format!("API returned {}", response.status()),
                    }
                }
            }
            Err(e) => {
                warn!("Ollama health check failed: {}", e);
                ProviderHealth::Unavailable {
                    reason: format!("Service unreachable at {}: {}", self.base_url, e),
                }
            }
        }
    }
}

// ── Conversion helpers ────────────────────────────────────────────────────────

/// Convert a ZP `ToolDefinition` to Ollama's OpenAI-compatible tool format.
fn tool_definition_to_ollama(tool: &ToolDefinition) -> OllamaTool {
    OllamaTool {
        tool_type: "function".to_string(),
        function: OllamaFunction {
            name: tool.name.clone(),
            description: tool.description.clone(),
            parameters: tool.parameters.clone(),
        },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_creation_conservative_defaults() {
        let provider = OllamaProvider::new("mistral".to_string());
        assert_eq!(provider.id().0, "ollama-mistral");
        assert!(provider.capabilities().is_local);
        assert!(!provider.capabilities().supports_tools);
        assert_eq!(provider.capabilities().max_context, 4096);
    }

    #[test]
    fn test_ollama_with_custom_url() {
        let provider = OllamaProvider::with_base_url(
            "http://192.168.1.100:11434".to_string(),
            "llama2".to_string(),
        );
        assert_eq!(provider.base_url, "http://192.168.1.100:11434");
        assert!(provider.capabilities().is_local);
        assert!(!provider.capabilities().supports_tools);
    }

    #[test]
    fn test_ollama_with_tool_support() {
        let provider = OllamaProvider::with_options(
            "http://localhost:11434".to_string(),
            "llama3.1:8b".to_string(),
            true,
            32768,
        );
        assert!(provider.capabilities().supports_tools);
        assert_eq!(provider.capabilities().max_context, 32768);
        assert!(provider.capabilities().is_local);
    }

    #[test]
    fn test_tool_definition_conversion() {
        let tool = ToolDefinition {
            name: "zp_gate_check".to_string(),
            description: "Check if an action is permitted by the gate".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string" }
                },
                "required": ["action"]
            }),
            required_credentials: vec![],
        };
        let ollama_tool = tool_definition_to_ollama(&tool);
        assert_eq!(ollama_tool.tool_type, "function");
        assert_eq!(ollama_tool.function.name, "zp_gate_check");
        assert_eq!(ollama_tool.function.description, "Check if an action is permitted by the gate");
    }
}
