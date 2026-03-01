//! Ollama API provider implementation (local models).

use crate::provider::{ChatRole, CompletionRequest, CompletionResponse, LlmProvider, Usage};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error, warn};
use zp_core::{ProviderCapabilities, ProviderHealth, ProviderId, ZpError};

/// Ollama API provider for local models.
pub struct OllamaProvider {
    id: ProviderId,
    base_url: String,
    model_name: String,
    capabilities: ProviderCapabilities,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
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

impl OllamaProvider {
    /// Create a new Ollama provider.
    pub fn new(model_name: String) -> Self {
        Self::with_base_url("http://localhost:11434".to_string(), model_name)
    }

    /// Create a new Ollama provider with custom base URL.
    pub fn with_base_url(base_url: String, model_name: String) -> Self {
        let id = ProviderId::new(&format!("ollama-{}", model_name));
        Self {
            id: id.clone(),
            base_url,
            model_name: model_name.clone(),
            capabilities: ProviderCapabilities {
                is_local: true,
                max_context: 4096,     // Typical local model context
                supports_tools: false, // Most local models don't support tools well
                strength: 0.6,         // Moderate strength for local models
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

        // Convert messages to Ollama format
        let mut messages = Vec::new();

        // Add system message
        messages.push(OllamaMessage {
            role: "system".to_string(),
            content: request.system_prompt.clone(),
        });

        // Add conversation messages
        for msg in &request.messages {
            messages.push(OllamaMessage {
                role: match msg.role {
                    ChatRole::System => "system".to_string(),
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                    ChatRole::Tool => "system".to_string(), // Ollama doesn't have a tool role
                },
                content: msg.content.clone(),
            });
        }

        let ollama_request = OllamaRequest {
            model: request
                .model
                .clone()
                .unwrap_or_else(|| self.model_name.clone()),
            messages,
            temperature: request.temperature,
            num_predict: request.max_tokens,
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

        // Calculate token usage (Ollama provides approximate counts)
        let prompt_tokens = ollama_response.prompt_eval_count.unwrap_or(0);
        let completion_tokens = ollama_response.eval_count.unwrap_or(0);

        Ok(CompletionResponse {
            content: ollama_response.message.content,
            tool_calls: vec![], // Local models typically don't support tools
            model: ollama_response.model,
            usage: Usage {
                prompt_tokens,
                completion_tokens,
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_creation() {
        let provider = OllamaProvider::new("mistral".to_string());
        assert_eq!(provider.id().0, "ollama-mistral");
        assert!(provider.capabilities().is_local);
        assert!(!provider.capabilities().supports_tools);
    }

    #[test]
    fn test_ollama_with_custom_url() {
        let provider = OllamaProvider::with_base_url(
            "http://192.168.1.100:11434".to_string(),
            "llama2".to_string(),
        );
        assert_eq!(provider.base_url, "http://192.168.1.100:11434");
        assert!(provider.capabilities().is_local);
    }
}
