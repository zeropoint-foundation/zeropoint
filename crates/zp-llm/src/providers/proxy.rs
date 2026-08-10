//! Proxy-through LLM provider.
//!
//! Routes completions through the ZP inference proxy, which adds receipt
//! signing, cost tracking, and policy gating on every call. This is the
//! canonical substrate-side provider — use it instead of the direct
//! AnthropicProvider or any other cloud provider implementation.

use crate::provider::{
    CompletionRequest, CompletionResponse, LlmProvider, Usage,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};
use zp_core::{ProviderCapabilities, ProviderHealth, ProviderId, ZpError};

/// LLM provider that routes through the ZP inference proxy.
///
/// Construct with `ProxyLlmProvider::new(zp_port, provider_id, model)` for
/// cloud providers, or `ProxyLlmProvider::local(zp_port, model)` for Ollama.
pub struct ProxyLlmProvider {
    id: ProviderId,
    zp_port: u16,
    /// Proxy provider segment — matches the proxy's `provider_base_url` keys.
    provider_id: String,
    model: String,
    capabilities: ProviderCapabilities,
}

impl ProxyLlmProvider {
    /// Create a provider that routes through the ZP proxy to a cloud backend.
    pub fn new(zp_port: u16, provider_id: impl Into<String>, model: impl Into<String>) -> Self {
        let provider_id = provider_id.into();
        let model = model.into();
        let id = ProviderId::new(&format!("proxy-{}-{}", provider_id, model));
        Self {
            id,
            zp_port,
            provider_id,
            model: model.clone(),
            capabilities: ProviderCapabilities {
                is_local: false,
                max_context: 200_000,
                supports_tools: true,
                strength: 0.9,
                model_name: model,
            },
        }
    }

    /// Create a provider that routes through the ZP proxy to a local Ollama backend.
    pub fn local(zp_port: u16, model: impl Into<String>) -> Self {
        let model = model.into();
        let id = ProviderId::new(&format!("proxy-ollama-{}", model));
        Self {
            id,
            zp_port,
            provider_id: "ollama".to_string(),
            model: model.clone(),
            capabilities: ProviderCapabilities {
                is_local: true,
                max_context: 128_000,
                supports_tools: false,
                strength: 0.6,
                model_name: model,
            },
        }
    }

    /// Override the declared strength (0.0–1.0) used by `ProviderPool` routing.
    ///
    /// The pool's `Strong` selection picks the highest strength, and
    /// `RequireStrong` demands `> 0.7`. The constructors ship conservative
    /// defaults; a pool holding a default tier and an escalation tier must
    /// separate them here or `Strong` cannot tell them apart.
    pub fn with_strength(mut self, strength: f64) -> Self {
        self.capabilities.strength = strength;
        self
    }

    /// Declare whether the backing model implements the OpenAI tool-call format.
    ///
    /// `local()` defaults to `false` because it cannot know which Ollama tag it
    /// was handed. Set `true` for tags that do support tools — the pipeline's
    /// tool-invocation loop is a no-op without it.
    pub fn with_tools(mut self, supports_tools: bool) -> Self {
        self.capabilities.supports_tools = supports_tools;
        self
    }

    fn proxy_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/api/v1/proxy/{}/v1/chat/completions",
            self.zp_port, self.provider_id
        )
    }
}

// ── OpenAI-format request/response types ────────────────────────────────────

#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Debug, Serialize)]
struct OpenAiMessage {
    role: &'static str,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
    model: String,
    usage: OpenAiUsage,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponseMessage {
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<OpenAiToolCall>,
}

#[derive(Debug, Deserialize)]
struct OpenAiToolCall {
    function: OpenAiToolCallFunction,
}

#[derive(Debug, Deserialize)]
struct OpenAiToolCallFunction {
    name: String,
    arguments: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

// ── LlmProvider impl ────────────────────────────────────────────────────────

#[async_trait]
impl LlmProvider for ProxyLlmProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, ZpError> {
        debug!(provider = %self.provider_id, model = %self.model, "ProxyLlmProvider: sending request");

        let mut messages: Vec<OpenAiMessage> = Vec::new();

        if !request.system_prompt.is_empty() {
            messages.push(OpenAiMessage {
                role: "system",
                content: request.system_prompt.clone(),
            });
        }

        for msg in &request.messages {
            let role = match msg.role {
                crate::provider::ChatRole::System => "system",
                crate::provider::ChatRole::User => "user",
                crate::provider::ChatRole::Assistant => "assistant",
                crate::provider::ChatRole::Tool => "tool",
            };
            messages.push(OpenAiMessage {
                role,
                content: msg.content.clone(),
            });
        }

        let body = OpenAiRequest {
            model: request.model.clone().unwrap_or_else(|| self.model.clone()),
            messages,
            max_tokens: request.max_tokens,
            temperature: request.temperature,
        };

        let client = reqwest::Client::new();
        let url = self.proxy_url();

        let resp = client
            .post(&url)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                error!(url = %url, error = %e, "ProxyLlmProvider: request failed");
                ZpError::ProviderError {
                    provider: self.id.0.clone(),
                    message: format!("Proxy request failed: {}", e),
                }
            })?;

        let cost_usd = resp
            .headers()
            .get("x-zp-cost-usd")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok());

        let status = resp.status();
        let text = resp.text().await.map_err(|e| ZpError::ProviderError {
            provider: self.id.0.clone(),
            message: format!("Failed to read proxy response: {}", e),
        })?;

        if !status.is_success() {
            error!(status = %status, body = %text, "ProxyLlmProvider: proxy returned error");
            return Err(ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: format!("Proxy returned {}: {}", status, text),
            });
        }

        let oai: OpenAiResponse = serde_json::from_str(&text).map_err(|e| {
            error!(error = %e, body = %text, "ProxyLlmProvider: failed to parse response");
            ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: format!("Failed to parse proxy response: {}", e),
            }
        })?;

        let choice = oai.choices.into_iter().next().ok_or_else(|| {
            warn!("ProxyLlmProvider: empty choices array");
            ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: "No choices in response".to_string(),
            }
        })?;

        let tool_calls = choice
            .message
            .tool_calls
            .into_iter()
            .map(|tc| crate::provider::ToolCall {
                tool_name: tc.function.name,
                arguments: serde_json::from_str(&tc.function.arguments)
                    .unwrap_or(serde_json::Value::Null),
            })
            .collect();

        Ok(CompletionResponse {
            content: choice.message.content.unwrap_or_default(),
            tool_calls,
            model: oai.model,
            usage: Usage {
                prompt_tokens: oai.usage.prompt_tokens,
                completion_tokens: oai.usage.completion_tokens,
            },
            cost_usd,
        })
    }

    async fn health(&self) -> ProviderHealth {
        let client = reqwest::Client::new();
        let url = format!(
            "http://127.0.0.1:{}/api/v1/proxy/{}/v1/models",
            self.zp_port, self.provider_id
        );

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => ProviderHealth::Healthy { latency_ms: 0 },
            Ok(resp) => ProviderHealth::Degraded {
                reason: format!("Proxy health check returned {}", resp.status()),
            },
            Err(e) => ProviderHealth::Unavailable {
                reason: format!("Proxy unreachable: {}", e),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_provider_creation() {
        let p = ProxyLlmProvider::new(7832, "anthropic", "claude-sonnet-4-6");
        assert_eq!(p.id().0, "proxy-anthropic-claude-sonnet-4-6");
        assert!(!p.capabilities().is_local);
    }

    #[test]
    fn test_proxy_local_creation() {
        let p = ProxyLlmProvider::local(7832, "mistral");
        assert_eq!(p.id().0, "proxy-ollama-mistral");
        assert!(p.capabilities().is_local);
    }

    #[test]
    fn test_proxy_url() {
        let p = ProxyLlmProvider::new(7832, "together", "llama-3");
        assert_eq!(
            p.proxy_url(),
            "http://127.0.0.1:7832/api/v1/proxy/together/v1/chat/completions"
        );
    }
}
