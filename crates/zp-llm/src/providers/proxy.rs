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
use std::sync::Arc;
use tracing::{debug, error, warn};
use zp_core::provider::RequestSigner;
use zp_core::{ProviderCapabilities, ProviderHealth, ProviderId, ZpError};

/// LLM provider that routes through the ZP inference proxy.
///
/// Construct with `ProxyLlmProvider::new(zp_port, provider_id, model, signer)`
/// for cloud providers, or `ProxyLlmProvider::local(zp_port, model, signer)`
/// for Ollama.
///
/// # Why the signer is mandatory
///
/// The gate requires authentication on `/api/v1/proxy/*`. A provider without
/// a signer can only ever produce 401s — but the danger is not the failure,
/// it is the *repair*. An engineer debugging a wall of 401s at 2am reaches
/// for the nearest switch, and `auth.rs` still accepts a legacy bearer path
/// pending removal. Making the signer a required constructor argument means
/// "an inference provider that cannot authenticate" is not a representable
/// state, so that repair is never available. Compare `OllamaProvider` in this
/// same crate, which takes no credential at all and talks straight to the
/// backend — that shape is exactly what this one refuses to be.
pub struct ProxyLlmProvider {
    id: ProviderId,
    zp_port: u16,
    /// Proxy provider segment — matches the proxy's `provider_base_url` keys.
    provider_id: String,
    model: String,
    capabilities: ProviderCapabilities,
    /// Supplies the per-request `Authorization` envelope. Never optional:
    /// see the type docs.
    signer: Arc<dyn RequestSigner>,
}

impl ProxyLlmProvider {
    /// Create a provider that routes through the ZP proxy to a cloud backend.
    pub fn new(
        zp_port: u16,
        provider_id: impl Into<String>,
        model: impl Into<String>,
        signer: Arc<dyn RequestSigner>,
    ) -> Self {
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
            signer,
        }
    }

    /// Create a provider that routes through the ZP proxy to a local Ollama backend.
    pub fn local(zp_port: u16, model: impl Into<String>, signer: Arc<dyn RequestSigner>) -> Self {
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
            signer,
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

    /// Request path, with leading slash and no scheme/host/port.
    ///
    /// This exact string is what the envelope binds to, and what the gate
    /// reconstructs from the live request. It is derived once here so the
    /// signed path and the requested path cannot diverge.
    fn proxy_path(&self) -> String {
        format!(
            "/api/v1/proxy/{}/v1/chat/completions",
            self.provider_id
        )
    }

    fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}{}", self.zp_port, self.proxy_path())
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
        let path = self.proxy_path();

        // Serialize ONCE and transmit exactly these bytes.
        //
        // The envelope binds a BLAKE3 hash of the request body, and the gate
        // recomputes that hash over the bytes it received. `.json(&body)`
        // would serialize independently inside reqwest, so the hash could be
        // taken over one serialization while a different one goes on the
        // wire. Any difference — key order, float formatting, escaping —
        // yields a valid-looking envelope that fails verification, reported
        // as `envelope-signature` and indistinguishable from a bad key.
        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            error!(error = %e, "ProxyLlmProvider: failed to serialize request body");
            ZpError::ProviderError {
                provider: self.id.0.clone(),
                message: format!("Failed to serialize request: {}", e),
            }
        })?;

        let mut req = client
            .post(&url)
            .header("content-type", "application/json");

        // Fail closed: if no credential can be produced we still send the
        // request, unauthenticated, and let the gate reject it. Skipping the
        // call would hide the misconfiguration; sending it surfaces a 401 that
        // names this provider.
        match self.signer.authorization("POST", &path, &body_bytes) {
            Some(auth) => req = req.header("authorization", auth),
            None => warn!(
                provider = %self.id.0,
                "ProxyLlmProvider: signer produced no credential — request will be rejected"
            ),
        }

        let resp = req
            .body(body_bytes)
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

    /// Test double. Records nothing and signs nothing — it exists only to
    /// satisfy the mandatory-signer constructor.
    ///
    /// It returns `Some`, not `None`, so these construction tests do not
    /// silently become the place where "provider without a credential" is
    /// normalised. The `None` case has its own test below, asserting the
    /// fail-closed contract explicitly.
    struct StubSigner;

    impl RequestSigner for StubSigner {
        fn authorization(&self, method: &str, path: &str, _body: &[u8]) -> Option<String> {
            Some(format!("Stub {} {}", method, path))
        }
    }

    /// A signer that cannot produce a credential. Models the pre-Genesis
    /// state, where there is no identity to sign with.
    struct SilentSigner;

    impl RequestSigner for SilentSigner {
        fn authorization(&self, _method: &str, _path: &str, _body: &[u8]) -> Option<String> {
            None
        }
    }

    fn stub() -> Arc<dyn RequestSigner> {
        Arc::new(StubSigner)
    }

    #[test]
    fn test_proxy_provider_creation() {
        let p = ProxyLlmProvider::new(7832, "anthropic", "claude-sonnet-4-6", stub());
        assert_eq!(p.id().0, "proxy-anthropic-claude-sonnet-4-6");
        assert!(!p.capabilities().is_local);
    }

    #[test]
    fn test_proxy_local_creation() {
        let p = ProxyLlmProvider::local(7832, "mistral", stub());
        assert_eq!(p.id().0, "proxy-ollama-mistral");
        assert!(p.capabilities().is_local);
    }

    #[test]
    fn test_proxy_url() {
        let p = ProxyLlmProvider::new(7832, "together", "llama-3", stub());
        assert_eq!(
            p.proxy_url(),
            "http://127.0.0.1:7832/api/v1/proxy/together/v1/chat/completions"
        );
    }

    /// The signed path and the requested path must be the same string. If
    /// these ever diverge, every envelope fails verification with a binding
    /// error that looks like a signature problem.
    #[test]
    fn signed_path_matches_requested_url() {
        let p = ProxyLlmProvider::local(7832, "gemma4:26b-mlx", stub());
        let path = p.proxy_path();
        assert!(path.starts_with('/'), "signed path needs a leading slash");
        assert_eq!(p.proxy_url(), format!("http://127.0.0.1:7832{}", path));
    }

    /// Fail closed: a signer that yields nothing must not cause the provider
    /// to invent a credential or to treat the request as authorised. The
    /// request goes out bare and the gate rejects it.
    #[test]
    fn absent_credential_yields_no_header() {
        let signer: Arc<dyn RequestSigner> = Arc::new(SilentSigner);
        assert!(signer.authorization("POST", "/api/v1/proxy/ollama/v1/chat/completions", b"{}").is_none());
    }
}
