# zp-llm Usage Examples

## Complete Provider Pool Setup

```rust
use zp_llm::{ProviderPool, AnthropicProvider, OllamaProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the provider pool
    let mut pool = ProviderPool::new();

    // Add Anthropic provider (cloud-based, strong)
    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
        pool.add_provider(Box::new(AnthropicProvider::new(
            api_key,
            "claude-3-5-sonnet-20241022".to_string(),
        )));
    }

    // Add Ollama provider (local, privacy-preserving)
    pool.add_provider(Box::new(OllamaProvider::new(
        "mistral".to_string(),
    )));

    // Check health of all providers
    let health_status = pool.health_check().await;
    for (provider_id, health) in health_status {
        match health {
            zp_core::ProviderHealth::Healthy { latency_ms } => {
                println!("{}: Healthy ({}ms)", provider_id, latency_ms);
            }
            zp_core::ProviderHealth::Degraded { reason } => {
                println!("{}: Degraded ({})", provider_id, reason);
            }
            zp_core::ProviderHealth::Unavailable { reason } => {
                println!("{}: Unavailable ({})", provider_id, reason);
            }
        }
    }

    Ok(())
}
```

## Risk-Based Routing

```rust
use zp_core::ModelClass;

// Low-risk task — any available model
let low_risk = zp_core::ModelPreference {
    preference: ModelClass::Any,
    reason: "Simple informational query".to_string(),
    overridable: true,
};
let provider = pool.select(&low_risk)?;

// Medium-risk task — needs strong model
let medium_risk = zp_core::ModelPreference {
    preference: ModelClass::Strong,
    reason: "Complex code generation".to_string(),
    overridable: true,
};
let provider = pool.select(&medium_risk)?;

// High-risk task — requires strongest model
let high_risk = zp_core::ModelPreference {
    preference: ModelClass::RequireStrong,
    reason: "Security policy analysis".to_string(),
    overridable: false,
};
let provider = pool.select(&high_risk)?;

// Data-sensitive task — local model only
let data_sensitive = zp_core::ModelPreference {
    preference: ModelClass::LocalOnly,
    reason: "Processing confidential data".to_string(),
    overridable: false,
};
let provider = pool.select(&data_sensitive)?;

// User override — specific model requested
let user_override = zp_core::ModelPreference {
    preference: ModelClass::Specific("ollama-mistral".to_string()),
    reason: "User requested local processing".to_string(),
    overridable: false,
};
let provider = pool.select(&user_override)?;
```

## Building Prompts

```rust
use zp_llm::PromptBuilder;

// Create operator identity
let operator = zp_core::OperatorIdentity::default();

// Define available capabilities (tools)
let capabilities = vec![
    zp_core::Capability {
        name: "web_search".to_string(),
        tools: vec![
            zp_core::ToolDefinition {
                name: "search".to_string(),
                description: "Search the web for information".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
                required_credentials: vec![],
            }
        ],
        source_skill: None,
    }
];

// Build request from context
let request = PromptBuilder::build(
    &operator,
    &capabilities,
    &conversation_history,
    "What's the latest news about AI?",
);
```

## Completion Workflow

```rust
#[tokio::main]
async fn complete_request(
    pool: &ProviderPool,
    operator: &zp_core::OperatorIdentity,
    capabilities: &[zp_core::Capability],
    history: &[zp_core::Message],
    user_message: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Build the completion request
    let request = PromptBuilder::build(
        operator,
        capabilities,
        history,
        user_message,
    );

    // Determine risk level (simplified — real implementation would use policy engine)
    let preference = zp_core::ModelPreference {
        preference: zp_core::ModelClass::Strong,
        reason: "Standard task".to_string(),
        overridable: true,
    };

    // Select provider
    let provider = pool.select(&preference)?;

    // Execute completion
    let response = provider.complete(&request).await?;

    // Log token usage
    println!(
        "Tokens: {} input + {} output = {} total",
        response.usage.prompt_tokens,
        response.usage.completion_tokens,
        response.usage.total()
    );

    // Check for tool calls
    if !response.tool_calls.is_empty() {
        println!("Model wants to call {} tools:", response.tool_calls.len());
        for tool_call in &response.tool_calls {
            println!("  - {}: {:?}", tool_call.tool_name, tool_call.arguments);
        }
    }

    Ok(response.content)
}
```

## Custom Provider Implementation

```rust
use zp_llm::{LlmProvider, CompletionRequest, CompletionResponse};
use zp_core::{ProviderId, ProviderCapabilities, ProviderHealth, ZpError};
use async_trait::async_trait;

pub struct MockProvider {
    id: ProviderId,
    capabilities: ProviderCapabilities,
}

#[async_trait]
impl LlmProvider for MockProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    async fn complete(
        &self,
        request: &CompletionRequest,
    ) -> Result<CompletionResponse, ZpError> {
        // Simulate processing
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        Ok(CompletionResponse::new(
            format!(
                "Mock response to: {}",
                request.messages.last().map(|m| &m.content).unwrap_or(&"(empty)".to_string())
            ),
            self.capabilities.model_name.clone(),
            zp_llm::Usage {
                prompt_tokens: 10,
                completion_tokens: 20,
            },
        ))
    }

    async fn health(&self) -> ProviderHealth {
        ProviderHealth::Healthy { latency_ms: 50 }
    }
}

// Use it
let mock = Box::new(MockProvider {
    id: ProviderId::new("mock"),
    capabilities: ProviderCapabilities {
        is_local: true,
        max_context: 4096,
        supports_tools: false,
        strength: 0.5,
        model_name: "mock-model".to_string(),
    },
});

pool.add_provider(mock);
```

## Error Handling

```rust
async fn safe_completion(
    pool: &ProviderPool,
    request: &zp_llm::CompletionRequest,
) -> Result<String, String> {
    // Validate request before sending
    zp_llm::RequestValidator::validate_request(request)
        .map_err(|e| format!("Invalid request: {}", e))?;

    // Select provider
    let preference = zp_core::ModelPreference {
        preference: zp_core::ModelClass::Any,
        reason: "test".to_string(),
        overridable: true,
    };

    let provider = pool.select(&preference)
        .map_err(|e| format!("No provider available: {}", e))?;

    // Execute
    match provider.complete(request).await {
        Ok(response) => {
            // Validate response
            zp_llm::RequestValidator::validate_response(&response)
                .map_err(|e| format!("Invalid response: {}", e))?;
            Ok(response.content)
        }
        Err(zp_core::ZpError::ProviderError { provider, message }) => {
            Err(format!("Provider {} failed: {}", provider, message))
        }
        Err(e) => Err(format!("Unexpected error: {}", e)),
    }
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_operations() {
        let pool = ProviderPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn test_provider_health_check() {
        let pool = ProviderPool::new();
        let health = pool.health_check().await;
        assert!(health.is_empty());
    }

    #[test]
    fn test_request_validation() {
        let request = zp_llm::CompletionRequest::new(
            "System prompt".to_string(),
            vec![zp_llm::ChatMessage::user("Hello".to_string())],
            vec![],
        );
        assert!(zp_llm::RequestValidator::validate_request(&request).is_ok());
    }
}
```

---

## Real-World Integration

In a real ZeroPoint deployment, the pool would be:

1. **Initialized** during system startup
2. **Configured** from policy engine output
3. **Monitored** with periodic health checks
4. **Selected** dynamically based on request risk
5. **Rate-limited** per provider (future enhancement)
6. **Logged** via tracing for auditability

The pool acts as the bridge between the policy-aware operator and actual LLM execution.
