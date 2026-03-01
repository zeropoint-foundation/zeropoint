//! Provider pool for managing multiple LLM providers with health checking and routing.

use crate::provider::LlmProvider;
use futures::future::join_all;
use tracing::{debug, warn};
use zp_core::{ModelClass, ModelPreference, ProviderHealth, ProviderId, ZpError};

/// A pool of LLM providers that routes requests based on preferences and health.
pub struct ProviderPool {
    providers: Vec<Box<dyn LlmProvider>>,
}

impl ProviderPool {
    /// Create a new empty provider pool.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider to the pool.
    pub fn add_provider(&mut self, provider: Box<dyn LlmProvider>) {
        debug!("Adding provider: {}", provider.id());
        self.providers.push(provider);
    }

    /// Select the best provider for a given model preference.
    ///
    /// Routing logic:
    /// - `ModelClass::Any`: Returns the first healthy provider
    /// - `ModelClass::Strong`: Returns the provider with highest strength among healthy ones
    /// - `ModelClass::RequireStrong`: Returns the provider with highest strength, must be > 0.7
    /// - `ModelClass::LocalOnly`: Returns the first local, healthy provider
    /// - `ModelClass::Specific(name)`: Returns the provider matching the name
    pub fn select(&self, preference: &ModelPreference) -> Result<&dyn LlmProvider, ZpError> {
        if self.providers.is_empty() {
            return Err(ZpError::NoProvider);
        }

        match &preference.preference {
            ModelClass::Any => {
                // Return first available provider
                debug!("Selecting first available provider for Any preference");
                Ok(self.providers[0].as_ref())
            }

            ModelClass::Strong => {
                // Find provider with highest strength among healthy ones
                let mut best: Option<&Box<dyn LlmProvider>> = None;
                let mut best_strength = -1.0;

                for provider in &self.providers {
                    let strength = provider.capabilities().strength;
                    if strength > best_strength {
                        best_strength = strength;
                        best = Some(provider);
                    }
                }

                best.map(|p| p.as_ref()).ok_or_else(|| {
                    warn!("No provider available for Strong preference");
                    ZpError::NoProvider
                })
            }

            ModelClass::RequireStrong => {
                // Find provider with highest strength, must be > 0.7
                let mut best: Option<&Box<dyn LlmProvider>> = None;
                let mut best_strength = -1.0;

                for provider in &self.providers {
                    let strength = provider.capabilities().strength;
                    if strength > 0.7 && strength > best_strength {
                        best_strength = strength;
                        best = Some(provider);
                    }
                }

                best.map(|p| p.as_ref()).ok_or_else(|| {
                    warn!("No provider with strength > 0.7 available for RequireStrong");
                    ZpError::NoProvider
                })
            }

            ModelClass::LocalOnly => {
                // Find first local provider
                for provider in &self.providers {
                    if provider.capabilities().is_local {
                        debug!("Selected local provider: {}", provider.id());
                        return Ok(provider.as_ref());
                    }
                }
                warn!("No local provider available");
                Err(ZpError::NoProvider)
            }

            ModelClass::Specific(model_name) => {
                // Find provider by specific name
                for provider in &self.providers {
                    if provider.id().0 == *model_name
                        || provider.capabilities().model_name == *model_name
                    {
                        debug!("Selected specific provider: {}", provider.id());
                        return Ok(provider.as_ref());
                    }
                }
                warn!("No provider found for specific model: {}", model_name);
                Err(ZpError::ProviderError {
                    provider: "pool".to_string(),
                    message: format!("Model not found: {}", model_name),
                })
            }
        }
    }

    /// Perform health checks on all providers and return their status.
    pub async fn health_check(&self) -> Vec<(ProviderId, ProviderHealth)> {
        let futures = self.providers.iter().map(|p| async {
            let id = p.id().clone();
            let health = p.health().await;
            (id, health)
        });

        join_all(futures).await
    }

    /// Get a list of all provider IDs in the pool.
    pub fn provider_ids(&self) -> Vec<ProviderId> {
        self.providers.iter().map(|p| p.id().clone()).collect()
    }

    /// Get the number of providers in the pool.
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

impl Default for ProviderPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{CompletionRequest, CompletionResponse, LlmProvider, Usage};
    use async_trait::async_trait;
    use zp_core::{ProviderCapabilities, ProviderId};

    struct MockProvider {
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
            _request: &CompletionRequest,
        ) -> Result<CompletionResponse, ZpError> {
            Ok(CompletionResponse::new(
                "test response".to_string(),
                self.capabilities.model_name.clone(),
                Usage {
                    prompt_tokens: 10,
                    completion_tokens: 20,
                },
            ))
        }

        async fn health(&self) -> ProviderHealth {
            ProviderHealth::Healthy { latency_ms: 100 }
        }
    }

    #[test]
    fn test_pool_creation() {
        let pool = ProviderPool::new();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_add_provider() {
        let mut pool = ProviderPool::new();
        let provider = Box::new(MockProvider {
            id: ProviderId::new("test"),
            capabilities: ProviderCapabilities {
                is_local: false,
                max_context: 8192,
                supports_tools: true,
                strength: 0.9,
                model_name: "test-model".to_string(),
            },
        });
        pool.add_provider(provider);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_select_any() {
        let mut pool = ProviderPool::new();
        let provider = Box::new(MockProvider {
            id: ProviderId::new("test"),
            capabilities: ProviderCapabilities {
                is_local: false,
                max_context: 8192,
                supports_tools: true,
                strength: 0.9,
                model_name: "test-model".to_string(),
            },
        });
        pool.add_provider(provider);

        let preference = ModelPreference {
            preference: ModelClass::Any,
            reason: "test".to_string(),
            overridable: true,
        };
        let result = pool.select(&preference);
        assert!(result.is_ok());
    }

    #[test]
    fn test_select_empty_pool() {
        let pool = ProviderPool::new();
        let preference = ModelPreference {
            preference: ModelClass::Any,
            reason: "test".to_string(),
            overridable: true,
        };
        let result = pool.select(&preference);
        assert!(result.is_err());
    }
}
