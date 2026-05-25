//! Pricing freshness — fetcher trait, per-provider implementations, and refresh orchestration.
//!
//! The substrate exposes pricing refresh as a first-class verb (`zp pricing refresh`,
//! `POST /api/v1/pricing/refresh`). This module contains the fetcher abstraction
//! and the initial Abacus implementation that reads live pricing from the RouteLLM
//! `/v1/models` endpoint.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::providers::ProviderProfile;

// ============================================================================
// Core types
// ============================================================================

/// A pricing update for a single provider, returned by a fetcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingUpdate {
    /// Provider catalog ID (e.g., "abacus", "openai").
    pub provider_id: String,
    /// New input cost per million tokens in USD, if the API exposed it.
    pub input_per_million_usd: Option<f64>,
    /// New output cost per million tokens in USD, if the API exposed it.
    pub output_per_million_usd: Option<f64>,
    /// New cached-input cost per million tokens in USD, if the API exposed it.
    pub cached_input_per_million_usd: Option<f64>,
    /// Source URL that was queried.
    pub source_url: String,
}

/// Summary of a completed pricing refresh run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingRefreshResult {
    /// Provider IDs that were targeted.
    pub host_ids: Vec<String>,
    /// Method used: "fetch" for API-based, "manual" for operator attestation.
    pub method: String,
    /// Source URLs that were queried (empty for manual).
    pub source_urls: Vec<String>,
    /// Number of providers whose pricing changed.
    pub changed_count: u32,
    /// Number of providers whose pricing was confirmed unchanged.
    pub unchanged_count: u32,
    /// Human-readable diff lines for changed entries.
    pub delta_lines: Vec<String>,
    /// Updated catalog entries (all targeted providers with refreshed timestamps).
    pub updated_profiles: Vec<ProviderProfile>,
}

// ============================================================================
// PricingFetcher trait
// ============================================================================

/// Abstraction over a pricing data source.
///
/// Each implementation knows how to query one provider's API for current
/// pricing and map the response to `PricingUpdate` values.
#[async_trait]
pub trait PricingFetcher: Send + Sync {
    /// Provider catalog ID this fetcher targets (e.g., "abacus").
    fn provider_id(&self) -> &str;

    /// Source URL that will be queried.
    fn source_url(&self) -> &str;

    /// Fetch current pricing data. `api_key` is the operator's credential for
    /// this provider; pass an empty string if the endpoint is unauthenticated.
    async fn fetch(&self, api_key: &str) -> Result<Vec<PricingUpdate>, String>;
}

// ============================================================================
// AbacusFetcher
// ============================================================================

/// Fetches pricing from the Abacus RouteLLM `/v1/models` endpoint.
///
/// The endpoint returns a list of model objects; we aggregate per-provider
/// pricing from those objects. Abacus exposes prompt/completion costs in
/// USD per token — we multiply by 1_000_000 to match the catalog's
/// per-million convention.
pub struct AbacusFetcher;

const ABACUS_MODELS_URL: &str = "https://routellm.abacus.ai/v1/models";

#[derive(Debug, Deserialize)]
struct AbacusModel {
    #[serde(default)]
    prompt_price: Option<f64>,
    #[serde(default)]
    completion_price: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct AbacusModelsResponse {
    data: Vec<AbacusModel>,
}

#[async_trait]
impl PricingFetcher for AbacusFetcher {
    fn provider_id(&self) -> &str { "abacus" }
    fn source_url(&self) -> &str { ABACUS_MODELS_URL }

    async fn fetch(&self, api_key: &str) -> Result<Vec<PricingUpdate>, String> {
        let client = reqwest::Client::new();
        let mut req = client.get(ABACUS_MODELS_URL);
        if !api_key.is_empty() {
            req = req.bearer_auth(api_key);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("Abacus fetch error: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Abacus returned HTTP {}", resp.status()));
        }

        let body: AbacusModelsResponse = resp
            .json()
            .await
            .map_err(|e| format!("Abacus JSON parse error: {e}"))?;

        // Aggregate: take the cheapest prompt and completion prices across
        // all models as the provider-level floor (matches what operators
        // care about when routing budget traffic through Abacus).
        let mut min_input: Option<f64> = None;
        let mut min_output: Option<f64> = None;

        for model in &body.data {
            if let Some(p) = model.prompt_price {
                let per_million = p * 1_000_000.0;
                min_input = Some(match min_input {
                    Some(cur) => cur.min(per_million),
                    None => per_million,
                });
            }
            if let Some(c) = model.completion_price {
                let per_million = c * 1_000_000.0;
                min_output = Some(match min_output {
                    Some(cur) => cur.min(per_million),
                    None => per_million,
                });
            }
        }

        Ok(vec![PricingUpdate {
            provider_id: "abacus".to_string(),
            input_per_million_usd: min_input,
            output_per_million_usd: min_output,
            cached_input_per_million_usd: None,
            source_url: ABACUS_MODELS_URL.to_string(),
        }])
    }
}

// ============================================================================
// Fetcher registry
// ============================================================================

/// Return the fetcher for a given provider ID, if one exists.
pub fn fetcher_for(provider_id: &str) -> Option<Box<dyn PricingFetcher>> {
    match provider_id {
        "abacus" => Some(Box::new(AbacusFetcher)),
        _ => None,
    }
}

// ============================================================================
// Refresh orchestration
// ============================================================================

/// Refresh pricing for a set of provider host IDs.
///
/// For each host ID: if a fetcher exists, call it with the operator's API key
/// (loaded from the vault or environment). If no fetcher exists, skip with a
/// warning. Compute a delta against the current catalog and return the result.
///
/// `api_key_for` is a closure that resolves an API key for a given provider ID;
/// pass `|_| String::new()` to skip authentication.
pub async fn refresh_hosts(
    catalog: &[ProviderProfile],
    host_ids: &[String],
    api_key_for: impl Fn(&str) -> String,
) -> PricingRefreshResult {
    let now = chrono::Utc::now().to_rfc3339();
    let mut source_urls = Vec::new();
    let mut delta_lines = Vec::new();
    let mut changed_count = 0u32;
    let mut unchanged_count = 0u32;
    let mut updated_profiles = catalog.to_vec();

    for host_id in host_ids {
        let Some(fetcher) = fetcher_for(host_id) else {
            tracing::warn!(provider = %host_id, "No pricing fetcher available; skipping");
            continue;
        };

        let api_key = api_key_for(host_id);
        source_urls.push(fetcher.source_url().to_string());

        match fetcher.fetch(&api_key).await {
            Ok(updates) => {
                for update in updates {
                    let target_id = &update.provider_id;
                    if let Some(profile) = updated_profiles.iter_mut().find(|p| &p.id == target_id)
                    {
                        let mut changed = false;

                        if let Some(new_in) = update.input_per_million_usd {
                            let old = profile.input_per_million_usd;
                            if old != Some(new_in) {
                                delta_lines.push(format!(
                                    "{target_id}: input {:.4} → {:.4} $/M",
                                    old.unwrap_or(0.0),
                                    new_in
                                ));
                                profile.input_per_million_usd = Some(new_in);
                                changed = true;
                            }
                        }
                        if let Some(new_out) = update.output_per_million_usd {
                            let old = profile.output_per_million_usd;
                            if old != Some(new_out) {
                                delta_lines.push(format!(
                                    "{target_id}: output {:.4} → {:.4} $/M",
                                    old.unwrap_or(0.0),
                                    new_out
                                ));
                                profile.output_per_million_usd = Some(new_out);
                                changed = true;
                            }
                        }
                        if let Some(new_cached) = update.cached_input_per_million_usd {
                            profile.cached_input_per_million_usd = Some(new_cached);
                            changed = true;
                        }

                        profile.pricing_verified_at = Some(now.clone());
                        profile.pricing_source =
                            crate::providers::PricingSource::Fetch {
                                source_url: update.source_url.clone(),
                            };

                        if changed {
                            changed_count += 1;
                        } else {
                            unchanged_count += 1;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(provider = %host_id, error = %e, "Pricing fetch failed");
            }
        }
    }

    PricingRefreshResult {
        host_ids: host_ids.to_vec(),
        method: "fetch".to_string(),
        source_urls,
        changed_count,
        unchanged_count,
        delta_lines,
        updated_profiles,
    }
}
