//! Storage implementations for observations and expertise profiles
//!
//! This module provides in-memory and trait-based storage for
//! observations and expertise data.

use crate::traits::{ExpertiseStore, ObservationStore};
use crate::types::{ExpertiseProfile, Observation};
use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// In-memory observation store
#[derive(Debug)]
pub struct InMemoryObservationStore {
    observations: Arc<RwLock<HashMap<String, Vec<Observation>>>>,
}

impl InMemoryObservationStore {
    pub fn new() -> Self {
        Self {
            observations: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryObservationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for InMemoryObservationStore {
    fn clone(&self) -> Self {
        Self {
            observations: self.observations.clone(),
        }
    }
}

#[async_trait]
impl ObservationStore for InMemoryObservationStore {
    async fn store(&self, observation: Observation) -> Result<(), String> {
        let mut store = self.observations.write();
        store
            .entry(observation.target_id.clone())
            .or_default()
            .push(observation);
        Ok(())
    }

    async fn get_for_target(&self, target_id: &str) -> Vec<Observation> {
        let store = self.observations.read();
        store.get(target_id).cloned().unwrap_or_default()
    }

    async fn get_by_category(&self, target_id: &str, category: &str) -> Vec<Observation> {
        let store = self.observations.read();
        store
            .get(target_id)
            .map(|obs| {
                obs.iter()
                    .filter(|o| o.task_category == category)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn get_recent(&self, target_id: &str, since_seconds: u64) -> Vec<Observation> {
        let store = self.observations.read();
        let cutoff = Utc::now() - chrono::Duration::seconds(since_seconds as i64);

        store
            .get(target_id)
            .map(|obs| {
                obs.iter()
                    .filter(|o| o.timestamp > cutoff)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn count(&self, target_id: &str) -> usize {
        let store = self.observations.read();
        store.get(target_id).map(|v| v.len()).unwrap_or(0)
    }

    async fn clear(&self, target_id: &str) -> Result<(), String> {
        let mut store = self.observations.write();
        store.remove(target_id);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "In-Memory Observations"
    }
}

/// In-memory expertise profile store
#[derive(Debug)]
pub struct InMemoryExpertiseStore {
    profiles: Arc<RwLock<HashMap<String, ExpertiseProfile>>>,
}

impl InMemoryExpertiseStore {
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryExpertiseStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for InMemoryExpertiseStore {
    fn clone(&self) -> Self {
        Self {
            profiles: self.profiles.clone(),
        }
    }
}

#[async_trait]
impl ExpertiseStore for InMemoryExpertiseStore {
    async fn store(&self, profile: ExpertiseProfile) -> Result<(), String> {
        let mut store = self.profiles.write();
        store.insert(profile.target_id.clone(), profile);
        Ok(())
    }

    async fn get(&self, target_id: &str) -> Option<ExpertiseProfile> {
        let store = self.profiles.read();
        store.get(target_id).cloned()
    }

    async fn list_targets(&self) -> Vec<String> {
        let store = self.profiles.read();
        store.keys().cloned().collect()
    }

    async fn exists(&self, target_id: &str) -> bool {
        let store = self.profiles.read();
        store.contains_key(target_id)
    }

    async fn delete(&self, target_id: &str) -> Result<(), String> {
        let mut store = self.profiles.write();
        store.remove(target_id);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "In-Memory Expertise"
    }
}

/// Combined store for both observations and expertise
#[derive(Debug, Clone)]
pub struct CombinedStore {
    pub observations: InMemoryObservationStore,
    pub expertise: InMemoryExpertiseStore,
}

impl CombinedStore {
    pub fn new() -> Self {
        Self {
            observations: InMemoryObservationStore::new(),
            expertise: InMemoryExpertiseStore::new(),
        }
    }
}

impl Default for CombinedStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_observation_store_crud() {
        let store = InMemoryObservationStore::new();

        // Store observation
        let obs = Observation::new("tool_1", "test")
            .with_success(true)
            .with_quality(0.9);

        store.store(obs.clone()).await.unwrap();

        // Count
        assert_eq!(store.count("tool_1").await, 1);
        assert_eq!(store.count("tool_2").await, 0);

        // Get
        let retrieved = store.get_for_target("tool_1").await;
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].target_id, "tool_1");

        // Clear
        store.clear("tool_1").await.unwrap();
        assert_eq!(store.count("tool_1").await, 0);
    }

    #[tokio::test]
    async fn test_observation_store_by_category() {
        let store = InMemoryObservationStore::new();

        // Store observations in different categories
        store
            .store(Observation::new("tool_1", "code"))
            .await
            .unwrap();
        store
            .store(Observation::new("tool_1", "analysis"))
            .await
            .unwrap();
        store
            .store(Observation::new("tool_1", "code"))
            .await
            .unwrap();

        let code_obs = store.get_by_category("tool_1", "code").await;
        assert_eq!(code_obs.len(), 2);

        let analysis_obs = store.get_by_category("tool_1", "analysis").await;
        assert_eq!(analysis_obs.len(), 1);
    }

    #[tokio::test]
    async fn test_expertise_store_crud() {
        let store = InMemoryExpertiseStore::new();

        // Create profile
        let profile = ExpertiseProfile::new("tool_1", "Test Tool");

        // Store
        store.store(profile.clone()).await.unwrap();

        // Exists
        assert!(store.exists("tool_1").await);
        assert!(!store.exists("tool_2").await);

        // Get
        let retrieved = store.get("tool_1").await.unwrap();
        assert_eq!(retrieved.target_id, "tool_1");

        // List
        let targets = store.list_targets().await;
        assert_eq!(targets.len(), 1);
        assert!(targets.contains(&"tool_1".to_string()));

        // Delete
        store.delete("tool_1").await.unwrap();
        assert!(!store.exists("tool_1").await);
    }

    #[tokio::test]
    async fn test_combined_store() {
        let store = CombinedStore::new();

        // Store observation
        store
            .observations
            .store(Observation::new("tool_1", "test"))
            .await
            .unwrap();

        // Store profile
        store
            .expertise
            .store(ExpertiseProfile::new("tool_1", "Test Tool"))
            .await
            .unwrap();

        // Verify both stores work
        assert_eq!(store.observations.count("tool_1").await, 1);
        assert!(store.expertise.exists("tool_1").await);
    }
}
