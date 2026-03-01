//! Skill registry — centralized management of registered skills.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::debug;

use zp_core::{SkillId, SkillManifest, SkillOrigin, SkillStats};

/// Errors that can occur in skill registry operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("skill already registered: {0}")]
    AlreadyRegistered(String),

    #[error("skill not found: {0}")]
    NotFound(String),

    #[error("invalid skill manifest: {0}")]
    InvalidManifest(String),
}

pub type RegistryResult<T> = Result<T, RegistryError>;

/// A skill registered in the registry with its metadata and runtime statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredSkill {
    /// The skill's manifest declaring what it can do
    pub manifest: SkillManifest,
    /// Where this skill came from
    pub origin: SkillOrigin,
    /// Runtime statistics (invocations, success rate, latency, etc.)
    pub stats: SkillStats,
    /// Whether this skill is enabled and available for matching
    pub enabled: bool,
}

/// The skill registry — manages all registered skills and their metadata.
///
/// This is the central store for skill definitions, statistics, and enabled/disabled states.
/// It uses interior mutability with `RwLock` to allow concurrent reads and exclusive writes.
pub struct SkillRegistry {
    skills: RwLock<HashMap<SkillId, RegisteredSkill>>,
}

impl SkillRegistry {
    /// Create a new, empty skill registry.
    pub fn new() -> Self {
        Self {
            skills: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new skill in the registry.
    ///
    /// Returns an error if a skill with the same ID is already registered.
    pub fn register(
        &self,
        id: SkillId,
        manifest: SkillManifest,
        origin: SkillOrigin,
    ) -> RegistryResult<()> {
        let mut skills = self.skills.write();

        if skills.contains_key(&id) {
            return Err(RegistryError::AlreadyRegistered(id.to_string()));
        }

        let registered = RegisteredSkill {
            manifest,
            origin,
            stats: SkillStats::default(),
            enabled: true,
        };

        skills.insert(id.clone(), registered);
        debug!("registered skill: {}", id);
        Ok(())
    }

    /// Unregister a skill from the registry.
    ///
    /// Returns an error if the skill is not found.
    pub fn unregister(&self, id: &SkillId) -> RegistryResult<()> {
        let mut skills = self.skills.write();

        skills
            .remove(id)
            .ok_or_else(|| RegistryError::NotFound(id.to_string()))?;

        debug!("unregistered skill: {}", id);
        Ok(())
    }

    /// Get a reference to a registered skill.
    pub fn get(&self, id: &SkillId) -> Option<RegisteredSkill> {
        self.skills.read().get(id).cloned()
    }

    /// List all registered skills.
    ///
    /// Returns a vector of (SkillId, RegisteredSkill) tuples.
    pub fn list(&self) -> Vec<(SkillId, RegisteredSkill)> {
        self.skills
            .read()
            .iter()
            .map(|(id, skill)| (id.clone(), skill.clone()))
            .collect()
    }

    /// Update statistics for a skill after execution.
    ///
    /// Updates the invocation count, success/failure count, and average latency.
    /// Returns an error if the skill is not found.
    pub fn update_stats(&self, id: &SkillId, success: bool, latency_ms: u64) -> RegistryResult<()> {
        let mut skills = self.skills.write();

        let skill = skills
            .get_mut(id)
            .ok_or_else(|| RegistryError::NotFound(id.to_string()))?;

        skill.stats.invocation_count += 1;

        if success {
            skill.stats.success_count += 1;
        } else {
            skill.stats.failure_count += 1;
        }

        // Update average latency using exponential moving average
        if skill.stats.invocation_count == 1 {
            skill.stats.avg_latency_ms = latency_ms as f64;
        } else {
            let prev_avg = skill.stats.avg_latency_ms;
            let new_count = skill.stats.invocation_count as f64;
            skill.stats.avg_latency_ms =
                (prev_avg * (new_count - 1.0) + latency_ms as f64) / new_count;
        }

        skill.stats.last_used = Some(chrono::Utc::now());

        debug!(
            "updated stats for skill {}: success={}, latency_ms={}",
            id, success, latency_ms
        );

        Ok(())
    }

    /// Enable a skill, making it available for matching.
    ///
    /// Returns an error if the skill is not found.
    pub fn enable(&self, id: &SkillId) -> RegistryResult<()> {
        let mut skills = self.skills.write();

        let skill = skills
            .get_mut(id)
            .ok_or_else(|| RegistryError::NotFound(id.to_string()))?;

        if !skill.enabled {
            skill.enabled = true;
            debug!("enabled skill: {}", id);
        }

        Ok(())
    }

    /// Disable a skill, preventing it from being matched.
    ///
    /// Returns an error if the skill is not found.
    pub fn disable(&self, id: &SkillId) -> RegistryResult<()> {
        let mut skills = self.skills.write();

        let skill = skills
            .get_mut(id)
            .ok_or_else(|| RegistryError::NotFound(id.to_string()))?;

        if skill.enabled {
            skill.enabled = false;
            debug!("disabled skill: {}", id);
        }

        Ok(())
    }

    /// Get the number of registered skills.
    pub fn skill_count(&self) -> usize {
        self.skills.read().len()
    }

    /// Get the number of enabled skills.
    pub fn enabled_count(&self) -> usize {
        self.skills.read().values().filter(|s| s.enabled).count()
    }
}

impl Default for SkillRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_skill(id: &str) -> (SkillId, SkillManifest, SkillOrigin) {
        let skill_id = SkillId::new(id);
        let manifest = SkillManifest {
            name: format!("Test Skill {}", id),
            description: format!("A test skill for {}", id),
            version: "0.1.0".to_string(),
            tools: vec![],
            required_credentials: vec![],
            keywords: vec!["test".to_string(), id.to_string()],
            prompt_template: None,
        };
        let origin = SkillOrigin::BuiltIn;
        (skill_id, manifest, origin)
    }

    #[test]
    fn test_registry_new() {
        let registry = SkillRegistry::new();
        assert_eq!(registry.skill_count(), 0);
    }

    #[test]
    fn test_register_skill() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        let result = registry.register(id.clone(), manifest, origin);
        assert!(result.is_ok());
        assert_eq!(registry.skill_count(), 1);
    }

    #[test]
    fn test_register_duplicate_skill() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        registry
            .register(id.clone(), manifest.clone(), origin.clone())
            .ok();
        let result = registry.register(id, manifest, origin);

        assert!(matches!(result, Err(RegistryError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_get_skill() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        registry.register(id.clone(), manifest.clone(), origin).ok();
        let retrieved = registry.get(&id);

        assert!(retrieved.is_some());
        let skill = retrieved.unwrap();
        assert_eq!(skill.manifest.name, manifest.name);
        assert!(skill.enabled);
    }

    #[test]
    fn test_get_nonexistent_skill() {
        let registry = SkillRegistry::new();
        let id = SkillId::new("nonexistent");

        let result = registry.get(&id);
        assert!(result.is_none());
    }

    #[test]
    fn test_unregister_skill() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        registry.register(id.clone(), manifest, origin).ok();
        assert_eq!(registry.skill_count(), 1);

        let result = registry.unregister(&id);
        assert!(result.is_ok());
        assert_eq!(registry.skill_count(), 0);
    }

    #[test]
    fn test_unregister_nonexistent_skill() {
        let registry = SkillRegistry::new();
        let id = SkillId::new("nonexistent");

        let result = registry.unregister(&id);
        assert!(matches!(result, Err(RegistryError::NotFound(_))));
    }

    #[test]
    fn test_list_skills() {
        let registry = SkillRegistry::new();

        for i in 0..3 {
            let (id, manifest, origin) = create_test_skill(&format!("test{}", i));
            registry.register(id, manifest, origin).ok();
        }

        let list = registry.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_enable_disable_skill() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        registry.register(id.clone(), manifest, origin).ok();
        assert!(registry.get(&id).unwrap().enabled);

        registry.disable(&id).ok();
        assert!(!registry.get(&id).unwrap().enabled);

        registry.enable(&id).ok();
        assert!(registry.get(&id).unwrap().enabled);
    }

    #[test]
    fn test_enabled_count() {
        let registry = SkillRegistry::new();

        for i in 0..3 {
            let (id, manifest, origin) = create_test_skill(&format!("test{}", i));
            registry.register(id, manifest, origin).ok();
        }

        assert_eq!(registry.enabled_count(), 3);

        let id1 = SkillId::new("test1");
        registry.disable(&id1).ok();
        assert_eq!(registry.enabled_count(), 2);
    }

    #[test]
    fn test_update_stats_success() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        registry.register(id.clone(), manifest, origin).ok();
        registry.update_stats(&id, true, 100).ok();

        let skill = registry.get(&id).unwrap();
        assert_eq!(skill.stats.invocation_count, 1);
        assert_eq!(skill.stats.success_count, 1);
        assert_eq!(skill.stats.failure_count, 0);
        assert_eq!(skill.stats.avg_latency_ms, 100.0);
    }

    #[test]
    fn test_update_stats_failure() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        registry.register(id.clone(), manifest, origin).ok();
        registry.update_stats(&id, false, 50).ok();

        let skill = registry.get(&id).unwrap();
        assert_eq!(skill.stats.invocation_count, 1);
        assert_eq!(skill.stats.success_count, 0);
        assert_eq!(skill.stats.failure_count, 1);
        assert_eq!(skill.stats.avg_latency_ms, 50.0);
    }

    #[test]
    fn test_update_stats_multiple_calls() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("test1");

        registry.register(id.clone(), manifest, origin).ok();

        // First call: 100ms success
        registry.update_stats(&id, true, 100).ok();
        assert_eq!(registry.get(&id).unwrap().stats.avg_latency_ms, 100.0);

        // Second call: 200ms success
        registry.update_stats(&id, true, 200).ok();
        assert_eq!(registry.get(&id).unwrap().stats.avg_latency_ms, 150.0);

        // Third call: 300ms failure
        registry.update_stats(&id, false, 300).ok();
        let stats = &registry.get(&id).unwrap().stats;
        assert_eq!(stats.invocation_count, 3);
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.failure_count, 1);
        assert!(stats.last_used.is_some());
    }

    #[test]
    fn test_update_stats_nonexistent_skill() {
        let registry = SkillRegistry::new();
        let id = SkillId::new("nonexistent");

        let result = registry.update_stats(&id, true, 100);
        assert!(matches!(result, Err(RegistryError::NotFound(_))));
    }

    #[test]
    fn test_default() {
        let registry = SkillRegistry::default();
        assert_eq!(registry.skill_count(), 0);
    }
}
