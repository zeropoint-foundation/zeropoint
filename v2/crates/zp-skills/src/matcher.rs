//! Skill matching engine — finds relevant skills for a given request.
//!
//! Phase 1 implements simple keyword-based matching.
//! Future phases will add semantic matching using embeddings.

use std::collections::HashMap;
use tracing::debug;

use crate::registry::SkillRegistry;
use zp_core::SkillId;

/// The skill matcher — finds relevant skills based on request content.
pub struct SkillMatcher;

impl SkillMatcher {
    /// Match skills against a request based on keyword overlap.
    ///
    /// This Phase 1 implementation uses simple keyword matching:
    /// - Tokenizes the request content into lowercase words
    /// - Counts keyword matches with each skill's manifest keywords
    /// - Returns enabled skills sorted by match count (descending)
    /// - Removes duplicates and maintains relevance order
    ///
    /// # Arguments
    /// * `registry` - The skill registry to search
    /// * `request_content` - The request text to match against
    ///
    /// # Returns
    /// A vector of SkillId in order of relevance (highest match count first)
    pub fn match_request(registry: &SkillRegistry, request_content: &str) -> Vec<SkillId> {
        // Tokenize request into words
        let lowercase = request_content.to_lowercase();
        let request_tokens: Vec<&str> = lowercase
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty())
            .collect();

        debug!(
            "matching request with {} tokens: {:?}",
            request_tokens.len(),
            request_tokens
        );

        // Score each enabled skill
        let mut scores: HashMap<SkillId, usize> = HashMap::new();

        for (skill_id, skill) in registry.list() {
            // Skip disabled skills
            if !skill.enabled {
                debug!("skipping disabled skill: {}", skill_id);
                continue;
            }

            // Count keyword matches
            let mut match_count = 0;

            for keyword in &skill.manifest.keywords {
                let keyword_lower = keyword.to_lowercase();
                // Count how many request tokens match this keyword
                for token in &request_tokens {
                    if keyword_lower.contains(*token) || token.contains(keyword_lower.as_str()) {
                        match_count += 1;
                    }
                }
            }

            if match_count > 0 {
                debug!(
                    "skill {} matched with {} keyword hits",
                    skill_id, match_count
                );
                scores.insert(skill_id, match_count);
            }
        }

        // Sort by score descending
        let mut results: Vec<(SkillId, usize)> = scores.into_iter().collect();
        results.sort_by(|a, b| b.1.cmp(&a.1).then(a.0 .0.cmp(&b.0 .0)));

        let matched_ids: Vec<SkillId> = results.into_iter().map(|(id, _)| id).collect();

        debug!("matched {} skills", matched_ids.len());
        matched_ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::{SkillManifest, SkillOrigin};

    fn create_test_skill(id: &str, keywords: Vec<&str>) -> (SkillId, SkillManifest, SkillOrigin) {
        let skill_id = SkillId::new(id);
        let manifest = SkillManifest {
            name: format!("Skill {}", id),
            description: format!("Test skill {}", id),
            version: "0.1.0".to_string(),
            tools: vec![],
            required_credentials: vec![],
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
            prompt_template: None,
        };
        let origin = SkillOrigin::BuiltIn;
        (skill_id, manifest, origin)
    }

    #[test]
    fn test_matcher_new() {
        let _matcher = SkillMatcher;
        // Just verifying it can be instantiated
    }

    #[test]
    fn test_match_request_empty_registry() {
        let registry = SkillRegistry::new();
        let results = SkillMatcher::match_request(&registry, "send an email");

        assert!(results.is_empty());
    }

    #[test]
    fn test_match_request_no_matches() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("email", vec!["send", "mail", "smtp"]);

        registry.register(id, manifest, origin).ok();

        let results = SkillMatcher::match_request(&registry, "calculate fibonacci numbers");
        assert!(results.is_empty());
    }

    #[test]
    fn test_match_request_single_match() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("email", vec!["send", "mail", "email"]);

        registry.register(id.clone(), manifest, origin).ok();

        let results = SkillMatcher::match_request(&registry, "send an email");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], id);
    }

    #[test]
    fn test_match_request_multiple_matches() {
        let registry = SkillRegistry::new();

        let (id1, manifest1, origin1) = create_test_skill("email", vec!["send", "mail", "email"]);
        let (id2, manifest2, origin2) =
            create_test_skill("scheduler", vec!["schedule", "calendar", "event"]);
        let (id3, manifest3, origin3) = create_test_skill("file", vec!["save", "open", "file"]);

        registry.register(id1, manifest1, origin1).ok();
        registry.register(id2, manifest2, origin2).ok();
        registry.register(id3, manifest3, origin3).ok();

        let results = SkillMatcher::match_request(&registry, "send email to calendar");
        assert_eq!(results.len(), 2); // email and scheduler should match
    }

    #[test]
    fn test_match_request_relevance_sorting() {
        let registry = SkillRegistry::new();

        // "email" has 2 matching keywords: "send" and "email"
        let (id1, manifest1, origin1) = create_test_skill("email", vec!["send", "mail", "email"]);
        // "message" has 1 matching keyword: "send"
        let (id2, manifest2, origin2) =
            create_test_skill("message", vec!["send", "message", "notify"]);

        registry.register(id1.clone(), manifest1, origin1).ok();
        registry.register(id2, manifest2, origin2).ok();

        let results = SkillMatcher::match_request(&registry, "send email");

        // Should be sorted by match count: email skill (2 matches) before message skill (1 match)
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], id1); // email skill has more matches
    }

    #[test]
    fn test_match_request_ignores_disabled_skills() {
        let registry = SkillRegistry::new();
        let (id1, manifest1, origin1) = create_test_skill("email", vec!["send", "email"]);
        let (id2, manifest2, origin2) = create_test_skill("sms", vec!["send", "message"]);

        registry.register(id1.clone(), manifest1, origin1).ok();
        registry.register(id2, manifest2, origin2).ok();

        // Disable the email skill
        registry.disable(&id1).ok();

        let results = SkillMatcher::match_request(&registry, "send email");

        // Should only match sms, not email
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], SkillId::new("sms"));
    }

    #[test]
    fn test_match_request_case_insensitive() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("email", vec!["SEND", "Email", "MAIL"]);

        registry.register(id.clone(), manifest, origin).ok();

        let results = SkillMatcher::match_request(&registry, "SEND an EMAIL");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], id);
    }

    #[test]
    fn test_match_request_partial_keyword_match() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) =
            create_test_skill("email", vec!["sending", "mailing", "emails"]);

        registry.register(id.clone(), manifest, origin).ok();

        // "send" should match "sending" and "mail" should match "mailing"
        let results = SkillMatcher::match_request(&registry, "send and mail");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], id);
    }

    #[test]
    fn test_match_request_handles_special_characters() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("email", vec!["send", "email"]);

        registry.register(id.clone(), manifest, origin).ok();

        // Request with special characters should still match
        let results = SkillMatcher::match_request(&registry, "send...email!!! (please)");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], id);
    }

    #[test]
    fn test_match_request_empty_request() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("email", vec!["send", "email"]);

        registry.register(id, manifest, origin).ok();

        let results = SkillMatcher::match_request(&registry, "");
        assert!(results.is_empty());
    }

    #[test]
    fn test_match_request_whitespace_only_request() {
        let registry = SkillRegistry::new();
        let (id, manifest, origin) = create_test_skill("email", vec!["send", "email"]);

        registry.register(id, manifest, origin).ok();

        let results = SkillMatcher::match_request(&registry, "   \t\n   ");
        assert!(results.is_empty());
    }

    #[test]
    fn test_match_request_deterministic_ordering() {
        let registry = SkillRegistry::new();

        // Create skills with same match count to test secondary sort
        let (id1, manifest1, origin1) = create_test_skill("alpha", vec!["send", "email"]);
        let (id2, manifest2, origin2) = create_test_skill("beta", vec!["send", "email"]);

        registry.register(id1.clone(), manifest1, origin1).ok();
        registry.register(id2.clone(), manifest2, origin2).ok();

        let results = SkillMatcher::match_request(&registry, "send email");

        // Both have same match count, should be sorted by ID
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], id1); // "alpha" < "beta" alphabetically
        assert_eq!(results[1], id2);
    }

    #[test]
    fn test_match_request_many_skills() {
        let registry = SkillRegistry::new();

        // Register many skills with varying relevance
        for i in 0..10 {
            let keywords = if i == 0 {
                vec!["send", "email", "mail", "message"]
            } else if i < 5 {
                vec!["send", "email"]
            } else {
                vec!["process", "data", "compute"]
            };

            let (id, manifest, origin) = create_test_skill(&format!("skill{}", i), keywords);
            registry.register(id, manifest, origin).ok();
        }

        let results = SkillMatcher::match_request(&registry, "send email");

        // Should match skills 0-4
        assert!(results.len() >= 5);

        // Skill 0 should be first (most matches)
        assert_eq!(results[0], SkillId::new("skill0"));
    }
}
