//! Observer agent prompt generation and result parsing.
//!
//! The Observer is a sub-agent (spawned via `LocalAgentTask`) that compresses
//! raw receipts/messages into structured observations. This module provides
//! the system prompt and output parsing logic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Observation, ObservationPriority, SourceRange};

/// System prompt for the Observer agent.
pub const OBSERVER_SYSTEM_PROMPT: &str = r#"You are an observation agent. Your job is to compress raw conversation history into concise, prioritized observations.

For each meaningful fact, produce a JSON object on its own line:
{"content": "<concise factual statement>", "priority": "high|medium|low|completed", "category": "<topic>", "referenced_at": "<ISO timestamp>", "relative_time": "<human-friendly>"}

Priority guidelines:
- high: Critical constraints, blockers, security issues, urgent deadlines, hard requirements
- medium: Active project details, technical decisions, ongoing work, architecture choices
- low: Preferences, background context, general knowledge, nice-to-haves
- completed: Resolved items, finished tasks, closed issues, done work

Rules:
1. Each observation must be a standalone fact — no references to "the above" or "as mentioned"
2. Preserve exact names, numbers, IDs, paths, and technical details
3. Merge duplicate or near-duplicate information into single observations
4. Timestamp observations with when the event happened, not the current time
5. One observation per distinct fact — do not combine unrelated items
6. Use the most specific category you can (e.g., "auth", "database", "deployment")
7. Keep each observation under 50 words
8. Output ONLY valid JSON lines — no markdown, no commentary"#;

/// Build the user prompt for the Observer agent, containing the raw messages
/// to observe.
pub fn build_observer_prompt(messages: &[(String, String)]) -> String {
    let mut prompt =
        String::from("Compress the following conversation segment into observations:\n\n");

    for (role, content) in messages {
        prompt.push_str(&format!("[{}]: {}\n\n", role, content));
    }

    prompt.push_str("\nOutput one JSON observation per line:");
    prompt
}

/// A raw observation parsed from Observer agent output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawObservation {
    pub content: String,
    pub priority: String,
    pub category: String,
    pub referenced_at: Option<String>,
    pub relative_time: Option<String>,
}

/// Parse Observer agent output into structured observations.
///
/// The Observer outputs one JSON object per line. We parse each line
/// independently so partial output still yields results.
pub fn parse_observer_output(output: &str, source_range: &SourceRange) -> Vec<Observation> {
    let now = Utc::now();

    output
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .filter_map(|line| {
            let raw: RawObservation = serde_json::from_str(line.trim()).ok()?;

            let priority = ObservationPriority::from_str_loose(&raw.priority)
                .unwrap_or(ObservationPriority::Low);

            let referenced_at = raw
                .referenced_at
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now);

            let token_estimate = Observation::estimate_tokens(&raw.content);

            Some(Observation {
                id: format!("obs-{}", uuid::Uuid::new_v4()),
                content: raw.content,
                priority,
                category: raw.category,
                referenced_at,
                observed_at: now,
                relative_time: raw.relative_time,
                source_range: source_range.clone(),
                superseded: false,
                token_estimate,
                receipt_id: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_output() {
        let output = r#"{"content": "User is building an auth system with JWT", "priority": "medium", "category": "auth", "referenced_at": "2026-04-01T10:00:00Z", "relative_time": "earlier today"}
{"content": "Database uses PostgreSQL 15", "priority": "low", "category": "database", "referenced_at": "2026-04-01T09:00:00Z", "relative_time": "this morning"}"#;

        let sr = SourceRange::new("chain-1", "aaa", "bbb", 0, 10);
        let observations = parse_observer_output(output, &sr);

        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations[0].content,
            "User is building an auth system with JWT"
        );
        assert_eq!(observations[0].priority, ObservationPriority::Medium);
        assert_eq!(observations[0].category, "auth");
        assert_eq!(observations[1].content, "Database uses PostgreSQL 15");
        assert_eq!(observations[1].priority, ObservationPriority::Low);
    }

    #[test]
    fn parse_with_noise() {
        let output = r#"Here are the observations:
{"content": "Critical: API rate limit is 100 req/s", "priority": "high", "category": "api"}
Some extra text that should be ignored
{"content": "Team prefers Rust", "priority": "low", "category": "preference"}"#;

        let sr = SourceRange::new("chain-1", "aaa", "bbb", 0, 5);
        let observations = parse_observer_output(output, &sr);

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].priority, ObservationPriority::High);
    }

    #[test]
    fn parse_empty_output() {
        let sr = SourceRange::new("chain-1", "aaa", "bbb", 0, 0);
        let observations = parse_observer_output("", &sr);
        assert!(observations.is_empty());
    }

    #[test]
    fn build_prompt_format() {
        let messages = vec![
            ("user".to_string(), "Help me with auth".to_string()),
            ("assistant".to_string(), "I'll set up JWT".to_string()),
        ];

        let prompt = build_observer_prompt(&messages);
        assert!(prompt.contains("[user]: Help me with auth"));
        assert!(prompt.contains("[assistant]: I'll set up JWT"));
    }

    #[test]
    fn parse_invalid_priority_defaults_to_low() {
        let output = r#"{"content": "some fact", "priority": "super-high", "category": "test"}"#;
        let sr = SourceRange::new("chain-1", "aaa", "bbb", 0, 0);
        let observations = parse_observer_output(output, &sr);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].priority, ObservationPriority::Low);
    }
}
