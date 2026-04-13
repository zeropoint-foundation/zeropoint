//! Reflector agent prompt generation and result parsing.
//!
//! The Reflector is a sub-agent that consolidates observations when the
//! observation store exceeds the reflection threshold. It merges duplicates,
//! upgrades/downgrades priorities, and drops stale observations.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::{Observation, ObservationData, ObservationPriority, ReflectorAction, SourceRange};

/// System prompt for the Reflector agent.
pub const REFLECTOR_SYSTEM_PROMPT: &str = r#"You are a reflection agent. Your job is to consolidate a set of observations to reduce token usage while preserving critical information.

For each action, output a JSON object on its own line:
{"action": "merge", "source_ids": ["id1", "id2"], "result": {"content": "...", "priority": "...", "category": "...", "referenced_at": "...", "relative_time": "..."}}
{"action": "upgrade", "source_ids": ["id1"], "result": {"content": "...", "priority": "high", "category": "...", "referenced_at": "...", "relative_time": "..."}}
{"action": "downgrade", "source_ids": ["id1"], "result": {"content": "...", "priority": "low", "category": "...", "referenced_at": "...", "relative_time": "..."}}
{"action": "complete", "source_ids": ["id1"]}
{"action": "drop", "source_ids": ["id1"]}

Actions:
- merge: Combine 2+ observations about the same topic into one richer observation
- upgrade: Increase priority if new evidence shows higher importance
- downgrade: Decrease priority if the observation is becoming stale or less relevant
- complete: Mark as resolved/done (will be retained briefly then pruned)
- drop: Remove entirely (no longer relevant at all)

Rules:
1. NEVER drop high-priority observations unless they are clearly resolved
2. Prefer merging over keeping duplicates — fewer, richer observations are better
3. Update relative_time annotations to reflect current time perspective
4. Target: total token count after reflection should be < 60% of input tokens
5. Preserve exact technical details (names, paths, versions, IDs) when merging
6. Output ONLY valid JSON lines — no markdown, no commentary"#;

/// Build the user prompt for the Reflector, containing all active observations.
pub fn build_reflector_prompt(observations: &[Observation]) -> String {
    let mut prompt = String::from("Consolidate the following observations. Current total: ");

    let total_tokens: usize = observations.iter().map(|o| o.token_estimate).sum();
    prompt.push_str(&format!(
        "{} tokens. Target: < {} tokens.\n\n",
        total_tokens,
        (total_tokens as f64 * 0.6) as usize
    ));

    for obs in observations {
        prompt.push_str(&format!(
            "ID: {}\nPriority: {} {}\nCategory: {}\nContent: {}\nObserved: {}\n\n",
            obs.id,
            obs.priority.emoji(),
            obs.priority,
            obs.category,
            obs.content,
            obs.relative_time.as_deref().unwrap_or("unknown"),
        ));
    }

    prompt.push_str("Output one action per line:");
    prompt
}

/// A raw reflector action parsed from output.
#[derive(Debug, Clone, Deserialize)]
struct RawReflectorOutput {
    action: String,
    source_ids: Vec<String>,
    result: Option<RawObservationData>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawObservationData {
    content: String,
    priority: String,
    category: String,
    referenced_at: Option<String>,
    relative_time: Option<String>,
}

/// Parse Reflector agent output into structured actions.
pub fn parse_reflector_output(output: &str) -> Vec<ReflectorAction> {
    output
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .filter_map(|line| {
            let raw: RawReflectorOutput = serde_json::from_str(line.trim()).ok()?;

            match raw.action.as_str() {
                "merge" => {
                    let data = raw.result?;
                    Some(ReflectorAction::Merge {
                        source_ids: raw.source_ids,
                        result: parse_observation_data(data),
                    })
                }
                "upgrade" => {
                    let data = raw.result?;
                    Some(ReflectorAction::Upgrade {
                        source_ids: raw.source_ids,
                        result: parse_observation_data(data),
                    })
                }
                "downgrade" => {
                    let data = raw.result?;
                    Some(ReflectorAction::Downgrade {
                        source_ids: raw.source_ids,
                        result: parse_observation_data(data),
                    })
                }
                "complete" => Some(ReflectorAction::Complete {
                    source_ids: raw.source_ids,
                }),
                "drop" => Some(ReflectorAction::Drop {
                    source_ids: raw.source_ids,
                }),
                _ => None,
            }
        })
        .collect()
}

fn parse_observation_data(raw: RawObservationData) -> ObservationData {
    let priority =
        ObservationPriority::from_str_loose(&raw.priority).unwrap_or(ObservationPriority::Low);

    let referenced_at = raw
        .referenced_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    ObservationData {
        content: raw.content,
        priority,
        category: raw.category,
        referenced_at,
        relative_time: raw.relative_time,
    }
}

/// Apply reflector actions to produce a Reflection result.
///
/// Takes the current active observations and the parsed actions,
/// returns lists of consumed IDs, produced observations, and dropped IDs.
pub fn apply_reflector_actions(
    current_observations: &[Observation],
    actions: &[ReflectorAction],
) -> (Vec<String>, Vec<Observation>, Vec<String>) {
    let now = Utc::now();
    let mut consumed = Vec::new();
    let mut produced = Vec::new();
    let mut dropped = Vec::new();

    // Build a default source range from the first observation (for new observations)
    let default_range = current_observations
        .first()
        .map(|o| o.source_range.clone())
        .unwrap_or_else(|| SourceRange::new("reflection", "none", "none", 0, 0));

    for action in actions {
        match action {
            ReflectorAction::Merge { source_ids, result }
            | ReflectorAction::Upgrade { source_ids, result }
            | ReflectorAction::Downgrade { source_ids, result } => {
                consumed.extend(source_ids.clone());

                let new_obs = Observation {
                    id: format!("obs-{}", uuid::Uuid::new_v4()),
                    content: result.content.clone(),
                    priority: result.priority,
                    category: result.category.clone(),
                    referenced_at: result.referenced_at,
                    observed_at: now,
                    relative_time: result.relative_time.clone(),
                    source_range: default_range.clone(),
                    superseded: false,
                    token_estimate: Observation::estimate_tokens(&result.content),
                    receipt_id: None,
                };

                produced.push(new_obs);
            }
            ReflectorAction::Complete { source_ids } => {
                // Completed observations get downgraded, not removed immediately
                for id in source_ids {
                    if let Some(obs) = current_observations.iter().find(|o| &o.id == id) {
                        let mut completed = obs.clone();
                        completed.id = format!("obs-{}", uuid::Uuid::new_v4());
                        completed.priority = ObservationPriority::Completed;
                        completed.observed_at = now;
                        produced.push(completed);
                    }
                    consumed.push(id.clone());
                }
            }
            ReflectorAction::Drop { source_ids } => {
                dropped.extend(source_ids.clone());
            }
        }
    }

    (consumed, produced, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_merge_action() {
        let output = r#"{"action": "merge", "source_ids": ["obs-1", "obs-2"], "result": {"content": "Auth system uses JWT with bcrypt hashing", "priority": "medium", "category": "auth", "referenced_at": "2026-04-01T10:00:00Z", "relative_time": "today"}}"#;

        let actions = parse_reflector_output(output);
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            ReflectorAction::Merge { source_ids, result } => {
                assert_eq!(source_ids.len(), 2);
                assert_eq!(result.content, "Auth system uses JWT with bcrypt hashing");
                assert_eq!(result.priority, ObservationPriority::Medium);
            }
            _ => panic!("expected merge action"),
        }
    }

    #[test]
    fn parse_drop_action() {
        let output = r#"{"action": "drop", "source_ids": ["obs-stale"]}"#;
        let actions = parse_reflector_output(output);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ReflectorAction::Drop { source_ids } => {
                assert_eq!(source_ids, &["obs-stale"]);
            }
            _ => panic!("expected drop action"),
        }
    }

    #[test]
    fn parse_mixed_output() {
        let output = r#"{"action": "merge", "source_ids": ["o1", "o2"], "result": {"content": "merged", "priority": "high", "category": "test"}}
{"action": "complete", "source_ids": ["o3"]}
{"action": "drop", "source_ids": ["o4", "o5"]}"#;

        let actions = parse_reflector_output(output);
        assert_eq!(actions.len(), 3);
    }

    #[test]
    fn apply_actions() {
        let observations = vec![
            Observation {
                id: "o1".into(),
                content: "fact A".into(),
                priority: ObservationPriority::Low,
                category: "test".into(),
                referenced_at: Utc::now(),
                observed_at: Utc::now(),
                relative_time: None,
                source_range: SourceRange::new("c1", "a", "b", 0, 1),
                superseded: false,
                token_estimate: 5,
                receipt_id: None,
            },
            Observation {
                id: "o2".into(),
                content: "fact A updated".into(),
                priority: ObservationPriority::Medium,
                category: "test".into(),
                referenced_at: Utc::now(),
                observed_at: Utc::now(),
                relative_time: None,
                source_range: SourceRange::new("c1", "c", "d", 2, 3),
                superseded: false,
                token_estimate: 8,
                receipt_id: None,
            },
        ];

        let actions = vec![ReflectorAction::Merge {
            source_ids: vec!["o1".into(), "o2".into()],
            result: ObservationData {
                content: "comprehensive fact A".into(),
                priority: ObservationPriority::Medium,
                category: "test".into(),
                referenced_at: Utc::now(),
                relative_time: Some("recently".into()),
            },
        }];

        let (consumed, produced, dropped) = apply_reflector_actions(&observations, &actions);

        assert_eq!(consumed.len(), 2);
        assert_eq!(produced.len(), 1);
        assert_eq!(produced[0].content, "comprehensive fact A");
        assert!(dropped.is_empty());
    }

    #[test]
    fn build_prompt_includes_all_observations() {
        let obs = vec![Observation {
            id: "o1".into(),
            content: "important fact".into(),
            priority: ObservationPriority::High,
            category: "test".into(),
            referenced_at: Utc::now(),
            observed_at: Utc::now(),
            relative_time: Some("just now".into()),
            source_range: SourceRange::new("c1", "a", "b", 0, 1),
            superseded: false,
            token_estimate: 5,
            receipt_id: None,
        }];

        let prompt = build_reflector_prompt(&obs);
        assert!(prompt.contains("important fact"));
        assert!(prompt.contains("o1"));
        assert!(prompt.contains("🔴"));
    }
}
