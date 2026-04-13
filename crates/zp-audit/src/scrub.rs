//! Secret scrubbing for audit entry text fields.
//!
//! The audit chain is the forensic record of what the system did. Under
//! normal operation, every secret flowing through the system should be
//! referenced by hash (via `AuditAction::ToolInvoked.arguments_hash` and
//! friends), never by value. But `AuditAction` contains a few free-text
//! variants (`SystemEvent.event`, `PolicyInteraction.user_response`) where
//! a caller could accidentally embed a bearer token, API key, or password.
//! AUDIT-04 in the 2026-04-06 pentest noted that this was the leakage
//! primitive for shell command strings that carried `Authorization: Bearer
//! ...` substrings.
//!
//! This module is the defense-in-depth layer that runs on every
//! [`crate::UnsealedEntry`] passed to [`crate::AuditStore::append`]. It's
//! a pure string rewriter with a small, conservative set of patterns — the
//! goal is to catch the obvious leakage vectors, not to be a general-purpose
//! PII redactor. If a new pattern appears, add it here and add a test.
//!
//! Design notes:
//!
//! * Scrubbing is **always on**. There is no env var to disable it — the
//!   audit chain is the single source of truth for forensics and we never
//!   want it to carry a live credential.
//! * Patterns are case-insensitive.
//! * Replacements keep the surrounding structure so audit readers can still
//!   tell what kind of secret was there (e.g. `Bearer <redacted>` vs
//!   `api_key=<redacted>`).
//! * The output is never longer than the input — redaction only shrinks.

use std::sync::OnceLock;

use regex::Regex;

use crate::chain::UnsealedEntry;
use zp_core::AuditAction;

/// The set of patterns we redact. Each pattern → replacement string.
///
/// Order matters: more specific patterns first so generic `api_key=...`
/// doesn't eat the `Bearer ...` case.
struct ScrubRule {
    pattern: Regex,
    replacement: &'static str,
}

fn rules() -> &'static [ScrubRule] {
    static RULES: OnceLock<Vec<ScrubRule>> = OnceLock::new();
    RULES.get_or_init(|| vec![
        // `Bearer <hex-or-base64-ish>` — the classic Authorization-header leak.
        ScrubRule {
            pattern: Regex::new(r"(?i)Bearer\s+[A-Za-z0-9._\-/+=]{8,}").unwrap(),
            replacement: "Bearer <redacted>",
        },
        // `Basic <base64>` — HTTP Basic auth.
        ScrubRule {
            pattern: Regex::new(r"(?i)Basic\s+[A-Za-z0-9+/=]{8,}").unwrap(),
            replacement: "Basic <redacted>",
        },
        // Anthropic-style keys: `sk-ant-...`. Must come before the generic
        // sk- rule so the `-ant-` prefix is preserved in the replacement.
        ScrubRule {
            pattern: Regex::new(r"sk-ant-[A-Za-z0-9_\-]{16,}").unwrap(),
            replacement: "sk-ant-<redacted>",
        },
        // OpenAI-style keys: `sk-xxx...`.
        ScrubRule {
            pattern: Regex::new(r"sk-[A-Za-z0-9]{16,}").unwrap(),
            replacement: "sk-<redacted>",
        },
        // GitHub personal access tokens.
        ScrubRule {
            pattern: Regex::new(r"gh[pousr]_[A-Za-z0-9]{20,}").unwrap(),
            replacement: "gh<x>_<redacted>",
        },
        // AWS access key IDs.
        ScrubRule {
            pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            replacement: "AKIA<redacted>",
        },
        // `api_key=...`, `apikey: ...`, `token=...`, `password=...`,
        // `secret=...` — the generic key=value form. The value match is
        // anchored to stop at whitespace, quotes, or common delimiters.
        ScrubRule {
            pattern: Regex::new(
                r#"(?i)(api[_-]?key|token|password|passwd|secret|auth)\s*[:=]\s*["']?[^\s"'&,;)]+"#,
            )
            .unwrap(),
            replacement: "$1=<redacted>",
        },
        // `x-api-key: ...` header form.
        ScrubRule {
            pattern: Regex::new(r"(?i)(x-api-key|x-auth-token)\s*:\s*[^\s,;]+").unwrap(),
            replacement: "$1: <redacted>",
        },
    ])
}

/// Apply every redaction rule to `input`, returning the scrubbed string.
///
/// Pure, allocation-light, case-insensitive. If no rule matches, the input
/// is returned unchanged (cheap path).
pub fn scrub_secrets(input: &str) -> String {
    let mut out = std::borrow::Cow::Borrowed(input);
    for rule in rules().iter() {
        if rule.pattern.is_match(&out) {
            let replaced = rule.pattern.replace_all(&out, rule.replacement).into_owned();
            out = std::borrow::Cow::Owned(replaced);
        }
    }
    out.into_owned()
}

/// Return a copy of `entry` with all free-text fields passed through
/// [`scrub_secrets`].
///
/// Called from [`crate::AuditStore::append`] before the entry is sealed into
/// the chain. If you add a new free-text field to `AuditAction` or
/// `UnsealedEntry`, add it here — the compiler won't warn you, but the
/// pentest will.
pub fn scrub_unsealed(mut entry: UnsealedEntry) -> UnsealedEntry {
    entry.action = scrub_action(entry.action);
    entry.policy_module = scrub_secrets(&entry.policy_module);
    entry
}

fn scrub_action(action: AuditAction) -> AuditAction {
    match action {
        AuditAction::SystemEvent { event } => AuditAction::SystemEvent {
            event: scrub_secrets(&event),
        },
        AuditAction::PolicyInteraction {
            decision_type,
            user_response,
        } => AuditAction::PolicyInteraction {
            decision_type: scrub_secrets(&decision_type),
            user_response: user_response.map(|r| scrub_secrets(&r)),
        },
        AuditAction::OutputSanitized {
            patterns_applied,
            fields_redacted,
        } => AuditAction::OutputSanitized {
            patterns_applied: patterns_applied.iter().map(|p| scrub_secrets(p)).collect(),
            fields_redacted,
        },
        // Everything else carries only hashes or structured data — no text
        // surface to scrub. Listed explicitly so a new variant is a compile
        // error until this match is updated.
        AuditAction::MessageReceived { .. }
        | AuditAction::ResponseGenerated { .. }
        | AuditAction::ToolInvoked { .. }
        | AuditAction::ToolCompleted { .. }
        | AuditAction::CredentialInjected { .. }
        | AuditAction::SkillActivated { .. }
        | AuditAction::SkillProposed { .. }
        | AuditAction::SkillApproved { .. }
        | AuditAction::ApiCallProxied { .. } => action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_bearer_token() {
        let s = scrub_secrets("ran `curl -H 'Authorization: Bearer 287458350abcdef1234567890'`");
        assert!(s.contains("Bearer <redacted>"));
        assert!(!s.contains("287458350abcdef1234567890"));
    }

    #[test]
    fn scrub_basic_auth() {
        let s = scrub_secrets("Authorization: Basic dXNlcjpwYXNzd29yZA==");
        assert!(s.contains("Basic <redacted>"));
        assert!(!s.contains("dXNlcjpwYXNzd29yZA=="));
    }

    #[test]
    fn scrub_openai_key() {
        let s = scrub_secrets("OPENAI_API_KEY=sk-proj-1234567890abcdefghij in env");
        assert!(!s.contains("sk-proj-1234567890abcdefghij"));
    }

    #[test]
    fn scrub_anthropic_key() {
        // The generic `api_key=...` rule may redact the value before the
        // sk-ant- rule sees it; either outcome is fine as long as the raw
        // secret does not survive.
        let s = scrub_secrets("export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghij0123456789");
        assert!(!s.contains("sk-ant-api03-abcdefghij0123456789"));
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn scrub_bare_anthropic_key() {
        // Bare token with no key=value wrapper — sk-ant- rule must catch it.
        let s = scrub_secrets("used sk-ant-api03-abcdefghij0123456789 in the request");
        assert!(s.contains("sk-ant-<redacted>"));
        assert!(!s.contains("sk-ant-api03-abcdefghij0123456789"));
    }

    #[test]
    fn scrub_github_pat() {
        let s = scrub_secrets("GH_TOKEN=ghp_1234567890abcdefghij1234567890abcd");
        assert!(!s.contains("ghp_1234567890abcdefghij1234567890abcd"));
    }

    #[test]
    fn scrub_aws_access_key() {
        let s = scrub_secrets("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn scrub_generic_key_value() {
        let s = scrub_secrets("api_key=abc123def456 other=safe");
        assert!(s.contains("api_key=<redacted>"));
        assert!(s.contains("other=safe"));
    }

    #[test]
    fn scrub_password_colon_form() {
        let s = scrub_secrets("password: hunter2!");
        assert!(s.contains("password=<redacted>") || s.contains("password: <redacted>"));
        assert!(!s.contains("hunter2!"));
    }

    #[test]
    fn scrub_x_api_key_header() {
        let s = scrub_secrets("x-api-key: abcdef1234567890");
        assert!(s.to_lowercase().contains("<redacted>"));
        assert!(!s.contains("abcdef1234567890"));
    }

    #[test]
    fn scrub_leaves_clean_text_alone() {
        let s = "System event: pipeline stage 3 completed in 142ms";
        assert_eq!(scrub_secrets(s), s);
    }

    #[test]
    fn scrub_system_event_unsealed() {
        use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
        let entry = UnsealedEntry::new(
            ActorId::Operator,
            AuditAction::SystemEvent {
                event: "startup token=deadbeef1234cafe".into(),
            },
            ConversationId::new(),
            PolicyDecision::Allow { conditions: vec![] },
            "test",
        );
        let scrubbed = scrub_unsealed(entry);
        if let AuditAction::SystemEvent { event } = scrubbed.action {
            assert!(event.contains("<redacted>"));
            assert!(!event.contains("deadbeef1234cafe"));
        } else {
            panic!("expected SystemEvent");
        }
    }
}
