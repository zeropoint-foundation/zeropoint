//! Argument projection for receipts.
//!
//! Receipts carry a hash of the full arguments and a bounded, redacted
//! projection — never the raw value. Two reasons, both structural:
//!
//! 1. Credential discipline. `zp-regent/src/config.rs` establishes that key
//!    material resolves at call time and is dropped, never entering the
//!    cognitive or receipt path. A tool call carrying `--header
//!    "Authorization: Bearer …"` would violate that through the audit chain
//!    rather than through context, which is worse: the chain is durable.
//!
//! 2. Chain economy. The chain verifies at 47K entries/sec because entries are
//!    small. Storing tool arguments verbatim makes receipt size a function of
//!    what the model happened to type.
//!
//! The hash is over the *full* value, so redaction never weakens verification:
//! a verifier with the original arguments can still reproduce the digest.

use serde_json::{Map, Value};

const MAX_DEPTH: usize = 4;
const MAX_STRING: usize = 512;
const MAX_ARRAY: usize = 20;

/// Keys whose values are replaced wholesale, regardless of content.
fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["key", "token", "secret", "password", "passwd", "auth", "credential", "cookie", "session"]
        .iter()
        .any(|needle| k.contains(needle))
}

/// Value-shaped secrets that appear in otherwise innocuous fields — a bearer
/// token pasted into a `bash` command, for instance.
fn scrub_value_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for token in s.split_inclusive(char::is_whitespace) {
        let trimmed = token.trim();
        let looks_secret = trimmed.len() >= 20
            && (trimmed.starts_with("sk-")
                || trimmed.starts_with("ghp_")
                || trimmed.starts_with("gho_")
                || trimmed.starts_with("ghu_")
                || trimmed.starts_with("ghs_")
                || trimmed.starts_with("ghr_")
                || trimmed.starts_with("eyJ")
                || trimmed.starts_with("xoxb-")
                || trimmed.starts_with("AKIA"));
        if looks_secret {
            out.push_str("«redacted»");
            if token.ends_with(char::is_whitespace) {
                out.push(' ');
            }
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Bounded, redacted projection of a tool-call argument value.
pub fn project(value: &Value) -> Value {
    project_at(value, 0)
}

fn project_at(value: &Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return Value::String("…".into());
    }
    match value {
        Value::String(s) => {
            let scrubbed = scrub_value_secrets(s);
            if scrubbed.len() > MAX_STRING {
                let mut truncated: String = scrubbed.chars().take(MAX_STRING).collect();
                truncated.push('…');
                Value::String(truncated)
            } else {
                Value::String(scrubbed)
            }
        }
        Value::Array(items) => {
            let mut out: Vec<Value> = items
                .iter()
                .take(MAX_ARRAY)
                .map(|v| project_at(v, depth + 1))
                .collect();
            if items.len() > MAX_ARRAY {
                out.push(Value::String(format!("…{} more", items.len() - MAX_ARRAY)));
            }
            Value::Array(out)
        }
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                if is_secret_key(k) {
                    out.insert(k.clone(), Value::String("«redacted»".into()));
                } else {
                    out.insert(k.clone(), project_at(v, depth + 1));
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_secret_keys() {
        let v = json!({ "url": "https://x", "api_key": "hunter2", "Authorization": "Bearer z" });
        let p = project(&v);
        assert_eq!(p["api_key"], "«redacted»");
        assert_eq!(p["Authorization"], "«redacted»");
        assert_eq!(p["url"], "https://x");
    }

    #[test]
    fn scrubs_inline_tokens_in_commands() {
        let v = json!({ "command": "curl -H 'x: ghp_abcdefghijklmnopqrstuvwxyz012345' https://api" });
        let p = project(&v);
        let cmd = p["command"].as_str().unwrap();
        assert!(cmd.contains("«redacted»"), "token survived: {cmd}");
        assert!(cmd.contains("curl"), "command body was destroyed: {cmd}");
    }

    #[test]
    fn bounds_depth_and_arrays() {
        let deep = json!({"a":{"b":{"c":{"d":{"e":{"f": 1}}}}}});
        assert_eq!(project(&deep)["a"]["b"]["c"]["d"]["e"], json!("…"));

        let wide = json!({ "items": (0..50).collect::<Vec<_>>() });
        assert_eq!(project(&wide)["items"].as_array().unwrap().len(), MAX_ARRAY + 1);
    }

    #[test]
    fn projection_does_not_affect_the_hash_input() {
        // Documents the invariant: callers hash the original value, then
        // project. A verifier holding the original reproduces the digest.
        let original = json!({ "api_key": "hunter2" });
        let projected = project(&original);
        assert_ne!(original, projected);
    }
}
