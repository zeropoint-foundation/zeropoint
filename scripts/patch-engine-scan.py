#!/usr/bin/env python3
"""
Patch onboard.rs: Replace handle_scan with zp-engine delegation.

Replaces the 260-line hand-rolled scan with a call to
zp_engine::scan::scan_tools() that translates results to events.
"""
import re

FILE = "crates/zp-server/src/onboard.rs"

with open(FILE, "r") as f:
    content = f.read()

# Find the old handle_scan function
# It starts with "async fn handle_scan" and ends before "/// Store a credential"
old_pattern = re.compile(
    r'(async fn handle_scan\(action: &OnboardAction, state: &mut OnboardState\) -> Vec<OnboardEvent> \{)'
    r'.*?'
    r'(\n/// Store a credential in the vault\.)',
    re.DOTALL
)

new_handle_scan = r'''async fn handle_scan(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let scan_path = action.params.get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("~/projects");

    // Expand ~ to home directory
    let expanded = if scan_path.starts_with("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(&scan_path[2..])
    } else {
        std::path::PathBuf::from(scan_path)
    };

    events.push(OnboardEvent::terminal(&format!("Scanning {}...", expanded.display())));

    if !expanded.exists() {
        events.push(OnboardEvent::error(&format!(
            "Directory not found: {}", expanded.display()
        )));
        return events;
    }

    // ── Delegate to zp-engine (single source of truth) ──
    let results = zp_engine::scan::scan_tools(&expanded);

    // Emit per-tool events for the UI
    for tool in &results.tools {
        let status_str = match tool.status {
            zp_engine::scan::ToolStatus::HasPlaintext => "has_plaintext",
            zp_engine::scan::ToolStatus::Unconfigured => "unconfigured",
        };

        let found_creds_json: Vec<serde_json::Value> = tool.found_credentials.iter().map(|c| {
            serde_json::json!({
                "var_name": c.var_name,
                "provider": c.provider,
                "masked_value": c.masked_value,
                "value": c.value,
            })
        }).collect();

        events.push(OnboardEvent::new(
            "scan_result",
            serde_json::json!({
                "tool_name": tool.name,
                "path": tool.path.to_string_lossy(),
                "status": status_str,
                "provider_vars": tool.provider_vars,
                "found_credentials": found_creds_json,
                "found_count": tool.found_credentials.len(),
            }),
        ));

        match tool.status {
            zp_engine::scan::ToolStatus::HasPlaintext => {
                events.push(OnboardEvent::terminal(&format!(
                    "  {} — configured · ⚠ {} plaintext credential(s)",
                    tool.name, tool.found_credentials.len()
                )));
            }
            zp_engine::scan::ToolStatus::Unconfigured => {
                events.push(OnboardEvent::terminal(&format!(
                    "  {} — unconfigured", tool.name
                )));
            }
        }
    }

    let tool_count = results.tools.len();
    state.scan_path = Some(scan_path.to_string());
    state.tools_discovered = tool_count;
    state.step = 5;

    events.push(OnboardEvent::terminal(&format!(
        "\n{} tool(s) found · {} unique provider(s)",
        tool_count,
        results.unique_providers.len()
    )));

    events.push(OnboardEvent::new(
        "scan_complete",
        serde_json::json!({
            "tool_count": tool_count,
            "unique_providers": results.unique_providers.len(),
        }),
    ));

    // ── Credential summary from engine's aggregation ──
    if results.total_plaintext > 0 {
        let provider_groups: Vec<serde_json::Value> = results.credential_groups.iter().map(|g| {
            let values: Vec<serde_json::Value> = g.values.iter().map(|v| {
                serde_json::json!({
                    "var_name": v.var_name,
                    "masked_value": v.masked_value,
                    "value": v.value,
                    "sources": v.sources,
                })
            }).collect();
            serde_json::json!({
                "provider": g.provider,
                "values": values,
                "has_conflict": g.has_conflict,
            })
        }).collect();

        let conflicts = results.credential_groups.iter()
            .filter(|g| g.has_conflict)
            .count();

        events.push(OnboardEvent::new(
            "credentials_summary",
            serde_json::json!({
                "providers": provider_groups,
                "total_plaintext": results.total_plaintext,
                "conflicts": conflicts,
            }),
        ));
    } else if tool_count > 0 {
        events.push(OnboardEvent::terminal(
            "\n✓ No plaintext credentials found in .env files"
        ));
        events.push(OnboardEvent::new(
            "credentials_summary",
            serde_json::json!({
                "providers": [],
                "total_plaintext": 0,
                "conflicts": 0,
            }),
        ));
    }

    events
}

'''

match = old_pattern.search(content)
if match:
    # Replace old function body, keep the "/// Store a credential" doc comment
    content = content[:match.start()] + new_handle_scan + match.group(2) + content[match.end():]
    with open(FILE, "w") as f:
        f.write(content)
    print(f"✓ Replaced handle_scan ({match.end() - match.start()} chars)")
else:
    print("✗ Could not find handle_scan function boundaries")
    print("  Looking for: 'async fn handle_scan' ... '/// Store a credential'")
    # Try to find the function for debugging
    if "async fn handle_scan" in content:
        idx = content.index("async fn handle_scan")
        print(f"  Found 'async fn handle_scan' at char {idx}")
    else:
        print("  'async fn handle_scan' not found at all!")

# Also update detect_provider and infer_provider_from_var to delegate to zp-engine
# (or remove them if no other code references them)
# For now, redirect them:

old_detect = '''fn detect_provider(var_name: &str) -> Option<String> {
    // Load catalog (this is cheap — the TOML is parsed from a static string)
    let catalog = load_provider_catalog();

    // Check exact match against every provider's env_patterns
    for provider in &catalog {
        for pattern in &provider.env_patterns {
            if var_name == pattern {
                return Some(provider.id.clone());
            }
        }
    }

    // Local inference runtime env vars (no API key — host/endpoint config)
    let local_runtimes = [
        ("OLLAMA_HOST", "ollama"),
        ("OLLAMA_BASE_URL", "ollama"),
        ("LM_STUDIO", "lm-studio"),
        ("LOCALAI", "localai"),
    ];
    for (var, name) in &local_runtimes {
        if var_name == *var {
            return Some(name.to_string());
        }
    }

    None
}'''

new_detect = '''fn detect_provider(var_name: &str) -> Option<String> {
    zp_engine::providers::detect_provider(var_name)
}'''

if old_detect in content:
    content = content.replace(old_detect, new_detect)
    with open(FILE, "w") as f:
        f.write(content)
    print("✓ Redirected detect_provider → zp_engine")
else:
    print("⚠ detect_provider not found (may already be updated)")

old_infer = '''fn infer_provider_from_var(var_name: &str) -> String {
    let lower = var_name.to_lowercase();
    // Strip common suffixes to find the service name
    let suffixes = ["_api_key", "_key", "_secret", "_token", "_id",
                    "_password", "_pass", "_host", "_url", "_endpoint",
                    "_operator_id", "_operator_key", "_access_key",
                    "_secret_key", "_account_id", "_project_id"];
    for suffix in &suffixes {
        if lower.ends_with(suffix) {
            let prefix = &lower[..lower.len() - suffix.len()];
            if !prefix.is_empty() {
                return prefix.to_string();
            }
        }
    }
    // Fallback: use everything before the first underscore
    lower.split(\'_\').next().unwrap_or("unknown").to_string()
}'''

new_infer = '''fn infer_provider_from_var(var_name: &str) -> String {
    zp_engine::providers::infer_provider_from_var(var_name)
}'''

if old_infer in content:
    content = content.replace(old_infer, new_infer)
    with open(FILE, "w") as f:
        f.write(content)
    print("✓ Redirected infer_provider_from_var → zp_engine")
else:
    print("⚠ infer_provider_from_var not found (may already be updated)")

print("\nDone. Run: ./zp-dev.sh")
