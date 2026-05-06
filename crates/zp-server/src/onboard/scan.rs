//! Tool discovery — delegates to zp_engine::scan.

use super::{OnboardAction, OnboardEvent, OnboardState};

/// Scan a directory for tools with .env / .env.example files.
/// Delegates entirely to zp-engine for the actual scanning logic.
pub async fn handle_scan(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let scan_path = action
        .params
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("~/projects");

    // Expand ~ to home directory
    let expanded = if let Some(suffix) = scan_path.strip_prefix("~/") {
        zp_core::paths::user_home_or(".").join(suffix)
    } else {
        std::path::PathBuf::from(scan_path)
    };

    events.push(OnboardEvent::terminal(&format!(
        "Scanning {}...",
        expanded.display()
    )));

    if !expanded.exists() {
        events.push(OnboardEvent::error(&format!(
            "Directory not found: {}",
            expanded.display()
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

        let found_creds_json: Vec<serde_json::Value> = tool
            .found_credentials
            .iter()
            .map(|c| {
                serde_json::json!({
                    "var_name": c.var_name,
                    "provider": c.provider,
                    "masked_value": c.masked_value,
                    "value": c.value,
                })
            })
            .collect();

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
                    tool.name,
                    tool.found_credentials.len()
                )));
            }
            zp_engine::scan::ToolStatus::Unconfigured => {
                events.push(OnboardEvent::terminal(&format!(
                    "  {} — unconfigured",
                    tool.name
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
        let provider_groups: Vec<serde_json::Value> = results
            .credential_groups
            .iter()
            .map(|g| {
                let values: Vec<serde_json::Value> = g
                    .values
                    .iter()
                    .map(|v| {
                        serde_json::json!({
                            "var_name": v.var_name,
                            "masked_value": v.masked_value,
                            "value": v.value,
                            "sources": v.sources,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "provider": g.provider,
                    "values": values,
                    "has_conflict": g.has_conflict,
                })
            })
            .collect();

        let conflicts = results
            .credential_groups
            .iter()
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
            "\n✓ No plaintext credentials found in .env files",
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
