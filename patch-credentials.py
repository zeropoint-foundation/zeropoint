#!/usr/bin/env python3
"""
Patch: Credential aggregation with priority mechanism.

Backend (onboard.rs):
  - Aggregate found credentials across all tools into a global summary
  - Emit 'credentials_summary' event after scan_complete
  - Add 'vault_import_all' action for bulk import

Frontend (onboard.html):
  - Add 'Found in Plaintext' section to Step 6
  - Priority controls for duplicate/conflicting keys
  - 'Vault All Found' button
"""

import re

# ============================================================================
# 1. Patch onboard.rs — aggregate credentials + vault_import_all
# ============================================================================

rs_path = "crates/zp-server/src/onboard.rs"
with open(rs_path) as f:
    rs = f.read()

# --- 1a. Add global credential aggregation after scan loop ---
# We need to collect found_credentials from each tool into a global list,
# then emit a credentials_summary event after scan_complete.

# First: add a global aggregator before the per-tool scan loop
old_scan_loop_start = '''    // Scan for .env.example files (simplified discovery)
    let mut tool_count = 0;
    let mut unique_providers: std::collections::HashSet<String> = std::collections::HashSet::new();'''

new_scan_loop_start = '''    // Scan for .env.example files (simplified discovery)
    let mut tool_count = 0;
    let mut unique_providers: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Global credential aggregation across all tools
    let mut all_found_creds: Vec<serde_json::Value> = Vec::new();'''

if old_scan_loop_start in rs:
    rs = rs.replace(old_scan_loop_start, new_scan_loop_start)
    print("✓ Added all_found_creds aggregator")
elif 'all_found_creds' in rs:
    print("· all_found_creds already present")
else:
    print("✗ Could not find scan loop start")

# --- 1b. After per-tool found_credentials, add to global aggregator ---
# Find the line after "let found_count = found_credentials.len();"
# and add the global accumulation

old_found_count = '''            let found_count = found_credentials.len();
            let status = if needed.is_empty() {'''

new_found_count = '''            let found_count = found_credentials.len();

            // Accumulate into global list with source tool name
            for cred in &found_credentials {
                let mut entry = cred.clone();
                entry.as_object_mut().map(|m| {
                    m.insert("source_tool".into(), serde_json::json!(tool_name));
                });
                all_found_creds.push(entry);
            }

            let status = if needed.is_empty() {'''

if old_found_count in rs:
    rs = rs.replace(old_found_count, new_found_count)
    print("✓ Added global credential accumulation")
elif 'source_tool' in rs and 'all_found_creds.push' in rs:
    print("· Global accumulation already present")
else:
    print("✗ Could not find found_count block")

# --- 1c. After scan_complete event, emit credentials_summary ---
old_scan_complete = '''    events.push(OnboardEvent::new(
        "scan_complete",
        serde_json::json!({
            "tool_count": tool_count,
            "unique_providers": unique_providers.len(),
        }),
    ));

    events
}'''

new_scan_complete = '''    events.push(OnboardEvent::new(
        "scan_complete",
        serde_json::json!({
            "tool_count": tool_count,
            "unique_providers": unique_providers.len(),
        }),
    ));

    // ── Aggregate credentials by provider for priority/dedup ──
    if !all_found_creds.is_empty() {
        // Group by (provider, var_name) → list of (value, source_tool)
        let mut by_provider: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
            std::collections::BTreeMap::new();

        for cred in &all_found_creds {
            let provider = cred.get("provider").and_then(|v| v.as_str()).unwrap_or("unknown");
            by_provider.entry(provider.to_string()).or_default().push(cred.clone());
        }

        // Build summary: for each provider, list unique values + sources
        let mut provider_groups: Vec<serde_json::Value> = Vec::new();
        for (provider, creds) in &by_provider {
            // Deduplicate by actual value
            let mut unique_values: Vec<serde_json::Value> = Vec::new();
            let mut seen_values: std::collections::HashSet<String> = std::collections::HashSet::new();

            for c in creds {
                let val = c.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let source = c.get("source_tool").and_then(|v| v.as_str()).unwrap_or("?").to_string();
                let var_name = c.get("var_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let masked = c.get("masked_value").and_then(|v| v.as_str()).unwrap_or("••••").to_string();

                if seen_values.contains(&val) {
                    // Same value already seen — just add source tool to existing entry
                    for uv in &mut unique_values {
                        if uv.get("value").and_then(|v| v.as_str()) == Some(&val) {
                            if let Some(sources) = uv.get_mut("sources").and_then(|s| s.as_array_mut()) {
                                sources.push(serde_json::json!(source));
                            }
                            break;
                        }
                    }
                } else {
                    seen_values.insert(val.clone());
                    unique_values.push(serde_json::json!({
                        "var_name": var_name,
                        "masked_value": masked,
                        "value": val,
                        "sources": [source],
                    }));
                }
            }

            let has_conflict = unique_values.len() > 1;

            provider_groups.push(serde_json::json!({
                "provider": provider,
                "values": unique_values,
                "total_occurrences": creds.len(),
                "has_conflict": has_conflict,
            }));
        }

        let total_plaintext = all_found_creds.len();
        let conflicts = provider_groups.iter().filter(|g| g.get("has_conflict").and_then(|v| v.as_bool()).unwrap_or(false)).count();

        events.push(OnboardEvent::terminal(&format!(
            "\\n⚠ {} credential(s) found in plaintext across {} provider(s){}",
            total_plaintext,
            provider_groups.len(),
            if conflicts > 0 { format!(" · {} conflict(s)", conflicts) } else { String::new() }
        )));

        events.push(OnboardEvent::new(
            "credentials_summary",
            serde_json::json!({
                "providers": provider_groups,
                "total_plaintext": total_plaintext,
                "conflicts": conflicts,
            }),
        ));
    }

    events
}'''

if old_scan_complete in rs:
    rs = rs.replace(old_scan_complete, new_scan_complete)
    print("✓ Added credentials_summary event after scan_complete")
elif 'credentials_summary' in rs:
    print("· credentials_summary already present")
else:
    print("✗ Could not find scan_complete block")

# --- 1d. Add vault_import_all action handler ---
# Insert after vault_store handler

old_dispatch_configure = '''        "configure" => handle_configure(action, state).await,'''
new_dispatch_configure = '''        "vault_import_all" => handle_vault_import_all(action, state).await,
        "configure" => handle_configure(action, state).await,'''

if old_dispatch_configure in rs and 'vault_import_all' not in rs:
    rs = rs.replace(old_dispatch_configure, new_dispatch_configure)
    print("✓ Added vault_import_all to dispatch")
elif 'vault_import_all' in rs:
    print("· vault_import_all dispatch already present")
else:
    print("✗ Could not find configure dispatch line")

# Now add the handler function before handle_configure
old_configure_fn = '''/// Configure tools with vault credentials.
async fn handle_configure'''

# Check if it exists with different comment
if old_configure_fn not in rs:
    # Try alternate
    m = re.search(r'(///.*?\n)?async fn handle_configure\(', rs)
    if m:
        old_configure_fn = m.group(0)
    else:
        print("✗ Could not find handle_configure function")
        old_configure_fn = None

if old_configure_fn and 'handle_vault_import_all' not in rs:
    vault_import_fn = '''/// Bulk-import found plaintext credentials into the vault.
async fn handle_vault_import_all(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let credentials = match action.params.get("credentials").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => {
            events.push(OnboardEvent::error("vault_import_all requires 'credentials' array"));
            return events;
        }
    };

    events.push(OnboardEvent::terminal(&format!("Importing {} credential(s) into vault...", credentials.len())));

    let mut stored = 0;
    for cred in credentials {
        let provider = cred.get("provider").and_then(|v| v.as_str()).unwrap_or("unknown");
        let var_name = cred.get("var_name").and_then(|v| v.as_str()).unwrap_or("api_key");
        let value = match cred.get("value").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => continue,
        };

        let vault_ref = format!("{}/{}", provider, var_name.to_lowercase());

        // Mask value for display
        let masked = if value.len() > 8 {
            format!("{}...{}", &value[..4], &value[value.len()-4..])
        } else {
            "••••••••".to_string()
        };

        // Store in vault (same logic as vault_store)
        let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        let vault_path = home.join(".zeropoint").join("vault.json");

        // Read existing vault or create new
        let mut vault: serde_json::Value = if vault_path.exists() {
            std::fs::read_to_string(&vault_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        // Store the credential
        vault.as_object_mut().map(|m| {
            m.insert(vault_ref.clone(), serde_json::json!({
                "value": value,
                "provider": provider,
                "var_name": var_name,
                "imported_from": "plaintext_scan",
            }));
        });

        // Write back
        if let Some(parent) = vault_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&vault) {
            let _ = std::fs::write(&vault_path, json);
        }

        stored += 1;
        state.credentials_stored += 1;

        events.push(OnboardEvent::new(
            "credential_stored",
            serde_json::json!({
                "vault_ref": vault_ref,
                "provider": provider,
                "var_name": var_name,
                "masked_value": masked,
                "total_stored": state.credentials_stored,
            }),
        ));

        events.push(OnboardEvent::terminal(&format!(
            "  ✓ {} → vault:{}", var_name, vault_ref
        )));
    }

    events.push(OnboardEvent::terminal(&format!(
        "\\n{} credential(s) secured in vault", stored
    )));

    events.push(OnboardEvent::new(
        "import_complete",
        serde_json::json!({
            "imported": stored,
            "total_stored": state.credentials_stored,
        }),
    ));

    events
}

''' + old_configure_fn

    rs = rs.replace(old_configure_fn, vault_import_fn)
    print("✓ Added handle_vault_import_all function")
elif 'handle_vault_import_all' in rs:
    print("· handle_vault_import_all already present")

with open(rs_path, "w") as f:
    f.write(rs)
print("✓ Wrote onboard.rs")

# ============================================================================
# 2. Patch onboard.html — Found in Plaintext UI with priority controls
# ============================================================================

html_path = "crates/zp-server/assets/onboard.html"
with open(html_path) as f:
    html = f.read()

# --- 2a. Add CSS for found-credentials section ---
# Insert before the .container rule

found_cred_css = """
  /* ── Found Credentials ─────────────────────────────── */

  .found-creds-section {
    background: rgba(221, 168, 85, 0.06);
    border: 1px solid rgba(221, 168, 85, 0.25);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    margin-bottom: 1.25rem;
  }
  .found-creds-section h3 {
    font-size: 0.82rem;
    color: var(--yellow);
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .found-creds-section h3 .count-badge {
    background: rgba(221, 168, 85, 0.2);
    color: var(--yellow);
    font-size: 0.7rem;
    padding: 0.15rem 0.5rem;
    border-radius: 10px;
    font-weight: 600;
  }
  .found-provider-group {
    margin-bottom: 0.75rem;
    padding: 0.6rem 0.8rem;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    transition: border-color 0.2s;
  }
  .found-provider-group:hover { border-color: var(--border-active); }
  .found-provider-group.has-conflict { border-color: rgba(221, 168, 85, 0.4); }
  .found-provider-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.4rem;
  }
  .found-provider-name {
    font-size: 0.82rem;
    font-weight: 500;
    color: var(--text-bright);
  }
  .found-source-tag {
    font-size: 0.65rem;
    color: var(--text-dim);
    background: rgba(255,255,255,0.05);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    display: inline-block;
    margin-left: 0.25rem;
  }
  .found-value-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0;
    font-size: 0.78rem;
  }
  .found-value-row input[type="radio"] {
    accent-color: var(--accent);
  }
  .found-masked-value {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--yellow);
    background: rgba(221, 168, 85, 0.08);
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
  }
  .found-var-name {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--text-dim);
  }
  .priority-controls {
    display: flex;
    gap: 0.2rem;
    margin-left: auto;
  }
  .priority-btn {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-dim);
    width: 20px;
    height: 20px;
    border-radius: 3px;
    font-size: 0.65rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
  }
  .priority-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }
  .vault-all-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid rgba(221, 168, 85, 0.15);
  }
  .vault-all-btn {
    background: linear-gradient(135deg, var(--yellow), #cc8833);
    color: #000;
    border: none;
    padding: 0.5rem 1.25rem;
    border-radius: 6px;
    font-size: 0.82rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
  }
  .vault-all-btn:hover { opacity: 0.85; }
  .vault-all-btn:disabled { opacity: 0.4; cursor: default; }
  .vault-all-status {
    font-size: 0.75rem;
    color: var(--text-dim);
  }
"""

css_insert_marker = '  /* ── Layout '
if '.found-creds-section' not in html:
    html = html.replace(css_insert_marker, found_cred_css + '\n' + css_insert_marker)
    print("✓ Added found-credentials CSS")
else:
    print("· Found-credentials CSS already present")

# --- 2b. Add HTML for found credentials section in Step 6 ---
old_step6_detected = '''    <!-- Detected providers (env vars found) -->
    <div id="detectedProviders" style="display:none">'''

new_step6_detected = '''    <!-- Found in plaintext (scraped from .env files) -->
    <div id="foundPlaintextSection" class="found-creds-section" style="display:none">
      <h3>
        <span>⚠ Found in Plaintext</span>
        <span class="count-badge" id="foundPlaintextCount">0</span>
      </h3>
      <p style="font-size:0.78rem; color:var(--text-dim); margin-bottom:0.75rem">
        These API keys are sitting unencrypted in your project <code>.env</code> files.
        Select which to vault — drag to reorder priority.
      </p>
      <div id="foundPlaintextCards"></div>
      <div class="vault-all-bar">
        <span class="vault-all-status" id="vaultAllStatus">Select credentials to secure</span>
        <button class="vault-all-btn" id="vaultAllBtn" onclick="vaultAllFound()" disabled>Vault All Found</button>
      </div>
    </div>

    <!-- Detected providers (env vars found) -->
    <div id="detectedProviders" style="display:none">'''

if 'foundPlaintextSection' not in html:
    html = html.replace(old_step6_detected, new_step6_detected)
    print("✓ Added Found in Plaintext HTML section")
else:
    print("· Found in Plaintext section already present")

# --- 2c. Add JS for credential summary handling + priority controls ---
# Insert after the storeCred / markCredentialStored block

old_js_marker = '''  window.storeCred = function(provider, vaultRef) {
    const input = document.getElementById(`cred-input-${provider}`);
    const value = input.value.trim();
    if (!value) return;

    send('vault_store', { vault_ref: vaultRef, value });
  };'''

new_js_with_found = '''  window.storeCred = function(provider, vaultRef) {
    const input = document.getElementById(`cred-input-${provider}`);
    const value = input.value.trim();
    if (!value) return;

    send('vault_store', { vault_ref: vaultRef, value });
  };

  // ── Found Credentials (plaintext .env scraping) ──────────
  let foundCredentialsSummary = null;  // Server response from credentials_summary
  let selectedFoundCreds = {};         // provider → selected value object

  function showFoundCredentials(data) {
    foundCredentialsSummary = data;
    const providers = data.providers || [];
    if (providers.length === 0) return;

    const section = document.getElementById('foundPlaintextSection');
    const container = document.getElementById('foundPlaintextCards');
    const countBadge = document.getElementById('foundPlaintextCount');

    section.style.display = 'block';
    countBadge.textContent = data.total_plaintext || providers.length;
    container.innerHTML = '';

    // Initialize selections — pick first value for each provider
    selectedFoundCreds = {};

    providers.forEach((group, gi) => {
      const provider = group.provider;
      const values = group.values || [];
      const hasConflict = group.has_conflict;

      const div = document.createElement('div');
      div.className = 'found-provider-group' + (hasConflict ? ' has-conflict' : '');
      div.id = `found-group-${provider}`;

      // Header
      let headerHtml = `
        <div class="found-provider-header">
          <div>
            <span class="found-provider-name">${provider}</span>
            ${hasConflict ? '<span style="font-size:0.68rem; color:var(--yellow); margin-left:0.5rem">⚠ conflicting values</span>' : ''}
          </div>
          <div class="priority-controls">
            <button class="priority-btn" onclick="moveProviderUp('${provider}')" title="Move up">▲</button>
            <button class="priority-btn" onclick="moveProviderDown('${provider}')" title="Move down">▼</button>
          </div>
        </div>
      `;

      let valuesHtml = '';
      values.forEach((v, vi) => {
        const sources = (v.sources || []).join(', ');
        const isSelected = vi === 0; // First value is default selection
        const radioName = `found-${provider}`;

        if (isSelected) {
          selectedFoundCreds[provider] = v;
        }

        if (hasConflict) {
          // Show radio buttons when values conflict
          valuesHtml += `
            <div class="found-value-row">
              <input type="radio" name="${radioName}" value="${vi}" ${isSelected ? 'checked' : ''}
                     onchange="selectFoundCred('${provider}', ${vi})">
              <span class="found-var-name">${v.var_name}</span>
              <span class="found-masked-value">${v.masked_value}</span>
              <span class="found-source-tag">${sources}</span>
            </div>
          `;
        } else {
          // Single value — just show it with checkbox to include/exclude
          valuesHtml += `
            <div class="found-value-row">
              <input type="checkbox" checked onchange="toggleFoundCred('${provider}', this.checked, ${vi})"
                     style="accent-color:var(--accent)">
              <span class="found-var-name">${v.var_name}</span>
              <span class="found-masked-value">${v.masked_value}</span>
              <span class="found-source-tag">${sources}</span>
            </div>
          `;
        }
      });

      div.innerHTML = headerHtml + valuesHtml;
      container.appendChild(div);
    });

    updateVaultAllStatus();
  }

  window.selectFoundCred = function(provider, valueIndex) {
    if (!foundCredentialsSummary) return;
    const group = foundCredentialsSummary.providers.find(g => g.provider === provider);
    if (group && group.values[valueIndex]) {
      selectedFoundCreds[provider] = group.values[valueIndex];
    }
    updateVaultAllStatus();
  };

  window.toggleFoundCred = function(provider, checked, valueIndex) {
    if (checked) {
      const group = foundCredentialsSummary.providers.find(g => g.provider === provider);
      if (group && group.values[valueIndex]) {
        selectedFoundCreds[provider] = group.values[valueIndex];
      }
    } else {
      delete selectedFoundCreds[provider];
    }
    updateVaultAllStatus();
  };

  window.moveProviderUp = function(provider) {
    const container = document.getElementById('foundPlaintextCards');
    const el = document.getElementById(`found-group-${provider}`);
    if (el && el.previousElementSibling) {
      container.insertBefore(el, el.previousElementSibling);
    }
  };

  window.moveProviderDown = function(provider) {
    const container = document.getElementById('foundPlaintextCards');
    const el = document.getElementById(`found-group-${provider}`);
    if (el && el.nextElementSibling) {
      container.insertBefore(el.nextElementSibling, el);
    }
  };

  function updateVaultAllStatus() {
    const count = Object.keys(selectedFoundCreds).length;
    const btn = document.getElementById('vaultAllBtn');
    const status = document.getElementById('vaultAllStatus');

    if (count === 0) {
      btn.disabled = true;
      status.textContent = 'No credentials selected';
    } else {
      btn.disabled = false;
      btn.textContent = `Vault ${count} Credential${count !== 1 ? 's' : ''}`;
      status.textContent = `${count} selected — plaintext will remain in .env until you remove it`;
    }
  }

  window.vaultAllFound = function() {
    const credentials = Object.entries(selectedFoundCreds).map(([provider, v]) => ({
      provider,
      var_name: v.var_name,
      value: v.value,
    }));

    if (credentials.length === 0) return;

    const btn = document.getElementById('vaultAllBtn');
    btn.disabled = true;
    btn.textContent = 'Importing...';

    send('vault_import_all', { credentials });
  };

  function handleImportComplete(data) {
    const btn = document.getElementById('vaultAllBtn');
    const status = document.getElementById('vaultAllStatus');
    btn.textContent = '✓ Vaulted';
    btn.disabled = true;
    status.textContent = `${data.imported} credential(s) secured · ${data.total_stored} total in vault`;
    status.style.color = 'var(--green)';

    // Mark provider cards as stored
    Object.keys(selectedFoundCreds).forEach(provider => {
      const group = document.getElementById(`found-group-${provider}`);
      if (group) {
        group.style.borderColor = 'var(--green)';
        group.style.opacity = '0.7';
      }
      // Also mark in the catalog section if present
      const catalogCard = document.getElementById(`cred-${provider}`);
      if (catalogCard && !catalogCard.classList.contains('stored')) {
        catalogCard.classList.add('stored');
        const input = catalogCard.querySelector('input[type="password"]');
        if (input) {
          const v = selectedFoundCreds[provider];
          input.value = v.masked_value || '••••••';
          input.disabled = true;
        }
        const storeBtn = catalogCard.querySelector('.store-btn');
        if (storeBtn) {
          storeBtn.textContent = '✓';
          storeBtn.disabled = true;
        }
      }
    });

    updateCredentialSummary();
  }'''

if 'showFoundCredentials' not in html:
    html = html.replace(old_js_marker, new_js_with_found)
    print("✓ Added found credentials JS (priority controls, vault all)")
else:
    print("· Found credentials JS already present")

# --- 2d. Wire up credentials_summary event in the WebSocket handler ---
old_scan_complete_handler = "      case 'scan_complete':"
# Find what's after it
scan_complete_idx = html.find(old_scan_complete_handler)
if scan_complete_idx > 0:
    # Find the next case statement after scan_complete
    next_case = html.find("      case '", scan_complete_idx + len(old_scan_complete_handler))
    if next_case > 0:
        existing_block = html[scan_complete_idx:next_case]

        # Check if credentials_summary case already exists
        if "credentials_summary" not in html:
            # Insert credentials_summary handler before the next case
            cred_summary_handler = """      case 'credentials_summary':
        showFoundCredentials(data);
        break;
      case 'import_complete':
        handleImportComplete(data);
        break;
"""
            html = html[:next_case] + cred_summary_handler + html[next_case:]
            print("✓ Added credentials_summary + import_complete event handlers")
        else:
            print("· credentials_summary handler already present")
else:
    print("✗ Could not find scan_complete case in WebSocket handler")

with open(html_path, "w") as f:
    f.write(html)
print("✓ Wrote onboard.html")

print("\n═══════════════════════════════════════════")
print("Done. Next steps:")
print("  1. cargo clean -p zp-server --release")
print("  2. cargo install --path crates/zp-server --release")
print("  3. cp ~/.cargo/bin/zp ~/.local/bin/zp")
print("  4. cp crates/zp-server/assets/onboard.html ~/.zeropoint/assets/onboard.html")
print("  5. Kill old zp serve, restart")
print("═══════════════════════════════════════════")
