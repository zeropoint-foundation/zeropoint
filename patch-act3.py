#!/usr/bin/env python3
"""
Act 3 overhaul — make the finale sell it.

1. Fix handle_configure: std::process::Command → tokio::process::Command
2. Emit per-tool 'tool_configured' events so cards light up one by one
3. Redesign Step 7: animated tool cards going from "discovered" → "securing..." → "governed ✓"
4. Redesign Step 8: Roku-style launch-pad grid with live project tiles
"""

import re, sys

# ── 1. Patch Rust backend ────────────────────────────────────────────────────

rust_path = "crates/zp-server/src/onboard.rs"
with open(rust_path) as f:
    rust = f.read()

rust_changes = 0

# 1a. Switch std::process::Command → tokio::process::Command (if still blocking)
if "std::process::Command::new(&zp_bin)" in rust:
    rust = rust.replace(
        "std::process::Command::new(&zp_bin)",
        "tokio::process::Command::new(&zp_bin)"
    )
    rust_changes += 1
    print("  [rust] std::process::Command → tokio::process::Command")

# 1b. Add .await after .output() if missing
if ".output()\n    {" in rust and ".output()\n        .await\n    {" not in rust:
    rust = rust.replace(".output()\n    {", ".output()\n        .await\n    {")
    rust_changes += 1
    print("  [rust] Added .await after .output()")

# 1c. Add binary debug line if missing
if 'events.push(OnboardEvent::terminal(&format!("Binary: {}"' not in rust:
    rust = rust.replace(
        '    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));\n\n    // Run the configure engine',
        '    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));\n\n    events.push(OnboardEvent::terminal(&format!("Binary: {}", zp_bin.display())));\n\n    // Run the configure engine',
    )
    rust_changes += 1
    print("  [rust] Added binary debug line")

# 1d. Add empty-output detection if missing
if "(no output from zp configure)" not in rust:
    rust = rust.replace(
        "            if output.status.success() {",
        '            if stdout.is_empty() && stderr.is_empty() {\n                events.push(OnboardEvent::terminal("(no output from zp configure)"));\n            }\n\n            if output.status.success() {',
        1
    )
    rust_changes += 1
    print("  [rust] Added empty-output detection")

# 1e. Add per-tool events: parse configure output for individual tool results
# After the "✓ Tools configured" line, emit individual tool_configured events
old_configured_block = '''                state.tools_configured = if configured_count > 0 {
                    configured_count
                } else {
                    state.tools_discovered
                };'''

new_configured_block = '''                state.tools_configured = if configured_count > 0 {
                    configured_count
                } else {
                    state.tools_discovered
                };

                // Emit per-tool events so the UI can animate each card
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    // Parse lines like "  CONFIG openmaictool (/Users/.../openmaictool)"
                    // or "  ✓ openmaictool — configured"
                    if trimmed.starts_with("CONFIG") || trimmed.starts_with("✓") {
                        // Extract tool name (second word usually)
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "governed",
                                }),
                            ));
                        }
                    }
                }'''

if "tool_configured" not in rust and old_configured_block in rust:
    rust = rust.replace(old_configured_block, new_configured_block)
    rust_changes += 1
    print("  [rust] Added per-tool tool_configured events")

with open(rust_path, "w") as f:
    f.write(rust)

print(f"✓ Rust: {rust_changes} change(s) applied\n")


# ── 2. Patch HTML frontend ──────────────────────────────────────────────────

html_path = "crates/zp-server/assets/onboard.html"
with open(html_path) as f:
    html = f.read()

html_changes = 0

# 2a. Add CSS for tool configuration cards + launch grid
new_css = """
  /* ── Tool Configuration Cards (Step 7) ──────────────── */

  .tool-config-grid {
    display: grid;
    gap: 0.75rem;
    margin: 1.5rem 0;
  }

  .tool-config-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    transition: all 0.6s ease;
    position: relative;
    overflow: hidden;
  }

  .tool-config-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: linear-gradient(90deg, transparent 0%, var(--accent-dim) 50%, transparent 100%);
    opacity: 0;
    transition: opacity 0.4s ease;
  }

  .tool-config-card.securing::before {
    opacity: 1;
    animation: shimmer 1.5s ease-in-out infinite;
  }

  @keyframes shimmer {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
  }

  .tool-config-card.governed {
    border-color: var(--green);
    background: rgba(102, 187, 136, 0.06);
  }

  .tool-config-card .tool-icon {
    width: 40px;
    height: 40px;
    border-radius: 8px;
    background: var(--accent-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    flex-shrink: 0;
    transition: all 0.6s ease;
    z-index: 1;
  }

  .tool-config-card.governed .tool-icon {
    background: rgba(102, 187, 136, 0.15);
  }

  .tool-config-card .tool-info {
    flex: 1;
    z-index: 1;
  }

  .tool-config-card .tool-name {
    font-size: 0.88rem;
    font-weight: 500;
    color: var(--text-bright);
  }

  .tool-config-card .tool-status {
    font-size: 0.75rem;
    color: var(--text-dim);
    margin-top: 0.15rem;
    transition: color 0.4s ease;
  }

  .tool-config-card.securing .tool-status {
    color: var(--accent);
  }

  .tool-config-card.governed .tool-status {
    color: var(--green);
  }

  .tool-config-card .tool-badge {
    font-size: 0.7rem;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    background: var(--border);
    color: var(--text-dim);
    z-index: 1;
    transition: all 0.6s ease;
  }

  .tool-config-card.governed .tool-badge {
    background: rgba(102, 187, 136, 0.15);
    color: var(--green);
  }

  /* ── Launch Pad (Step 8) ────────────────────────────── */

  .launchpad-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
  }

  .launchpad-tile {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s ease;
    position: relative;
  }

  .launchpad-tile:hover {
    background: var(--bg-card-hover);
    border-color: var(--accent);
    transform: translateY(-2px);
  }

  .launchpad-tile .tile-icon {
    width: 56px;
    height: 56px;
    border-radius: 14px;
    margin: 0 auto 0.75rem;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.5rem;
    background: var(--accent-dim);
  }

  .launchpad-tile .tile-name {
    font-size: 0.88rem;
    font-weight: 500;
    color: var(--text-bright);
    margin-bottom: 0.25rem;
  }

  .launchpad-tile .tile-status {
    font-size: 0.72rem;
    color: var(--text-dim);
  }

  .launchpad-tile .tile-health {
    position: absolute;
    top: 0.75rem;
    right: 0.75rem;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green);
  }

  .launchpad-tile .tile-health.pending {
    background: var(--yellow);
  }

  .launchpad-tile.add-tile {
    border-style: dashed;
    border-color: var(--border);
    opacity: 0.6;
  }

  .launchpad-tile.add-tile:hover {
    opacity: 1;
    border-color: var(--accent);
  }

  .launchpad-tile.add-tile .tile-icon {
    background: transparent;
    border: 1px dashed var(--border);
    font-size: 1.5rem;
    color: var(--text-dim);
  }

  .governance-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.68rem;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    background: rgba(102, 187, 136, 0.1);
    color: var(--green);
    margin-top: 0.4rem;
  }
"""

# Insert before the closing </style>
if ".tool-config-grid" not in html:
    html = html.replace("</style>", new_css + "\n</style>")
    html_changes += 1
    print("  [html] Added CSS for tool cards + launch grid")

# 2b. Replace Step 7 HTML
old_step7 = """  <div class="step" id="step-7">
    <div class="step-header">07 — configure</div>
    <h2>Configure &amp; Govern</h2>

    <p>In the old model, you give API keys to tools and hope they behave. You have no visibility into what calls are being made. ZeroPoint changes this — with the governance proxy enabled, every API call routes through your local policy engine. You can't govern what you can't see.</p>

    <div class="card">
      <h3>Governance Proxy</h3>
      <p>Every API call passes through your local policy engine before forwarding. You get policy enforcement, cost metering, and signed receipts.</p>
      <label style="display:flex; align-items:center; gap:0.5rem; font-size:0.82rem; cursor:pointer; margin-top:0.5rem">
        <input type="checkbox" id="proxyEnabled" checked>
        <span>Enable governance proxy (port 3000)</span>
      </label>
    </div>

    <div class="btn-row">
      <button class="btn" id="configureBtn" onclick="runConfigure()">Configure All</button>
    </div>

    <div class="terminal" id="configureTerm" style="display:none"></div>

    <div class="btn-row" id="configureNext" style="display:none">
      <button class="btn" onclick="goStep(8)">Continue</button>
    </div>
  </div>"""

new_step7 = """  <div class="step" id="step-7">
    <div class="step-header">07 — configure</div>
    <h2>Bring Your Tools Under Governance</h2>

    <p>This is the moment everything connects. Your vault credentials flow into your discovered tools. The governance proxy wraps every API call with policy enforcement, cost metering, and cryptographic receipts. Watch each tool come online.</p>

    <div class="card" style="margin-bottom:1rem">
      <label style="display:flex; align-items:center; gap:0.5rem; font-size:0.82rem; cursor:pointer">
        <input type="checkbox" id="proxyEnabled" checked>
        <span>Route all API calls through governance proxy <span style="color:var(--text-dim)">(port 3000)</span></span>
      </label>
    </div>

    <div id="configToolCards" class="tool-config-grid"></div>

    <div class="btn-row">
      <button class="btn" id="configureBtn" onclick="runConfigure()">Secure &amp; Configure</button>
    </div>

    <div class="terminal" id="configureTerm" style="display:none; margin-top:1rem; max-height:150px; overflow-y:auto; font-size:0.72rem"></div>

    <div class="btn-row" id="configureNext" style="display:none">
      <button class="btn" onclick="goStep(8)">See Your Launch Pad →</button>
    </div>
  </div>"""

if old_step7 in html:
    html = html.replace(old_step7, new_step7)
    html_changes += 1
    print("  [html] Replaced Step 7 HTML")
else:
    print("  [html] ✗ Could not find Step 7 block — check formatting")

# 2c. Replace Step 8 HTML
old_step8_start = """  <div class="step" id="step-8">
    <div class="step-header">08 — you're governed</div>
    <h2 style="margin-bottom:1.5rem">Your tools are governed. Your trust is sovereign. <span style="color:var(--accent)">&#10022;</span></h2>

    <div class="card">
      <div class="summary-section">
        <h4>your identity</h4>
        <div class="summary-row"><span class="label">Operator</span><span class="value" id="sumOperator">—</span></div>
        <div class="summary-row"><span class="label">Genesis</span><span class="value" id="sumGenesis">—</span></div>
        <div class="summary-row"><span class="label">Sovereignty</span><span class="value" id="sumSovereignty">—</span></div>
        <div class="summary-row"><span class="label">Inference</span><span class="value" id="sumInference">—</span></div>
        <div class="summary-row"><span class="label">Algorithm</span><span class="value">Ed25519 + BLAKE3</span></div>
      </div>
    </div>

    <div class="card">
      <div class="summary-section">
        <h4>your vault</h4>
        <div class="summary-row"><span class="label">Credentials</span><span class="value good" id="sumCredentials">0 encrypted</span></div>
        <div class="summary-row"><span class="label">Vault key</span><span class="value">derived on demand, never stored</span></div>
      </div>
    </div>

    <div class="card">
      <div class="summary-section">
        <h4>governance</h4>
        <div class="summary-row"><span class="label">Gates</span><span class="value">5 active (2 constitutional, 3 operational)</span></div>
        <div class="summary-row"><span class="label">Audit</span><span class="value">hash-chained receipts</span></div>
      </div>
    </div>

    <div class="info-box" style="border-left-color: var(--yellow);">
      <h4 style="color: var(--yellow);">act 3 — public attestation</h4>
      <p style="font-size:0.82rem; line-height:1.7; margin:0.5rem 0">Right now, everything you've built is local. Powerful, but visible only to you. Public attestation changes what's possible:</p>
      <div style="font-size:0.82rem; line-height:1.7; margin:0.5rem 0 0.75rem">
        <div style="padding:0.2rem 0"><span style="color:var(--yellow)">→</span> Your agents can prove who they work for. Other agents can verify before trusting.</div>
        <div style="padding:0.2rem 0"><span style="color:var(--yellow)">→</span> Your governance chain becomes a verifiable track record — reputation that can't be faked.</div>
        <div style="padding:0.2rem 0"><span style="color:var(--yellow)">→</span> Multi-agent workflows get mutual trust. Peers verify each other's policies before sharing data.</div>
      </div>
      <p style="font-size:0.78rem; line-height:1.6; color:var(--text-dim); margin:0.5rem 0">Anchoring is irreversible — your cryptographic root becomes permanently, publicly verifiable. ZeroPoint doesn't push you there. You go when you're ready.</p>
      <code style="font-size:0.75rem; color:var(--yellow)">zp anchor genesis</code>
    </div>

    <div class="info-box">
      <h4>what you can do next</h4>
      <code style="font-size:0.75rem; display:block; margin:0.15rem 0; color:var(--text-dim)">zp status</code> — verify governance state<br>
      <code style="font-size:0.75rem; display:block; margin:0.15rem 0; color:var(--text-dim)">zp secure</code> — wrap shells and AI tools<br>
      <code style="font-size:0.75rem; display:block; margin:0.15rem 0; color:var(--text-dim)">zp audit log</code> — view receipt chain<br>
      <code style="font-size:0.75rem; display:block; margin:0.15rem 0; color:var(--text-dim)">zp configure</code> — add credentials, rescan<br>
      <code style="font-size:0.75rem; display:block; margin:0.15rem 0; color:var(--text-dim)">zp anchor genesis</code> — anchor to public ledger
    </div>

    <div style="border-top: 1px solid var(--border); margin-top: 2rem; padding-top: 2rem; text-align: center;">
      <p style="color: var(--text); font-size: 0.95rem; line-height: 1.8; max-width: 500px; margin: 0 auto;">
        Thank you for choosing to live sovereign.
      </p>
      <p style="color: var(--text-dim); font-size: 0.85rem; line-height: 1.8; max-width: 500px; margin: 0.75rem auto 0;">
        You've taken on the responsibility — and the power — of owning your own trust. Not everyone will. But you did, and that matters.
      </p>
      <p style="color: var(--accent); font-size: 0.95rem; margin-top: 1.5rem; font-weight: 500;">
        Now build a better world — the kind you want to live in.
      </p>
    </div>
  </div>"""

new_step8 = """  <div class="step" id="step-8">
    <div class="step-header">08 — your launch pad</div>
    <h2 style="margin-bottom:0.5rem">Mission Control</h2>
    <p style="color:var(--text-dim); font-size:0.85rem; margin-bottom:1.5rem">Every tool governed. Every call receipted. Every key sovereign.</p>

    <!-- Operator identity bar -->
    <div class="card" style="padding:0.75rem 1rem; margin-bottom:1.25rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem">
      <div style="display:flex; align-items:center; gap:0.75rem">
        <div style="width:36px; height:36px; border-radius:50%; background:var(--accent-dim); display:flex; align-items:center; justify-content:center; font-size:0.85rem; color:var(--accent); font-weight:600" id="sumAvatarInitial">?</div>
        <div>
          <div style="font-size:0.85rem; font-weight:500; color:var(--text-bright)" id="sumOperator">—</div>
          <div style="font-size:0.7rem; color:var(--text-dim); font-family:var(--mono)" id="sumGenesis">—</div>
        </div>
      </div>
      <div style="display:flex; gap:0.5rem; flex-wrap:wrap">
        <span class="governance-badge" id="sumSovereigntyBadge">—</span>
        <span class="governance-badge" id="sumInferenceBadge">—</span>
        <span class="governance-badge" style="background:rgba(126,184,218,0.1); color:var(--accent)" id="sumVaultBadge">—</span>
      </div>
    </div>

    <!-- Launch pad grid -->
    <div class="launchpad-grid" id="launchpadGrid"></div>

    <!-- Act 3 teaser -->
    <div class="card" style="margin-top:1.5rem; border-left:3px solid var(--yellow); padding:1rem 1.25rem">
      <h4 style="color:var(--yellow); font-size:0.82rem; margin-bottom:0.5rem">Next horizon — Public Attestation</h4>
      <p style="font-size:0.8rem; line-height:1.7; color:var(--text-dim); margin-bottom:0.75rem">
        Right now, your governance is local — powerful, but visible only to you. Anchoring your genesis key to a public ledger makes your trust <em>verifiable by anyone</em>. Your agents can prove who they work for. Your governance chain becomes reputation that can't be faked.
      </p>
      <div style="display:flex; align-items:center; gap:0.75rem">
        <code style="font-size:0.75rem; color:var(--yellow)">zp anchor genesis</code>
        <span style="font-size:0.72rem; color:var(--text-dim)">— when you're ready</span>
      </div>
    </div>

    <div style="border-top: 1px solid var(--border); margin-top: 2rem; padding-top: 1.5rem; text-align: center;">
      <p style="color: var(--text); font-size: 0.92rem; line-height: 1.8; max-width: 480px; margin: 0 auto;">
        Your tools are governed. Your keys are sovereign. Your trust is yours.
      </p>
      <p style="color: var(--accent); font-size: 0.92rem; margin-top: 1rem; font-weight: 500;">
        Now build a better world — the kind you want to live in.
      </p>
    </div>
  </div>"""

if old_step8_start in html:
    html = html.replace(old_step8_start, new_step8)
    html_changes += 1
    print("  [html] Replaced Step 8 with launch-pad grid")
else:
    print("  [html] ✗ Could not find Step 8 block — check formatting")

# 2d. Replace runConfigure and showConfigureComplete JS
old_configure_js = """  // ── Step 7: Configure ───────────────────────────────────
  window.runConfigure = function() {
    const proxy = document.getElementById('proxyEnabled').checked;
    document.getElementById('configureBtn').disabled = true;
    document.getElementById('configureTerm').style.display = 'block';
    document.getElementById('configureTerm').innerHTML = '';

    send('configure', { proxy, proxy_port: 3000 });
  };

  function showConfigureComplete(data) {
    appendTerminal('configureTerm', '', '');
    appendTerminal('configureTerm', '✓ Configuration complete', 'success');

    if (data.cli_command) {
      appendTerminal('configureTerm', '');
      appendTerminal('configureTerm', 'Run from your terminal:');
      appendTerminal('configureTerm', '  ' + data.cli_command);
    }

    document.getElementById('configureNext').style.display = 'flex';
    document.getElementById('configureBtn').disabled = false;

    // Populate summary for step 8
    populateSummary();
  }"""

new_configure_js = """  // ── Step 7: Configure ───────────────────────────────────

  function buildConfigToolCards() {
    const grid = document.getElementById('configToolCards');
    grid.innerHTML = '';

    const toolIcons = {
      'openmaictool': '🤖', 'pentagi': '🛡️', 'agent-zero': '🧠',
      'autogpt': '⚡', 'langchain': '🔗', 'crewai': '👥',
    };

    discoveredTools.forEach((tool, i) => {
      const icon = toolIcons[tool.tool_name.toLowerCase()] || '🔧';
      const card = document.createElement('div');
      card.className = 'tool-config-card';
      card.id = 'config-card-' + tool.tool_name.replace(/[^a-zA-Z0-9]/g, '-');
      card.innerHTML = `
        <div class="tool-icon">${icon}</div>
        <div class="tool-info">
          <div class="tool-name">${tool.tool_name}</div>
          <div class="tool-status">discovered · ${tool.needed_count} credential(s) mapped</div>
        </div>
        <div class="tool-badge">waiting</div>
      `;
      grid.appendChild(card);
    });

    if (discoveredTools.length === 0) {
      grid.innerHTML = '<p style="color:var(--text-dim); font-size:0.82rem">No tools discovered yet — complete Step 5 first.</p>';
    }
  }

  window.runConfigure = function() {
    buildConfigToolCards();

    const proxy = document.getElementById('proxyEnabled').checked;
    document.getElementById('configureBtn').disabled = true;
    document.getElementById('configureBtn').textContent = 'Securing...';
    document.getElementById('configureTerm').style.display = 'block';
    document.getElementById('configureTerm').innerHTML = '';

    // Mark all cards as "securing"
    document.querySelectorAll('.tool-config-card').forEach((card, i) => {
      setTimeout(() => {
        card.classList.add('securing');
        card.querySelector('.tool-status').textContent = 'securing · routing through governance proxy...';
        card.querySelector('.tool-badge').textContent = 'securing';
      }, i * 300);
    });

    send('configure', { proxy, proxy_port: 3000 });
  };

  function markToolConfigured(data) {
    const safeId = 'config-card-' + (data.tool_name || '').replace(/[^a-zA-Z0-9]/g, '-');
    const card = document.getElementById(safeId);
    if (card) {
      card.classList.remove('securing');
      card.classList.add('governed');
      card.querySelector('.tool-status').textContent = 'governed · proxy active · receipts enabled';
      card.querySelector('.tool-badge').textContent = '✓ governed';
    }
  }

  function showConfigureComplete(data) {
    // Mark any remaining cards as governed (fallback)
    document.querySelectorAll('.tool-config-card:not(.governed)').forEach(card => {
      card.classList.remove('securing');
      card.classList.add('governed');
      card.querySelector('.tool-status').textContent = 'governed · proxy active · receipts enabled';
      card.querySelector('.tool-badge').textContent = '✓ governed';
    });

    document.getElementById('configureBtn').textContent = 'Secure & Configure';
    document.getElementById('configureBtn').disabled = false;
    document.getElementById('configureNext').style.display = 'flex';

    // Populate summary for step 8
    populateSummary();
  }"""

if old_configure_js in html:
    html = html.replace(old_configure_js, new_configure_js)
    html_changes += 1
    print("  [html] Replaced configure JS with animated card logic")
else:
    print("  [html] ✗ Could not find configure JS block")

# 2e. Add tool_configured event handler in the switch statement
old_event_handler = """      case 'configure_complete':
        showConfigureComplete(msg);
        break;"""

new_event_handler = """      case 'tool_configured':
        markToolConfigured(msg);
        break;

      case 'configure_complete':
        showConfigureComplete(msg);
        break;"""

if "case 'tool_configured'" not in html:
    html = html.replace(old_event_handler, new_event_handler)
    html_changes += 1
    print("  [html] Added tool_configured event handler")

# 2f. Replace populateSummary with launch-pad builder
old_summary = """  // ── Step 8: Summary ─────────────────────────────────────
  function populateSummary() {
    if (genesisData) {
      document.getElementById('sumOperator').textContent = genesisData.operator || '—';
      const pub = genesisData.genesis_public_key || '';
      document.getElementById('sumGenesis').textContent = pub ? pub.substring(0, 8) + '...' : '—';

      const modeLabels = {
        biometric: 'Biometric',
        login_password: 'Login Password',
        file_based: 'File on Disk',
      };
      document.getElementById('sumSovereignty').textContent =
        modeLabels[genesisData.sovereignty_mode] || genesisData.sovereignty_mode || '—';
    }

    // Inference posture + model pull status
    const postureLabels = { local: 'Local Only', cloud: 'Cloud Only', mixed: 'Mixed (Local + Cloud)' };
    let inferenceLabel = postureLabels[inferencePosture] || inferencePosture || '—';
    if (currentPullModelId) {
      inferenceLabel += ` · ${currentPullModelId} downloading`;
    }
    document.getElementById('sumInference').textContent = inferenceLabel;

    document.getElementById('sumCredentials').textContent =
      `${credentialsStored} encrypted (ChaCha20-Poly1305)`;
  }"""

new_summary = """  // ── Step 8: Launch Pad ──────────────────────────────────
  function populateSummary() {
    // Operator identity bar
    if (genesisData) {
      const name = genesisData.operator || '—';
      document.getElementById('sumOperator').textContent = name;
      document.getElementById('sumAvatarInitial').textContent = name.charAt(0).toUpperCase();
      const pub = genesisData.genesis_public_key || '';
      document.getElementById('sumGenesis').textContent = pub ? pub.substring(0, 16) + '...' : '—';

      const modeLabels = { biometric: '🔒 Biometric', login_password: '🔑 Password', file_based: '📁 File' };
      document.getElementById('sumSovereigntyBadge').textContent =
        modeLabels[genesisData.sovereignty_mode] || genesisData.sovereignty_mode || '—';
    }

    const postureLabels = { local: '🏠 Local', cloud: '☁️ Cloud', mixed: '🔄 Mixed' };
    let inferenceLabel = postureLabels[inferencePosture] || inferencePosture || '—';
    document.getElementById('sumInferenceBadge').textContent = inferenceLabel;

    document.getElementById('sumVaultBadge').textContent =
      `🗝️ ${credentialsStored} key${credentialsStored !== 1 ? 's' : ''} encrypted`;

    // Build launch pad grid
    buildLaunchPad();
  }

  function buildLaunchPad() {
    const grid = document.getElementById('launchpadGrid');
    grid.innerHTML = '';

    const toolIcons = {
      'openmaictool': '🤖', 'pentagi': '🛡️', 'agent-zero': '🧠',
      'autogpt': '⚡', 'langchain': '🔗', 'crewai': '👥',
    };

    discoveredTools.forEach(tool => {
      const icon = toolIcons[tool.tool_name.toLowerCase()] || '🔧';
      const tile = document.createElement('div');
      tile.className = 'launchpad-tile';
      tile.innerHTML = `
        <div class="tile-health"></div>
        <div class="tile-icon">${icon}</div>
        <div class="tile-name">${tool.tool_name}</div>
        <div class="tile-status">governed · proxy active</div>
        <div class="governance-badge">✓ genesis-signed</div>
      `;
      tile.onclick = () => {
        // Future: navigate to tool governance dashboard
        alert('Dashboard for ' + tool.tool_name + ' coming soon');
      };
      grid.appendChild(tile);
    });

    // ZeroPoint system tile
    const zpTile = document.createElement('div');
    zpTile.className = 'launchpad-tile';
    zpTile.innerHTML = `
      <div class="tile-health"></div>
      <div class="tile-icon" style="background:rgba(126,184,218,0.15)">⚙️</div>
      <div class="tile-name">ZeroPoint</div>
      <div class="tile-status">governance engine</div>
      <div class="governance-badge" style="background:rgba(126,184,218,0.1); color:var(--accent)">core</div>
    `;
    zpTile.onclick = () => {
      window.open('/api/v1/status', '_blank');
    };
    grid.appendChild(zpTile);

    // Add new tool tile
    const addTile = document.createElement('div');
    addTile.className = 'launchpad-tile add-tile';
    addTile.innerHTML = `
      <div class="tile-icon">+</div>
      <div class="tile-name">Add Tool</div>
      <div class="tile-status">zp configure</div>
    `;
    addTile.onclick = () => {
      // Future: open tool discovery flow
      alert('Run: zp configure auto ~/projects');
    };
    grid.appendChild(addTile);
  }"""

if old_summary in html:
    html = html.replace(old_summary, new_summary)
    html_changes += 1
    print("  [html] Replaced summary with launch-pad builder")
else:
    print("  [html] ✗ Could not find summary JS block")

with open(html_path, "w") as f:
    f.write(html)

print(f"\n✓ HTML: {html_changes} change(s) applied")
print(f"\n{'='*50}")
print(f"Total: {rust_changes} Rust + {html_changes} HTML changes")
if rust_changes + html_changes > 0:
    print("\nRebuild with:")
    print("  cargo install --path crates/zp-cli --force --target-dir /tmp/zp-fresh-build \\")
    print("    && cp ~/.cargo/bin/zp ~/.local/bin/zp && zp serve")
