    // ── Session auth ─────────────────────────────────────
    // AUTH-VULN-02: session token now lives in an HttpOnly cookie set by
    // the dashboard response. It is intentionally NOT reachable from page
    // JavaScript so that an injected script cannot exfiltrate it. Every
    // API call goes through `zpFetch`, which forwards same-origin
    // credentials automatically.

    /** Authenticated fetch — the HttpOnly session cookie rides along. */
    function zpFetch(url, opts = {}) {
      if (!opts.credentials) opts.credentials = 'same-origin';
      return fetch(url, opts);
    }

    /** Authenticated WebSocket — cookies attach automatically on same-origin. */
    function zpWebSocket(url) {
      return new WebSocket(url);
    }

    // ── Toast helper ──────────────────────────────────────
    function showToast(html, duration = 3000) {
      const t = document.getElementById('zpToast');
      t.innerHTML = html;
      t.classList.add('visible');
      clearTimeout(t._timer);
      t._timer = setTimeout(() => t.classList.remove('visible'), duration);
    }

    const endpoints = {
      identity: '/api/v1/identity',
      genesis: '/api/v1/genesis',
      rules: '/api/v1/policy/rules',
      audit: '/api/v1/audit/verify',
      stats: '/api/v1/stats',
      security: '/api/v1/security/posture',
      topology: '/api/v1/security/topology',
      tools: '/api/v1/tools'
    };

    // Tracks whether we've already surfaced the stale-session banner so we
    // don't spam the DOM with 8 copies (one per endpoint).
    var _staleSessionNoticeShown = false;

    function showStaleSessionBanner() {
      if (_staleSessionNoticeShown) return;
      _staleSessionNoticeShown = true;
      var bar = document.createElement('div');
      bar.setAttribute('data-action', 'reload-page');
      bar.style.cssText = [
        'position:fixed', 'top:0', 'left:0', 'right:0',
        'z-index:99999',
        'background:#5b3a1a', 'color:#f5d59a',
        'border-bottom:1px solid #8a5a2a',
        'font-family:JetBrains Mono, monospace', 'font-size:13px',
        'padding:10px 16px', 'text-align:center',
        'cursor:pointer', 'box-shadow:0 2px 8px rgba(0,0,0,0.3)'
      ].join(';');
      bar.innerHTML = '\u26A0 Session expired or server restarted &middot; ' +
                      '<u>click to reload and reconnect</u>';
      document.body.appendChild(bar);
    }

    async function fetchEndpoint(url, retried) {
      try {
        const r = await zpFetch(url);
        if (r.status === 401) {
          // Distinguish stale cookie (from a previous `zp serve` run, ARTEMIS
          // result 035 issue 3) from genuine "no session yet". The server
          // emits X-Auth-Reason: stale|missing.
          var reason = r.headers.get('x-auth-reason') || 'missing';
          if (reason === 'stale') {
            showStaleSessionBanner();
            return { error: 'Session stale', staleSession: true };
          }
          if (!retried) {
            // Session cookie may not have been processed yet — retry once
            // after a short delay (addresses result 031 stall).
            await new Promise(function(ok) { setTimeout(ok, 500); });
            return fetchEndpoint(url, true);
          }
        }
        if (!r.ok) return { error: 'HTTP ' + r.status };
        return await r.json();
      } catch (err) { return { error: 'Unreachable' }; }
    }

    function truncateKey(key, length = 32) {
      if (!key || key.length <= length) return key;
      return `${key.substring(0, Math.floor(length/2))}...${key.substring(key.length - Math.floor(length/2))}`;
    }

    // ── Welcome ───────────────────────────────────────────
    function showWelcome(op) {
      if (localStorage.getItem('zp-welcome-dismissed') === 'true') return;
      const o = document.getElementById('welcomeOverlay');
      if (op) document.getElementById('welcomeGreeting').textContent = `Welcome, ${op}. Your node is live.`;
      o.style.display = 'flex';
    }
    function dismissWelcome(perm) {
      const o = document.getElementById('welcomeOverlay');
      if (perm) localStorage.setItem('zp-welcome-dismissed', 'true');
      o.classList.add('dismissing');
      setTimeout(() => o.style.display = 'none', 300);
    }

    // ── Cockpit ───────────────────────────────────────────
    const toolIcons = {
      'openmaictool': '\u{1F916}', 'pentagi': '\u{1F6E1}', 'agent-zero': '\u{1F9E0}',
      'autogpt': '\u26A1', 'langchain': '\u{1F517}', 'crewai': '\u{1F465}',
      'bolt': '\u26A1', 'cline': '\u{1F4BB}', 'continue': '\u25B6',
      'open-webui': '\u{1F310}', 'lmstudio': '\u{1F9EA}', 'anything-llm': '\u{1F4AC}',
    };

    // ── Port probe ─────────────────────────────────────────
    async function isPortOpen(url) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2000);
      try {
        // Subdomain URLs (ember.localhost:3000) are cross-origin but
        // our CORS predicate allows *.localhost:{port}, so use 'cors'
        // mode to get a real status code back.
        const isSubdomain = url.includes('.localhost');
        const resp = await fetch(url, {
          mode: isSubdomain ? 'cors' : 'no-cors',
          signal: controller.signal,
        });
        clearTimeout(timer);
        // 502/503/504 = ZP proxy running but tool not up yet
        // 404 = no port assignment for this tool
        if (isSubdomain && (resp.status === 404 || resp.status === 502 || resp.status === 503 || resp.status === 504)) {
          return false;
        }
        return true;
      } catch {
        clearTimeout(timer);
        return false;
      }
    }

    async function waitForPort(url, maxWaitMs = 30000, intervalMs = 1000) {
      const deadline = Date.now() + maxWaitMs;
      while (Date.now() < deadline) {
        if (await isPortOpen(url)) return true;
        await new Promise(r => setTimeout(r, intervalMs));
      }
      return false;
    }

    // ── Diagnostic panel — graduated disclosure ────────────────
    let _diagRetryTool = null;
    let _diagTerm = null;       // xterm.js instance
    let _diagFitAddon = null;   // fit addon
    let _diagExecWs = null;     // WebSocket for governed exec
    let _diagToolPath = null;   // cwd for terminal

    function dismissDiag() {
      // Clean up terminal
      if (_diagExecWs) { _diagExecWs.close(); _diagExecWs = null; }
      if (_diagTerm) { _diagTerm.dispose(); _diagTerm = null; _diagFitAddon = null; }
      // Collapse terminal pane
      const toggle = document.getElementById('diagTermToggle');
      const pane = document.getElementById('diagTermPane');
      if (toggle) toggle.classList.remove('open');
      if (pane) pane.classList.remove('open');

      const o = document.getElementById('diagOverlay');
      o.classList.add('dismissing');
      setTimeout(() => { o.style.display = 'none'; o.classList.remove('dismissing'); }, 200);
    }

    function diagRetry() {
      dismissDiag();
      if (_diagRetryTool) launchTool(_diagRetryTool);
    }

    function toggleTerminal() {
      const toggle = document.getElementById('diagTermToggle');
      const pane = document.getElementById('diagTermPane');
      const isOpen = toggle.classList.toggle('open');
      pane.classList.toggle('open');

      if (isOpen && !_diagTerm) {
        initTerminal();
      }
      if (isOpen && _diagFitAddon) {
        setTimeout(() => _diagFitAddon.fit(), 50);
      }
    }

    function initTerminal() {
      const container = document.getElementById('diagXterm');
      container.innerHTML = '';

      _diagTerm = new Terminal({
        theme: {
          background: '#0A0A0C',
          foreground: '#E8E6E3',
          cursor: '#7eb8da',
          selectionBackground: 'rgba(126,184,218,0.2)',
          black: '#0A0A0C',
          red: '#FF4444',
          green: '#00C896',
          yellow: '#FFB020',
          blue: '#7eb8da',
          magenta: '#B48EAD',
          cyan: '#88C0D0',
          white: '#E8E6E3',
        },
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 12,
        lineHeight: 1.4,
        cursorBlink: false,
        disableStdin: true,
        scrollback: 1000,
      });

      _diagFitAddon = new FitAddon.FitAddon();
      _diagTerm.loadAddon(_diagFitAddon);
      _diagTerm.open(container);
      setTimeout(() => _diagFitAddon.fit(), 50);
    }

    /// Run a command through the governed exec WebSocket, streaming output to the terminal.
    function execInTerminal(cmd, cwd) {
      if (!_diagTerm) initTerminal();
      // Ensure terminal pane is open
      const toggle = document.getElementById('diagTermToggle');
      const pane = document.getElementById('diagTermPane');
      if (!toggle.classList.contains('open')) {
        toggle.classList.add('open');
        pane.classList.add('open');
        if (_diagFitAddon) setTimeout(() => _diagFitAddon.fit(), 50);
      }

      // Update cwd display
      document.getElementById('diagTermCwd').textContent = cwd || '~';
      document.getElementById('diagTermReceipt').textContent = '';

      _diagTerm.clear();
      _diagTerm.writeln('\x1b[90m$ ' + cmd + '\x1b[0m');
      _diagTerm.writeln('');

      // Connect via WebSocket
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      _diagExecWs = zpWebSocket(`${proto}//${location.host}/ws/exec`);

      _diagExecWs.onopen = () => {
        _diagExecWs.send(JSON.stringify({
          action: 'exec',
          cmd: cmd,
          cwd: cwd || '.',
        }));
      };

      _diagExecWs.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'stdout') {
            _diagTerm.write(msg.data);
          } else if (msg.type === 'stderr') {
            _diagTerm.write('\x1b[31m' + msg.data + '\x1b[0m');
          } else if (msg.type === 'exit') {
            _diagTerm.writeln('');
            if (msg.code === 0) {
              _diagTerm.writeln('\x1b[32m✓ Exited successfully\x1b[0m');
            } else {
              _diagTerm.writeln(`\x1b[31m✗ Exited with code ${msg.code}\x1b[0m`);
            }
          } else if (msg.type === 'exec_complete') {
            if (msg.receipt_hash) {
              document.getElementById('diagTermReceipt').textContent =
                '⛓ ' + msg.receipt_hash.substring(0, 12);
            }
          } else if (msg.type === 'error') {
            _diagTerm.writeln('\x1b[31m' + msg.message + '\x1b[0m');
          }
        } catch {}
      };

      _diagExecWs.onerror = () => {
        _diagTerm.writeln('\x1b[31mWebSocket connection failed\x1b[0m');
      };

      _diagExecWs.onclose = () => {
        _diagExecWs = null;
      };
    }

    // ── Resolve engine — builds and executes the right sequence ──
    let _resolveToolRef = null;  // tool object for the current resolve
    let _resolveResult = null;   // result object for the current resolve

    function runResolve() {
      const tool = _resolveToolRef;
      const result = _resolveResult;
      if (!tool) return;

      const btn = document.getElementById('diagResolveBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Resolving...';

      // Build the command sequence based on what's actually wrong
      const toolPath = tool.path || `~/projects/${tool.name}`;
      const steps = buildResolveSteps(tool, result);

      // Open terminal and stream the sequence
      const toggle = document.getElementById('diagTermToggle');
      const pane = document.getElementById('diagTermPane');
      if (!toggle.classList.contains('open')) {
        toggle.classList.add('open');
        pane.classList.add('open');
      }
      if (!_diagTerm) initTerminal();
      if (_diagFitAddon) setTimeout(() => _diagFitAddon.fit(), 50);
      _diagTerm.clear();

      execSequence(steps, 0, toolPath, (allOk) => {
        btn.disabled = false;
        if (allOk) {
          btn.innerHTML = '&#10003; Resolved';
          btn.className = 'diag-btn retry';  // green
          _diagTerm.writeln('');
          _diagTerm.writeln('\x1b[32m═══ All steps completed successfully ═══\x1b[0m');

          // Refresh the dashboard after a short delay
          setTimeout(() => {
            dismissDiag();
            refreshAll();
          }, 1500);
        } else {
          btn.innerHTML = 'Resolve';
          _diagTerm.writeln('');
          _diagTerm.writeln('\x1b[31m═══ Resolution stopped — see errors above ═══\x1b[0m');
        }
      });
    }

    function buildResolveSteps(tool, result) {
      const toolPath = tool.path || `~/projects/${tool.name}`;
      const errorLower = ((result && result.error) || '').toLowerCase();
      const hintLower = ((result && result.hint) || '').toLowerCase();
      const steps = [];

      // 1. Configuration needed
      if (tool.status === 'unconfigured' || errorLower.includes('needs configuration') ||
          hintLower.includes('vault') || hintLower.includes('.env')) {
        steps.push({
          label: 'Resolving vault credentials',
          cmd: `zp configure tool --path "${toolPath}" --name "${tool.name}"`,
          cwd: toolPath,
        });
      }

      // 2. Port didn't respond — likely needs build + restart
      if (errorLower.includes('port') && errorLower.includes('did not respond')) {
        const launch = tool.launch || {};
        const isPnpm = launch.kind === 'pnpm';
        const isNpm = launch.kind === 'npm' || (!isPnpm && launch.cmd && launch.cmd.includes('npm'));
        const pm = isPnpm ? 'pnpm' : isNpm ? 'npm' : null;
        const port = result.port || launch.port;

        if (pm) {
          steps.push({
            label: `Building ${tool.name}`,
            cmd: `${pm} run build`,
            cwd: toolPath,
          });
          steps.push({
            label: `Starting ${tool.name} on port ${port || '?'}`,
            cmd: port ? `PORT=${port} ${pm} start` : `${pm} start`,
            cwd: toolPath,
          });
        }
      }

      // 3. Docker not running
      if (errorLower.includes('docker') || errorLower.includes('daemon')) {
        steps.push({
          label: 'Starting Docker containers',
          cmd: 'docker compose up -d',
          cwd: toolPath,
        });
      }

      // 4. Port conflict — something else occupying the port
      if (errorLower.includes('port') && (errorLower.includes('blocked') || errorLower.includes('conflict'))) {
        const portMatch = (result.error || '').match(/Port (\d+)/);
        if (portMatch) {
          steps.push({
            label: `Checking port ${portMatch[1]}`,
            cmd: `lsof -i :${portMatch[1]} || echo "Port ${portMatch[1]} is free"`,
            cwd: toolPath,
          });
        }
      }

      return steps;
    }

    /// Execute a sequence of commands, one at a time, streaming each to the terminal.
    function execSequence(steps, index, defaultCwd, onComplete) {
      if (index >= steps.length) {
        onComplete(true);
        return;
      }

      const step = steps[index];
      const cwd = step.cwd || defaultCwd;

      _diagTerm.writeln(`\x1b[36m── Step ${index + 1}/${steps.length}: ${step.label} ──\x1b[0m`);
      _diagTerm.writeln('\x1b[90m$ ' + step.cmd + '\x1b[0m');
      _diagTerm.writeln('');

      document.getElementById('diagTermCwd').textContent = cwd;
      document.getElementById('diagTermReceipt').textContent = '';

      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = zpWebSocket(`${proto}//${location.host}/ws/exec`);

      ws.onopen = () => {
        ws.send(JSON.stringify({ action: 'exec', cmd: step.cmd, cwd: cwd }));
      };

      let exitCode = null;

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'stdout') {
            _diagTerm.write(msg.data);
          } else if (msg.type === 'stderr') {
            _diagTerm.write('\x1b[31m' + msg.data + '\x1b[0m');
          } else if (msg.type === 'exit') {
            exitCode = msg.code;
            _diagTerm.writeln('');
            if (msg.code === 0) {
              _diagTerm.writeln('\x1b[32m✓ Done\x1b[0m');
            } else {
              _diagTerm.writeln(`\x1b[31m✗ Exited with code ${msg.code}\x1b[0m`);
            }
            _diagTerm.writeln('');
          } else if (msg.type === 'exec_complete') {
            if (msg.receipt_hash) {
              document.getElementById('diagTermReceipt').textContent =
                '⛓ ' + msg.receipt_hash.substring(0, 12);
            }
            // Command fully complete — close the socket so onclose fires
            // and the sequence can advance to the next step.
            ws.close();
          } else if (msg.type === 'error') {
            _diagTerm.writeln('\x1b[31m' + msg.message + '\x1b[0m');
          }
        } catch {}
      };

      ws.onerror = () => {
        _diagTerm.writeln('\x1b[31mWebSocket connection failed\x1b[0m');
        onComplete(false);
      };

      ws.onclose = () => {
        // Proceed to next step if this one succeeded (or is optional)
        if (exitCode === 0 || step.optional) {
          execSequence(steps, index + 1, defaultCwd, onComplete);
        } else {
          onComplete(false);
        }
      };
    }

    /// Generate contextual suggested commands based on the error.
    function suggestCommands(tool, result) {
      const cmds = [];
      const toolPath = tool.path || `~/projects/${tool.name}`;
      const launch = tool.launch || {};
      const errorLower = ((result && result.error) || '').toLowerCase();
      const hintLower = ((result && result.hint) || '').toLowerCase();

      // Docker not running
      if (errorLower.includes('docker') || errorLower.includes('daemon') || hintLower.includes('docker')) {
        cmds.push({ label: 'docker ps', cmd: 'docker ps', cwd: toolPath,
          hint: 'Check if Docker is running' });
        cmds.push({ label: 'docker compose up -d', cmd: 'docker compose up -d', cwd: toolPath,
          hint: 'Start containers' });
      }

      // Port not responding
      if (errorLower.includes('port') || errorLower.includes('respond')) {
        const port = result.port || launch.port;
        if (port) {
          cmds.push({ label: `lsof -i :${port}`, cmd: `lsof -i :${port}`, cwd: toolPath,
            hint: 'Check what is using this port' });
        }
      }

      // Node.js / package manager issues — detect pnpm vs npm
      if (errorLower.includes('npm') || errorLower.includes('pnpm') ||
          errorLower.includes('node') || hintLower.includes('npm') ||
          hintLower.includes('pnpm') || (tool.launch && tool.launch.kind === 'pnpm')) {
        const isPnpm = (tool.launch && tool.launch.kind === 'pnpm') || errorLower.includes('pnpm');
        const pm = isPnpm ? 'pnpm' : 'npm';
        cmds.push({ label: `${pm} install`, cmd: `${pm} install`, cwd: toolPath,
          hint: 'Install dependencies' });
        cmds.push({ label: `${pm} start`, cmd: `${pm} start`, cwd: toolPath,
          hint: 'Start the app' });
      }

      // Configuration needed
      if (errorLower.includes('needs configuration') || errorLower.includes('unconfigured') ||
          hintLower.includes('vault') || hintLower.includes('.env')) {
        cmds.push({ label: 'Configure tool', cmd: `zp configure tool --path "${toolPath}" --name "${tool.name}"`, cwd: toolPath,
          hint: 'Resolve vault credentials and write .env' });
        cmds.push({ label: 'Configure all', cmd: 'zp configure auto ~/projects', cwd: '~/projects',
          hint: 'Auto-configure all discovered tools' });
        cmds.push({ label: 'Check vault', cmd: 'zp configure providers', cwd: toolPath,
          hint: 'List vault-stored credentials' });
      }

      // Always offer: retry the original command
      if (result && result.cmd && !errorLower.includes('needs configuration')) {
        cmds.push({ label: 'Retry original', cmd: result.cmd, cwd: toolPath,
          hint: 'Run the launch command again' });
      }

      // Always offer: check files
      cmds.push({ label: 'ls -la', cmd: 'ls -la', cwd: toolPath,
        hint: 'List files in tool directory' });

      return cmds;
    }

    // ── Main showDiagnostic — graduated disclosure ─────────────
    async function showDiagnostic(tool, result) {
      const body = document.getElementById('diagBody');
      const overlay = document.getElementById('diagOverlay');
      const title = document.getElementById('diagTitle');
      const retryBtn = document.getElementById('diagRetryBtn');
      const suggestedEl = document.getElementById('diagSuggested');
      const suggestedCmds = document.getElementById('diagSuggestedCmds');
      const termDisclosure = document.getElementById('diagTermDisclosure');
      const termCwd = document.getElementById('diagTermCwd');

      const errorLower = ((result && result.error) || '').toLowerCase();
      const isConfigIssue = errorLower.includes('needs configuration') || errorLower.includes('add a tool');
      const isGateBlocked = errorLower.includes('blocked by') || errorLower.includes('trust tier');
      const isRunning = result && result.status === 'running';
      const isLaunchFailure = !isConfigIssue && !isRunning;

      title.textContent = isConfigIssue
        ? `${tool.name} — Configuration Required`
        : isRunning
        ? `${tool.name} — Running`
        : isGateBlocked
        ? `${tool.name} — Governance Gate Blocked`
        : `${tool.name} — Launch Failed`;
      // Color the title and card border: green for running, amber for config, red for failure
      title.style.color = isRunning ? '#7CDB8A' : isConfigIssue ? '#E8C547' : '#FF4444';
      const card = overlay.querySelector('.diag-card');
      if (card) {
        card.classList.toggle('running', isRunning);
        card.classList.toggle('config', isConfigIssue);
      }
      _diagRetryTool = isLaunchFailure ? tool : null;
      _diagToolPath = tool.path || `~/projects/${tool.name}`;
      _resolveToolRef = tool;
      _resolveResult = result;

      // Show action buttons based on state:
      //   Running  → only Close (nothing to resolve or retry)
      //   Config   → Resolve only
      //   Failure  → Resolve + Retry Launch
      const resolveBtn = document.getElementById('diagResolveBtn');
      resolveBtn.style.display = isRunning ? 'none' : 'inline-block';
      resolveBtn.disabled = false;
      resolveBtn.innerHTML = 'Resolve';
      resolveBtn.className = 'diag-btn resolve';
      retryBtn.style.display = isLaunchFailure ? 'inline-block' : 'none';

      // ── Layer 1: Human-readable summary ───────────────────
      let html = '';
      if (isConfigIssue) {
        html += `<div class="diag-field"><div class="diag-value hint-text" style="font-size:13px;">Vault credentials need to be resolved and <code>.env</code> written. Click <strong>Resolve</strong> to configure automatically.</div></div>`;
      } else if (isRunning) {
        if (result && result.error) {
          html += `<div class="diag-field"><div class="diag-label">Status</div><div class="diag-value" style="color:#7CDB8A;">${result.error}</div></div>`;
        }
        if (result && result.hint) {
          html += `<div class="diag-field"><div class="diag-label">Details</div><div class="diag-value hint-text">${result.hint}</div></div>`;
        }
      } else if (isGateBlocked) {
        html += `<div class="diag-field"><div class="diag-label">Governance</div><div class="diag-value error-text">${result.error}</div></div>`;
        html += `<div class="diag-field"><div class="diag-label">Explanation</div><div class="diag-value hint-text">The governance engine blocked this launch. Tool execution requires sufficient trust tier authorization. Check that the server&#39;s gate context matches the action&#39;s required tier.</div></div>`;
      } else {
        if (result && result.error) {
          html += `<div class="diag-field"><div class="diag-label">Error</div><div class="diag-value error-text">${result.error}</div></div>`;
        }
        if (result && result.hint) {
          html += `<div class="diag-field"><div class="diag-label">Suggestion</div><div class="diag-value hint-text">${result.hint}</div></div>`;
        }
        if (result && result.port) {
          html += `<div class="diag-field"><div class="diag-label">Expected Port</div><div class="diag-value">${result.port} (no response)</div></div>`;
        }
        if (result && result.stage) {
          html += `<div class="diag-field"><div class="diag-label">Stage</div><div class="diag-value">${result.stage}</div></div>`;
        }
        if (result && result.preflight_issues && result.preflight_issues.length > 0) {
          html += `<div class="diag-field"><div class="diag-label">Preflight Issues</div><div class="diag-value hint-text">${result.preflight_issues.join('<br>')}</div></div>`;
        }
      }
      body.innerHTML = html;

      // ── Layer 2: Suggested commands ──────────────────────
      const cmds = suggestCommands(tool, result);
      if (cmds.length > 0) {
        suggestedCmds.innerHTML = cmds.map(c =>
          `<button class="diag-cmd-btn" title="${escapeHtml(c.hint)}" data-action="exec-in-terminal" data-cmd="${escapeHtml(c.cmd)}" data-cwd="${escapeHtml(c.cwd || _diagToolPath)}">` +
          `<span class="cmd-play">&#9654;</span> ${escapeHtml(c.label)}</button>`
        ).join('');
        suggestedEl.style.display = 'block';
      } else {
        suggestedEl.style.display = 'none';
      }

      // ── Layer 3: Terminal disclosure (ready but collapsed) ──
      termDisclosure.style.display = 'block';
      termCwd.textContent = _diagToolPath;

      // Show the overlay
      overlay.style.display = 'flex';

      // ── Auto-populate terminal with launch log (if available) ──
      try {
        const logResp = await zpFetch(`/api/v1/tools/log?name=${encodeURIComponent(tool.name)}`);
        const logData = await logResp.json();
        if (logData.log && logData.log.trim()) {
          // Pre-populate the terminal with the log so it's ready when disclosed
          if (!_diagTerm) initTerminal();
          _diagTerm.clear();
          _diagTerm.writeln('\x1b[90m── Launch output ──────────────────\x1b[0m');
          logData.log.split('\n').forEach(line => {
            const lower = line.toLowerCase();
            if (lower.includes('error') || lower.includes('fatal') || lower.includes('failed')) {
              _diagTerm.writeln('\x1b[31m' + line + '\x1b[0m');
            } else if (lower.includes('warn') || lower.includes('timeout')) {
              _diagTerm.writeln('\x1b[33m' + line + '\x1b[0m');
            } else {
              _diagTerm.writeln(line);
            }
          });
          _diagTerm.writeln('\x1b[90m──────────────────────────────────\x1b[0m');
          _diagTerm.writeln('');
        }
      } catch {}
    }

    function escapeHtml(str) {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // ── Launch logic ─────────────────────────────────────────
    const launching = new Set();

    async function launchTool(tool) {
      const launch = tool.launch || {};

      if (tool.status === 'unconfigured') {
        showDiagnostic(tool, {
          error: `${tool.name} needs configuration`,
          hint: 'Vault credentials need to be resolved and .env written before launch.',
          cmd: `zp configure auto ~/projects`,
        });
        return;
      }

      if (launching.has(tool.name)) return;

      // ── Preflight gate: if not ready, run preflight first ──
      const issues = tool.preflight_issues || [];
      if (tool.ready === false || issues.length > 0) {
        launching.add(tool.name);
        showToast(`<strong>${escapeHtml(tool.name)}</strong> needs preflight &mdash; resolving issues...`, 30000);
        setTileLaunching(tool.name, true);

        try {
          const pfResp = await zpFetch('/api/v1/tools/preflight', { method: 'POST' });
          const pfResult = await pfResp.json();

          // Check if this specific tool passed after preflight
          const toolPf = (pfResult.tools || []).find(t => t.name === tool.name);
          if (toolPf && toolPf.checks) {
            const stillFailing = toolPf.checks.filter(c => c.status === 'fail');
            if (stillFailing.length > 0) {
              showToast('');
              showDiagnostic(tool, {
                error: `Preflight still failing for ${tool.name}`,
                hint: stillFailing.map(c => c.detail || c.name).join('; '),
              });
              return;
            }
          }

          // Preflight passed — update local tool state and continue to launch
          showToast(`<strong>${escapeHtml(tool.name)}</strong> preflight passed — launching...`);
          tool.ready = true;
          tool.preflight_issues = [];
          // Refresh the tile visuals
          refreshTileState(tool);
        } catch (err) {
          showToast('');
          showDiagnostic(tool, {
            error: `Preflight request failed: ${err.message}`,
            hint: 'Is the ZeroPoint server running?',
          });
          return;
        } finally {
          setTileLaunching(tool.name, false);
          launching.delete(tool.name);
        }
      }

      // ── Already running? Just open it via the ZP proxy. ───
      const proxyUrl = `http://${tool.name}.localhost:${window.location.port || 3000}/`;
      if (launch.url || launch.kind === 'web' || launch.kind === 'native') {
        // Open tab synchronously (user gesture) before any async check
        const earlyTab = window.open('about:blank', '_blank');
        showToast(`Checking <strong>${escapeHtml(tool.name)}</strong>...`);
        if (await isPortOpen(proxyUrl)) {
          showToast(`Opening <strong>${escapeHtml(tool.name)}</strong>`);
          if (earlyTab && !earlyTab.closed) {
            earlyTab.location.href = proxyUrl;
          } else {
            window.open(proxyUrl, '_blank');
          }
          return;
        }
        // Not actually running — close the blank tab and fall through to launch
        if (earlyTab) earlyTab.close();
      }

      // ── Non-web tools: launch via API, show status instead of browser tab ──
      const hasWebUI = launch.url || launch.port || launch.kind === 'web' || launch.kind === 'native' || launch.kind === 'pnpm' || launch.kind === 'npm';

      if (!hasWebUI) {
        // Check if already running (avoid re-launching on repeat clicks)
        if (tool.running_pid) {
          showDiagnostic(tool, {
            status: 'running',
            error: `${tool.name} — ${launch.kind || 'headless'} tool running`,
            hint: `Already running (PID ${tool.running_pid}). This tool doesn't serve a web UI — use the terminal below to interact with it.`,
            cmd: launch.cmd,
          });
          return;
        }

        // Not running yet — launch via API
        launching.add(tool.name);
        showToast(`Starting <strong>${escapeHtml(tool.name)}</strong>...`, 15000);
        setTileLaunching(tool.name, true);
        try {
          const resp = await zpFetch('/api/v1/tools/launch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: tool.name }),
          });
          const result = await resp.json();
          if (!resp.ok) {
            showToast('');
            showDiagnostic(tool, result);
          } else {
            tool.running_pid = result.pid;  // cache PID to prevent re-launch on next click
            showToast(`<strong>${escapeHtml(tool.name)}</strong> started (PID ${result.pid})`, 5000);
            showDiagnostic(tool, {
              status: 'running',
              error: `${tool.name} — ${launch.kind || 'headless'} tool running`,
              hint: `Process started (PID ${result.pid}). This tool doesn't serve a web UI — use the terminal below to interact with it.`,
              cmd: result.cmd,
            });
          }
        } catch (err) {
          showToast('');
          showDiagnostic(tool, {
            error: `Launch failed: ${err.message}`,
            hint: 'Is the ZeroPoint server running?',
          });
        } finally {
          setTileLaunching(tool.name, false);
          launching.delete(tool.name);
        }
        return;
      }

      // ── Web tools: ask the server to start, then open in browser ──
      launching.add(tool.name);
      showToast(`Starting <strong>${escapeHtml(tool.name)}</strong>...`, 30000);
      setTileLaunching(tool.name, true);

      // Open the tab NOW (synchronous with user click) to avoid popup
      // blockers.  We'll navigate it once the tool is ready, or close it
      // if something fails.
      const pendingTab = window.open('about:blank', '_blank');

      try {
        const resp = await zpFetch('/api/v1/tools/launch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: tool.name }),
        });
        const result = await resp.json();

        if (!resp.ok) {
          showToast('');
          if (pendingTab) pendingTab.close();
          showDiagnostic(tool, result);
          return;
        }

        // Wait for the tool to come up via the ZP proxy URL.
        // Native (cargo) builds can take minutes on first compile, so
        // give them a much longer leash than container/script tools.
        // result.url = subdomain URL (http://name.localhost:port/) — null for headless tools
        // result.port = ZP-assigned port — null for headless tools
        const openUrl = result.url || (result.port ? `http://${tool.name}.localhost:${window.location.port || 3000}/` : null);
        const pollUrl = openUrl;  // poll the subdomain proxy — returns 502 until tool is up
        if (openUrl && result.port) {
          const isNative = result.kind === 'native';
          const isDocker = result.kind === 'docker';
          const maxWait = isNative ? 600000 : isDocker ? 120000 : 30000;
          const pollInterval = isNative ? 3000 : 1500;

          // ── Phased progress for native builds ──────────────────
          // Native (cargo) tools compile from source — first builds can
          // take 5-10+ minutes.  Show elapsed time, a progress bar, and
          // the current crate being compiled by tailing the build log.
          if (isNative) {
            const buildStart = Date.now();
            const fmtElapsed = () => {
              const s = Math.floor((Date.now() - buildStart) / 1000);
              return s < 60 ? `${s}s` : `${Math.floor(s/60)}m ${s%60}s`;
            };
            const buildToast = (phase, detail, pct) => {
              const bar = pct != null
                ? `<div style="margin:6px 0 2px;height:3px;background:#1a1a1e;border-radius:2px;overflow:hidden">` +
                  `<div style="height:100%;width:${pct}%;background:#7eb8da;transition:width 0.5s ease"></div></div>`
                : `<div style="margin:6px 0 2px;height:3px;background:#1a1a1e;border-radius:2px;overflow:hidden">` +
                  `<div style="height:100%;width:30%;background:#7eb8da;border-radius:2px;animation:zpPulse 1.5s ease-in-out infinite"></div></div>`;
              const elapsed = `<span style="opacity:.5;float:right">${fmtElapsed()}</span>`;
              showToast(
                `<strong>${escapeHtml(tool.name)}</strong> ${phase} ${elapsed}<br>` +
                (detail ? `<code style="font-size:0.8em;opacity:.7">${escapeHtml(detail)}</code>` : '') +
                bar,
                maxWait
              );
            };
            // Inject keyframe for indeterminate pulse (once)
            if (!document.getElementById('zpPulseStyle')) {
              const sty = document.createElement('style');
              sty.id = 'zpPulseStyle';
              sty.textContent = '@keyframes zpPulse{0%{transform:translateX(-100%)}50%{transform:translateX(250%)}100%{transform:translateX(-100%)}}';
              document.head.appendChild(sty);
            }
            buildToast('compiling', 'cargo run --release', null);

            // Auto-open diagnostic panel with live build log stream
            showDiagnostic(tool, {
              status: 'running',
              error: `${tool.name} — building (cargo run --release)`,
              hint: 'Compiling release binary. Build output is streaming below.',
            });
            // Stream the build log via tail -f in the terminal
            const toolPath = tool.path || `~/projects/${tool.name}`;
            execInTerminal('tail -f ' + (result.log_path || '/tmp/zp-no-log'), toolPath);

            // Track compiled crate count for progress estimation
            let compiledCount = 0;
            let lastPhase = 'compiling';
            const logPollId = setInterval(async () => {
              try {
                const logResp = await zpFetch(`/api/v1/tools/log?name=${encodeURIComponent(tool.name)}&tail=5`);
                if (logResp.ok) {
                  const logData = await logResp.json();
                  const totalLines = logData.lines || 0;
                  const logText = logData.log || '';
                  const logLines = logText.split('\n').filter(l => l.trim());
                  const lastLine = logLines[logLines.length - 1] || '';

                  // Count total Compiling lines from total log line count
                  // (rough: most log lines during cargo build are Compiling lines)
                  compiledCount = totalLines;

                  // Detect phase from last log line
                  if (/Compiling|Downloading|Updating/.test(lastLine)) {
                    lastPhase = 'compiling';
                  } else if (/Linking|Finished/.test(lastLine)) {
                    lastPhase = 'linking';
                  } else if (/Running|Listening|listening|Started|Serving|Binding|bound|ready/i.test(lastLine)) {
                    lastPhase = 'starting';
                  }

                  // Extract crate name from "Compiling foo v1.2.3"
                  const crateMatch = lastLine.match(/Compiling\s+(\S+)\s+v/);
                  const detail = crateMatch
                    ? `${crateMatch[1]} (${compiledCount} crates compiled)`
                    : lastPhase === 'linking' ? `linking release binary (${compiledCount} crates compiled)`
                    : lastPhase === 'starting' ? 'binary ready — starting server'
                    : lastLine.length > 70 ? lastLine.slice(0, 67) + '...' : lastLine;

                  // Progress: use indeterminate until we see Linking/Finished
                  const pct = lastPhase === 'linking' ? 92
                    : lastPhase === 'starting' ? 98
                    : null;  // indeterminate during compilation

                  buildToast(lastPhase, detail, pct);
                }
              } catch {}
            }, 3000);
            const ready = await waitForPort(pollUrl, maxWait, pollInterval);
            clearInterval(logPollId);
            // Kill the tail -f stream and dismiss the build panel
            if (_diagExecWs) { _diagExecWs.close(); _diagExecWs = null; }
            if (ready) {
              buildToast('ready', 'opening in browser', 100);
              dismissDiag();
              setTimeout(() => {
                showToast(`Opening <strong>${escapeHtml(tool.name)}</strong>`);
                if (pendingTab && !pendingTab.closed) {
                  pendingTab.location.href = openUrl;
                } else {
                  window.open(openUrl, '_blank');
                }
              }, 400);
            } else {
              if (pendingTab) pendingTab.close();
              showToast('');
              // Update the already-open diagnostic panel with timeout info
              const diagTitle = document.getElementById('diagTitle');
              if (diagTitle) {
                diagTitle.textContent = `${tool.name} — Build Timed Out (${fmtElapsed()})`;
                diagTitle.style.color = '#FFB020';
              }
              const body = document.getElementById('diagBody');
              if (body) {
                body.innerHTML =
                  `<div class="diag-field"><div class="diag-label">Status</div><div class="diag-value" style="color:#FFB020">Port ${result.port} did not respond after ${fmtElapsed()}</div></div>` +
                  `<div class="diag-field"><div class="diag-label">Hint</div><div class="diag-value hint-text">The build may still be running in the background. The terminal below is still streaming output. Once you see "Listening on ...", click Retry.</div></div>` +
                  `<div class="diag-field"><div class="diag-label">Command</div><div class="diag-value"><code>${escapeHtml(result.cmd || '')}</code></div></div>`;
              }
              // Re-stream the log tail (the old tail -f was killed above)
              execInTerminal('tail -f ' + (result.log_path || '/tmp/zp-no-log'), toolPath);
              // Show retry button
              const retryBtn = document.getElementById('diagRetryBtn');
              if (retryBtn) { retryBtn.style.display = 'inline-block'; }
            }
          } else {
            showToast(`<strong>${escapeHtml(tool.name)}</strong> starting &mdash; waiting for port ${escapeHtml(String(result.port || ''))}...`, maxWait);
            const ready = await waitForPort(pollUrl, maxWait, pollInterval);
            if (ready) {
              showToast(`Opening <strong>${escapeHtml(tool.name)}</strong>`);
              if (pendingTab && !pendingTab.closed) {
                pendingTab.location.href = openUrl;
              } else {
                window.open(openUrl, '_blank');
              }
            } else {
              if (pendingTab) pendingTab.close();
              showToast('');
              const timeLabel = isDocker ? '2 minutes' : '30 seconds';
              showDiagnostic(tool, {
                error: `Port ${result.port} did not respond within ${timeLabel}`,
                cmd: result.cmd,
                port: result.port,
                hint: isDocker
                  ? 'Container may still be pulling images. Check: docker compose logs -f'
                  : 'The process may have crashed on startup. Check the log below.',
              });
            }
          }
        } else {
          if (pendingTab) pendingTab.close();
          showToast(`<strong>${escapeHtml(tool.name)}</strong> started (PID ${result.pid || '?'})`, 4000);
          // Show diagnostic panel for headless tools so user can see logs
          showDiagnostic(tool, {
            status: 'running',
            error: `${tool.name} — ${result.kind || 'headless'} tool running`,
            hint: `Process started (PID ${result.pid}). This tool doesn't expose a web UI. Check the terminal below for output.`,
            cmd: result.cmd,
          });
        }
      } catch (err) {
        showToast('');
        showDiagnostic(tool, {
          error: `Request to ZeroPoint failed: ${err.message}`,
          hint: 'Is the ZeroPoint server running?',
        });
      } finally {
        setTileLaunching(tool.name, false);
        launching.delete(tool.name);
      }
    }

    // Update a tile's visual state after preflight resolves
    function refreshTileState(tool) {
      const tile = document.querySelector(`.cockpit-tile[data-tool-name="${tool.name}"]`);
      if (!tile) return;
      const healthEl = tile.querySelector('.tile-health');
      const statusEl = tile.querySelector('.tile-status');
      const badgeEl = tile.querySelector('.tile-badge');
      const issuesEl = tile.querySelector('.tile-preflight-issues');

      // Remove not-ready, apply governed if applicable
      tile.classList.remove('not-ready');
      if (tool.status === 'governed') tile.classList.add('governed');

      if (healthEl) healthEl.className = 'tile-health' + (tool.status === 'governed' ? '' : tool.governance === 'unanchored' ? ' unanchored' : '');
      if (statusEl) statusEl.textContent = tool.status === 'governed' ? 'governed \u00B7 launch ready' : '.env present';
      if (badgeEl) {
        badgeEl.className = 'tile-badge governed';
        badgeEl.textContent = tool.status === 'governed' ? '\u2713 genesis-bound' : 'configured';
      }
      if (issuesEl) issuesEl.remove();
    }

    // Visual feedback: pulse the tile while it's starting
    function setTileLaunching(name, active) {
      const tile = document.querySelector(`.cockpit-tile[data-tool-name="${name}"]`);
      if (!tile) return;
      if (active) {
        tile.style.borderColor = '#7eb8da';
        tile.style.animation = 'tilePulse 1.5s ease-in-out infinite';
      } else {
        tile.style.borderColor = '';
        tile.style.animation = '';
      }
    }

    // ── Add Tool Dialog ───────────────────────────────────
    let _addToolResult = null; // stash register response for the configure step

    function showAddTool() {
      const overlay = document.getElementById('addToolOverlay');
      overlay.style.display = 'flex';
      _addToolResult = null;
      document.getElementById('addToolPath').value = '';
      document.getElementById('addToolError').textContent = '';
      document.getElementById('addToolDetection').classList.remove('visible');
      document.getElementById('addToolScanBtn').style.display = '';
      document.getElementById('addToolRegisterBtn').style.display = 'none';
      // Focus the input after animation
      setTimeout(() => document.getElementById('addToolPath').focus(), 100);
    }

    function dismissAddTool() {
      const overlay = document.getElementById('addToolOverlay');
      overlay.classList.add('dismissing');
      setTimeout(() => {
        overlay.style.display = 'none';
        overlay.classList.remove('dismissing');
      }, 300);
    }

    async function addToolScan() {
      const pathInput = document.getElementById('addToolPath');
      const errorEl = document.getElementById('addToolError');
      const scanBtn = document.getElementById('addToolScanBtn');
      const registerBtn = document.getElementById('addToolRegisterBtn');
      const detectionEl = document.getElementById('addToolDetection');
      const detBody = document.getElementById('addToolDetectBody');
      const rawPath = pathInput.value.trim();

      // Clear previous state
      errorEl.textContent = '';
      pathInput.classList.remove('error');
      detectionEl.classList.remove('visible');
      registerBtn.style.display = 'none';

      if (!rawPath) {
        errorEl.textContent = 'Enter a path to a project directory.';
        pathInput.classList.add('error');
        return;
      }

      // Disable button during scan
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning…';

      try {
        const resp = await zpFetch('/api/v1/tools/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: rawPath }),
        });
        const data = await resp.json();

        if (!resp.ok || data.error) {
          errorEl.textContent = data.error || `HTTP ${resp.status}`;
          pathInput.classList.add('error');
          return;
        }

        // Success — show detection results
        _addToolResult = data;
        const tool = data.tool;
        const det = data.detection;

        // Build detection summary
        const ecosystemLabels = {
          'rust': 'Rust (Cargo)',
          'go': 'Go',
          'node-pnpm': 'Node.js (pnpm)',
          'node-yarn': 'Node.js (Yarn)',
          'node-npm': 'Node.js (npm)',
          'node': 'Node.js',
          'python': 'Python',
          'docker': 'Docker',
          'unknown': 'Unknown',
        };

        let html = '';
        html += `<div class="addtool-detect-row"><span>Name</span><span class="val">${tool.name}</span></div>`;
        html += `<div class="addtool-detect-row"><span>Ecosystem</span><span class="val">${ecosystemLabels[tool.ecosystem] || tool.ecosystem}</span></div>`;
        html += `<div class="addtool-detect-row"><span>Launch</span><span class="val">${tool.launch.kind}${tool.launch.port ? ' :' + tool.launch.port : ''}</span></div>`;

        // Config status
        const statusLabels = {
          'configured': '✓ .env present',
          'has_env': '✓ .env present (manual)',
          'unconfigured': '.env.example found — needs credentials',
          'no_env_template': 'No .env.example',
        };
        const statusClass = (tool.status === 'configured' || tool.status === 'has_env') ? 'good' : 'warn';
        html += `<div class="addtool-detect-row"><span>Config</span><span class="val ${statusClass}">${statusLabels[tool.status] || tool.status}</span></div>`;

        // Files detected
        const files = [];
        if (det.package_json) files.push('package.json');
        if (det.cargo_toml) files.push('Cargo.toml');
        if (det.docker_compose) files.push('docker-compose.yml');
        if (det.dockerfile) files.push('Dockerfile');
        if (det.requirements_txt) files.push('requirements.txt');
        if (det.pyproject_toml) files.push('pyproject.toml');
        if (det.go_mod) files.push('go.mod');
        if (det.makefile) files.push('Makefile');
        if (det.env_example) files.push('.env.example');
        if (det.env) files.push('.env');
        html += `<div class="addtool-detect-row"><span>Files</span><span class="val">${files.join(', ') || 'none detected'}</span></div>`;

        if (tool.symlinked) {
          html += `<div class="addtool-detect-row"><span>Linked</span><span class="val">symlinked into ~/projects/</span></div>`;
        }

        // Provider tags
        if (tool.providers && tool.providers.length > 0) {
          html += '<div class="addtool-providers">';
          html += '<div class="addtool-label" style="margin-top:8px;">Required Credentials</div>';
          for (const p of tool.providers) {
            html += `<span class="addtool-provider-tag">${p}</span>`;
          }
          html += '</div>';
        }

        detBody.innerHTML = html;
        detectionEl.classList.add('visible');

        // Show register button, hide scan
        scanBtn.style.display = 'none';
        registerBtn.style.display = '';

      } catch (err) {
        errorEl.textContent = `Connection error: ${err.message}`;
        pathInput.classList.add('error');
      } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = 'Scan';
      }
    }

    function addToolRegister() {
      // Dismiss the Add Tool dialog and flow into the existing diagnostic/configure path
      const result = _addToolResult;
      if (!result || !result.tool) return;

      dismissAddTool();

      const tool = {
        name: result.tool.name,
        path: result.tool.path,
        status: result.tool.needs_config ? 'unconfigured' : result.tool.status,
        launch: result.tool.launch,
        providers: result.tool.providers,
      };

      // If the tool needs configuration, go to the diagnostic panel
      if (result.tool.needs_config) {
        setTimeout(() => {
          showDiagnostic(tool, {
            error: `${tool.name} needs configuration`,
            hint: 'Vault credentials need to be resolved and .env written.',
          });
        }, 400);
      } else {
        // Already configured — just refresh the cockpit
        showToast(`<span style="color:#00C896">✓</span> <b>${escapeHtml(tool.name)}</b> added to governance`);
        initialize();
      }
    }

    async function removeTool(toolName) {
      if (!confirm(`Remove "${toolName}" from ZeroPoint governance?\n\nThe project files will not be deleted.`)) {
        return;
      }
      try {
        const resp = await zpFetch(`/api/v1/tools/${encodeURIComponent(toolName)}/unregister`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
        const data = await resp.json();
        if (!resp.ok || data.error) {
          showToast(`<span style="color:#FF4444">✗</span> ${data.error || 'Failed to remove tool'}`);
          return;
        }
        showToast(`<span style="color:#8B8984">✓</span> <b>${escapeHtml(toolName)}</b> removed from governance`);
        initialize();
      } catch (err) {
        showToast(`<span style="color:#FF4444">✗</span> Connection error: ${err.message}`);
      }
    }

    // Handle Enter key in path input
    document.addEventListener('DOMContentLoaded', () => {
      const input = document.getElementById('addToolPath');
      if (input) {
        input.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            if (_addToolResult) {
              addToolRegister();
            } else {
              addToolScan();
            }
          }
        });
      }
    });

    function renderCockpit(data, hasGenesis) {
      const grid = document.getElementById('cockpitGrid');

      if (!data || data.error || !data.tools) {
        grid.innerHTML = `<div class="cockpit-empty">Tools endpoint unavailable.</div>`;
        return;
      }

      const tools = data.tools;
      const chainBacked = !!data.chain_receipts;
      grid.innerHTML = '';

      if (tools.length === 0 && !hasGenesis) {
        grid.innerHTML = `
          <div class="cockpit-empty" style="grid-column: 1 / -1;">
            No tools discovered yet.<br>
            Complete <a href="/onboard" style="color:#7eb8da; text-decoration:none; border-bottom:1px solid rgba(126,184,218,0.3)">onboarding</a> to scan and configure your agentic tools.
          </div>
        `;
        return;
      }

      // Tool tiles
      tools.forEach(tool => {
        const icon = toolIcons[tool.name.toLowerCase()] || '\u{1F527}';
        const tile = document.createElement('div');
        const isReady = tool.ready !== false; // default true if field absent
        const issues = tool.preflight_issues || [];
        const hasIssues = issues.length > 0;

        const neverPreflightedCheck = issues.length > 0 &&
          issues.every(i => i.toLowerCase().includes('not preflighted') || i.toLowerCase().includes('preflight not run'));
        let tileClass = 'cockpit-tile';
        if (neverPreflightedCheck) { /* neutral — no red border */ }
        else if (!isReady || hasIssues) tileClass += ' not-ready';
        else if (tool.status === 'governed') tileClass += ' governed';
        tile.className = tileClass;

        let healthClass = '';
        let badgeHtml = '';
        let statusText = '';

        // Distinguish "never preflighted" from "preflighted and failed"
        const neverPreflighted = issues.length > 0 &&
          issues.every(i => i.toLowerCase().includes('not preflighted') || i.toLowerCase().includes('preflight not run'));

        if (neverPreflighted) {
          // Tool discovered but preflight hasn't run yet — neutral state, not an error
          healthClass = 'unconfigured';
          badgeHtml = '<div class="tile-badge pending">awaiting preflight</div>';
          statusText = 'discovered \u00B7 click to preflight';
        } else if (!isReady || hasIssues) {
          // Preflight actually ran and failed
          healthClass = 'not-ready';
          badgeHtml = '<div class="tile-badge not-ready">preflight failed</div>';
          statusText = issues[0] || 'not launch-ready';
        } else if (tool.status === 'governed') {
          healthClass = '';
          badgeHtml = '<div class="tile-badge governed">\u2713 genesis-bound</div>';
          statusText = chainBacked ? 'governed \u00B7 chain-verified' : 'governed \u00B7 launch ready';
        } else if (tool.status === 'configured' && tool.governance === 'unanchored') {
          healthClass = 'unanchored';
          badgeHtml = '<div class="tile-badge unanchored">unanchored</div>';
          statusText = 'configured \u00B7 no genesis';
        } else if (tool.status === 'configured') {
          healthClass = '';
          badgeHtml = '<div class="tile-badge governed">configured</div>';
          statusText = '.env present';
        } else {
          healthClass = 'unconfigured';
          badgeHtml = '<div class="tile-badge pending">needs setup</div>';
          statusText = 'unconfigured';
        }

        // Launch type hint
        const launch = tool.launch || {};
        let launchHint = '';
        if (launch.kind === 'web' && launch.port) {
          launchHint = `<div class="tile-launch web">:${launch.port}</div>`;
        } else if (launch.kind === 'docker') {
          launchHint = '<div class="tile-launch docker">docker</div>';
        } else if (launch.kind === 'cli') {
          launchHint = '<div class="tile-launch">cli</div>';
        }

        // Preflight issues tooltip (show first 2 issues)
        let issuesHtml = '';
        if (hasIssues) {
          const shown = issues.slice(0, 2).map(i => escapeHtml(i)).join('<br>');
          const more = issues.length > 2 ? `<br>+${issues.length - 2} more` : '';
          issuesHtml = `<div class="tile-preflight-issues">${shown}${more}</div>`;
        }

        tile.innerHTML = `
          <button class="tile-remove" title="Remove from governance" data-action="remove-tool" data-tool-name="${escapeHtml(tool.name)}">&times;</button>
          <div class="tile-health ${healthClass}"></div>
          <div class="tile-icon">${icon}</div>
          <div class="tile-name">${escapeHtml(tool.name)}</div>
          <div class="tile-status">${escapeHtml(statusText)}</div>
          ${launchHint}
          ${issuesHtml}
          ${badgeHtml}
        `;

        tile.onclick = () => launchTool(tool);
        tile.dataset.toolName = tool.name;
        grid.appendChild(tile);
      });

      // ZeroPoint system tile
      const zpTile = document.createElement('div');
      zpTile.className = 'cockpit-tile zp-core';
      zpTile.innerHTML = `
        <div class="tile-health ${hasGenesis ? '' : 'unanchored'}"></div>
        <div class="tile-icon">\u2699\uFE0F</div>
        <div class="tile-name">ZeroPoint</div>
        <div class="tile-status">${hasGenesis ? 'governance engine \u00B7 genesis active' : 'governance engine \u00B7 no genesis'}</div>
        <div class="tile-badge ${hasGenesis ? 'governed' : 'unanchored'}">${hasGenesis ? 'core' : 'incomplete'}</div>
      `;
      zpTile.onclick = () => {
        document.getElementById('identityRow').scrollIntoView({ behavior: 'smooth', block: 'start' });
      };
      grid.appendChild(zpTile);

      // Add tool tile
      const addTile = document.createElement('div');
      addTile.className = 'cockpit-tile add-tile';
      addTile.innerHTML = `
        <div class="tile-icon">+</div>
        <div class="tile-name">Add Tool</div>
        <div class="tile-status">zp configure</div>
      `;
      addTile.onclick = () => showAddTool();
      grid.appendChild(addTile);
    }

    // ── Identity ──────────────────────────────────────────
    function renderIdentity(data, gen) {
      const el = (id) => document.getElementById(id);
      if (gen && gen.staleSession) {
        // Don't lie about identity state when we just have a stale cookie.
        // The banner tells the user to reload — render neutral placeholders.
        el('operatorName').innerHTML = '<span class="unreachable">Session expired &mdash; reload to reconnect</span>';
        ['sovereigntyMode','publicKey','destinationHash','algorithm'].forEach(id => el(id).textContent = '\u2014');
        return;
      }
      if (!gen || gen.error) {
        el('operatorName').innerHTML = `<span class="unreachable">No Genesis established</span> &middot; <a href="/onboard" style="color:#7eb8da; text-decoration:none; border-bottom:1px solid rgba(126,184,218,0.3)">Begin Onboarding &rarr;</a>`;
        ['sovereigntyMode','publicKey','destinationHash','algorithm'].forEach(id => el(id).textContent = '\u2014');
        return;
      }
      const op = gen.operator || null;
      el('operatorName').textContent = op || '\u2014';
      el('headerOperator').textContent = op ? `Operator: ${op}` : '';
      el('sovereigntyMode').textContent = gen.sovereignty_mode || '\u2014';
      const gk = gen.genesis_public_key || gen.public_key || (data && data.public_key) || null;
      el('publicKey').textContent = gk ? truncateKey(gk) : '\u2014';
      el('destinationHash').textContent = (data && !data.error && data.destination_hash) ? truncateKey(data.destination_hash) : '\u2014';
      el('algorithm').textContent = gen.algorithm || (data && data.algorithm) || 'Ed25519';
      showWelcome(op);
    }

    // ── Topology ──────────────────────────────────────────
    const roleIcons = {
      gateway: '\u25C7',   // diamond
      router: '\u25CE',    // bullseye
      sentinel: '\u25C8',  // filled diamond in circle
      node: '\u25C9',      // fisheye
      device: '\u25CB',    // circle
    };

    function renderTopology(topo) {
      const map = document.getElementById('topologyMap');
      if (!topo || topo.error || !topo.nodes || topo.nodes.length === 0) {
        map.innerHTML = `<div class="topology-desc">No topology data. Configure <code>~/ZeroPoint/config/topology.toml</code> to map your network.</div>`;
        return;
      }

      let html = '';
      topo.nodes.forEach((node, i) => {
        const icon = roleIcons[node.role] || roleIcons.device;
        const statusClass = node.status === 'active' ? 'active' : 'inactive';
        const isZP = node.role === 'node';
        html += `
          <div class="topology-node ${statusClass} ${isZP ? 'zp-node' : ''}">
            <div class="topo-icon">${icon}</div>
            <div class="topo-info">
              <div class="topo-name">${escapeHtml(node.name || '')}</div>
              <div class="topo-role">${escapeHtml(node.role || '')}${node.address ? ' &mdash; ' : ''}<span class="topo-address">${escapeHtml(node.address || '')}</span></div>
              ${node.detail ? `<div class="topo-detail">${escapeHtml(node.detail)}</div>` : ''}
            </div>
          </div>
        `;
        if (i < topo.nodes.length - 1) {
          html += `<div class="topology-connector"></div>`;
        }
      });

      if (topo.description) {
        html += `<div class="topology-desc">${escapeHtml(topo.description)}</div>`;
      }
      map.innerHTML = html;
    }

    // ── Gates ─────────────────────────────────────────────
    function renderGates(rulesData) {
      const statusEl = document.getElementById('gateStatus');
      const rulesEl = document.getElementById('gateRules');
      const ok = !rulesData.error && rulesData.rules && rulesData.rules.length > 0;
      statusEl.innerHTML = `<div class="status-indicator ${ok ? 'pass' : 'fail'}"></div><div>${ok ? 'GATES INSTALLED' : 'GATES COMPROMISED'}</div>`;
      if (!ok) { rulesEl.innerHTML = `<div class="unreachable">No rules loaded</div>`; return; }
      rulesEl.innerHTML = rulesData.rules.map(r => {
        const c = r.category === 'constitutional';
        return `<div class="gate-rule ${c ? 'constitutional' : ''}"><div class="gate-rule-dot"></div><div class="gate-rule-name">${escapeHtml(r.name || 'Unknown')}</div><div class="gate-rule-category">${escapeHtml(r.category || 'standard')}</div></div>`;
      }).join('');
    }

    // ── Chain ─────────────────────────────────────────────
    function renderChain(audit) {
      const s = document.getElementById('chainStatus');
      const d = document.getElementById('chainDetails');
      if (audit.error) {
        s.innerHTML = `<div class="status-indicator fail"></div><div>CHAIN UNREACHABLE</div>`;
        d.innerHTML = `<div class="chain-detail-line unreachable">Unable to verify chain</div>`;
        return;
      }
      const ok = audit.valid === true;
      s.innerHTML = `<div class="status-indicator ${ok?'pass':'fail'}"></div><div>${ok ? 'CHAIN VERIFIED' : 'CHAIN BROKEN'}</div>`;
      d.innerHTML = `
        <div class="chain-detail-line"><span class="chain-detail-label">Entries Examined:</span><span>${audit.entries_examined||0}</span></div>
        <div class="chain-detail-line"><span class="chain-detail-label">Validity:</span><span class="${ok?'success':'error-text'}">${ok?'\u2713':'\u2715'}</span></div>
        ${audit.error_message ? `<div class="chain-detail-line error">${audit.error_message}</div>` : ''}
      `;
    }

    // ── Security Posture ──────────────────────────────────
    function renderPosture(data) {
      const scoreEl = document.getElementById('postureScore');
      const checksEl = document.getElementById('postureChecks');
      const summaryEl = document.getElementById('postureSummary');

      if (data.error) {
        scoreEl.textContent = '\u2014';
        checksEl.innerHTML = `<div class="unreachable">Posture data unavailable</div>`;
        summaryEl.textContent = '';
        return;
      }

      // Score with color
      const score = data.score !== undefined ? data.score : 0;
      scoreEl.textContent = score;
      scoreEl.className = 'score-value ' + (score >= 85 ? 'green' : score >= 60 ? 'yellow' : 'red');

      // Summary
      summaryEl.textContent = data.summary || '';

      // Checks with full detail
      if (data.checks && data.checks.length > 0) {
        checksEl.innerHTML = data.checks.map(c => {
          const st = c.status || 'pass';
          const ic = st === 'pass' ? 'pass' : st === 'warning' ? 'warning' : 'fail';
          return `
            <div class="posture-check">
              <div class="check-indicator ${ic}"></div>
              <div class="check-body">
                <div class="check-name">${escapeHtml(c.name || 'Unknown')}</div>
                <div class="check-detail">${escapeHtml(c.detail || '')}</div>
                <div class="check-category">${escapeHtml(c.category || '')}</div>
              </div>
            </div>
          `;
        }).join('');
      } else {
        checksEl.innerHTML = `<div class="loading">No checks available</div>`;
      }
    }

    // ── Init ──────────────────────────────────────────────
    const refreshAll = () => initialize();
    async function initialize() {
      try {
        const [identity, genesis, rules, audit, stats, posture, topo, tools] = await Promise.all([
          fetchEndpoint(endpoints.identity),
          fetchEndpoint(endpoints.genesis),
          fetchEndpoint(endpoints.rules),
          fetchEndpoint(endpoints.audit),
          fetchEndpoint(endpoints.stats),
          fetchEndpoint(endpoints.security),
          fetchEndpoint(endpoints.topology),
          fetchEndpoint(endpoints.tools)
        ]);

        const hasGenesis = genesis && !genesis.error && (genesis.genesis_public_key || genesis.public_key);

        renderCockpit(tools, !!hasGenesis);
        renderIdentity(identity, genesis);
        renderTopology(topo);
        renderGates(rules);
        renderChain(audit);
        renderPosture(posture);
      } catch (err) {
        console.error('Verification surface error:', err);
      }
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initialize);
    } else {
      initialize();
    }

// ── CSP-safe event delegation ─────────────────────────────
// All static buttons & dynamically-generated buttons route through data-action.
// No inline onclick handlers — CSP 'script-src self' compliant.
document.addEventListener('click', function(e) {
  const target = e.target.closest('[data-action]');
  if (!target) return;
  const action = target.getAttribute('data-action');
  switch (action) {
    case 'dismiss-welcome':
      dismissWelcome(false);
      break;
    case 'dismiss-welcome-silence':
      dismissWelcome(true);
      break;
    case 'add-tool-scan':
      addToolScan();
      break;
    case 'add-tool-register':
      addToolRegister();
      break;
    case 'dismiss-add-tool':
      dismissAddTool();
      break;
    case 'run-resolve':
      runResolve();
      break;
    case 'diag-retry':
      diagRetry();
      break;
    case 'dismiss-diag':
      dismissDiag();
      break;
    case 'toggle-terminal':
      toggleTerminal();
      break;
    case 'toggle-next-sibling':
      target.classList.toggle('open');
      if (target.nextElementSibling) {
        target.nextElementSibling.classList.toggle('open');
      }
      break;
    case 'exec-in-terminal': {
      const cmd = target.getAttribute('data-cmd') || '';
      const cwd = target.getAttribute('data-cwd') || '';
      execInTerminal(cmd, cwd);
      break;
    }
    case 'remove-tool': {
      e.stopPropagation();
      const name = target.getAttribute('data-tool-name') || '';
      if (name) removeTool(name);
      break;
    }
    case 'reload-page':
      window.location.reload();
      break;
  }
});

// ── P4-3: Observability Panels ────────────────────────────────────

// Cognition Pipeline panel
(async function loadCognitionPanel() {
  const panel = document.getElementById('cognitionPanel');
  if (!panel) return;
  try {
    const res = await zpFetch('/api/v1/cognition/status');
    if (!res.ok) throw new Error('Status ' + res.status);
    const data = await res.json();
    const cards = [
      { label: 'Observations', value: data.observation_count || data.total_observations || 0 },
      { label: 'Promoted', value: data.promoted_count || 0 },
      { label: 'Pending Review', value: data.pending_reviews || 0 },
      { label: 'Pipeline', value: data.pipeline_active ? 'Active' : 'Idle', active: data.pipeline_active },
    ];
    panel.innerHTML = cards.map(c =>
      '<div class="cognition-card">' +
        '<div class="cognition-card-label">' + c.label + '</div>' +
        '<div class="cognition-card-value' + (c.active ? ' active' : '') + '">' + c.value + '</div>' +
      '</div>'
    ).join('');
  } catch (e) {
    panel.innerHTML = '<div style="color:#555;font-size:12px">Cognition pipeline not available</div>';
  }
})();

// Analysis Engines panel
(async function loadAnalysisPanel() {
  const panel = document.getElementById('analysisPanel');
  if (!panel) return;
  try {
    const res = await zpFetch('/api/v1/analysis/tools');
    if (!res.ok) throw new Error('Status ' + res.status);
    const data = await res.json();
    if (!data.tools || data.tools.length === 0) {
      panel.innerHTML = '<div style="color:#555;font-size:12px">No analysis data yet — launch and use tools to generate observations</div>';
      return;
    }
    panel.innerHTML = data.tools.map(t => {
      const pct = Math.round((t.readiness_score || 0) * 100);
      const cls = pct >= 80 ? 'green' : pct >= 50 ? 'yellow' : 'red';
      return '<div class="analysis-tool">' +
        '<div class="analysis-tool-name">' + (t.name || '?') + '</div>' +
        '<div class="analysis-tool-bar"><div class="analysis-tool-fill ' + cls + '" style="width:' + pct + '%"></div></div>' +
        '<div class="analysis-tool-score">' + pct + '%</div>' +
        '<div class="analysis-tool-obs">' + (t.observation_count || 0) + ' obs</div>' +
      '</div>';
    }).join('');
  } catch (e) {
    panel.innerHTML = '<div style="color:#555;font-size:12px">Analysis engines not available</div>';
  }
})();

// Live Event Feed via SSE
(function initEventFeed() {
  const feed = document.getElementById('eventFeed');
  const status = document.getElementById('eventFeedStatus');
  const counter = document.getElementById('eventFeedCount');
  if (!feed || !status) return;

  var eventCount = 0;
  var maxEvents = 100;

  function connect() {
    var es = new EventSource('/api/v1/events/stream');

    es.onopen = function() {
      status.textContent = '● Connected';
      status.classList.add('connected');
    };

    es.onerror = function() {
      status.textContent = '● Reconnecting...';
      status.classList.remove('connected');
    };

    // Listen for all event types
    ['audit', 'channel', 'system'].forEach(function(cat) {
      es.addEventListener(cat, function(e) {
        try {
          var item = JSON.parse(e.data);
          addEventRow(item, cat);
        } catch (_) {}
      });
    });
  }

  function addEventRow(item, cat) {
    // Remove empty placeholder
    var empty = feed.querySelector('.event-feed-empty');
    if (empty) empty.remove();

    var row = document.createElement('div');
    row.className = 'event-row';

    var ts = item.timestamp ? new Date(item.timestamp) : new Date();
    var timeStr = ts.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    row.innerHTML =
      '<span class="event-time">' + timeStr + '</span>' +
      '<span class="event-cat ' + cat + '">' + cat + '</span>' +
      '<span class="event-text">' + escapeHtml(item.event_type || '') +
        (item.summary ? ' — ' + escapeHtml(item.summary) : '') +
      '</span>';

    feed.insertBefore(row, feed.firstChild);
    eventCount++;

    // Trim old events
    while (feed.children.length > maxEvents) {
      feed.removeChild(feed.lastChild);
    }

    if (counter) counter.textContent = eventCount + ' events';
  }

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  connect();
})();

// Channel Status panel
(async function loadChannelsPanel() {
  const panel = document.getElementById('channelsPanel');
  if (!panel) return;
  try {
    const res = await zpFetch('/api/v1/channels/status');
    if (!res.ok) throw new Error('Status ' + res.status);
    const data = await res.json();
    if (!data.channels || data.channels.length === 0) {
      panel.innerHTML = '<div style="color:#555;font-size:12px">No channels configured</div>';
      return;
    }
    panel.innerHTML = data.channels.map(ch => {
      const dotCls = ch.connected ? 'connected' : ch.configured ? 'disconnected' : 'error';
      const statusText = ch.connected ? 'Connected' : ch.error || 'Not configured';
      return '<div class="channel-card">' +
        '<div class="channel-platform">' +
          '<span class="channel-status-dot ' + dotCls + '"></span>' +
          ch.platform.charAt(0).toUpperCase() + ch.platform.slice(1) +
        '</div>' +
        '<div class="channel-status-text">' + statusText + '</div>' +
      '</div>';
    }).join('');
  } catch (e) {
    panel.innerHTML = '<div style="color:#555;font-size:12px">Channel status not available</div>';
  }
})();

// ── WASM Policy Panel (P6-4) ──
(async function loadWasmPolicyPanel() {
  const panel = document.getElementById('wasmPolicyPanel');
  if (!panel) return;
  try {
    const res = await zpFetch('/api/v1/policy/wasm');
    if (!res.ok) throw new Error('Status ' + res.status);
    const data = await res.json();
    if (!data.runtime_available) {
      panel.innerHTML = '<div style="color:#555;font-size:12px">Native rules only (WASM feature not enabled)</div>';
      return;
    }
    if (data.count === 0) {
      panel.innerHTML = '<div style="color:#555;font-size:12px">WASM runtime ready · no modules loaded</div>';
      return;
    }
    let html = '';
    for (const m of data.modules) {
      const dotCls = m.status === 'Active' ? 'connected' : 'disconnected';
      html +=
        '<div class="channel-card">' +
          '<div class="channel-platform">' +
            '<span class="channel-status-dot ' + dotCls + '"></span>' +
            m.name +
          '</div>' +
          '<div class="channel-status-text">' + m.status + ' · ' + m.size_bytes + ' bytes</div>' +
        '</div>';
    }
    panel.innerHTML = html;
  } catch (e) {
    panel.innerHTML = '<div style="color:#555;font-size:12px">Policy runtime not available</div>';
  }
})();

// ── Fleet Status Panel (P5-2) ──
(async function loadFleetPanel() {
  const panel = document.getElementById('fleetPanel');
  if (!panel) return;
  try {
    const res = await zpFetch('/api/v1/fleet/summary');
    if (!res.ok) throw new Error('Status ' + res.status);
    const data = await res.json();
    if (data.total_nodes === 0) {
      panel.innerHTML = '<div style="color:#555;font-size:12px">No fleet nodes registered</div>';
      return;
    }
    panel.innerHTML =
      '<div class="channel-card">' +
        '<div class="channel-platform">' +
          '<span class="channel-status-dot connected"></span>' +
          'Online: ' + data.online +
        '</div>' +
        '<div class="channel-status-text">of ' + data.total_nodes + ' nodes</div>' +
      '</div>' +
      '<div class="channel-card">' +
        '<div class="channel-platform">' +
          '<span class="channel-status-dot ' + (data.stale > 0 ? 'disconnected' : 'connected') + '"></span>' +
          'Stale: ' + data.stale +
        '</div>' +
        '<div class="channel-status-text">' + (data.offline > 0 ? data.offline + ' offline' : 'All responsive') + '</div>' +
      '</div>' +
      '<div class="channel-card">' +
        '<div class="channel-platform">Policy Versions</div>' +
        '<div class="channel-status-text">' + (data.policy_versions || []).join(', ') + '</div>' +
      '</div>';
  } catch (e) {
    panel.innerHTML = '<div style="color:#555;font-size:12px">Fleet status not available</div>';
  }
})();
