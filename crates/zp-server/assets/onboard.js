(function() {
  'use strict';

  // ── HTML escaping (XSS-VULN-09, XSS-VULN-10, XSS-VULN-11) ──
  function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ── State ───────────────────────────────────────────────
  let ws = null;
  let currentStep = 0;
  let selectedSovereignty = null;
  let platformInfo = null;
  let genesisData = null;
  let discoveredTools = [];
  let credentialsStored = 0;
  let narrationAudio = null;
  let isNarrating = false;

  // ── WebSocket ───────────────────────────────────────────
  let heartbeatInterval = null;
  let pendingSends = [];  // Messages queued while WS is reconnecting

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/api/onboard/ws`);

    ws.onopen = () => {
      console.log('onboard ws connected');
      // Flush any messages queued during reconnect
      while (pendingSends.length > 0) {
        const msg = pendingSends.shift();
        ws.send(msg);
      }
      // Start heartbeat: ping every 30s to keep connection alive
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      heartbeatInterval = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ action: 'status' }));
        }
      }, 30000);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        handleEvent(msg);
      } catch (err) {
        console.error('ws parse error:', err);
      }
    };

    ws.onclose = () => {
      console.log('onboard ws closed — reconnecting in 1s');
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      setTimeout(connect, 1000);
    };

    ws.onerror = (e) => {
      console.error('onboard ws error:', e);
    };
  }

  function send(action, params) {
    const msg = JSON.stringify({ action, ...params });
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      console.warn('ws not connected — queueing message for reconnect');
      pendingSends.push(msg);
      return;
    }
    ws.send(msg);
  }

  // ── Event handler ───────────────────────────────────────
  function handleEvent(msg) {
    switch (msg.event) {
      case 'state':
        // Reconstruct UI from server state (filesystem-backed).
        // Only advance FORWARD — never regress the user to an earlier step.
        // This prevents heartbeat/reconnect state events from yanking the
        // user backwards while they're mid-step.
        if (msg.step && msg.step > 0 && msg.step > currentStep) {
          console.log('[ZP] Resuming from step', msg.step, '(current:', currentStep, ')', msg);

          // Restore known state into JS globals
          if (msg.genesis_public_key) {
            genesisData = {
              genesis_public_key: msg.genesis_public_key,
              operator: msg.operator_name,
              sovereignty_mode: msg.sovereignty_mode,
            };
          }
          if (msg.credentials_stored) {
            credentialsStored = msg.credentials_stored;
          }
          if (msg.operator_name) {
            platformInfo = platformInfo || {};
            platformInfo.operator_name = msg.operator_name;
          }
          if (msg.inference_posture) {
            window._resumedPosture = msg.inference_posture;
          }
          if (msg.tools_discovered) {
            window._resumedToolCount = msg.tools_discovered;
          }

          // Jump to the reconstructed step
          setTimeout(() => {
            goStep(msg.step);
          }, 300);
        }
        break;

      case 'heartbeat_ack':
        // Silent keepalive confirmation — no UI action needed
        break;

      case 'platform':
        platformInfo = msg;
        updatePlatformUI(msg);
        break;

      case 'genesis_complete':
        genesisData = msg;
        showGenesisComplete(msg);
        break;

      case 'recovery_kit':
        showRecoveryKit(msg);
        break;

      case 'genesis_failed':
        handleGenesisFailed(msg);
        break;

      case 'awaiting_provider':
        // Server is about to block on an OS dialog or terminal password prompt.
        // Show the user what's happening so the UI doesn't appear dead (result 028).
        appendTerminal('genesisTerm', '');
        appendTerminal('genesisTerm', '⏳ ' + (msg.hint || 'Waiting for system authorization...'));
        appendTerminal('genesisTerm', '   If nothing appears, check your terminal for a password prompt.');
        break;

      case 'hw_connect_prompt':
        showHwConnectStatus('detecting', msg.device);
        break;

      case 'hw_not_detected':
        showHwConnectStatus('not-detected', msg.device, msg.description);
        break;

      case 'vault_ready':
        appendTerminal('genesisTerm', '✓ Vault key derivation confirmed', 'success');
        break;

      case 'system_resources':
        // Consumed via local_inference_status event (which includes system data)
        break;

      case 'local_inference_status':
        showLocalInferenceStatus(msg);
        break;

      case 'ollama_status':
        // Legacy event — handled by local_inference_status now
        break;

      case 'setup_guidance':
        showSetupGuidance(msg);
        break;

      case 'model_pull_started':
        showModelPullStatus(msg);
        break;

      case 'inference_posture_set':
        // Acknowledged — no UI update needed
        break;

      case 'scan_result':
        addScanResult(msg);
        break;

      case 'scan_complete':
        showScanComplete(msg);
        break;

      case 'credentials_summary':
        showFoundCredentials(msg);
        break;

      case 'import_complete':
        handleImportComplete(msg);
        break;

      case 'provider_catalog':
        showProviderCatalog(msg);
        break;

      case 'credential_stored':
        markCredentialStored(msg);
        break;

      case 'credential_validated':
        handleCredentialValidated(msg);
        break;

      case 'validation_sweep':
        handleValidationSweep(msg);
        break;

      case 'tool_configured':
        markToolConfigured(msg);
        break;

      case 'configure_complete':
        showConfigureComplete(msg);
        break;

      case 'preflight_complete':
        // Preflight done — now show the Next button and summary
        document.getElementById('configureNext').style.display = 'flex';
        populateSummary();
        break;

      case 'terminal':
        // Route to the currently visible terminal
        const activeTerm = document.querySelector('.step.active .terminal');
        if (activeTerm) {
          activeTerm.style.display = 'block';
          appendTerminal(activeTerm.id, msg.line);
        }
        break;

      case 'error':
        const errTerm = document.querySelector('.step.active .terminal');
        if (errTerm) {
          errTerm.style.display = 'block';
          appendTerminal(errTerm.id, '✗ ' + msg.message, 'error');
        }
        // Reset any Store buttons stuck in "..." state (vault_store errors)
        document.querySelectorAll('.store-btn').forEach(btn => {
          if (btn.textContent === '...') {
            btn.textContent = 'Retry';
            btn.disabled = false;
          }
        });
        break;
    }
  }

  // ── Terminal helper ─────────────────────────────────────
  function appendTerminal(termId, text, cls) {
    const term = document.getElementById(termId);
    if (!term) return;
    const line = document.createElement('div');
    line.className = 'line' + (cls ? ' ' + cls : '');
    line.textContent = text;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
  }

  // ── Step navigation ─────────────────────────────────────
  window.goStep = function(step, animate) {
    // Hide all steps
    document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
    // Show target
    const target = document.getElementById('step-' + step);
    if (target) target.classList.add('active');

    // Update nav tabs
    document.querySelectorAll('.step-tab').forEach(tab => {
      const tabStep = parseInt(tab.dataset.step);
      tab.classList.remove('active', 'disabled');
      if (tabStep === step) {
        tab.classList.add('active');
      } else if (tabStep > step && tabStep > currentStep) {
        tab.classList.add('disabled');
      }
      if (tabStep < step) {
        tab.classList.add('complete');
      }
    });

    currentStep = step;

    // Trigger local inference runtime detection when entering inference step
    if (step === 4) {
      send('detect_local_inference');
    }

    // Load provider catalog when entering credential step
    if (step === 6) {
      send('get_provider_catalog');
    }

    // Rebuild tool config cards with saved state when revisiting Step 7
    if (step === 7) {
      buildConfigToolCards();
      // Run credential health check before configure
      send('validate_all', {});
    }

    // Rebuild launch pad when entering Step 8
    if (step === 8) {
      populateSummary();
    }

    // Auto-play narration on step transition
    stopNarration();
    setTimeout(() => startNarration(), 400); // slight delay for step animation
  };

  // Enable clicking completed/active tabs
  document.querySelectorAll('.step-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      if (!tab.classList.contains('disabled')) {
        goStep(parseInt(tab.dataset.step));
      }
    });
  });

  // ── Step 0: Begin ───────────────────────────────────────
  window.startOnboard = function() {
    // Remove first-click listener so it doesn't double-fire with goStep's auto-play
    document.removeEventListener('click', autoplayOnFirstInteraction);
    document.removeEventListener('keydown', autoplayOnFirstInteraction);
    document.removeEventListener('touchstart', autoplayOnFirstInteraction);
    send('detect');
    goStep(1);
  };

  // ── Step 1: Sovereignty ─────────────────────────────────
  function updatePlatformUI(info) {
    const loginDetail = document.getElementById('login_password-detail');

    // New: process sovereignty_providers array from detection
    if (info.sovereignty_providers && info.sovereignty_providers.length > 0) {
      let bestAvailable = null;
      // Track which modes need external device connection (for HW plug-in prompt)
      window._externalDeviceModes = {};

      info.sovereignty_providers.forEach(function(prov) {
        if (prov.requires_external_device) {
          window._externalDeviceModes[prov.mode] = true;
        }
        // Map provider mode to card element ID
        const cardId = 'card-' + prov.mode;
        const detailId = prov.mode + '-detail';
        const card = document.getElementById(cardId);
        const detail = document.getElementById(detailId);

        if (!card) return; // No card for this provider

        // Track implementation status for ceremony gating
        card.dataset.ceremonyReady = prov.ceremony_ready ? 'true' : 'false';
        card.dataset.implementationStatus = prov.implementation_status || 'ready';

        if (prov.implementation_status === 'detection_only') {
          // DetectionOnly: show but clearly mark as not yet available for ceremony.
          // Don't show "connect your device" instructions for unimplemented providers
          // — that contradicts the "Coming soon" badge (result 026).
          if (detail) {
            detail.textContent = prov.available
              ? (prov.display_name + ' detected — full support coming soon')
              : 'Full support coming soon';
          }
          card.style.opacity = '0.4';
          card.style.pointerEvents = 'auto';
          card.dataset.providerAvailable = 'false';
          card.classList.remove('recommended');
          // Add "coming soon" badge if not already present
          if (!card.querySelector('.coming-soon-badge')) {
            const badge = document.createElement('span');
            badge.className = 'coming-soon-badge';
            badge.textContent = 'Coming soon';
            badge.style.cssText = 'display:inline-block;font-size:0.65rem;background:rgba(126,184,218,0.15);color:var(--accent);padding:0.15rem 0.5rem;border-radius:3px;margin-left:0.5rem;vertical-align:middle;';
            const h3 = card.querySelector('h3');
            if (h3) h3.appendChild(badge);
          }
        } else if (prov.available) {
          if (detail) detail.textContent = prov.description || 'Available';
          card.style.opacity = '1';
          card.style.pointerEvents = 'auto';
          card.dataset.providerAvailable = 'true';

          // Track best available ceremony-ready provider (biometric > hw wallet > software)
          if (prov.ceremony_ready && (!bestAvailable ||
              (prov.category === 'Biometric' && bestAvailable.category !== 'Biometric') ||
              (prov.category === 'HardwareWallet' && bestAvailable.category === 'Software'))) {
            bestAvailable = prov;
          }
        } else {
          if (detail) detail.textContent = prov.description || 'Not detected — select to use anyway';
          card.style.opacity = '0.55';
          card.style.pointerEvents = 'auto';  // Still selectable — gating happens in Step 2
          card.dataset.providerAvailable = 'false';
          card.classList.remove('recommended');
        }
      });

      // Auto-select the best available provider
      if (bestAvailable) {
        const bestCard = document.getElementById('card-' + bestAvailable.mode);
        if (bestCard) bestCard.classList.add('recommended');
        selectSovereignty(bestAvailable.mode);
      } else {
        selectSovereignty('login_password');
      }
    } else {
      // Fallback: legacy detection format (no sovereignty_providers array)
      const touchIdCard = document.getElementById('card-touch_id');
      const touchIdDetail = document.getElementById('touch_id-detail');

      if (info.biometric_available) {
        if (touchIdDetail) touchIdDetail.textContent = info.description || info.biometric_type || 'Available';
        if (touchIdCard) touchIdCard.classList.add('recommended');
        selectSovereignty('touch_id');
      } else {
        if (touchIdDetail) touchIdDetail.textContent = 'Not available on this hardware';
        if (touchIdCard) {
          touchIdCard.style.opacity = '0.55';
          touchIdCard.style.pointerEvents = 'auto';
        }
        document.getElementById('card-login_password').classList.add('recommended');
        selectSovereignty('login_password');
      }
    }

    // Login detail from credential store
    if (info.credential_store_available) {
      const storeNames = {
        macos: 'macOS Keychain',
        linux: 'Secret Service',
        windows: 'Windows Credential Manager',
      };
      loginDetail.textContent = (storeNames[info.platform] || 'OS credential store') + ' available';
    } else {
      loginDetail.textContent = 'Credential store not available';
    }

    // Show/hide platform-specific cards
    if (info.platform === 'linux') {
      const fpCard = document.getElementById('card-fingerprint');
      if (fpCard) fpCard.style.display = '';
      const tidCard = document.getElementById('card-touch_id');
      if (tidCard) tidCard.style.display = 'none';
    }
    if (info.platform === 'windows') {
      const whCard = document.getElementById('card-windows_hello');
      if (whCard) whCard.style.display = '';
      // Hide macOS-only Touch ID on Windows
      const tidCard = document.getElementById('card-touch_id');
      if (tidCard) tidCard.style.display = 'none';
    }
  }

  window.selectSovereignty = function(mode) {
    selectedSovereignty = mode;
    // Reset all cards: remove selected, restore dimming for unavailable/detection-only
    document.querySelectorAll('#sovereigntyCards .card').forEach(function(c) {
      c.classList.remove('selected');
      if (c.dataset.implementationStatus === 'detection_only') {
        c.style.opacity = '0.4';
      } else if (c.dataset.providerAvailable === 'false') {
        c.style.opacity = '0.55';
      }
    });
    const card = document.getElementById('card-' + mode);
    const btn = document.getElementById('sovereigntyNext');
    if (card) {
      card.classList.add('selected');
      card.style.opacity = '1';

      // Gate ceremony: DetectionOnly providers cannot proceed.
      // ceremonyReady is set by updatePlatformUI from server detection data.
      // If it hasn't been set yet (undefined), allow — the server will gate.
      if (card.dataset.ceremonyReady === 'false' && card.dataset.implementationStatus === 'detection_only') {
        btn.disabled = true;
        btn.textContent = 'Provider not yet available';
      } else {
        btn.disabled = false;
        btn.textContent = 'Continue';
      }
    } else {
      btn.disabled = false;
      btn.textContent = 'Continue';
    }
  };

  window.goGenesis = function() {
    goStep(2);
    // Show hardware connect prompt if a HW wallet mode is selected
    updateHwPromptVisibility();
  };

  // External device modes that need a plug-in prompt (populated from server detection)
  const hwWalletModesFallback = ['yubi_key', 'ledger', 'trezor', 'only_key'];

  function isHwWalletMode(mode) {
    // Use server-provided data if available, otherwise fallback to hardcoded list
    if (window._externalDeviceModes) {
      return !!window._externalDeviceModes[mode];
    }
    return hwWalletModesFallback.indexOf(mode) !== -1;
  }

  function updateHwPromptVisibility() {
    const prompt = document.getElementById('hwConnectPrompt');
    if (!prompt) return;
    if (isHwWalletMode(selectedSovereignty)) {
      const deviceNames = {
        'yubi_key': 'YubiKey',
        'ledger': 'Ledger', 'trezor': 'Trezor',
        'only_key': 'OnlyKey',
      };
      const name = deviceNames[selectedSovereignty] || 'hardware wallet';
      document.getElementById('hwConnectTitle').textContent = 'Connect your ' + name;
      document.getElementById('hwConnectDetail').textContent =
        'Plug in your ' + name + ' via USB before starting the Genesis ceremony. ' +
        'ZeroPoint will derive a wrapping key from it to seal your Genesis secret.';
      document.getElementById('hwStatusText').textContent = 'Waiting for device...';
      prompt.className = 'hw-connect-prompt';
      prompt.style.display = '';
    } else {
      prompt.style.display = 'none';
    }
  }

  function showHwConnectStatus(status, device, description) {
    const prompt = document.getElementById('hwConnectPrompt');
    const statusText = document.getElementById('hwStatusText');
    if (!prompt) return;

    if (status === 'detecting') {
      prompt.className = 'hw-connect-prompt';
      statusText.textContent = 'Detecting ' + (device || 'device') + '...';
      prompt.style.display = '';
    } else if (status === 'detected') {
      prompt.className = 'hw-connect-prompt detected';
      statusText.textContent = (device || 'Device') + ' detected';
    } else if (status === 'not-detected') {
      prompt.className = 'hw-connect-prompt not-detected';
      statusText.textContent = (device || 'Device') + ' not detected — ' +
        (description || 'ensure it is plugged in via USB');
    }
  }

  // ── Step 2: Genesis ─────────────────────────────────────
  window.runGenesis = function() {
    const name = document.getElementById('operatorName').value.trim() || 'Operator';
    document.getElementById('genesisBtn').disabled = true;
    document.getElementById('genesisTerm').style.display = 'block';
    document.getElementById('genesisTerm').innerHTML = '';

    // Update HW prompt to detecting state
    if (isHwWalletMode(selectedSovereignty)) {
      showHwConnectStatus('detecting', selectedSovereignty);
    }

    send('genesis', {
      operator_name: name,
      sovereignty_mode: selectedSovereignty || 'auto'
    });
  };

  function showGenesisComplete(data) {
    const infoDiv = document.getElementById('genesisInfoContent');
    const shortPub = (data.genesis_public_key || '').substring(0, 8);

    const sovereigntyLabels = {
      'touch_id': 'Touch ID',
      'fingerprint': 'Fingerprint',
      'face_enroll': 'Face Enrollment',
      'windows_hello': 'Windows Hello',
      'yubi_key': 'YubiKey',
      'ledger': 'Ledger',
      'trezor': 'Trezor',
      'only_key': 'OnlyKey',
      'login_password': 'Login Password',
      'file_based': 'File on Disk',
      // Legacy compat
      'biometric': 'Biometric',
    };

    let details = [
      '✓ Ed25519 keypair generated (Genesis + Operator)',
      '✓ Constitutional bedrock sealed (5 governance gates)',
    ];

    if (data.secret_in_credential_store) {
      const mode = data.sovereignty_mode || '';
      const storeNames = {
        macos: 'macOS Keychain',
        linux: 'Secret Service',
        windows: 'Windows Credential Manager',
      };
      const storeName = storeNames[data.platform] || 'OS credential store';

      // Describe the gating mechanism based on sovereignty mode
      const gateDescriptions = {
        'touch_id': 'Touch ID (Secure Enclave)',
        'fingerprint': 'fingerprint (fprintd)',
        'face_enroll': 'face verification (OpenCV)',
        'windows_hello': 'Windows Hello (TPM 2.0)',
        'yubi_key': 'YubiKey (FIDO2)',
        'ledger': 'Ledger hardware wallet',
        'trezor': 'Trezor hardware wallet',
        'only_key': 'OnlyKey token',
        // Legacy
        'biometric': data.platform === 'linux' ? 'fingerprint (fprintd)' : 'biometric (Secure Enclave)',
      };
      const gateName = gateDescriptions[mode];
      if (gateName) {
        details.push(`✓ Genesis secret sealed in ${storeName}, gated by ${gateName}`);
      } else {
        details.push(`✓ Genesis secret sealed in ${storeName}`);
      }
    } else {
      details.push('✓ Genesis secret written to file (credential store unavailable)');
    }

    details.push('✓ Genesis record written to ~/.zeropoint/');
    details.push('');
    details.push('<span style="color:var(--text-dim)">This key is local for now. Later, you can anchor it to a public ledger — making your identity and governance verifiable by anyone, including other agents.</span>');

    infoDiv.innerHTML = details.map(d =>
      `<div style="font-size:0.82rem; padding:0.15rem 0">${d}</div>`
    ).join('');

    document.getElementById('genesisInfo').style.display = 'block';
    document.getElementById('genesisNext').style.display = 'flex';

    // Update HW connect prompt to final status
    const mode = data.sovereignty_mode || '';
    if (isHwWalletMode(mode)) {
      showHwConnectStatus('detected', mode);
    }

    // Store for summary
    genesisData = data;
  }

  function handleGenesisFailed(data) {
    // The Genesis ceremony failed honestly — show the user what happened
    // and return them to Step 1 to choose a different provider.
    const term = document.getElementById('genesisTerm');
    if (term) {
      term.style.display = 'block';
    }

    // Re-enable the genesis button so they can retry
    const genesisBtn = document.getElementById('genesisBtn');
    if (genesisBtn) genesisBtn.disabled = false;

    const reason = data.reason || 'unknown';
    const modeName = data.display_name || data.mode || 'Provider';

    // Build a clear error message based on failure reason
    let userMessage = '';
    let actionMessage = '';

    if (reason === 'provider_not_implemented') {
      userMessage = modeName + ' is detection-only — full support is coming soon.';
      actionMessage = 'Go back to Step 1 and choose a different sovereignty provider.';
    } else if (reason === 'enrollment_failed') {
      userMessage = modeName + ' enrollment failed: ' + (data.error || 'unknown error');
      if (data.is_transient) {
        actionMessage = 'This may be temporary. Check the device and try again, or choose a different provider.';
      } else {
        actionMessage = 'Choose a different sovereignty provider, or troubleshoot the device.';
      }
    } else if (reason === 'save_failed') {
      userMessage = modeName + ' failed to store the Genesis secret: ' + (data.error || 'unknown error');
      if (data.is_transient) {
        actionMessage = 'This may be temporary. Check the device connection and try again.';
      } else if (data.is_security_concern) {
        actionMessage = '⚠ SECURITY: This may indicate a device mismatch. Verify your hardware before retrying.';
      } else {
        actionMessage = 'Choose a different provider or troubleshoot the issue.';
      }
    } else {
      userMessage = 'Genesis ceremony failed: ' + (data.message || reason);
      actionMessage = 'Choose a different sovereignty provider or try again.';
    }

    // Show failure in terminal
    appendTerminal('genesisTerm', '', '');
    appendTerminal('genesisTerm', '✗ ' + userMessage, 'error');
    appendTerminal('genesisTerm', '  ' + actionMessage, '');

    // Show a "Return to Step 1" button
    const infoDiv = document.getElementById('genesisInfoContent');
    if (infoDiv) {
      infoDiv.innerHTML =
        '<div style="color:var(--accent);font-size:0.85rem;margin-bottom:0.5rem">' + userMessage + '</div>' +
        '<div style="color:var(--text-dim);font-size:0.8rem;margin-bottom:1rem">' + actionMessage + '</div>';
      document.getElementById('genesisInfo').style.display = 'block';
    }

    // Show a back-to-sovereignty button instead of the "Continue" next button
    const nextBtn = document.getElementById('genesisNext');
    if (nextBtn) {
      nextBtn.style.display = 'flex';
      nextBtn.textContent = 'Choose Different Provider';
      nextBtn.onclick = function() {
        // Reset for retry
        nextBtn.textContent = 'Continue';
        nextBtn.style.display = 'none';
        nextBtn.onclick = function() { goStep(3); };
        document.getElementById('genesisInfo').style.display = 'none';
        goStep(1);
      };
    }

    // Update HW prompt if applicable
    if (isHwWalletMode(data.mode)) {
      showHwConnectStatus('not-detected', modeName, data.error);
    }
  }

  function showRecoveryKit(data) {
    const container = document.getElementById('recoveryWords');
    container.innerHTML = '';

    data.words.forEach((word, i) => {
      const div = document.createElement('div');
      div.className = 'word';
      div.innerHTML = `<span class="word-num">${i + 1}.</span> ${escapeHtml(word)}`;
      container.appendChild(div);
    });

    document.getElementById('recoveryKit').style.display = 'block';

    // Play recovery narration (conditional — only for biometric path)
    stopNarration();
    narrationAudio = new Audio('/assets/narration/onboard/onboard-recovery.mp3');
    showNarrationBar();
    document.getElementById('narrateLabel').textContent = 'Why your recovery kit matters';
    if (!isMuted) {
      narrationAudio.play().catch(() => {});
      isNarrating = true;
      document.getElementById('narrateToggle').innerHTML = '&#10074;&#10074;';
      document.getElementById('narrationBar').classList.add('playing');
      progressInterval = setInterval(updateProgress, 300);
      narrationAudio.onended = () => {
        isNarrating = false;
        clearInterval(progressInterval);
        document.getElementById('narrateProgress').style.width = '100%';
        document.getElementById('narrateToggle').innerHTML = '&#9654;';
        document.getElementById('narrationBar').classList.remove('playing');
      };
    }
    narrationAudio.onerror = () => {
      document.getElementById('narrationBar').style.display = 'none';
      isNarrating = false;
    };
  }

  // ── Step 3 → 4: Vault → Inference Posture ──────────────
  // (goStep(4) is called by vault Continue button)

  // ── Step 4: Inference Posture ─────────────────────────
  let inferencePosture = null;

  window.selectPosture = function(posture) {
    inferencePosture = posture;
    // Visual selection
    document.querySelectorAll('.posture-card').forEach(c => {
      c.style.borderColor = 'var(--border)';
    });
    const selected = document.getElementById('posture-' + posture);
    if (selected) selected.style.borderColor = 'var(--accent)';
    document.getElementById('postureBtn').disabled = false;

    // Tell server about the choice
    send('set_inference_posture', { posture });
  };

  function showLocalInferenceStatus(data) {
    const box = document.getElementById('localInferenceStatus');
    const title = document.getElementById('localInferenceTitle');
    const text = document.getElementById('localInferenceText');
    box.style.display = 'block';

    const sys = data.system || {};
    const runtimes = data.runtimes || [];
    const available = data.available || false;
    let statusLines = [];

    // System resources line
    if (sys.ram_gb) {
      let sysLine = `${sys.ram_gb}GB RAM · ${sys.cpu_cores || '?'} cores`;
      if (sys.chip) sysLine += ` · ${sys.chip}`;
      if (sys.gpu) sysLine += `<br>${sys.gpu}`;
      else if (sys.unified_memory) sysLine += ' (unified memory)';
      statusLines.push(`<span style="color:var(--text-dim); font-size:0.75rem">${sysLine}</span>`);
    }

    // Runtime status
    if (available && runtimes.length > 0) {
      title.style.color = 'var(--green)';
      const allModels = data.models || [];

      // Show each detected runtime
      runtimes.forEach(rt => {
        let rtLine = `<span style="color:var(--green)">✓</span> ${escapeHtml(rt.name)} detected`;
        if (rt.version) rtLine += ` (v${escapeHtml(rt.version)})`;
        rtLine += ` <span style="color:var(--text-dim)">at ${escapeHtml(rt.endpoint)}</span>`;
        if (rt.models && rt.models.length > 0) {
          rtLine += `<br><span style="color:var(--text-dim)">${rt.models.length} model(s): ${rt.models.map(m => escapeHtml(m)).join(', ')}</span>`;
        }
        statusLines.unshift(rtLine);
      });

      // Update local-models display if it exists
      const localModels = document.getElementById('local-models');
      if (localModels && allModels.length > 0) {
        localModels.style.display = 'block';
        localModels.textContent = `Models: ${allModels.join(', ')}`;
      }
    } else {
      title.style.color = 'var(--text-dim)';
      statusLines.unshift(
        `<span style="color:var(--text-dim)">⚠ No local inference runtime detected.</span>`
      );

      // Show setup assistant for capable hardware
      if (sys.local_inference_fit && sys.local_inference_fit !== 'limited') {
        document.getElementById('setupAssistant').style.display = 'block';
      } else {
        // Limited hardware — still show assistant but note the constraint
        const sa = document.getElementById('setupAssistant');
        sa.style.display = 'block';
        const phase1 = document.getElementById('setupPhase1');
        const existingNote = phase1.querySelector('.hw-note');
        if (!existingNote) {
          const note = document.createElement('p');
          note.className = 'hw-note';
          note.style.cssText = 'font-size:0.72rem; color:var(--yellow); margin:0 0 0.5rem 0';
          note.textContent = 'Your hardware is limited for local inference — small models will work, but Mixed or Cloud mode may be a better fit.';
          phase1.insertBefore(note, phase1.firstChild.nextSibling);
        }
      }
    }

    // Recommendation line
    if (sys.recommendation) {
      statusLines.push(`<span style="font-size:0.75rem; color:var(--accent); margin-top:0.25rem; display:inline-block">${sys.recommendation}</span>`);
    }

    text.innerHTML = statusLines.join('<br>');

    // Store system resources for setup assistant
    lastSystemResources = sys;

    // Adaptive recommendation: highlight the best-fit posture card
    applyPostureRecommendation(available, sys.local_inference_fit);

    // Update setup assistant state (handles re-detection flow)
    updateSetupAssistantAfterDetect(data);
  }

  function applyPostureRecommendation(localAvailable, fit) {
    // Remove any existing recommendation tags
    // Clear previous recommendation labels
    document.querySelectorAll('.posture-card').forEach(el => el.classList.remove('recommended'));

    let recommended = 'mixed'; // default and fallback for unknown
    if (fit === 'limited') {
      recommended = 'cloud';
    } else if (fit === 'moderate' && !localAvailable) {
      recommended = 'cloud';
    } else if (fit === 'strong' || fit === 'moderate') {
      recommended = 'mixed';
    }
    // fit === 'unknown' → stays 'mixed' (safe default)

    const card = document.getElementById('posture-' + recommended);
    if (card) {
      card.classList.add('recommended');
    }
  }

  // ── Setup Assistant: guided local inference setup ──────

  // Store the last system resources for the setup flow
  let lastSystemResources = null;

  window.requestSetupGuidance = function(runtime) {
    // Highlight selected runtime button
    document.querySelectorAll('.runtime-pick').forEach(b => {
      b.style.borderColor = 'var(--border)';
      b.style.opacity = '0.6';
    });
    event.currentTarget.style.borderColor = 'var(--accent)';
    event.currentTarget.style.opacity = '1';

    send('get_setup_guidance', { runtime: runtime });
  };

  function showSetupGuidance(data) {
    const install = data.install || {};
    const model = data.model || {};

    // If phase 3 is currently visible (model-pull step), just update the model rec
    if (document.getElementById('setupPhase3').style.display === 'block') {
      if (model && model.model_id) {
        populateModelRecommendation(model);
      }
      return;
    }

    // Switch to phase 2
    document.getElementById('setupPhase1').style.display = 'none';
    document.getElementById('setupPhase2').style.display = 'block';
    document.getElementById('setupPhase3').style.display = 'none';

    // Build install instructions
    const instrEl = document.getElementById('setupInstructions');
    instrEl.innerHTML = `<span style="color:var(--accent)">▸</span> Install <strong>${escapeHtml(install.runtime)}</strong> <span style="color:var(--text-dim)">(${escapeHtml(install.method)})</span>`;

    // Build command block
    const cmdEl = document.getElementById('setupCommands');
    if (install.commands && install.commands.length > 0) {
      cmdEl.style.display = 'block';
      cmdEl.innerHTML = install.commands
        .map(cmd => `<div style="margin:0.15rem 0"><span style="color:var(--accent)">$</span> <code>${escapeHtml(cmd)}</code></div>`)
        .join('');

      if (install.alt_url) {
        cmdEl.innerHTML += `<div style="margin:0.35rem 0 0 0; font-size:0.72rem; color:var(--text-dim)">or download directly: <a href="${escapeHtml(install.alt_url)}" target="_blank" style="color:var(--accent)">${escapeHtml(install.alt_url)}</a></div>`;
      }
    } else if (install.alt_url) {
      cmdEl.style.display = 'block';
      cmdEl.innerHTML = `<div style="margin:0.15rem 0"><span style="color:var(--accent)">→</span> <a href="${escapeHtml(install.alt_url)}" target="_blank" style="color:var(--accent)">${escapeHtml(install.alt_url)}</a></div>`;
    } else {
      cmdEl.style.display = 'none';
    }

    // Notes
    const notesEl = document.getElementById('setupNotes');
    notesEl.textContent = install.notes || '';

    // Store model recommendation for phase 3
    cmdEl.dataset.modelRec = JSON.stringify(model);
  }

  window.showSetupPhase1 = function() {
    document.getElementById('setupPhase1').style.display = 'block';
    document.getElementById('setupPhase2').style.display = 'none';
    document.getElementById('setupPhase3').style.display = 'none';
    // Reset button highlights
    document.querySelectorAll('.runtime-pick').forEach(b => {
      b.style.borderColor = 'var(--border)';
      b.style.opacity = '1';
    });
  };

  window.redetectRuntimes = function() {
    // Clear the status display and re-probe
    const box = document.getElementById('localInferenceStatus');
    const text = document.getElementById('localInferenceText');
    text.innerHTML = '<span style="color:var(--text-dim)">Re-scanning for local inference runtimes...</span>';
    box.style.display = 'block';

    send('detect_local_inference');
  };

  // Called when re-detection finds a runtime with models → hide assistant
  // Called when re-detection finds a runtime without models → show phase 3
  function updateSetupAssistantAfterDetect(data) {
    const runtimes = data.runtimes || [];
    const available = data.available || false;
    const allModels = data.models || [];
    const sa = document.getElementById('setupAssistant');

    if (available && allModels.length > 0) {
      // Full success — runtime + models found. Hide assistant.
      sa.style.display = 'none';
    } else if (available && allModels.length === 0) {
      // Runtime running but no models — show model recommendation (phase 3)
      sa.style.display = 'block';
      document.getElementById('setupPhase1').style.display = 'none';
      document.getElementById('setupPhase2').style.display = 'none';
      document.getElementById('setupPhase3').style.display = 'block';

      // Try to load model rec from the last setup_guidance, or request fresh
      const cmdEl = document.getElementById('setupCommands');
      let model;
      try { model = JSON.parse(cmdEl.dataset.modelRec || '{}'); } catch(e) { model = {}; }

      if (model && model.model_id) {
        populateModelRecommendation(model);
      } else {
        // Request fresh guidance to get model recommendation
        const rtName = runtimes[0] ? runtimes[0].name.toLowerCase().replace(' ', '-') : 'ollama';
        send('get_setup_guidance', { runtime: rtName });
      }
    }
    // If not available, the showLocalInferenceStatus already handles showing the assistant
  }

  function populateModelRecommendation(model) {
    const titleEl = document.getElementById('modelRecTitle');
    titleEl.innerHTML = `Now pull a model. Based on your hardware, we recommend:`;

    // Source attribution line — show where this recommendation comes from
    let sourceHtml = '';
    if (model.source_url) {
      sourceHtml = `<div style="font-size:0.65rem; color:var(--text-dim); margin-top:0.35rem; border-top:1px solid var(--border); padding-top:0.3rem">` +
        `<a href="${escapeHtml(model.source_url)}" target="_blank" style="color:var(--accent); text-decoration:none">model card ↗</a>`;
      if (model.last_verified) {
        sourceHtml += ` · verified ${escapeHtml(model.last_verified)}`;
      }
      sourceHtml += `</div>`;
    }

    const primaryEl = document.getElementById('modelRecPrimary');
    primaryEl.innerHTML =
      `<div style="display:flex; justify-content:space-between; align-items:baseline">` +
      `<strong style="font-size:0.85rem">${escapeHtml(model.display_name)}</strong>` +
      `<span style="font-size:0.68rem; color:var(--text-dim)">${escapeHtml(model.size)}</span>` +
      `</div>` +
      `<p style="font-size:0.75rem; color:var(--text-dim); margin:0.25rem 0 0 0; line-height:1.5">${escapeHtml(model.rationale)}</p>` +
      sourceHtml;

    // Pull command
    const cmdEl = document.getElementById('modelRecCommand');
    cmdEl.innerHTML = `<div style="margin:0.15rem 0"><span style="color:var(--accent)">$</span> <code>${escapeHtml(model.pull_command)}</code></div>`;

    // Alternative model
    if (model.alternative) {
      const alt = model.alternative;
      const altEl = document.getElementById('modelRecAlt');
      altEl.style.display = 'block';

      let altSourceHtml = '';
      if (alt.source_url) {
        altSourceHtml = ` · <a href="${escapeHtml(alt.source_url)}" target="_blank" style="color:var(--accent); text-decoration:none; font-size:0.62rem">model card ↗</a>`;
      }

      document.getElementById('modelRecAltCard').innerHTML =
        `<div style="display:flex; justify-content:space-between; align-items:baseline">` +
        `<strong style="font-size:0.78rem">${escapeHtml(alt.display_name)}</strong>` +
        `<span style="font-size:0.68rem; color:var(--text-dim)">${escapeHtml(alt.size)}${altSourceHtml}</span>` +
        `</div>` +
        `<p style="font-size:0.72rem; color:var(--text-dim); margin:0.15rem 0 0 0; line-height:1.4">${escapeHtml(alt.rationale)}</p>` +
        `<div style="font-size:0.72rem; margin-top:0.25rem"><span style="color:var(--accent)">$</span> <code>${escapeHtml(alt.pull_command)}</code></div>`;
    }
  }

  // Track current model being pulled for the pull-and-continue flow
  let currentPullModelId = null;
  let currentPullRuntime = null;

  window.startModelPull = function() {
    // Get model info from the stored recommendation
    const cmdEl = document.getElementById('setupCommands');
    let model;
    try { model = JSON.parse(cmdEl.dataset.modelRec || '{}'); } catch(e) { model = {}; }

    if (!model || !model.model_id) return;

    currentPullModelId = model.model_id;
    currentPullRuntime = 'ollama'; // TODO: track from setup guidance

    // Disable the button to prevent double-pulls
    const btn = document.getElementById('pullAndContinueBtn');
    btn.disabled = true;
    btn.textContent = 'Starting download...';

    send('start_model_pull', {
      model_id: model.model_id,
      runtime: currentPullRuntime,
    });
  };

  function showModelPullStatus(data) {
    const statusEl = document.getElementById('modelPullStatus');
    const msgEl = document.getElementById('modelPullMessage');
    const actionsEl = document.getElementById('modelPullActions');

    statusEl.style.display = 'block';

    if (data.error) {
      // Pull failed — show the manual command
      msgEl.innerHTML =
        `<span style="color:var(--yellow)">⚠</span> ${escapeHtml(data.message)}`;
      // Re-enable the button
      const btn = document.getElementById('pullAndContinueBtn');
      btn.disabled = false;
      btn.textContent = 'Pull model & continue';
    } else {
      // Pull started successfully — show status and enable continue
      msgEl.innerHTML =
        `<span style="color:var(--green)">✓</span> <span style="color:var(--green)">${escapeHtml(data.message)}</span>`;

      // Replace action buttons with a "Continue" that moves on + optional notification
      actionsEl.innerHTML =
        `<button class="btn" data-action="goDiscover" style="font-size:0.75rem; padding:0.4rem 0.8rem">` +
        `Continue onboarding →</button>` +
        `<label style="font-size:0.72rem; color:var(--text-dim); display:flex; align-items:center; gap:0.35rem; cursor:pointer">` +
        `<input type="checkbox" id="notifyOnModelReady" checked style="accent-color:var(--accent)">` +
        `Notify me when the model is ready</label>`;
    }
  }

  // ── Step 4 → 5: Inference → Discover ──────────────────
  window.goDiscover = function() {
    // If a model pull is in progress, store notification preference
    if (currentPullModelId) {
      const notifyBox = document.getElementById('notifyOnModelReady');
      const wantsNotify = notifyBox ? notifyBox.checked : false;
      send('set_inference_posture', {
        posture: inferencePosture || 'mixed',
        model_pulling: currentPullModelId,
        notify_when_ready: wantsNotify,
      });
    }
    send('vault_check');
    goStep(5);
  };

  // ── Step 5: Scan ────────────────────────────────────────
  window.runScan = function() {
    const path = document.getElementById('scanPath').value.trim() || '~/projects';
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanBtn').textContent = 'Scanning...';
    document.getElementById('scanTerm').style.display = 'block';
    document.getElementById('scanTerm').innerHTML = '';
    document.getElementById('scanResultsList').innerHTML = '';
    discoveredTools = [];

    send('scan', { path });
  };

  function addScanResult(data) {
    discoveredTools.push(data);

    const list = document.getElementById('scanResultsList');
    const div = document.createElement('div');
    div.className = 'card';
    div.style.padding = '0.75rem 1rem';

    let status;
    if (data.status === 'has_plaintext') {
      status = `<span style="color:var(--yellow)">⚠ ${data.found_count} plaintext credential(s)</span>`;
    } else if (data.status === 'configured' || data.status === 'ready') {
      status = '<span style="color:var(--green)">✓ configured</span>';
    } else {
      status = '<span style="color:var(--text-dim)">○ unconfigured</span>';
    }

    div.innerHTML = `<div style="display:flex; justify-content:space-between; align-items:center">
      <strong style="font-size:0.85rem">${escapeHtml(data.tool_name)}</strong>
      <span style="font-size:0.75rem">${status}</span>
    </div>`;

    list.appendChild(div);
    document.getElementById('scanResults').style.display = 'block';
  }

  function showScanComplete(data) {
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('scanBtn').textContent = 'Scan';
    document.getElementById('scanSummary').textContent =
      `${data.tool_count} tool(s) found · ${data.unique_providers} unique provider(s)`;
    document.getElementById('scanNext').style.display = 'flex';

    // Credential cards now built by catalog response in step 6
  }

  // ── Step 6: Credentials (catalog-driven) ────────────────
  let providerCatalog = []; // Full catalog from server

  const categoryLabels = {
    llm: 'LLM / Foundation Models',
    embedding: 'Embedding',
    platform: 'Cloud Platforms',
    aggregator: 'Aggregators',
    search: 'Search / Tools',
  };

  function showProviderCatalog(data) {
    providerCatalog = data.providers || [];
    const detected = providerCatalog.filter(p => p.detected);
    const undetected = providerCatalog.filter(p => !p.detected);

    // ── Detected section ──
    const detectedContainer = document.getElementById('detectedCards');
    const detectedSection = document.getElementById('detectedProviders');
    detectedContainer.innerHTML = '';

    if (detected.length > 0) {
      detectedSection.style.display = 'block';
      detected.forEach(p => {
        detectedContainer.appendChild(buildProviderCard(p, true));
      });
    }

    // ── Full catalog section ──
    // Collapsed if detected providers exist (user has something to focus on);
    // expanded if nothing was detected (catalog IS the step content).
    const catalogContainer = document.getElementById('catalogCards');
    const catalogSection = document.getElementById('catalogProviders');
    const catalogToggle = document.getElementById('catalogToggle');
    catalogContainer.innerHTML = '';
    document.getElementById('catalogCount').textContent = undetected.length;

    if (undetected.length > 0) {
      catalogSection.style.display = 'block';

      if (detected.length > 0) {
        // Detected providers shown above — keep catalog collapsed
        catalogContainer.style.display = 'none';
        catalogToggle.textContent = '▸';
        document.getElementById('catalogLabel').textContent = 'More providers';
      } else {
        // Nothing detected — expand catalog so the step isn't empty
        catalogContainer.style.display = 'block';
        catalogToggle.textContent = '▾';
        document.getElementById('catalogLabel').textContent = 'Providers';
      }

      // Group by category
      const byCategory = {};
      undetected.forEach(p => {
        const cat = p.profile?.category || p.category || 'llm';
        if (!byCategory[cat]) byCategory[cat] = [];
        byCategory[cat].push(p);
      });

      const categoryOrder = ['llm', 'embedding', 'platform', 'aggregator', 'search'];
      categoryOrder.forEach(cat => {
        if (!byCategory[cat]) return;
        const label = categoryLabels[cat] || cat;
        const heading = document.createElement('div');
        heading.style.cssText = 'font-size:0.75rem; color:var(--text-dim); margin:1rem 0 0.4rem; text-transform:uppercase; letter-spacing:0.04em';
        heading.textContent = label;
        catalogContainer.appendChild(heading);
        byCategory[cat].forEach(p => {
          catalogContainer.appendChild(buildProviderCard(p, false));
        });
      });
    } else if (detected.length === 0) {
      // No providers at all (catalog failed to load?)
      catalogSection.style.display = 'block';
      catalogContainer.style.display = 'block';
      catalogContainer.innerHTML = '<p style="font-size:0.82rem; color:var(--text-dim)">Provider catalog unavailable. You can add credentials later with <code>zp configure vault-add</code>.</p>';
    }

    // ── Mark already-stored credentials from vault ──
    // The server includes stored_refs (e.g. ["anthropic/api_key", "openai/api_key"])
    // so we can restore checkmarks after WS reconnect or page refresh.
    const storedRefs = data.stored_refs || [];
    if (storedRefs.length > 0) {
      // Extract provider IDs from vault refs (format: "provider_id/var_name")
      const storedProviders = new Set(storedRefs.map(r => r.split('/')[0]));
      storedProviders.forEach(providerId => {
        const card = document.getElementById(`cred-${providerId}`);
        if (card && !card.classList.contains('stored')) {
          card.classList.add('stored');
          const input = card.querySelector('input');
          if (input) {
            input.value = '••••••';
            input.disabled = true;
          }
          const btn = card.querySelector('.store-btn');
          if (btn) {
            btn.textContent = '✓';
            btn.disabled = true;
          }
        }
      });
      credentialsStored = Math.max(credentialsStored, storedRefs.length);
    }

    updateCredentialSummary();
  }

  function buildProviderCard(provider, isDetected) {
    const p = provider.profile || provider;
    const id = p.id;
    const vaultRef = `${id}/api_key`;

    // Find tools from scan that need this provider
    const toolNames = discoveredTools
      .filter(t => (t.provider_vars || t.needed_vars || []).some(v => {
        return (p.env_patterns || []).some(pattern => v === pattern);
      }))
      .map(t => t.tool_name);

    const div = document.createElement('div');
    div.className = 'credential-card' + (isDetected ? ' detected' : '');
    div.id = `cred-${id}`;

    let metaHtml = '';
    if (isDetected && provider.detected_vars && provider.detected_vars.length) {
      metaHtml += `<div style="font-size:0.72rem; color:var(--green); margin-bottom:0.3rem">✓ Found: ${provider.detected_vars.map(v => escapeHtml(v)).join(', ')}</div>`;
    }
    if (toolNames.length) {
      metaHtml += `<div class="used-by">Used by: ${toolNames.map(t => escapeHtml(t)).join(', ')}</div>`;
    }
    if (p.coverage) {
      metaHtml += `<div style="font-size:0.72rem; color:var(--accent); margin-bottom:0.3rem; font-style:italic">${escapeHtml(p.coverage)}</div>`;
    }
    if (p.key_hint) {
      metaHtml += `<div style="font-size:0.72rem; color:var(--text-dim)">${escapeHtml(p.key_hint)}</div>`;
    }

    let sourceHtml = '';
    if (p.source_url) {
      sourceHtml = `<div style="font-size:0.68rem; color:var(--text-dim); margin-top:0.3rem">`;
      sourceHtml += `<a href="${escapeHtml(p.source_url)}" target="_blank" style="color:var(--accent); text-decoration:none">docs ↗</a>`;
      if (p.last_verified) {
        sourceHtml += ` · verified ${escapeHtml(p.last_verified)}`;
      }
      sourceHtml += `</div>`;
    }

    div.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:baseline">
        <div class="provider">${escapeHtml(p.name)}</div>
        ${p.key_url ? `<a class="help-link" href="${escapeHtml(p.key_url)}" target="_blank" style="font-size:0.75rem; color:var(--accent); text-decoration:none">get key ↗</a>` : ''}
      </div>
      ${metaHtml}
      <div class="input-row">
        <input type="password" id="cred-input-${escapeHtml(id)}" placeholder="${escapeHtml(p.env_patterns?.[0] || 'API Key')}">
        <button class="store-btn" data-action="storeCred" data-cred-id="${escapeHtml(id)}" data-vault-ref="${escapeHtml(vaultRef)}">Store</button>
      </div>
      ${sourceHtml}
    `;
    return div;
  }

  window.toggleCatalog = function() {
    const cards = document.getElementById('catalogCards');
    const toggle = document.getElementById('catalogToggle');
    if (cards.style.display === 'none') {
      cards.style.display = 'block';
      toggle.textContent = '▾';
    } else {
      cards.style.display = 'none';
      toggle.textContent = '▸';
    }
  };

  // Track pending validation requests — provider → raw value (held briefly for validation)
  let pendingValidations = {};

  window.storeCred = function(provider, vaultRef) {
    const input = document.getElementById(`cred-input-${provider}`);
    if (!input) {
      console.error('storeCred: input not found for', provider);
      return;
    }
    const value = input.value.trim();
    if (!value) {
      // Flash the input to indicate it's empty
      input.style.borderColor = 'var(--accent)';
      input.placeholder = 'Paste your API key first';
      setTimeout(() => { input.style.borderColor = ''; }, 1500);
      return;
    }

    // Visual feedback: button shows sending state
    const card = document.getElementById(`cred-${provider}`);
    const btn = card ? card.querySelector('.store-btn') : null;
    if (btn) {
      btn.textContent = '...';
      btn.disabled = true;
    }

    // Cache value for post-store validation
    pendingValidations[provider] = { value, vaultRef };

    // send() now queues if WS is reconnecting — message will flush on reconnect
    send('vault_store', { vault_ref: vaultRef, value });

    // Safety timeout: if no credential_stored event in 8s, re-enable button
    setTimeout(() => {
      if (btn && btn.textContent === '...') {
        btn.textContent = 'Store';
        btn.disabled = false;
      }
    }, 8000);
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
            <span class="found-provider-name">${escapeHtml(provider)}</span>
            ${hasConflict ? '<span style="font-size:0.68rem; color:var(--yellow); margin-left:0.5rem">⚠ conflicting values</span>' : ''}
          </div>
          <div class="priority-controls">
            <button class="priority-btn" data-action="moveProviderUp" data-provider="${escapeHtml(provider)}" title="Move up">▲</button>
            <button class="priority-btn" data-action="moveProviderDown" data-provider="${escapeHtml(provider)}" title="Move down">▼</button>
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
              <input type="radio" name="${escapeHtml(radioName)}" value="${vi}" ${isSelected ? 'checked' : ''}
                     data-action="select-found-cred" data-provider="${escapeHtml(provider)}" data-value-index="${vi}">
              <span class="found-var-name">${escapeHtml(v.var_name)}</span>
              <span class="found-masked-value">${escapeHtml(v.masked_value)}</span>
              <span class="found-source-tag">${escapeHtml(sources)}</span>
            </div>
          `;
        } else {
          // Single value — just show it with checkbox to include/exclude
          valuesHtml += `
            <div class="found-value-row">
              <input type="checkbox" checked data-action="toggle-found-cred" data-provider="${escapeHtml(provider)}" data-value-index="${vi}"
                     style="accent-color:var(--accent)">
              <span class="found-var-name">${escapeHtml(v.var_name)}</span>
              <span class="found-masked-value">${escapeHtml(v.masked_value)}</span>
              <span class="found-source-tag">${escapeHtml(sources)}</span>
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
  }

  function markCredentialStored(data) {
    credentialsStored = data.total_stored || credentialsStored + 1;

    // Find the card by vault_ref
    const provider = (data.vault_ref || '').split('/')[0];
    const card = document.getElementById(`cred-${provider}`);
    if (card) {
      card.classList.add('stored');
      const input = card.querySelector('input');
      if (input) {
        input.value = data.masked_value || '••••••';
        input.disabled = true;
      }
      const btn = card.querySelector('.store-btn');
      if (btn) {
        btn.textContent = '✓';
        btn.disabled = true;
      }

      // Show "checking..." validation badge
      let badge = card.querySelector('.validation-badge');
      if (!badge) {
        badge = document.createElement('div');
        badge.className = 'validation-badge checking';
        card.appendChild(badge);
      }
      badge.className = 'validation-badge checking';
      badge.textContent = 'validating...';
    }

    // Trigger instant validation if we have the cached value
    if (pendingValidations[provider]) {
      const pending = pendingValidations[provider];
      const varName = (pending.vaultRef || '').split('/')[1] || 'api_key';
      send('validate_credential', {
        provider_id: provider,
        var_name: varName,
        value: pending.value,
      });
      // Clear cached value immediately (don't hold secrets longer than needed)
      delete pendingValidations[provider];
    }

    updateCredentialSummary();
  }

  function updateCredentialSummary() {
    const summary = document.getElementById('credentialSummary');
    const total = document.querySelectorAll('.credential-card').length;
    if (total === 0) {
      summary.textContent = '';
      return;
    }
    summary.textContent = `${credentialsStored} of ${total} credential(s) stored`;
  }

  // ── Credential Validation ──────────────────────────────

  // Validation results indexed by provider_id
  let validationResults = {};

  function handleCredentialValidated(data) {
    const provider = data.provider_id;
    validationResults[provider] = data;

    // Update the credential card's validation badge
    const card = document.getElementById(`cred-${provider}`);
    if (card) {
      let badge = card.querySelector('.validation-badge');
      if (!badge) {
        badge = document.createElement('div');
        badge.className = 'validation-badge';
        card.appendChild(badge);
      }

      const icons = { valid: '✓', invalid: '✗', unreachable: '⚠', unsupported: '○', skipped: '–' };
      const icon = icons[data.status] || '?';
      badge.className = `validation-badge ${data.status}`;
      badge.innerHTML = `${icon} ${data.detail}`;
      if (data.latency_ms) {
        badge.innerHTML += ` <span style="opacity:0.6">${data.latency_ms}ms</span>`;
      }

      // Also update card border hint
      if (data.status === 'valid') {
        card.style.borderColor = 'var(--green)';
      } else if (data.status === 'invalid') {
        card.style.borderColor = 'var(--red)';
      }
    }

    // Update the Step 6 validation summary
    updateValidationStatus();
  }

  function updateValidationStatus() {
    const container = document.getElementById('validationStatusCards');
    const section = document.getElementById('validationStatus');
    if (!container) return;

    const results = Object.values(validationResults);
    if (results.length === 0) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';
    container.innerHTML = '';

    const statusIcons = { valid: '✓', invalid: '✗', unreachable: '⚠', unsupported: '○', skipped: '–' };
    const statusColors = {
      valid: 'var(--green)',
      invalid: 'var(--red)',
      unreachable: 'var(--yellow)',
      unsupported: 'var(--text-dim)',
      skipped: 'var(--text-dim)',
    };

    results.forEach(r => {
      const div = document.createElement('div');
      div.className = 'health-check-row';
      div.innerHTML = `
        <span class="provider-name">${r.provider_name || r.provider_id}</span>
        <span class="check-status">
          <span class="check-detail">${r.detail || ''}</span>
          <span style="color:${statusColors[r.status] || 'var(--text-dim)'}; font-weight:600">${statusIcons[r.status] || '?'} ${r.status}</span>
        </span>
      `;
      container.appendChild(div);
    });
  }

  function handleValidationSweep(data) {
    const section = document.getElementById('configHealthCheck');
    const resultsDiv = document.getElementById('healthCheckResults');
    const statusEl = document.getElementById('healthCheckStatus');

    if (!section) return;
    section.style.display = 'block';
    resultsDiv.innerHTML = '';

    const results = data.results || [];

    if (results.length === 0) {
      statusEl.textContent = 'no credentials to check';
      statusEl.style.color = 'var(--text-dim)';
      resultsDiv.innerHTML = '<p style="font-size:0.78rem; color:var(--text-dim)">No credentials stored in vault yet.</p>';
      return;
    }

    // Summary line
    const summary = [];
    if (data.valid > 0) summary.push(`${data.valid} valid`);
    if (data.invalid > 0) summary.push(`${data.invalid} invalid`);
    if (data.unreachable > 0) summary.push(`${data.unreachable} unreachable`);
    if (data.unsupported > 0) summary.push(`${data.unsupported} no probe`);
    statusEl.textContent = summary.join(' · ');
    statusEl.style.color = data.invalid > 0 ? 'var(--red)' : (data.valid > 0 ? 'var(--green)' : 'var(--text-dim)');

    const statusIcons = { valid: '✓', invalid: '✗', unreachable: '⚠', unsupported: '○', skipped: '–' };
    const statusColors = {
      valid: 'var(--green)',
      invalid: 'var(--red)',
      unreachable: 'var(--yellow)',
      unsupported: 'var(--text-dim)',
      skipped: 'var(--text-dim)',
    };

    results.forEach(r => {
      const div = document.createElement('div');
      div.className = 'health-check-row';
      div.innerHTML = `
        <span class="provider-name">${r.provider_name || r.provider_id}</span>
        <span class="check-status">
          <span class="check-detail">${r.detail || ''} ${r.latency_ms ? `(${r.latency_ms}ms)` : ''}</span>
          <span style="color:${statusColors[r.status] || 'var(--text-dim)'}; font-weight:600">${statusIcons[r.status] || '?'} ${r.status}</span>
        </span>
      `;
      resultsDiv.appendChild(div);

      // Also update per-provider validation results for Step 6
      validationResults[r.provider_id] = r;
    });
  }

  // ── Step 7: Configure ───────────────────────────────────

  let configResults = {};  // tool_name -> { status, missing } — persists across step navigation
  let configDone = false;

  const toolIcons = {
    'ember': '🔥', 'pentagi': '🛡️',
    'agent-zero': '🧠', 'autogpt': '⚡', 'langchain': '🔗',
    'crewai': '👥', 'zp-hedera': '⛓️', 'ironclaw': '🦀', 'deploy': '🚀',
  };

  function getToolIcon(name) {
    return toolIcons[name] || toolIcons[name.toLowerCase()] || '🔧';
  }

  // Find a card by fuzzy-matching the configure engine's tool name
  // against the scan's directory names (case-insensitive, substring)
  function findCardForTool(configName) {
    const lower = configName.toLowerCase().replace(/[^a-z0-9]/g, '');
    const cards = document.querySelectorAll('.tool-config-card');
    for (const card of cards) {
      const cardName = (card.dataset.toolName || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      if (cardName === lower || cardName.includes(lower) || lower.includes(cardName)) {
        return card;
      }
    }
    return null;
  }

  function applyCardState(card, status, missing) {
    card.classList.remove('securing');
    const hasGenesis = !!(genesisData && genesisData.genesis_public_key);
    if (status === 'governed') {
      card.classList.add('governed');
      card.querySelector('.tool-status').textContent = hasGenesis
        ? 'governed · .env written · genesis-bound'
        : 'configured · .env written · no genesis anchor';
      card.querySelector('.tool-badge').textContent = hasGenesis ? '✓ governed' : '⚠ unanchored';
      card.querySelector('.tool-badge').style.background = hasGenesis ? '' : 'rgba(221,168,85,0.15)';
      card.querySelector('.tool-badge').style.color = hasGenesis ? '' : 'var(--yellow)';
    } else if (status === 'skipped') {
      card.classList.add('skipped');
      card.style.borderColor = 'var(--yellow)';
      card.style.background = 'rgba(221,168,85,0.04)';
      card.querySelector('.tool-status').textContent = 'skipped · missing credentials';
      card.querySelector('.tool-badge').textContent = 'needs keys';
      card.querySelector('.tool-badge').style.background = 'rgba(221,168,85,0.15)';
      card.querySelector('.tool-badge').style.color = 'var(--yellow)';
    }
  }

  function buildConfigToolCards() {
    const grid = document.getElementById('configToolCards');
    grid.innerHTML = '';

    discoveredTools.forEach((tool) => {
      const icon = getToolIcon(tool.tool_name);
      const card = document.createElement('div');
      card.className = 'tool-config-card';
      card.dataset.toolName = tool.tool_name;

      // If we already have results (revisiting step), show final state
      const existing = findConfigResult(tool.tool_name);
      if (existing) {
        card.innerHTML = `
          <div class="tool-icon">${icon}</div>
          <div class="tool-info">
            <div class="tool-name">${tool.tool_name}</div>
            <div class="tool-status">...</div>
          </div>
          <div class="tool-badge">...</div>
        `;
        grid.appendChild(card);
        applyCardState(card, existing.status, existing.missing);
      } else {
        card.innerHTML = `
          <div class="tool-icon">${icon}</div>
          <div class="tool-info">
            <div class="tool-name">${tool.tool_name}</div>
            <div class="tool-status">${tool.status === 'has_plaintext' ? 'plaintext credentials found' : tool.status === 'unconfigured' ? 'unconfigured · no .env' : 'pending'}</div>
          </div>
          <div class="tool-badge">waiting</div>
        `;
        grid.appendChild(card);
      }
    });

    if (discoveredTools.length === 0) {
      grid.innerHTML = '<p style="color:var(--text-dim); font-size:0.82rem">No tools discovered yet — complete Step 5 first.</p>';
    }

    // If configure already ran, show the continue button
    if (configDone) {
      document.getElementById('configureNext').style.display = 'flex';
      document.getElementById('configureTerm').style.display = 'block';
    }
  }

  function findConfigResult(toolName) {
    const lower = toolName.toLowerCase().replace(/[^a-z0-9]/g, '');
    for (const [key, val] of Object.entries(configResults)) {
      const keyLower = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (keyLower === lower || keyLower.includes(lower) || lower.includes(keyLower)) {
        return val;
      }
    }
    return null;
  }

  let configEventQueue = [];
  let configProcessing = false;

  window.runConfigure = function() {
    // Reset state for a fresh run (allows re-running)
    configDone = false;
    configResults = {};
    configEventQueue = [];
    configProcessing = false;

    buildConfigToolCards();

    const proxy = document.getElementById('proxyEnabled').checked;
    document.getElementById('configureBtn').disabled = true;
    document.getElementById('configureBtn').textContent = 'Securing...';
    document.getElementById('configureNext').style.display = 'none';
    document.getElementById('configureTerm').style.display = 'block';
    document.getElementById('configureTerm').innerHTML = '';

    // Stagger the "securing" shimmer onto each card
    const cards = document.querySelectorAll('.tool-config-card');
    cards.forEach((card, i) => {
      setTimeout(() => {
        if (!card.classList.contains('governed') && !card.classList.contains('skipped')) {
          card.classList.add('securing');
          card.querySelector('.tool-status').textContent = 'securing · routing through governance proxy...';
          card.querySelector('.tool-badge').textContent = 'securing';
        }
      }, i * 400);
    });

    // Delay sending so the user sees the shimmer animation start
    setTimeout(() => {
      send('configure', { proxy, proxy_port: 3000 });
    }, cards.length * 400 + 300);
  };

  function queueConfigEvent(handler) {
    configEventQueue.push(handler);
    if (!configProcessing) processConfigQueue();
  }

  function processConfigQueue() {
    if (configEventQueue.length === 0) { configProcessing = false; return; }
    configProcessing = true;
    const next = configEventQueue.shift();
    next();
    setTimeout(processConfigQueue, 800);
  }

  function markToolConfigured(data) {
    const name = data.tool_name || '';
    const status = data.status || 'governed';
    const missing = data.missing || 0;

    // Save result for state persistence
    configResults[name] = { status, missing };

    queueConfigEvent(() => {
      const card = findCardForTool(name);
      if (!card) return;
      applyCardState(card, status, missing);
    });
  }

  function showConfigureComplete(data) {
    configDone = true;

    queueConfigEvent(() => {
      // Any cards still in "securing" that didn't get an event — mark as unknown (don't assume success)
      document.querySelectorAll('.tool-config-card.securing').forEach(card => {
        card.classList.remove('securing');
        card.querySelector('.tool-status').textContent = 'no response — check manually';
        card.querySelector('.tool-badge').textContent = '? unknown';
        card.querySelector('.tool-badge').style.background = 'rgba(136,136,160,0.15)';
        card.querySelector('.tool-badge').style.color = 'var(--text-dim)';
      });

      document.getElementById('configureBtn').textContent = 'Secure & Configure';
      document.getElementById('configureBtn').disabled = false;

      // Auto-trigger preflight: pull images, install deps, validate launch chain.
      // Terminal output streams in real-time so the user sees progress.
      ws.send(JSON.stringify({ action: 'preflight' }));
    });
  }

  // ── Step 8: Launch Pad ──────────────────────────────────
  function populateSummary() {
    // Operator identity bar
    if (genesisData) {
      const name = genesisData.operator || '—';
      document.getElementById('sumOperator').textContent = name;
      document.getElementById('sumAvatarInitial').textContent = name.charAt(0).toUpperCase();
      const pub = genesisData.genesis_public_key || '';
      document.getElementById('sumGenesis').textContent = pub ? pub.substring(0, 16) + '...' : '—';

      const modeLabels = {
        touch_id: '🔒 Touch ID', fingerprint: '🔒 Fingerprint', face_enroll: '🔒 Face',
        windows_hello: '🔒 Windows Hello',
        yubi_key: '🔑 YubiKey', ledger: '🔑 Ledger', trezor: '🔑 Trezor', only_key: '🔑 OnlyKey',
        login_password: '🔑 Password', file_based: '📁 File',
        biometric: '🔒 Biometric',
      };
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
      'ember': '🔥', 'pentagi': '🛡️', 'agent-zero': '🧠',
      'autogpt': '⚡', 'langchain': '🔗', 'crewai': '👥',
    };

    discoveredTools.forEach(tool => {
      const icon = toolIcons[tool.tool_name.toLowerCase()] || '🔧';
      const tile = document.createElement('div');
      tile.className = 'launchpad-tile';

      // Use actual configure results if available
      const result = configResults[tool.tool_name] || configResults[tool.tool_name.toLowerCase()];
      const isGoverned = result && result.status === 'governed';
      const isSkipped = result && result.status === 'skipped';
      const isTimeout = result && result.status === 'unknown';
      const hasGenesis = !!(genesisData && genesisData.genesis_public_key);

      let statusText, badgeHtml, healthColor;
      if (isGoverned && hasGenesis) {
        statusText = 'governed · .env written';
        badgeHtml = '<div class="governance-badge">✓ genesis-bound</div>';
        healthColor = '';
      } else if (isGoverned && !hasGenesis) {
        statusText = 'configured · no genesis anchor';
        badgeHtml = '<div class="governance-badge" style="background:rgba(221,168,85,0.15); color:var(--yellow)">unanchored</div>';
        healthColor = 'background: var(--yellow)';
      } else if (isSkipped) {
        statusText = 'skipped · needs credentials';
        badgeHtml = '<div class="governance-badge" style="background:rgba(221,168,85,0.15); color:var(--yellow)">needs setup</div>';
        healthColor = 'background: var(--yellow)';
      } else if (isTimeout) {
        statusText = 'no response · check manually';
        badgeHtml = '<div class="governance-badge" style="background:rgba(136,136,160,0.15); color:var(--text-dim)">unknown</div>';
        healthColor = 'background: var(--text-dim)';
      } else {
        statusText = tool.status === 'has_plaintext' ? 'has credentials · not yet governed' : 'unconfigured';
        badgeHtml = '<div class="governance-badge" style="background:rgba(136,136,160,0.15); color:var(--text-dim)">pending</div>';
        healthColor = 'background: var(--text-dim)';
      }

      tile.innerHTML = `
        <div class="tile-health" style="${healthColor}"></div>
        <div class="tile-icon">${icon}</div>
        <div class="tile-name">${tool.tool_name}</div>
        <div class="tile-status">${statusText}</div>
        ${badgeHtml}
      `;
      tile.onclick = () => {
        alert('Dashboard for ' + tool.tool_name + ' coming soon');
      };
      grid.appendChild(tile);
    });

    // ZeroPoint system tile — only claim "core" if genesis is established
    const zpTile = document.createElement('div');
    zpTile.className = 'launchpad-tile';
    const zpHasGenesis = !!(genesisData && genesisData.genesis_public_key);
    zpTile.innerHTML = `
      <div class="tile-health" style="${zpHasGenesis ? '' : 'background: var(--yellow)'}"></div>
      <div class="tile-icon" style="background:rgba(126,184,218,0.15)">⚙️</div>
      <div class="tile-name">ZeroPoint</div>
      <div class="tile-status">${zpHasGenesis ? 'governance engine · genesis active' : 'governance engine · no genesis'}</div>
      <div class="governance-badge" style="background:rgba(126,184,218,0.1); color:var(--accent)">${zpHasGenesis ? 'core' : 'incomplete'}</div>
    `;
    zpTile.onclick = () => {
      window.location.href = '/';
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
  }

  // ── Narration (auto-play) ────────────────────────────────
  // Narration files expected at /assets/narration/onboard/
  const stepNarrations = {
    0: 'onboard-welcome.mp3',
    1: 'onboard-sovereignty.mp3',
    2: 'onboard-genesis.mp3',
    3: 'onboard-vault.mp3',
    4: 'onboard-inference.mp3',
    5: 'onboard-discover.mp3',
    6: 'onboard-credentials.mp3',
    7: 'onboard-configure.mp3',
    8: 'onboard-complete.mp3',
  };

  const stepLabels = {
    0: 'The old model vs. the new model',
    1: 'Why your body is the credential',
    2: 'What it means to create your own root of trust',
    3: 'How your vault protects your credentials',
    4: 'Where your inference runs — and why it matters',
    5: 'How tool discovery works',
    6: 'Encrypting your keys — and proving they work',
    7: 'Governance with verified credentials',
    8: 'What you\'ve built — and what comes next',
  };

  let isMuted = false;
  let progressInterval = null;

  function showNarrationBar() {
    const bar = document.getElementById('narrationBar');
    // Insert bar at the top of the active step, right after step-header
    const step = document.getElementById('step-' + currentStep);
    if (step) {
      const header = step.querySelector('.step-header');
      if (header && header.nextSibling) {
        step.insertBefore(bar, header.nextSibling);
      } else {
        step.prepend(bar);
      }
    }
    bar.style.display = 'flex';
    document.getElementById('narrateLabel').textContent = stepLabels[currentStep] || 'Narrating...';
  }

  function updateProgress() {
    if (!narrationAudio || !narrationAudio.duration) return;
    const pct = (narrationAudio.currentTime / narrationAudio.duration) * 100;
    document.getElementById('narrateProgress').style.width = pct + '%';
  }

  function startNarration() {
    const file = stepNarrations[currentStep];
    if (!file || isMuted) {
      // Still show the bar even if muted, so user can unmute
      showNarrationBar();
      if (isMuted) {
        document.getElementById('narrateToggle').innerHTML = '&#9654;';
        document.getElementById('narrationBar').classList.remove('playing');
      }
      return;
    }

    if (narrationAudio) {
      narrationAudio.pause();
      clearInterval(progressInterval);
    }

    showNarrationBar();
    document.getElementById('narrateProgress').style.width = '0%';

    narrationAudio = new Audio(`/assets/narration/onboard/${file}`);
    narrationAudio.play().catch(() => {});

    narrationAudio.onended = () => {
      isNarrating = false;
      clearInterval(progressInterval);
      document.getElementById('narrateProgress').style.width = '100%';
      document.getElementById('narrateToggle').innerHTML = '&#9654;';
      document.getElementById('narrationBar').classList.remove('playing');
    };

    narrationAudio.onerror = () => {
      // Audio file not found — hide bar gracefully
      document.getElementById('narrationBar').style.display = 'none';
      isNarrating = false;
    };

    isNarrating = true;
    document.getElementById('narrateToggle').innerHTML = '&#10074;&#10074;';
    document.getElementById('narrationBar').classList.add('playing');

    progressInterval = setInterval(updateProgress, 300);
  }

  function stopNarration() {
    if (narrationAudio) {
      narrationAudio.pause();
      narrationAudio.currentTime = 0;
    }
    clearInterval(progressInterval);
    isNarrating = false;
    const prog = document.getElementById('narrateProgress');
    const tog = document.getElementById('narrateToggle');
    const bar = document.getElementById('narrationBar');
    if (prog) prog.style.width = '0%';
    if (tog) tog.innerHTML = '&#9654;';
    if (bar) bar.classList.remove('playing');
  }

  window.toggleNarration = function() {
    if (isNarrating) {
      stopNarration();
    } else {
      startNarration();
    }
  };

  window.toggleMute = function() {
    isMuted = !isMuted;
    const muteBtn = document.getElementById('narrateMute');
    if (isMuted) {
      muteBtn.innerHTML = '&#x1f507;';
      muteBtn.classList.add('muted');
      muteBtn.title = 'Unmute narration';
      stopNarration();
    } else {
      muteBtn.innerHTML = '&#x1f50a;';
      muteBtn.classList.remove('muted');
      muteBtn.title = 'Mute narration';
      startNarration();
    }
  };

  // ── Event Delegation (CSP-compliant — no inline handlers) ──
  // All interactive elements use data-action attributes instead of onclick.
  // This single listener dispatches to the appropriate handler.
  document.addEventListener('click', function(e) {
    var el = e.target.closest('[data-action]');
    if (!el) return;

    var action = el.dataset.action;

    switch (action) {
      // Step 0
      case 'startOnboard':
        startOnboard();
        break;

      // Step 1: Sovereignty selection
      case 'selectSovereignty':
        selectSovereignty(el.dataset.sovereignty);
        break;
      case 'goGenesis':
        goGenesis();
        break;

      // Step 2: Genesis
      case 'runGenesis':
        runGenesis();
        break;

      // Step navigation
      case 'goStep':
        goStep(parseInt(el.dataset.step, 10));
        break;

      // Step 4: Inference posture
      case 'requestSetupGuidance':
        requestSetupGuidance(el.dataset.runtime);
        break;
      case 'redetectRuntimes':
        redetectRuntimes();
        break;
      case 'showSetupPhase1':
        showSetupPhase1();
        break;
      case 'startModelPull':
        startModelPull();
        break;
      case 'selectPosture':
        selectPosture(el.dataset.posture);
        break;
      case 'goDiscover':
        goDiscover();
        break;

      // Step 5: Scan
      case 'runScan':
        runScan();
        break;

      // Step 6: Credentials
      case 'storeCred':
        storeCred(el.dataset.credId, el.dataset.vaultRef);
        break;
      case 'vaultAllFound':
        vaultAllFound();
        break;
      case 'toggleCatalog':
        toggleCatalog();
        break;
      case 'moveProviderUp':
        moveProviderUp(el.dataset.provider);
        break;
      case 'moveProviderDown':
        moveProviderDown(el.dataset.provider);
        break;

      // Step 7: Configure
      case 'runConfigure':
        runConfigure();
        break;

      // Narration
      case 'toggleNarration':
        toggleNarration();
        break;
      case 'toggleMute':
        toggleMute();
        break;

      // Verification link hover (CSS handles this instead of JS)
      case 'viewVerification':
        // Navigation handled by the <a> href
        break;
    }
  });

  // ── Change event delegation (radios, checkboxes) ─────────
  document.addEventListener('change', function(e) {
    var el = e.target.closest('[data-action]');
    if (!el) return;
    var action = el.dataset.action;
    switch (action) {
      case 'select-found-cred': {
        var provider = el.dataset.provider;
        var vi = parseInt(el.dataset.valueIndex, 10);
        if (typeof selectFoundCred === 'function') selectFoundCred(provider, vi);
        break;
      }
      case 'toggle-found-cred': {
        var provider = el.dataset.provider;
        var vi = parseInt(el.dataset.valueIndex, 10);
        if (typeof toggleFoundCred === 'function') toggleFoundCred(provider, el.checked, vi);
        break;
      }
    }
  });

  // Hover effect for verification link (replaces onmouseover/onmouseout)
  var verifyLink = document.querySelector('[data-action="viewVerification"]');
  if (verifyLink) {
    verifyLink.addEventListener('mouseenter', function() {
      this.style.background = 'rgba(126,184,218,0.1)';
    });
    verifyLink.addEventListener('mouseleave', function() {
      this.style.background = 'none';
    });
  }

  // ── Init ────────────────────────────────────────────────
  connect();

  // Show narration bar after WebSocket has a chance to set the correct step.
  // 600ms > the 300ms goStep delay in the state handler, so the bar appears
  // on the right step even when resuming a session.
  setTimeout(() => showNarrationBar(), 600);

  // Auto-play Step 0 narration on first user interaction
  // (browsers require a user gesture before playing audio)
  function autoplayOnFirstInteraction() {
    startNarration();
    document.removeEventListener('click', autoplayOnFirstInteraction);
    document.removeEventListener('keydown', autoplayOnFirstInteraction);
    document.removeEventListener('touchstart', autoplayOnFirstInteraction);
  }
  document.addEventListener('click', autoplayOnFirstInteraction);
  document.addEventListener('keydown', autoplayOnFirstInteraction);
  document.addEventListener('touchstart', autoplayOnFirstInteraction);

})();
