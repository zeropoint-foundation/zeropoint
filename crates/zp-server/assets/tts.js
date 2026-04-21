/**
 * ZeroPoint — Live TTS Module
 *
 * Speaks arbitrary text through the local Piper TTS server (voice-tuner-server.py).
 * Drop <script src="/assets/tts.js"></script> into any page to get:
 *   - zpTTS.speak(text)        — synthesize & play
 *   - zpTTS.stop()             — stop playback
 *   - zpTTS.isAvailable()      — check if server responds
 *   - A floating "speak" button auto-injected into the page
 *
 * Config: set window.ZP_TTS_CONFIG before loading this script to override defaults.
 */
(function () {
  'use strict';

  const DEFAULT_CONFIG = {
    serverUrl: 'http://localhost:8473',
    voice: 'en_US-ryan-medium',        // primary narrator voice
    lengthScale: '0.7407',             // 1.35x speed
    noiseScale: '0.670',
    noiseW: '0.670',
    sentenceSilence: '0.30',
    // Selector for the content area to read when the floating button is clicked.
    // Defaults to the visible .step element (onboarding), or .container, or body.
    contentSelector: null,
    // If true, inject a floating speak button into the page
    floatingButton: true,
    // Max characters per synthesis request (Piper handles long text fine, but
    // we chunk for responsiveness — first chunk plays while others synthesize)
    chunkSize: 800,
  };

  const cfg = Object.assign({}, DEFAULT_CONFIG, window.ZP_TTS_CONFIG || {});

  // ── State ──────────────────────────────────────────────────────
  let available = null;     // null = unknown, true/false after probe
  let audio = null;         // current HTMLAudioElement
  let queue = [];           // queued audio blob URLs
  let speaking = false;
  let aborted = false;

  // ── Server probe ───────────────────────────────────────────────
  async function probe() {
    try {
      const r = await fetch(cfg.serverUrl + '/health', { signal: AbortSignal.timeout(2000) });
      available = r.ok;
    } catch {
      available = false;
    }
    return available;
  }

  // ── Core synthesis ─────────────────────────────────────────────
  async function synthesize(text) {
    const resp = await fetch(cfg.serverUrl + '/synthesize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text,
        voice_file: cfg.voice,
        length_scale: cfg.lengthScale,
        noise_scale: cfg.noiseScale,
        noise_w: cfg.noiseW,
        sentence_silence: cfg.sentenceSilence,
      }),
    });
    if (!resp.ok) throw new Error(`TTS ${resp.status}`);
    const blob = await resp.blob();
    return URL.createObjectURL(blob);
  }

  // ── Chunker ────────────────────────────────────────────────────
  // Split text at sentence boundaries, keeping chunks under chunkSize.
  function chunkText(text) {
    const sentences = text.match(/[^.!?]+[.!?]+[\s]*/g) || [text];
    const chunks = [];
    let buf = '';
    for (const s of sentences) {
      if (buf.length + s.length > cfg.chunkSize && buf.length > 0) {
        chunks.push(buf.trim());
        buf = '';
      }
      buf += s;
    }
    if (buf.trim()) chunks.push(buf.trim());
    return chunks;
  }

  // ── Playback pipeline ─────────────────────────────────────────
  async function speak(text) {
    stop();
    aborted = false;
    speaking = true;
    updateButton('speaking');

    const chunks = chunkText(text);

    for (let i = 0; i < chunks.length; i++) {
      if (aborted) break;
      try {
        const url = await synthesize(chunks[i]);
        if (aborted) { URL.revokeObjectURL(url); break; }
        await playBlob(url);
        URL.revokeObjectURL(url);
      } catch (e) {
        console.warn('TTS chunk error:', e);
        break;
      }
    }

    speaking = false;
    if (!aborted) updateButton('idle');
  }

  function playBlob(url) {
    return new Promise((resolve, reject) => {
      audio = new Audio(url);
      audio.onended = resolve;
      audio.onerror = reject;
      audio.play().catch(reject);
    });
  }

  function stop() {
    aborted = true;
    if (audio) {
      audio.pause();
      audio.currentTime = 0;
      audio = null;
    }
    queue = [];
    speaking = false;
    updateButton('idle');
  }

  // ── Content extraction ─────────────────────────────────────────
  function getVisibleText() {
    // Priority 1: data-tts-script attribute on the active element
    // This allows pages to provide curated narration scripts instead of
    // raw DOM text (e.g., onboarding steps with explanatory narration).
    const steps = document.querySelectorAll('.step');
    for (const s of steps) {
      if (s.style.display !== 'none' && s.offsetParent !== null) {
        if (s.dataset.ttsScript) return s.dataset.ttsScript;
        return extractText(s);
      }
    }

    // Priority 2: custom selector with data-tts-script check
    if (cfg.contentSelector) {
      const el = document.querySelector(cfg.contentSelector);
      if (el) {
        if (el.dataset.ttsScript) return el.dataset.ttsScript;
        return extractText(el);
      }
    }

    // Fallback: main container or body
    const container = document.querySelector('.container') || document.body;
    if (container.dataset && container.dataset.ttsScript) return container.dataset.ttsScript;
    return extractText(container);
  }

  function extractText(el) {
    // Walk the DOM, skip buttons, inputs, scripts, hidden elements, terminals
    const skip = new Set(['BUTTON', 'INPUT', 'TEXTAREA', 'SELECT', 'SCRIPT', 'STYLE', 'SVG', 'AUDIO', 'VIDEO']);
    const parts = [];

    function walk(node) {
      if (node.nodeType === Node.TEXT_NODE) {
        const t = node.textContent.trim();
        if (t) parts.push(t);
        return;
      }
      if (node.nodeType !== Node.ELEMENT_NODE) return;
      if (skip.has(node.tagName)) return;
      // Skip hidden elements and terminals (code output)
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden') return;
      if (node.classList.contains('terminal')) return;
      if (node.classList.contains('tts-float')) return;
      // Skip step-header (the small "05 — discover" labels)
      if (node.classList.contains('step-header')) return;

      for (const child of node.childNodes) walk(child);
    }

    walk(el);
    return parts.join(' ').replace(/\s+/g, ' ').trim();
  }

  // ── Floating button ────────────────────────────────────────────
  let btn = null;

  function injectButton() {
    if (!cfg.floatingButton) return;

    btn = document.createElement('button');
    btn.className = 'tts-float';
    btn.title = 'Read aloud (Piper TTS)';
    btn.innerHTML = speakerIcon();
    btn.addEventListener('click', handleClick);
    document.body.appendChild(btn);

    // Start hidden until we know the server is up
    btn.style.display = 'none';
    probe().then(ok => {
      if (ok) btn.style.display = 'flex';
    });
  }

  function handleClick() {
    if (speaking) {
      stop();
    } else {
      const text = getVisibleText();
      if (text) speak(text);
    }
  }

  function updateButton(state) {
    if (!btn) return;
    if (state === 'speaking') {
      btn.innerHTML = stopIcon();
      btn.classList.add('active');
      btn.title = 'Stop reading';
    } else {
      btn.innerHTML = speakerIcon();
      btn.classList.remove('active');
      btn.title = 'Read aloud (Piper TTS)';
    }
  }

  // ── Icons ──────────────────────────────────────────────────────
  function speakerIcon() {
    return `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>
      <path d="M15.54 8.46a5 5 0 0 1 0 7.07"/>
      <path d="M19.07 4.93a10 10 0 0 1 0 14.14"/>
    </svg>`;
  }

  function stopIcon() {
    return `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" stroke="none">
      <rect x="6" y="6" width="12" height="12" rx="2"/>
    </svg>`;
  }

  // ── Inject CSS ─────────────────────────────────────────────────
  function injectStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .tts-float {
        position: fixed;
        bottom: 1.5rem;
        right: 1.5rem;
        width: 48px;
        height: 48px;
        border-radius: 50%;
        background: var(--bg-elevated, #111116);
        border: 1px solid var(--rule, #222228);
        color: var(--accent, #7eb8da);
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999;
        transition: all 0.2s ease;
        box-shadow: 0 2px 12px rgba(0,0,0,0.4);
      }
      .tts-float:hover {
        border-color: var(--accent, #7eb8da);
        transform: scale(1.08);
        box-shadow: 0 2px 20px rgba(126,184,218,0.2);
      }
      .tts-float.active {
        background: var(--accent, #7eb8da);
        color: var(--bg, #0a0a0c);
        border-color: var(--accent, #7eb8da);
        animation: tts-pulse 2s ease-in-out infinite;
      }
      @keyframes tts-pulse {
        0%, 100% { box-shadow: 0 2px 12px rgba(126,184,218,0.3); }
        50% { box-shadow: 0 2px 24px rgba(126,184,218,0.5); }
      }
    `;
    document.head.appendChild(style);
  }

  // ── Public API ─────────────────────────────────────────────────
  window.zpTTS = {
    speak,
    stop,
    isAvailable: () => available,
    probe,
    getVisibleText,
    config: cfg,
  };

  // ── Boot ───────────────────────────────────────────────────────
  injectStyles();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectButton);
  } else {
    injectButton();
  }

})();
