/**
 * zp-receipt-chain — Molecular chain visualizer v1
 *
 * Custom element: <zp-receipt-chain>
 * Design: docs/handoffs/chain-viz-v1-foundation-deployment-design-2026-05.md
 * Post-deploy patches: docs/handoffs/chain-viz-v1-render-bugs-investigation-2026-05.md
 *   — ambient-window cap, single-row backbone in ambient mode,
 *     sovereign color shifted from #e8b87f → #ff9d4d so the
 *     heteroatom reads as visually distinct from ceremony,
 *     chain:read filtered out of ambient render.
 *
 * §8 calibration rules are enforced structurally, not by convention.
 * composeViz is deterministic (no LLM). Narration is pre-authored (§9).
 */

// ─── Category & color mapping (§5) ──────────────────────────────────────────

const CATEGORY_PREFIXES = {
  'onboard:':          'ceremony',
  'gate:':             'gate',
  'audit:':            'audit',
  'feedback:':         'operational',
};

const CATEGORY_COLORS = {
  ceremony:    '#d4a574',
  operational: '#7eb8da',
  gate:        '#a890d4',
  audit:       '#7adbc1',
  // Sovereign: deeper amber/orange so the Ω heteroatom reads as
  // visually distinct from ceremony (#d4a574 tan) even at ambient
  // opacity (0.25). The previous #e8b87f peach blended with
  // ceremony at low opacity — verified during 2026-05-21
  // production walkthrough.
  sovereign:   '#ff9d4d',
};

// Claims that exist on the chain for audit purposes but aren't
// director-meaningful events — suppressed from ambient render,
// still surfaced in expanded view (real audit events all the same).
const SUBSTRATE_BOOKKEEPING_CLAIMS = new Set(['chain:read']);

// §8 Rule 3: Pulse intensity from this table only — never interpolated
const PULSE_INTENSITIES = {
  routine:    0.15,
  gate:       0.20,
  audit:      0.25,
  ceremony:   0.40,
  sovereign:  0.85,
};

// §4: operator-pref → attention bounds and expand-on-event ceiling
const PREF_BOUNDS = {
  hidden:  { floor: 'hidden',      ceiling: 'hidden',      expand: 'none' },
  quiet:   { floor: 'ambient',     ceiling: 'ambient',     expand: 'none' },
  default: { floor: 'ambient',     ceiling: 'foreground',  expand: 'sovereign-only' },
  lively:  { floor: 'ambient',     ceiling: 'celebratory', expand: 'any' },
};

const ATTENTION_ORDER = ['hidden', 'ambient', 'foreground', 'celebratory', 'expanded'];

// §9: Pre-authored narration corpus — all phrases fixed at design time
const NARRATION = {
  'onboard:start':
    "Your first atom — the ceremony starting. It's already bonded back to the foundation's Genesis.",
  'onboard:identity:generated':
    "Your keypair — generated on this device. The bond to the previous atom is the hash-link.",
  'operator:registered':
    "This one's a heteroatom — labeled Ω, your Genesis. Everything you do from now on attaches back to this atom.",
  'onboard:recovery:acknowledged':
    "Your recovery path. If you ever lose this device, this is the atom that remembers how to bring you back.",
  'onboard:passkey:registered':
    "A new bond — your passkey is now part of the structure.",
  'onboard:passkey:skipped':
    "You chose to skip; the chain records that too. Not absence — a recorded decision.",
  'onboard:voice:selected':
    "Voice selected. The chain just learned how you want to be addressed.",
  'onboard:capability:demonstrated:allow':
    "That's the foundation letting through what you asked for. The bond closes.",
  'onboard:capability:demonstrated:deny':
    "A refusal. The bond closes around the refusal — it's still part of the structure.",
  'onboard:complete':
    "That's your chain. The Ω is your anchor. Everything you do in the foundation will attach to this structure, and you'll see it grow in the background as you work.",
  '_legacy':
    "Open valence — this one arrived before the foundation closed its bonds. As the chain matures, all atoms will have closed bonds.",
  '_invalid_sig':
    "Something doesn't compose. A signature didn't verify. The expanded view shows which atom and why.",
  '_post_sovereign':
    "A heteroatom. The chain's character just shifted; check the expanded view if you want to see what changed.",
};

// Post-ceremony routine phrases, rotated
const ROUTINE_PHRASES = [
  "A new bond just formed.",
  "The chain just grew.",
  "Another atom — the structure extends.",
];

// ─── Component ────────────────────────────────────────────────────────────────

class ZpReceiptChain extends HTMLElement {
  static get observedAttributes() {
    return [
      'mode', 'intensity', 'attention', 'pulse-rate',
      'expand-on-event', 'operator-pref', 'max-receipts',
      'ambient-window',
      'shadow-bg', 'auth-token', 'narration-pref',
    ];
  }

  constructor() {
    super();
    this._shadow = this.attachShadow({ mode: 'open' });

    // Receipts in time order (oldest first)
    this._receipts = [];
    // Map: receipt.id → SVG <g> element
    this._atomEls = new Map();
    // Bond SVG elements (re-created on each render)
    this._bondEls = [];

    // Current state
    this._mode = 'ambient';
    this._attention = 'ambient';
    this._ceremonyDone = false;
    this._legacyNarratedOnce = false;
    this._routinePhraseIdx = 0;

    // §8 Rule 4: debounce state
    this._pulseTimer = null;
    this._pendingPulseIntensity = 0;

    // §9: narration rate-limiting
    this._lastNarrationMs = 0;
    this._phraseCooldowns = new Map(); // phrase → lastFiredMs

    // SSE
    this._sseAbort = null;

    // Lifecycle
    this._rendered = false;
    this._resizeObserver = null;
  }

  connectedCallback() {
    this._buildShadow();
    this._rendered = true;
    this._applyMode(this.getAttribute('mode') || 'ambient');
    this._updateFixedPositioning();

    this._resizeObserver = new ResizeObserver(() => this._reRenderAll());
    this._resizeObserver.observe(this._shadow.host);

    this._init();
  }

  disconnectedCallback() {
    this._closeSSE();
    this._resizeObserver?.disconnect();
  }

  attributeChangedCallback(name, _old, next) {
    if (!this._rendered) return;
    if (name === 'mode')         this._applyMode(next || 'ambient');
    if (name === 'attention')    this._clampAndSetAttention(next || 'ambient');
    if (name === 'shadow-bg')    this._updateFixedPositioning();
    if (name === 'operator-pref') this._clampAndSetAttention(this._attention);
    if (name === 'auth-token')   this._init();
    if (name === 'intensity')    this._updateAtomOpacities();
    if (name === 'ambient-window') this._reRenderAll();
  }

  // ─── Shadow DOM ────────────────────────────────────────────────────────────

  _buildShadow() {
    this._shadow.innerHTML = `
<style>
  :host {
    display: block;
    contain: style;
  }
  :host(.fixed-bg) {
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    width: 100vw;
    height: 100vh;
  }
  :host(.fixed-bg.expanded) {
    pointer-events: auto;
    z-index: 100;
  }
  #chain-svg {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    overflow: visible;
    cursor: pointer;
    /* Background of the SVG (empty space, bonds) stays non-interactive
       so page content underneath remains reachable in ambient mode.
       Atom groups below opt back into pointer events as hit targets. */
    pointer-events: none;
  }
  #chain-svg > g {
    pointer-events: auto;
  }
  #narration {
    position: fixed;
    bottom: 32px;
    left: 50%;
    transform: translateX(-50%);
    max-width: 440px;
    width: calc(100% - 48px);
    background: rgba(10,10,14,0.90);
    border: 1px solid rgba(126,184,218,0.18);
    border-radius: 10px;
    padding: 13px 18px;
    font-family: 'Inter', -apple-system, sans-serif;
    font-size: 13px;
    line-height: 1.55;
    color: #c4c4cc;
    opacity: 0;
    transition: opacity 0.5s;
    pointer-events: none;
    z-index: 2;
  }
  #narration.on { opacity: 1; }
  .sage-dot {
    display: inline-block;
    width: 5px; height: 5px;
    background: #7eb8da;
    border-radius: 50%;
    margin-right: 8px;
    vertical-align: middle;
    flex-shrink: 0;
  }
  #reconnect {
    position: fixed;
    bottom: 8px;
    right: 14px;
    font-family: monospace;
    font-size: 10px;
    color: #3a3a48;
    opacity: 0;
    transition: opacity 0.4s;
    z-index: 2;
  }
  #reconnect.on { opacity: 1; }
  #expanded {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 110;
    background: rgba(10,10,12,0.94);
    overflow-y: auto;
    padding: 40px 24px 80px;
    font-family: 'Inter', -apple-system, sans-serif;
    color: #d8d8e0;
    font-size: 14px;
  }
  #expanded.on { display: block; }
  .exp-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 28px;
    max-width: 640px;
    margin-inline: auto;
  }
  .exp-title {
    font-size: 17px;
    font-weight: 600;
    color: #fff;
    letter-spacing: -0.01em;
  }
  .exp-subtitle { font-size: 12px; color: #555; margin-top: 2px; }
  #close-btn {
    background: none;
    border: 1px solid #2a2a38;
    border-radius: 6px;
    color: #666;
    padding: 6px 14px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
  }
  #close-btn:hover { border-color: #444; color: #aaa; }
  #atom-list {
    list-style: none;
    padding: 0;
    max-width: 640px;
    margin-inline: auto;
  }
  .atom-item {
    border: 1px solid #1c1c28;
    border-radius: 8px;
    padding: 11px 14px;
    margin-bottom: 6px;
    font-size: 12px;
  }
  .atom-item .a-claim { color: #7eb8da; font-weight: 600; margin-bottom: 3px; }
  .atom-item .a-meta  { color: #555; font-family: monospace; font-size: 11px; }
  .atom-item .a-meta .sig-ok      { color: #3ddc84; }
  .atom-item .a-meta .sig-legacy  { color: #555; }
  .atom-item .a-meta .sig-invalid { color: #ff6b6b; }
  .atom-item .a-detail { color: #444; font-family: monospace; font-size: 10px; margin-top: 3px; word-break: break-all; }
  .feedback-area {
    max-width: 640px;
    margin: 32px auto 0;
    padding-top: 24px;
    border-top: 1px solid #1a1a28;
  }
  .feedback-label { font-size: 12px; color: #555; margin-bottom: 8px; }
  #feedback-input {
    width: 100%;
    background: #0e0e14;
    border: 1px solid #222230;
    border-radius: 6px;
    color: #d0d0d8;
    padding: 10px 12px;
    font-size: 13px;
    font-family: 'Inter', sans-serif;
    resize: vertical;
    min-height: 68px;
    box-sizing: border-box;
  }
  #feedback-btn {
    margin-top: 8px;
    background: none;
    border: 1px solid #2a2a3a;
    border-radius: 6px;
    color: #7eb8da;
    padding: 7px 16px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
  }
  #feedback-btn:hover { border-color: #7eb8da; }
</style>
<svg id="chain-svg" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"></svg>
<div id="narration"></div>
<div id="reconnect">reconnecting…</div>
<div id="expanded">
  <div class="exp-header">
    <div>
      <div class="exp-title">Your chain</div>
      <div class="exp-subtitle">Most recent first — click any atom for full detail</div>
    </div>
    <button id="close-btn">Close</button>
  </div>
  <ul id="atom-list"></ul>
  <div class="feedback-area">
    <div class="feedback-label">Tell Sage what's confusing or what you wish you could see.</div>
    <textarea id="feedback-input" placeholder="Your feedback…"></textarea>
    <button id="feedback-btn">Send</button>
  </div>
</div>`;

    this._svg = this._shadow.getElementById('chain-svg');
    this._narrationEl = this._shadow.getElementById('narration');
    this._reconnectEl = this._shadow.getElementById('reconnect');
    this._expandedEl = this._shadow.getElementById('expanded');

    this._shadow.getElementById('close-btn').addEventListener('click', () => this._exitExpanded());
    this._shadow.getElementById('feedback-btn').addEventListener('click', () => this._submitFeedback());

    // §8 Rule 7: SVG click opens expanded mode — no flourish on the click itself
    this._svg.addEventListener('click', () => {
      if (this._mode !== 'expanded') this._enterExpanded();
    });
  }

  // ─── Auth token resolution ─────────────────────────────────────────────────

  _token() {
    const attr = this.getAttribute('auth-token');
    if (attr) return attr;
    try {
      return (
        sessionStorage.getItem('zp-session-token') ||
        localStorage.getItem('zp_session_id')
      );
    } catch {
      return null;
    }
  }

  // ─── Init / data pipeline ──────────────────────────────────────────────────

  async _init() {
    this._closeSSE();
    const token = this._token();
    if (!token) return;

    const initialUrl = this.getAttribute('initial') || '/api/operator/me/chain';
    const limit = Math.min(
      parseInt(this.getAttribute('max-receipts') || '120', 10),
      500,
    );

    try {
      const res = await fetch(`${initialUrl}?limit=${limit}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return;
      const data = await res.json();
      const receipts = (data.receipts || []);

      // Rebuild from scratch — deterministic render of known-history
      this._receipts = [];
      this._atomEls.clear();
      this._bondEls = [];
      if (this._svg) this._svg.innerHTML = '';

      for (const r of receipts) {
        this._receipts.push(r);
      }
      this._reRenderAll();
    } catch {}

    this._openSSE();
  }

  // ─── SSE (fetch-based — supports Authorization header) ────────────────────

  _openSSE() {
    const token = this._token();
    if (!token) return;

    const feedUrl = this.getAttribute('feed') || '/api/operator/me/chain/stream';
    const ctrl = new AbortController();
    this._sseAbort = ctrl;

    const lastSeq = this._receipts.reduce((m, r) => Math.max(m, r.sequence || 0), 0);

    const connect = async (retryDelayMs = 0) => {
      if (retryDelayMs) await new Promise(r => setTimeout(r, retryDelayMs));
      if (ctrl.signal.aborted) return;

      try {
        const res = await fetch(feedUrl, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Last-Event-ID': String(lastSeq),
            Accept: 'text/event-stream',
          },
          signal: ctrl.signal,
        });

        if (!res.ok || !res.body) {
          this._reconnectEl?.classList.add('on');
          connect(5000);
          return;
        }

        this._reconnectEl?.classList.remove('on');
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        let evt = {};

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split('\n');
          buf = lines.pop(); // hold incomplete last line

          for (const line of lines) {
            if (line.startsWith('event: ')) {
              evt.type = line.slice(7).trim();
            } else if (line.startsWith('data: ')) {
              evt.data = (evt.data || '') + line.slice(6);
            } else if (line.startsWith('id: ')) {
              evt.id = line.slice(4).trim();
            } else if (line === '') {
              if (evt.data) {
                try {
                  const receipt = JSON.parse(evt.data);
                  this._onLiveReceipt(receipt);
                } catch {}
              }
              evt = {};
            }
          }
        }
      } catch (e) {
        if (ctrl.signal.aborted) return;
      }

      if (!ctrl.signal.aborted) {
        this._reconnectEl?.classList.add('on');
        connect(3000);
      }
    };

    connect();
  }

  _closeSSE() {
    this._sseAbort?.abort();
    this._sseAbort = null;
  }

  // ─── Live receipt handling ─────────────────────────────────────────────────

  _onLiveReceipt(receipt) {
    if (this._receipts.some(r => r.id === receipt.id)) return;

    this._appendReceipt(receipt);
    this._schedulePulse(receipt);   // §8 Rule 4
    this._composeViz();             // §4
    this._narrate(receipt);         // §9

    if (receipt.claim === 'onboard:complete') {
      this._runCeremonyCompletion();
    }
  }

  _appendReceipt(receipt) {
    const max = parseInt(this.getAttribute('max-receipts') || '120', 10);
    this._receipts.push(receipt);
    if (this._receipts.length > max) {
      const evicted = this._receipts.shift();
      const el = this._atomEls.get(evicted.id);
      if (el) { el.remove(); this._atomEls.delete(evicted.id); }
    }
    // In ambient mode, a new arrival shifts the visible window forward —
    // the oldest visible atom must drop from the SVG and the new one
    // takes its place. The single-atom incremental render path can't
    // evict the displaced atom, so re-render the whole window. In
    // expanded mode the incremental path is correct (no window cap).
    if (this._mode === 'ambient' || this._mode === 'ceremony') {
      this._reRenderAll();
    } else {
      this._renderAtom(receipt, true);
      this._rebuildBonds();
    }
  }

  // ─── Layout ───────────────────────────────────────────────────────────────

  _ambientWindow() {
    return Math.max(1, parseInt(this.getAttribute('ambient-window') || '18', 10));
  }

  /**
   * Receipts visible in the current mode.
   *
   * - Ambient (and ceremony, which is the ambient surface during
   *   onboarding): substrate book-keeping claims are filtered out;
   *   the tail of the remaining list is taken up to `ambient-window`.
   *   Restores the design's calm-by-default property — the background
   *   shows recent activity only, not the full chain history.
   * - Expanded: returns the full `_receipts` array unchanged.
   *   chain:read entries surface here (they're real audit events).
   *
   * This is the single source of truth for which atoms get rendered.
   * `_layout()`, `_reRenderAll()`, `_rebuildBonds()`, and
   * `_updateAtomOpacities()` all consume it.
   */
  _visibleReceipts() {
    if (this._mode === 'expanded') return this._receipts;
    const filtered = this._receipts.filter(
      (r) => !SUBSTRATE_BOOKKEEPING_CLAIMS.has(r.claim),
    );
    const window = this._ambientWindow();
    return filtered.length > window ? filtered.slice(-window) : filtered;
  }

  /**
   * True when at least one visible-window-eligible receipt was
   * trimmed off the front by the ambient-window cap — drives the
   * left-edge "older atoms exist offscreen" stub in `_rebuildBonds`.
   * Bookkeeping receipts don't count toward the overflow signal.
   */
  _hasOlderAtomsOffscreen() {
    if (this._mode === 'expanded') return false;
    const visibleEligible = this._receipts.filter(
      (r) => !SUBSTRATE_BOOKKEEPING_CLAIMS.has(r.claim),
    ).length;
    return visibleEligible > this._ambientWindow();
  }

  _layout() {
    const visible = this._visibleReceipts();
    const padding = 48;
    const rowH = 64;
    const vw = (this._svg?.clientWidth) || window.innerWidth;

    // Ambient (and ceremony) — single horizontal row, centered.
    // The window cap is small enough that the row fits in viewport
    // at typical widths; spacing compresses on narrow viewports
    // to keep the backbone single-line per the design's "one
    // operator, one backbone" metaphor.
    if (this._mode !== 'expanded') {
      const n = visible.length;
      if (n === 0) return [];
      const baseSpacing = 80;
      const minSpacing = 28;
      const usable = Math.max(0, vw - padding * 2);
      // Fit-or-compress: prefer 80px, fall back to whatever keeps a
      // single row, floored at 28px so atoms don't visually overlap.
      const fittedSpacing =
        n > 1 ? Math.max(minSpacing, Math.min(baseSpacing, usable / (n - 1))) : 0;
      const rowWidth = (n - 1) * fittedSpacing;
      const startX = (vw - rowWidth) / 2;
      const y = 56;
      return visible.map((r, i) => ({
        receipt: r,
        x: startX + i * fittedSpacing,
        y,
      }));
    }

    // Expanded — existing wrapping grid (works inside the bounded
    // expanded scroll container).
    const spacing = 80;
    const perRow = Math.max(1, Math.floor((vw - padding * 2) / spacing));
    return visible.map((r, i) => ({
      receipt: r,
      x: padding + (i % perRow) * spacing + spacing / 2,
      y: 56 + Math.floor(i / perRow) * rowH,
    }));
  }

  _reRenderAll() {
    if (!this._svg) return;
    // Clear everything
    this._svg.innerHTML = '';
    this._atomEls.clear();
    this._bondEls = [];

    const positions = this._layout();
    for (const pos of positions) {
      this._renderAtomAt(pos.receipt, pos.x, pos.y, false);
    }
    this._rebuildBonds();
  }

  // ─── Atom rendering ───────────────────────────────────────────────────────

  _category(claim) {
    if (claim === 'operator:registered') return 'sovereign';
    for (const [pfx, cat] of Object.entries(CATEGORY_PREFIXES)) {
      if (claim.startsWith(pfx)) return cat;
    }
    return 'operational';
  }

  _isSovereign(receipt) {
    return receipt.claim === 'operator:registered';
  }

  _atomColor(receipt) {
    return CATEGORY_COLORS[this._category(receipt.claim)];
  }

  _atomRadius(receipt) {
    const base = this._isSovereign(receipt) ? 3 : 1;
    if (this._mode === 'expanded') return (this._isSovereign(receipt) ? 12 : 8);
    if (this._mode === 'ceremony') return 4 + base * 2;
    return 4 + base; // ambient
  }

  _atomOpacity(receipt) {
    const att = this._attention;
    if (att === 'hidden') return 0;
    const intensity = parseFloat(this.getAttribute('intensity') || '1.0');
    if (this._isSovereign(receipt)) {
      const base = att === 'ambient' ? 0.25 : att === 'foreground' ? 0.70 : 1.0;
      return base * intensity;
    }
    const base = att === 'ambient' ? 0.20 : att === 'foreground' ? 0.55 : 1.0;
    return base * intensity;
  }

  _renderAtom(receipt, animate) {
    const positions = this._layout();
    const pos = positions.find(p => p.receipt.id === receipt.id);
    if (!pos) { this._reRenderAll(); return; }
    this._renderAtomAt(receipt, pos.x, pos.y, animate);
  }

  _renderAtomAt(receipt, x, y, animate) {
    const ns = 'http://www.w3.org/2000/svg';
    const g = document.createElementNS(ns, 'g');
    g.dataset.id = receipt.id;

    const color = this._atomColor(receipt);
    const r = this._atomRadius(receipt);
    const opacity = animate ? 0 : this._atomOpacity(receipt);
    const isSovereign = this._isSovereign(receipt);

    // Main circle
    const circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', x);
    circle.setAttribute('cy', y);
    circle.setAttribute('r', r);
    circle.setAttribute('fill', color);
    circle.setAttribute('opacity', opacity);
    if (animate) circle.style.transition = 'opacity 0.35s ease-out';
    g.appendChild(circle);

    if (isSovereign) {
      // Outer ring for sovereign atom (Ω)
      const ring = document.createElementNS(ns, 'circle');
      ring.setAttribute('cx', x);
      ring.setAttribute('cy', y);
      ring.setAttribute('r', r + 5);
      ring.setAttribute('fill', 'none');
      ring.setAttribute('stroke', color);
      ring.setAttribute('stroke-width', '1.5');
      ring.setAttribute('opacity', opacity);
      if (animate) ring.style.transition = 'opacity 0.35s ease-out';
      g.appendChild(ring);

      // Ω label (always visible in ambient+ if sovereign)
      const label = document.createElementNS(ns, 'text');
      label.setAttribute('x', x);
      label.setAttribute('y', y + r + 14);
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('font-family', 'Inter, -apple-system, sans-serif');
      label.setAttribute('font-size', '10');
      label.setAttribute('fill', color);
      label.setAttribute('opacity', opacity);
      if (animate) label.style.transition = 'opacity 0.35s ease-out';
      label.textContent = 'Ω';
      g.appendChild(label);
    }

    // Open valence stub for pre-signing-era or unsigned receipts
    const isOpenValence = receipt.pre_signing_era || !receipt.signatures?.length;
    if (isOpenValence) {
      const stub = document.createElementNS(ns, 'line');
      stub.setAttribute('x1', x + r);
      stub.setAttribute('y1', y);
      stub.setAttribute('x2', x + r + 10);
      stub.setAttribute('y2', y);
      stub.setAttribute('stroke', color);
      stub.setAttribute('stroke-width', '1');
      stub.setAttribute('opacity', opacity * 0.5);
      if (animate) stub.style.transition = 'opacity 0.35s ease-out';
      g.appendChild(stub);
    }

    this._svg.appendChild(g);
    this._atomEls.set(receipt.id, g);

    if (animate) {
      // Trigger transition after paint
      requestAnimationFrame(() => {
        const target = this._atomOpacity(receipt);
        for (const el of g.querySelectorAll('circle, text, line')) {
          el.setAttribute('opacity', target);
        }
      });
    }
  }

  // ─── Bond rendering ───────────────────────────────────────────────────────

  _bondType(receipt) {
    if (receipt.pre_signing_era) return 'open';
    if (!receipt.signatures?.length) return 'open';
    return 'double'; // signed = double bond (§6)
  }

  _rebuildBonds() {
    for (const el of this._bondEls) el.remove();
    this._bondEls = [];

    const positions = this._layout();
    const ns = 'http://www.w3.org/2000/svg';

    // Upstream genesis stub on leftmost atom (§11 open question 5 — visual stub only).
    // When the chain has more eligible atoms than the ambient window
    // can hold, the stub becomes the "older atoms exist offscreen"
    // signal — dotted ellipsis treatment so the operator reads the
    // tail as "history extends to the left" rather than "this is the
    // beginning of the chain."
    if (positions.length > 0) {
      const first = positions[0];
      const hasOlder = this._hasOlderAtomsOffscreen();
      const stub = document.createElementNS(ns, 'line');
      stub.setAttribute('x1', Math.max(0, first.x - 28));
      stub.setAttribute('y1', first.y);
      stub.setAttribute('x2', first.x);
      stub.setAttribute('y2', first.y);
      stub.setAttribute('stroke', '#7eb8da');
      stub.setAttribute('stroke-width', '1');
      // Tighter dash pattern + slightly higher opacity reads as
      // continuation ("…") rather than the original "open valence"
      // gesture which used a looser dash.
      stub.setAttribute('stroke-dasharray', hasOlder ? '1 4' : '3 4');
      stub.setAttribute('opacity', hasOlder ? '0.18' : '0.08');
      stub.setAttribute('stroke-linecap', 'round');
      this._svg.insertBefore(stub, this._svg.firstChild);
      this._bondEls.push(stub);
    }

    for (let i = 1; i < positions.length; i++) {
      const prev = positions[i - 1];
      const cur  = positions[i];
      const type = this._bondType(cur.receipt);
      const opacity = this._atomOpacity(cur.receipt) * 0.75;

      const dx = cur.x - prev.x;
      const dy = cur.y - prev.y;
      const len = Math.hypot(dx, dy) || 1;
      const nx = -dy / len;
      const ny =  dx / len;

      if (type === 'open') {
        // Open valence: dashed, desaturated
        const line = document.createElementNS(ns, 'line');
        line.setAttribute('x1', prev.x); line.setAttribute('y1', prev.y);
        line.setAttribute('x2', cur.x);  line.setAttribute('y2', cur.y);
        line.setAttribute('stroke', '#444450');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('stroke-dasharray', '4 4');
        line.setAttribute('stroke-linecap', 'round');
        line.setAttribute('opacity', opacity);
        this._svg.insertBefore(line, this._svg.firstChild);
        this._bondEls.push(line);
      } else {
        // Double bond (signed) — two parallel 1px lines, 2px apart
        for (const sign of [-1, 1]) {
          const off = sign * 1.5;
          const line = document.createElementNS(ns, 'line');
          line.setAttribute('x1', prev.x + nx * off); line.setAttribute('y1', prev.y + ny * off);
          line.setAttribute('x2', cur.x  + nx * off); line.setAttribute('y2', cur.y  + ny * off);
          line.setAttribute('stroke', '#7eb8da');
          line.setAttribute('stroke-width', '1');
          line.setAttribute('stroke-linecap', 'round');
          line.setAttribute('opacity', opacity);
          this._svg.insertBefore(line, this._svg.firstChild);
          this._bondEls.push(line);
        }
      }
    }
  }

  // ─── Attention / mode management ──────────────────────────────────────────

  _applyMode(mode) {
    this._mode = mode;
    if (mode === 'ceremony') {
      // Ceremony starts at foreground attention, mandatory narration
      this._clampAndSetAttention('foreground');
    } else if (mode === 'ambient') {
      this._clampAndSetAttention('ambient');
      // Re-render at correct atom sizes for ambient
      this._reRenderAll();
    } else if (mode === 'expanded') {
      this._enterExpanded();
    }
  }

  _clampAndSetAttention(requested) {
    const pref = this.getAttribute('operator-pref') || 'default';
    const bounds = PREF_BOUNDS[pref] || PREF_BOUNDS.default;
    const floorIdx   = ATTENTION_ORDER.indexOf(bounds.floor);
    const ceilingIdx = ATTENTION_ORDER.indexOf(bounds.ceiling);
    const reqIdx     = ATTENTION_ORDER.indexOf(requested);
    const clamped    = ATTENTION_ORDER[Math.max(floorIdx, Math.min(ceilingIdx, reqIdx))];

    if (clamped !== this._attention) {
      this._attention = clamped;
      this._updateAtomOpacities();
    }
  }

  _updateAtomOpacities() {
    const positions = this._layout();
    for (const pos of positions) {
      const g = this._atomEls.get(pos.receipt.id);
      if (!g) continue;
      const opacity = this._atomOpacity(pos.receipt);
      for (const el of g.querySelectorAll('circle, text, line')) {
        el.setAttribute('opacity', opacity);
      }
    }
    this._rebuildBonds();
  }

  _updateFixedPositioning() {
    const isBg = this.getAttribute('shadow-bg') === 'true';
    this.classList.toggle('fixed-bg', isBg);
  }

  // ─── §4: composeViz — deterministic, no LLM ───────────────────────────────

  _composeViz() {
    const pref = this.getAttribute('operator-pref') || 'default';
    const bounds = PREF_BOUNDS[pref] || PREF_BOUNDS.default;
    const ceremonyActive = this._mode === 'ceremony';
    const idleSinceMs = Date.now() - (this._lastReceiptMs || 0);

    let proposed;
    if (ceremonyActive) {
      proposed = 'foreground';
    } else if (idleSinceMs < 8000) {
      // Brief elevation after a burst — respect ceiling
      proposed = 'foreground';
    } else {
      proposed = 'ambient';
    }

    // §8 Rule 7: expand-on-event must be respected
    const lastReceipt = this._receipts[this._receipts.length - 1];
    if (lastReceipt && this._isSovereign(lastReceipt)) {
      if (bounds.expand === 'sovereign-only' || bounds.expand === 'any') {
        proposed = 'foreground';
      }
    }

    this._clampAndSetAttention(proposed);
    this._lastReceiptMs = Date.now();
  }

  // ─── §8: Pulse system (calibrated to substrate weight only) ───────────────

  _pulseIntensity(claim) {
    const cat = this._category(claim);
    // §8 Rule 3: from table only
    if (cat === 'sovereign') return PULSE_INTENSITIES.sovereign;
    if (cat === 'ceremony')  return PULSE_INTENSITIES.ceremony;
    if (cat === 'audit')     return PULSE_INTENSITIES.audit;
    if (cat === 'gate')      return PULSE_INTENSITIES.gate;
    return PULSE_INTENSITIES.routine;
  }

  // §8 Rule 4: 300ms debounce, merge by max intensity
  _schedulePulse(receipt) {
    const raw = this._pulseIntensity(receipt.claim);
    const attenuated = raw * parseFloat(this.getAttribute('intensity') || '1.0');

    // Merge: track max intensity across the debounce window
    this._pendingPulseIntensity = Math.max(this._pendingPulseIntensity, attenuated);

    if (this._pulseTimer) return; // already scheduled — merge handled above
    this._pulseTimer = setTimeout(() => {
      const intensity = this._pendingPulseIntensity;
      this._pendingPulseIntensity = 0;
      this._pulseTimer = null;
      this._executePulse(intensity);
    }, 300);
  }

  _executePulse(intensity) {
    // Pulse the most recently added atom
    const last = this._receipts[this._receipts.length - 1];
    if (!last) return;
    const g = this._atomEls.get(last.id);
    if (!g) return;

    const circle = g.querySelector('circle');
    if (!circle) return;

    const baseOpacity = this._atomOpacity(last);
    const pulseTarget = Math.min(1.0, baseOpacity + intensity * 0.65);

    circle.style.transition = 'opacity 0.12s ease-out';
    circle.setAttribute('opacity', pulseTarget);

    setTimeout(() => {
      circle.style.transition = 'opacity 0.55s ease-out';
      circle.setAttribute('opacity', baseOpacity);
    }, 150);

    // Sovereign: ring pulse (§1 storyboard — 600ms cycle)
    if (this._isSovereign(last)) {
      const ring = g.querySelectorAll('circle')[1];
      if (ring) {
        ring.style.transition = 'opacity 0.3s ease-in-out';
        ring.setAttribute('opacity', Math.min(1.0, pulseTarget * 1.2));
        setTimeout(() => {
          ring.style.transition = 'opacity 0.6s ease-in-out';
          ring.setAttribute('opacity', baseOpacity);
        }, 600);
      }
    }
  }

  // ─── §9: Narration ─────────────────────────────────────────────────────────

  _narrate(receipt) {
    const narrationPref = this.getAttribute('narration-pref');
    if (narrationPref === 'off') return;
    const operatorPref = this.getAttribute('operator-pref') || 'default';
    if (operatorPref === 'hidden') return;

    const now = Date.now();
    const ceremonyActive = this._mode === 'ceremony';

    // §9: ≤1 phrase per 30s in ambient (ceremony bypasses)
    if (!ceremonyActive && now - this._lastNarrationMs < 30_000) return;

    let phrase = null;

    if (ceremonyActive) {
      phrase = NARRATION[receipt.claim] || null;
    } else if (this._isSovereign(receipt)) {
      phrase = NARRATION._post_sovereign;
    } else if (receipt.pre_signing_era && !this._legacyNarratedOnce) {
      phrase = NARRATION._legacy;
      this._legacyNarratedOnce = true;
    } else {
      phrase = ROUTINE_PHRASES[this._routinePhraseIdx % ROUTINE_PHRASES.length];
      this._routinePhraseIdx++;
    }

    if (!phrase) return;

    // §9: same phrase ≤ once per 5 minutes (ceremony exempt)
    if (!ceremonyActive) {
      const lastFired = this._phraseCooldowns.get(phrase) || 0;
      if (now - lastFired < 5 * 60_000) return;
      this._phraseCooldowns.set(phrase, now);
    }

    this._lastNarrationMs = now;
    this._showNarration(phrase);
  }

  _showNarration(phrase) {
    const el = this._narrationEl;
    if (!el) return;
    el.innerHTML = `<span class="sage-dot"></span>${phrase}`;
    el.classList.add('on');
    clearTimeout(this._narrationTimer);
    this._narrationTimer = setTimeout(() => el.classList.remove('on'), 7000);
  }

  // ─── §1: Ceremony completion sequence ────────────────────────────────────

  _runCeremonyCompletion() {
    if (this._ceremonyDone) return;
    this._ceremonyDone = true;

    const positions = this._layout();
    if (!positions.length) return;

    const xs = positions.map(p => p.x);
    const ys = positions.map(p => p.y);
    const minX = Math.min(...xs) - 40;
    const maxX = Math.max(...xs) + 40;
    const minY = Math.min(...ys) - 40;
    const maxY = Math.max(...ys) + 40;
    const ns = 'http://www.w3.org/2000/svg';

    // Highlight sweep: linear left-to-right over 800ms (§1 animation table)
    const highlightW = 28;
    const sweep = document.createElementNS(ns, 'rect');
    sweep.setAttribute('x', minX);
    sweep.setAttribute('y', minY);
    sweep.setAttribute('width', highlightW);
    sweep.setAttribute('height', maxY - minY);
    sweep.setAttribute('fill', 'rgba(126,184,218,0.12)');
    sweep.setAttribute('opacity', '0');
    this._svg.appendChild(sweep);

    const spanX = maxX - minX;
    const start = performance.now();
    const animateSweep = (now) => {
      const t = Math.min(1, (now - start) / 800);
      sweep.setAttribute('x', minX + t * spanX);
      sweep.setAttribute('opacity', t < 0.5 ? t * 2 : (1 - t) * 2);
      if (t < 1) requestAnimationFrame(animateSweep);
      else {
        sweep.remove();
        // Hold 3s (§1: "Holds for ~3s"), then transition to ambient
        setTimeout(() => {
          this.setAttribute('mode', 'ambient');
        }, 3000);
      }
    };
    requestAnimationFrame(animateSweep);
  }

  // ─── Expanded mode ─────────────────────────────────────────────────────────

  _enterExpanded() {
    this._mode = 'expanded';
    this.classList.add('expanded');
    this._expandedEl?.classList.add('on');
    this._buildExpandedList();
  }

  _exitExpanded() {
    this._mode = 'ambient';
    this.classList.remove('expanded');
    this._expandedEl?.classList.remove('on');
    this._clampAndSetAttention('ambient');
  }

  _buildExpandedList() {
    const list = this._shadow.getElementById('atom-list');
    if (!list) return;
    list.innerHTML = [...this._receipts].reverse().map(r => {
      const isSigned = !r.pre_signing_era && r.signatures?.length;
      const sigClass = r.pre_signing_era ? 'sig-legacy' : isSigned ? 'sig-ok' : 'sig-legacy';
      const sigLabel = r.pre_signing_era ? 'open valence' : isSigned ? 'verified' : 'open valence';
      const ts = r.created_at ? new Date(r.created_at).toLocaleString() : '';
      const seq = r.sequence ? ` · seq ${r.sequence}` : '';
      const detail = r.entry_hash ? `hash ${r.entry_hash.slice(0, 16)}…` : (r.id || '').slice(0, 16);
      return `<li class="atom-item">
        <div class="a-claim">${r.claim}</div>
        <div class="a-meta">
          ${ts}${seq} · <span class="${sigClass}">${sigLabel}</span>
        </div>
        ${detail ? `<div class="a-detail">${detail}</div>` : ''}
      </li>`;
    }).join('');
  }

  // ─── §10: Feedback ─────────────────────────────────────────────────────────

  async _submitFeedback() {
    const input = this._shadow.getElementById('feedback-input');
    const text = input?.value.trim();
    if (!text) return;

    const token = this._token();
    if (!token) return;

    const context = {
      current_mode: this._mode,
      last_receipts: this._receipts.slice(-5).map(r => r.id),
      operator_pref: this.getAttribute('operator-pref') || 'default',
    };

    try {
      const res = await fetch('/api/feedback/viz', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ feedback: text, context }),
      });
      if (res.ok) {
        if (input) input.value = '';
        const btn = this._shadow.getElementById('feedback-btn');
        if (btn) {
          btn.textContent = 'Sent';
          setTimeout(() => { btn.textContent = 'Send'; }, 3000);
        }
      }
    } catch {}
  }
}

customElements.define('zp-receipt-chain', ZpReceiptChain);
