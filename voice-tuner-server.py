#!/usr/bin/env python3
"""
voice-tuner-server.py — Local Piper voice tuner with instant playback.

Serves the voice tuner UI and runs Piper TTS on demand,
returning audio directly to the browser.

Usage:
  cd ~/projects/zeropoint
  python3 voice-tuner-server.py

Then open http://localhost:8473 in your browser.
"""

import http.server
import json
import subprocess
import tempfile
import os
import urllib.parse
from pathlib import Path

PORT = 8473
PIPER_BIN = "/Users/kenrom/anaconda3/bin/piper"
MODEL_DIR = "/Users/kenrom/projects/zeropoint/models/piper"

# ─── Discover available voices ───────────────────────────────────
def get_voices():
    models = sorted(Path(MODEL_DIR).glob("*.onnx"))
    voices = []
    for m in models:
        stem = m.stem  # e.g. en_US-ryan-medium
        parts = stem.split("-")
        if len(parts) >= 2:
            locale = parts[0]           # en_US
            name = parts[1]             # ryan
            quality = parts[2] if len(parts) > 2 else "medium"
            accent = "US" if "US" in locale else "GB" if "GB" in locale else locale
            voices.append({
                "id": name,
                "file": stem,
                "name": name.replace("_", " ").title(),
                "accent": accent,
                "quality": quality,
                "path": str(m),
            })
    return voices


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZeroPoint — Piper Voice Tuner</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --bg: #0a0a0c;
  --bg-elevated: #111116;
  --bg-subtle: #18181f;
  --bg-input: #1e1e26;
  --text: #e0ded9;
  --text-muted: #9a9a9e;
  --text-dim: #5a5a5e;
  --accent: #7eb8da;
  --accent-dim: #4a7a96;
  --accent-glow: rgba(126, 184, 218, 0.15);
  --success: #6ec87a;
  --warn: #d4a853;
  --error: #d45858;
  --rule: #222228;
  --font-body: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'JetBrains Mono', 'SF Mono', monospace;
  --radius: 8px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 16px; }
body {
  font-family: var(--font-body);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  padding: 2rem;
}
.container { max-width: 920px; margin: 0 auto; }

h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 0.25rem; }
.subtitle { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 2rem; }

.panel {
  background: var(--bg-elevated);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  padding: 1.5rem;
  margin-bottom: 1.25rem;
}
.panel-title {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--accent);
  margin-bottom: 1rem;
}

/* Voice Grid */
.voice-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 0.5rem;
}
.voice-card {
  background: var(--bg-subtle);
  border: 2px solid transparent;
  border-radius: 6px;
  padding: 0.75rem 1rem;
  cursor: pointer;
  transition: all 0.15s ease;
  position: relative;
}
.voice-card:hover { border-color: var(--accent-dim); background: var(--bg-input); }
.voice-card.selected { border-color: var(--accent); background: var(--accent-glow); }
.voice-card .vn { font-weight: 600; font-size: 0.9rem; margin-bottom: 0.2rem; }
.voice-card .vm { font-size: 0.75rem; color: var(--text-muted); }
.voice-card .vc {
  position: absolute; top: 0.5rem; right: 0.5rem;
  width: 18px; height: 18px; border-radius: 50%;
  background: var(--accent); display: none;
  align-items: center; justify-content: center;
}
.voice-card.selected .vc { display: flex; }
.vc svg { width: 12px; height: 12px; fill: var(--bg); }

/* Controls */
.controls-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.25rem;
}
@media (max-width: 600px) { .controls-grid { grid-template-columns: 1fr; } }

.cg { display: flex; flex-direction: column; gap: 0.4rem; }
.cl { display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-muted); }
.cv { font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent); font-weight: 500; }

input[type="range"] {
  -webkit-appearance: none; appearance: none;
  width: 100%; height: 6px; border-radius: 3px;
  background: var(--bg-subtle); outline: none; cursor: pointer;
}
input[type="range"]::-webkit-slider-thumb {
  -webkit-appearance: none; appearance: none;
  width: 18px; height: 18px; border-radius: 50%;
  background: var(--accent); border: 2px solid var(--bg-elevated);
  cursor: pointer; transition: transform 0.1s;
}
input[type="range"]::-webkit-slider-thumb:hover { transform: scale(1.15); }

/* Preview */
.preview-text {
  width: 100%; background: var(--bg-input);
  border: 1px solid var(--rule); border-radius: 6px;
  padding: 0.75rem 1rem; color: var(--text);
  font-family: var(--font-body); font-size: 0.85rem;
  line-height: 1.5; resize: vertical; min-height: 80px;
}
.preview-text:focus { outline: none; border-color: var(--accent-dim); }

.presets { display: flex; gap: 0.4rem; flex-wrap: wrap; margin-top: 0.5rem; }
.preset-btn {
  font-size: 0.7rem; padding: 0.3rem 0.6rem;
  background: var(--bg-subtle); border: 1px solid var(--rule);
  border-radius: 4px; color: var(--text-muted);
  cursor: pointer; font-family: var(--font-body); transition: all 0.15s;
}
.preset-btn:hover { border-color: var(--accent-dim); color: var(--text); }

/* Buttons */
.btn-row { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }

.btn {
  padding: 0.7rem 1.5rem; border: none; border-radius: 6px;
  font-weight: 600; font-size: 0.85rem; font-family: var(--font-body);
  cursor: pointer; transition: all 0.15s;
  display: flex; align-items: center; gap: 0.5rem;
}
.btn-primary { background: var(--accent); color: var(--bg); }
.btn-primary:hover { filter: brightness(1.1); }
.btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

.btn-secondary {
  padding: 0.7rem 1.25rem; background: transparent;
  color: var(--text-muted); border: 1px solid var(--rule);
  border-radius: 6px; font-size: 0.8rem; font-family: var(--font-body);
  cursor: pointer; transition: all 0.15s;
}
.btn-secondary:hover { border-color: var(--accent-dim); color: var(--text); }

.btn svg { width: 16px; height: 16px; }

.status { font-size: 0.8rem; color: var(--text-muted); padding: 0.5rem 0; }
.status.error { color: var(--error); }
.status.success { color: var(--success); }
.status.working { color: var(--warn); }

/* Audio player */
.player-row {
  display: flex; align-items: center; gap: 1rem;
  padding: 1rem; background: var(--bg-subtle);
  border-radius: 6px; margin-top: 1rem; display: none;
}
.player-row.visible { display: flex; }
.player-row audio { flex: 1; height: 36px; }
.player-row .player-label {
  font-size: 0.75rem; color: var(--text-dim); white-space: nowrap;
}

/* Export */
.cmd-box {
  background: var(--bg-input); border: 1px solid var(--rule);
  border-radius: 6px; padding: 1rem;
  font-family: var(--font-mono); font-size: 0.75rem;
  color: var(--accent); white-space: pre-wrap; word-break: break-all;
  position: relative; line-height: 1.6;
}
.copy-btn {
  position: absolute; top: 0.5rem; right: 0.5rem;
  padding: 0.3rem 0.6rem; background: var(--bg-subtle);
  border: 1px solid var(--rule); border-radius: 4px;
  color: var(--text-muted); font-size: 0.7rem;
  font-family: var(--font-body); cursor: pointer;
}
.copy-btn:hover { color: var(--text); border-color: var(--accent-dim); }

.config-row {
  display: flex; gap: 1.5rem; flex-wrap: wrap;
  font-size: 0.8rem; color: var(--text-muted);
  padding-top: 0.75rem; border-top: 1px solid var(--rule); margin-top: 1rem;
}
.config-row strong { color: var(--text); }

/* Spinner */
@keyframes spin { to { transform: rotate(360deg); } }
.spinner {
  display: inline-block; width: 14px; height: 14px;
  border: 2px solid var(--accent-dim); border-top-color: var(--accent);
  border-radius: 50%; animation: spin 0.6s linear infinite;
}
</style>
</head>
<body>
<div class="container">

<h1>Piper Voice Tuner</h1>
<p class="subtitle">Pick a voice, tune the parameters, click Generate to hear it instantly.</p>

<div class="panel">
  <div class="panel-title">Voice</div>
  <div class="voice-grid" id="voiceGrid"></div>
</div>

<div class="panel">
  <div class="panel-title">Parameters</div>
  <div class="controls-grid">
    <div class="cg">
      <div class="cl"><span>Speech Rate</span><span class="cv" id="rateVal">1.20x</span></div>
      <input type="range" id="rate" min="0.5" max="2.0" step="0.05" value="1.2">
    </div>
    <div class="cg">
      <div class="cl"><span>Noise Scale (expressiveness)</span><span class="cv" id="noiseVal">0.667</span></div>
      <input type="range" id="noise" min="0.0" max="1.5" step="0.01" value="0.667">
    </div>
    <div class="cg">
      <div class="cl"><span>Noise Width (phoneme variation)</span><span class="cv" id="noiseWVal">0.800</span></div>
      <input type="range" id="noiseW" min="0.0" max="1.5" step="0.01" value="0.8">
    </div>
    <div class="cg">
      <div class="cl"><span>Sentence Silence (sec)</span><span class="cv" id="silenceVal">0.30</span></div>
      <input type="range" id="silence" min="0.0" max="2.0" step="0.05" value="0.3">
    </div>
  </div>
</div>

<div class="panel">
  <div class="panel-title">Preview Text</div>
  <textarea class="preview-text" id="previewText">ZeroPoint is portable trust infrastructure — cryptographic governance primitives that make actions provable, auditable, and policy-bound without requiring central control.</textarea>
  <div class="presets">
    <button class="preset-btn" onclick="setPreset('abstract')">Abstract</button>
    <button class="preset-btn" onclick="setPreset('presence')">Presence Plane</button>
    <button class="preset-btn" onclick="setPreset('technical')">Technical</button>
    <button class="preset-btn" onclick="setPreset('conclusion')">Conclusion</button>
  </div>
</div>

<div class="panel">
  <div class="panel-title">Preview</div>
  <div class="btn-row">
    <button class="btn btn-primary" id="genBtn" onclick="generate()">
      <svg viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
      Generate Preview
    </button>
    <button class="btn-secondary" onclick="resetDefaults()">Reset Defaults</button>
    <span class="status" id="status"></span>
  </div>
  <div class="player-row" id="playerRow">
    <audio id="audio" controls></audio>
    <span class="player-label" id="playerLabel"></span>
  </div>
  <div class="config-row" id="configRow"></div>
</div>

<div class="panel">
  <div class="panel-title">Export for Full Narration Run</div>
  <p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:1rem;">
    Happy with the voice? Update <code>generate-narration.py</code> with these values, then regenerate.
  </p>
  <div class="cmd-box" id="exportBox"><button class="copy-btn" onclick="copyEl('exportBox')">Copy</button></div>
</div>

</div>

<script>
const VOICES = __VOICES_JSON__;

const PRESETS = {
  abstract: "ZeroPoint is portable trust infrastructure \\u2014 cryptographic governance primitives that make actions provable, auditable, and policy-bound without requiring central control.",
  presence: "The Presence Plane enforces a reciprocity rule: you must announce before you receive. A connection that only subscribes without publishing its own announce is structurally suspicious \\u2014 it is a consumer-only node, a passive scanner.",
  technical: "Both backends share the same announce wire format: combined key, capabilities JSON, and Ed25519 signature. A peer discovered via web and a peer discovered via Reticulum end up in the same peer table with the same destination hash.",
  conclusion: "Make trust portable, and you make exit real. Make exit real, and you make extraction optional. Trust is infrastructure."
};

let selectedVoice = 'ryan';

function init() {
  const grid = document.getElementById('voiceGrid');
  VOICES.forEach(v => {
    const card = document.createElement('div');
    card.className = 'voice-card' + (v.id === selectedVoice ? ' selected' : '');
    card.dataset.id = v.id;
    card.onclick = () => selectVoice(v.id);
    card.innerHTML = '<div class="vc"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>' +
      '<div class="vn">' + v.name + '</div>' +
      '<div class="vm">' + v.accent + ' \\u00b7 ' + v.quality + '</div>';
    grid.appendChild(card);
  });

  ['rate','noise','noiseW','silence'].forEach(p => {
    const s = document.getElementById(p);
    const d = document.getElementById(p + 'Val');
    s.addEventListener('input', () => {
      d.textContent = p === 'rate' ? parseFloat(s.value).toFixed(2) + 'x'
        : parseFloat(s.value).toFixed(p === 'silence' ? 2 : 3);
      updateExport();
    });
  });
  updateExport();
  updateConfig();
}

function selectVoice(id) {
  selectedVoice = id;
  document.querySelectorAll('.voice-card').forEach(c =>
    c.classList.toggle('selected', c.dataset.id === id));
  updateExport();
  updateConfig();
}

function setPreset(k) { document.getElementById('previewText').value = PRESETS[k] || ''; }

function resetDefaults() {
  document.getElementById('rate').value = 1.2;
  document.getElementById('rateVal').textContent = '1.20x';
  document.getElementById('noise').value = 0.667;
  document.getElementById('noiseVal').textContent = '0.667';
  document.getElementById('noiseW').value = 0.8;
  document.getElementById('noiseWVal').textContent = '0.800';
  document.getElementById('silence').value = 0.3;
  document.getElementById('silenceVal').textContent = '0.30';
  selectVoice('ryan');
}

function getParams() {
  const rate = parseFloat(document.getElementById('rate').value);
  const noise = parseFloat(document.getElementById('noise').value);
  const noiseW = parseFloat(document.getElementById('noiseW').value);
  const silence = parseFloat(document.getElementById('silence').value);
  const voice = VOICES.find(v => v.id === selectedVoice) || VOICES[0];
  return { rate, noise, noiseW, silence, voice, ls: (1/rate).toFixed(4) };
}

async function generate() {
  const text = document.getElementById('previewText').value.trim();
  if (!text) return;

  const btn = document.getElementById('genBtn');
  const status = document.getElementById('status');
  btn.disabled = true;
  status.innerHTML = '<span class="spinner"></span> Generating...';
  status.className = 'status working';

  const p = getParams();
  try {
    const resp = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text,
        voice: p.voice.file,
        length_scale: parseFloat(p.ls),
        noise_scale: p.noise,
        noise_w: p.noiseW,
        sentence_silence: p.silence,
      })
    });

    if (!resp.ok) {
      const err = await resp.text();
      throw new Error(err);
    }

    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const audio = document.getElementById('audio');
    audio.src = url;

    const playerRow = document.getElementById('playerRow');
    playerRow.classList.add('visible');
    document.getElementById('playerLabel').textContent =
      p.voice.name + ' \\u00b7 ' + p.rate.toFixed(2) + 'x';

    audio.play();
    status.textContent = 'Playing';
    status.className = 'status success';
  } catch (e) {
    status.textContent = 'Error: ' + e.message;
    status.className = 'status error';
  }
  btn.disabled = false;
  updateConfig();
}

function updateExport() {
  const p = getParams();
  const txt =
`# Voice: ${p.voice.name} (${p.voice.file})
# Rate: ${p.rate.toFixed(2)}x

# Paste into generate-narration.py:
PIPER_VOICE = "${p.voice.id}"
PIPER_LENGTH_SCALE = ${p.ls}
PIPER_NOISE_SCALE = ${p.noise.toFixed(3)}
PIPER_NOISE_W = ${p.noiseW.toFixed(3)}
PIPER_SENTENCE_SILENCE = ${p.silence.toFixed(2)}

# Then regenerate:
#   python3 generate-narration.py && bash generate-audio.sh`;

  const box = document.getElementById('exportBox');
  box.innerHTML = '<button class="copy-btn" onclick="copyEl(\\'exportBox\\')">Copy</button>' + esc(txt);
}

function updateConfig() {
  const p = getParams();
  document.getElementById('configRow').innerHTML =
    '<span><strong>Voice:</strong> ' + p.voice.name + '</span>' +
    '<span><strong>Rate:</strong> ' + p.rate.toFixed(2) + 'x</span>' +
    '<span><strong>length_scale:</strong> ' + p.ls + '</span>' +
    '<span><strong>noise:</strong> ' + p.noise.toFixed(3) + '</span>' +
    '<span><strong>silence:</strong> ' + p.silence.toFixed(2) + 's</span>';
}

function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function copyEl(id) {
  const box = document.getElementById(id);
  const text = box.textContent.replace('Copy','').trim();
  navigator.clipboard.writeText(text);
  const btn = box.querySelector('.copy-btn');
  btn.textContent = 'Copied!';
  setTimeout(() => btn.textContent = 'Copy', 1500);
}

init();
</script>
</body>
</html>"""


class TunerHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Quieter logging
        print(f"  {args[0]}" if args else "")

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            voices = get_voices()
            page = HTML_PAGE.replace("__VOICES_JSON__", json.dumps(voices))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page.encode("utf-8"))
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/generate":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))

            text = body.get("text", "")
            voice_file = body.get("voice", "en_US-ryan-medium")
            length_scale = body.get("length_scale", 0.833)
            noise_scale = body.get("noise_scale", 0.667)
            noise_w = body.get("noise_w", 0.8)
            sentence_silence = body.get("sentence_silence", 0.3)

            model_path = os.path.join(MODEL_DIR, voice_file + ".onnx")
            if not os.path.exists(model_path):
                self.send_error(400, f"Model not found: {model_path}")
                return

            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp_path = tmp.name

            try:
                proc = subprocess.run(
                    [
                        PIPER_BIN,
                        "--model", model_path,
                        "--length_scale", str(length_scale),
                        "--noise_scale", str(noise_scale),
                        "--noise_w", str(noise_w),
                        "--sentence_silence", str(sentence_silence),
                        "--output_file", tmp_path,
                    ],
                    input=text.encode("utf-8"),
                    capture_output=True,
                    timeout=30,
                )

                if proc.returncode != 0:
                    self.send_error(500, f"Piper error: {proc.stderr.decode()}")
                    return

                with open(tmp_path, "rb") as f:
                    wav_data = f.read()

                self.send_response(200)
                self.send_header("Content-Type", "audio/wav")
                self.send_header("Content-Length", str(len(wav_data)))
                self.end_headers()
                self.wfile.write(wav_data)

            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        else:
            self.send_error(404)


if __name__ == "__main__":
    voices = get_voices()
    print(f"\n  ZeroPoint Voice Tuner")
    print(f"  ─────────────────────")
    print(f"  Voices: {len(voices)} ({', '.join(v['id'] for v in voices)})")
    print(f"  Piper:  {PIPER_BIN}")
    print(f"  Models: {MODEL_DIR}")
    print(f"\n  Open http://localhost:{PORT}\n")

    server = http.server.HTTPServer(("127.0.0.1", PORT), TunerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()
