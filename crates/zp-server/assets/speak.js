const TTS_SERVER = 'http://localhost:8473';
const VOICE_PARAMS = {
  length_scale: '0.7692',
  noise_scale: '0.360',
  noise_w: '0.930',
  sentence_silence: '0.30',
};
const CHUNK_SIZE = 800;

let speaking = false;
let aborted = false;
let audio = null;
let totalChunks = 0;
let currentChunk = 0;

// ── Server probe ─────────────────────────────────────────────
async function probe() {
  const dot = document.getElementById('statusDot');
  try {
    const r = await fetch(TTS_SERVER + '/health', { signal: AbortSignal.timeout(2000) });
    if (r.ok) {
      dot.className = 'status-dot connected';
      dot.title = 'TTS server connected';
      return true;
    }
  } catch {}
  dot.className = 'status-dot error';
  dot.title = 'TTS server not responding — run: python3 voice-tuner-server.py';
  return false;
}

// ── Text chunking ────────────────────────────────────────────
function chunkText(text) {
  // Clean up markdown-ish formatting for spoken form
  text = text
    .replace(/```[\s\S]*?```/g, ' (code block omitted) ')  // skip code blocks
    .replace(/`([^`]+)`/g, '$1')                             // inline code → plain
    .replace(/\*\*([^*]+)\*\*/g, '$1')                       // bold → plain
    .replace(/\*([^*]+)\*/g, '$1')                           // italic → plain
    .replace(/^#{1,6}\s+/gm, '')                             // strip markdown headers
    .replace(/^[-*]\s+/gm, '')                               // strip list markers
    .replace(/^\d+\.\s+/gm, '')                              // strip numbered lists
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')                 // links → text
    .replace(/\n{2,}/g, '. ')                                // paragraph breaks → sentence pause
    .replace(/\n/g, ' ')                                     // newlines → space
    .replace(/\s+/g, ' ')
    .trim();

  const sentences = text.match(/[^.!?]+[.!?]+[\s]*/g) || [text];
  const chunks = [];
  let buf = '';
  for (const s of sentences) {
    if (buf.length + s.length > CHUNK_SIZE && buf.length > 0) {
      chunks.push(buf.trim());
      buf = '';
    }
    buf += s;
  }
  if (buf.trim()) chunks.push(buf.trim());
  return chunks;
}

// ── Synthesis ────────────────────────────────────────────────
async function synthesize(text) {
  const voice = document.getElementById('voiceSelect').value;
  const resp = await fetch(TTS_SERVER + '/synthesize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text,
      voice_file: voice,
      ...VOICE_PARAMS,
    }),
  });
  if (!resp.ok) throw new Error(`TTS ${resp.status}`);
  const blob = await resp.blob();
  return URL.createObjectURL(blob);
}

function playBlob(url) {
  return new Promise((resolve, reject) => {
    audio = new Audio(url);
    audio.onended = resolve;
    audio.onerror = reject;
    audio.play().catch(reject);
  });
}

// ── Speak pipeline ───────────────────────────────────────────
async function startSpeak() {
  const text = document.getElementById('textInput').value.trim();
  if (!text) return;

  aborted = false;
  speaking = true;
  updateUI();

  const chunks = chunkText(text);
  totalChunks = chunks.length;
  currentChunk = 0;

  for (let i = 0; i < chunks.length; i++) {
    if (aborted) break;
    currentChunk = i;
    updateProgress();

    try {
      const url = await synthesize(chunks[i]);
      if (aborted) { URL.revokeObjectURL(url); break; }
      await playBlob(url);
      URL.revokeObjectURL(url);
    } catch (e) {
      console.warn('TTS chunk error:', e);
      document.getElementById('infoText').textContent = 'TTS error — is the server running?';
      break;
    }
  }

  speaking = false;
  aborted = false;
  audio = null;
  updateUI();
  document.getElementById('progressBar').classList.remove('active');
  document.getElementById('progressFill').style.width = '0%';
}

function stopSpeak() {
  aborted = true;
  if (audio) {
    audio.pause();
    audio.currentTime = 0;
    audio = null;
  }
  speaking = false;
  updateUI();
}

function toggleSpeak() {
  if (speaking) stopSpeak();
  else startSpeak();
}

// ── UI updates ───────────────────────────────────────────────
function updateUI() {
  const btn = document.getElementById('speakBtn');
  if (speaking) {
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="currentColor" stroke="none" width="16" height="16"><rect x="6" y="6" width="12" height="12" rx="2"/></svg> Stop`;
    btn.classList.add('speaking');
    document.getElementById('progressBar').classList.add('active');
    document.getElementById('infoText').textContent = '';
  } else {
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/></svg> Speak`;
    btn.classList.remove('speaking');
    document.getElementById('progressBar').classList.remove('active');
  }
}

function updateProgress() {
  const pct = totalChunks > 0 ? ((currentChunk + 1) / totalChunks) * 100 : 0;
  document.getElementById('progressFill').style.width = pct + '%';
}

// ── Auto-paste on focus ──────────────────────────────────────
let lastPaste = '';
window.addEventListener('focus', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (text && text !== lastPaste && text.length > 20) {
      lastPaste = text;
      const ta = document.getElementById('textInput');
      // Only auto-fill if the textarea is empty or unchanged
      if (!ta.value.trim() || ta.dataset.autofilled === 'true') {
        ta.value = text;
        ta.dataset.autofilled = 'true';
        document.getElementById('infoText').textContent = `Clipboard: ${text.length} chars`;
      }
    }
  } catch {
    // Clipboard permission denied — that's fine
  }
});

// Mark as user-edited when they type
document.getElementById('textInput').addEventListener('input', function() {
  this.dataset.autofilled = 'false';
});

// ── Keyboard shortcuts ───────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && speaking) {
    stopSpeak();
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
    e.preventDefault();
    toggleSpeak();
  }
});

// ── Init ─────────────────────────────────────────────────────
probe();
setInterval(probe, 15000);  // re-probe every 15s

// ── CSP-safe event delegation ─────────────────────────────
document.addEventListener('click', function(e) {
  const target = e.target.closest('[data-action]');
  if (!target) return;
  if (target.getAttribute('data-action') === 'toggle-speak') {
    if (typeof toggleSpeak === 'function') toggleSpeak();
  }
});
