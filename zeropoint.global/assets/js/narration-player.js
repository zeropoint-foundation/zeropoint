/**
 * NarrationPlayer — Reusable audio narration component
 *
 * Usage:
 *   <script src="/assets/js/narration-player.js"></script>
 *   <script>
 *     NarrationPlayer.init({
 *       basePath: '/assets/narration/wp',
 *       cacheBust: '20260503',
 *       sections: [
 *         { id: 'intro', prefix: 'wp-intro', title: 'Introduction', paragraphs: 5 },
 *         ...
 *       ],
 *       // Optional: scroll to and highlight sections during playback
 *       highlightSections: true,
 *       // Optional: element ID or selector for the launch button
 *       launchButton: '#narrateBtn'
 *     });
 *   </script>
 */
(function() {
  'use strict';

  // ── State ──────────────────────────────────────────────
  var config = null;
  var currentSection = -1;
  var currentParagraph = 0;
  var audio = null;
  var playing = false;
  var playbackRate = 1.0;
  var progressRAF = null;
  var totalParagraphs = 0;
  var sectionOffsets = []; // cumulative paragraph offsets per section

  // ── DOM refs (set in init) ─────────────────────────────
  var playerEl, scrubBar, scrubFill, scrubHandle, scrubHover;
  var timeCurrentEl, timeTotalEl;
  var labelEl, titleEl;
  var playBtn, pauseIcon, playIcon;
  var speedBtn, speedMenu;
  var sectionSelect;
  var isScrubbing = false;

  // ── Helpers ────────────────────────────────────────────
  function pad(n) { return n < 10 ? '0' + n : '' + n; }

  function formatTime(s) {
    if (!s || !isFinite(s)) return '0:00';
    var m = Math.floor(s / 60);
    var sec = Math.floor(s % 60);
    return m + ':' + pad(sec);
  }

  function audioFile(sectionIdx, paraNum) {
    var s = config.sections[sectionIdx];
    var url = config.basePath + '/' + s.prefix + '-p' + pad(paraNum) + '.mp3';
    if (config.cacheBust) url += '?v=' + config.cacheBust;
    return url;
  }

  function globalParaIndex(sectionIdx, paraNum) {
    return sectionOffsets[sectionIdx] + paraNum - 1;
  }

  function sectionFromGlobal(globalIdx) {
    for (var i = config.sections.length - 1; i >= 0; i--) {
      if (globalIdx >= sectionOffsets[i]) {
        return { section: i, paragraph: globalIdx - sectionOffsets[i] + 1 };
      }
    }
    return { section: 0, paragraph: 1 };
  }

  // ── CSS injection ──────────────────────────────────────
  function injectStyles() {
    var style = document.createElement('style');
    style.textContent = [
      /* Container */
      '.np-player {',
      '  position: fixed; bottom: 0; left: 0; right: 0; z-index: 200;',
      '  background: rgba(17,17,22,0.97);',
      '  backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);',
      '  border-top: 1px solid var(--rule, #222228);',
      '  transform: translateY(100%);',
      '  transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);',
      '  font-family: var(--font-mono, "JetBrains Mono", "SF Mono", monospace);',
      '}',
      '.np-player.visible { transform: translateY(0); }',

      /* Scrub bar */
      '.np-scrub {',
      '  position: absolute; top: -12px; left: 0; right: 0; height: 24px;',
      '  cursor: pointer; z-index: 201;',
      '}',
      '.np-scrub-track {',
      '  position: absolute; top: 10px; left: 0; right: 0; height: 3px;',
      '  background: var(--rule, #222228); border-radius: 2px;',
      '  transition: height 0.15s, top 0.15s;',
      '}',
      '.np-scrub:hover .np-scrub-track { height: 5px; top: 9px; }',
      '.np-scrub-fill {',
      '  height: 100%; background: var(--accent, #7eb8da); border-radius: 2px;',
      '  width: 0%; position: relative;',
      '}',
      '.np-scrub-handle {',
      '  position: absolute; right: -6px; top: 50%; transform: translateY(-50%);',
      '  width: 12px; height: 12px; border-radius: 50%;',
      '  background: var(--accent, #7eb8da);',
      '  opacity: 0; transition: opacity 0.15s;',
      '  box-shadow: 0 0 6px rgba(126,184,218,0.4);',
      '}',
      '.np-scrub:hover .np-scrub-handle, .np-scrub.scrubbing .np-scrub-handle { opacity: 1; }',
      '.np-scrub-hover {',
      '  position: absolute; top: -20px; transform: translateX(-50%);',
      '  background: var(--bg-elevated, #111116); color: var(--text, #e0ded9);',
      '  font-size: 0.65rem; padding: 2px 6px; border-radius: 3px;',
      '  pointer-events: none; opacity: 0; transition: opacity 0.15s;',
      '  white-space: nowrap;',
      '}',
      '.np-scrub:hover .np-scrub-hover { opacity: 1; }',

      /* Inner layout */
      '.np-inner {',
      '  max-width: 820px; margin: 0 auto; padding: 0.55rem 1.5rem;',
      '  display: flex; align-items: center; gap: 0.6rem;',
      '}',

      /* Transport buttons */
      '.np-btn {',
      '  background: none; border: none; color: var(--text-muted, #9a9a9e);',
      '  cursor: pointer; padding: 0.25rem; display: flex; align-items: center;',
      '  justify-content: center; transition: color 0.15s; flex-shrink: 0;',
      '}',
      '.np-btn:hover { color: var(--text, #e0ded9); }',
      '.np-btn svg { width: 16px; height: 16px; }',
      '.np-btn.np-play svg { width: 22px; height: 22px; }',

      /* Time display */
      '.np-time {',
      '  font-size: 0.65rem; color: var(--text-dim, #5a5a5e);',
      '  white-space: nowrap; min-width: 70px; text-align: center; flex-shrink: 0;',
      '}',

      /* Section info */
      '.np-info { flex: 1; min-width: 0; }',
      '.np-label {',
      '  font-size: 0.6rem; color: var(--accent-dim, #4a7a96);',
      '  letter-spacing: 0.08em; text-transform: uppercase;',
      '  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;',
      '}',
      '.np-title {',
      '  font-size: 0.8rem; color: var(--text, #e0ded9); font-weight: 400;',
      '  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;',
      '  margin-top: 0.05rem;',
      '}',

      /* Speed control */
      '.np-speed-wrap { position: relative; flex-shrink: 0; }',
      '.np-speed-btn {',
      '  background: none; border: 1px solid var(--rule, #222228);',
      '  color: var(--text-muted, #9a9a9e); cursor: pointer;',
      '  padding: 0.15rem 0.45rem; border-radius: 3px;',
      '  font-family: inherit; font-size: 0.65rem; transition: all 0.15s;',
      '}',
      '.np-speed-btn:hover { color: var(--text, #e0ded9); border-color: var(--accent-dim, #4a7a96); }',
      '.np-speed-menu {',
      '  position: absolute; bottom: calc(100% + 6px); right: 0;',
      '  background: var(--bg-elevated, #111116);',
      '  border: 1px solid var(--rule, #222228);',
      '  border-radius: 6px; padding: 0.3rem 0;',
      '  display: none; min-width: 70px;',
      '  box-shadow: 0 -4px 20px rgba(0,0,0,0.5);',
      '}',
      '.np-speed-menu.open { display: block; }',
      '.np-speed-opt {',
      '  display: block; width: 100%; background: none; border: none;',
      '  color: var(--text-muted, #9a9a9e); font-family: inherit;',
      '  font-size: 0.7rem; padding: 0.3rem 0.8rem; cursor: pointer;',
      '  text-align: left; transition: all 0.1s;',
      '}',
      '.np-speed-opt:hover { background: rgba(126,184,218,0.08); color: var(--text, #e0ded9); }',
      '.np-speed-opt.active { color: var(--accent, #7eb8da); }',

      /* Section select */
      '.np-section-select {',
      '  background: none; border: 1px solid var(--rule, #222228);',
      '  color: var(--text-muted, #9a9a9e); cursor: pointer;',
      '  padding: 0.15rem 0.3rem; border-radius: 3px;',
      '  font-family: inherit; font-size: 0.65rem;',
      '  max-width: 130px; flex-shrink: 0;',
      '  -webkit-appearance: none; appearance: none;',
      '  background-image: url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'8\' height=\'5\'%3E%3Cpath d=\'M0 0l4 5 4-5z\' fill=\'%239a9a9e\'/%3E%3C/svg%3E");',
      '  background-repeat: no-repeat; background-position: right 6px center;',
      '  padding-right: 18px;',
      '}',
      '.np-section-select option { background: #111116; color: #e0ded9; }',

      /* Close */
      '.np-close {',
      '  background: none; border: none; color: var(--text-dim, #5a5a5e);',
      '  cursor: pointer; padding: 0.25rem; font-size: 1rem; line-height: 1;',
      '  transition: color 0.15s; flex-shrink: 0;',
      '}',
      '.np-close:hover { color: var(--text, #e0ded9); }',

      /* Body padding when player visible */
      'body.np-active { padding-bottom: 60px; }',

      /* Mobile */
      '@media (max-width: 640px) {',
      '  .np-inner { padding: 0.5rem 0.8rem; gap: 0.4rem; }',
      '  .np-title { font-size: 0.72rem; }',
      '  .np-time { font-size: 0.6rem; min-width: 60px; }',
      '  .np-section-select { display: none; }',
      '}',
    ].join('\n');
    document.head.appendChild(style);
  }

  // ── DOM construction ───────────────────────────────────
  function buildPlayer() {
    playerEl = document.createElement('div');
    playerEl.className = 'np-player';
    playerEl.id = 'npPlayer';

    playerEl.innerHTML = [
      /* Scrub bar */
      '<div class="np-scrub" id="npScrub">',
      '  <div class="np-scrub-hover" id="npScrubHover"></div>',
      '  <div class="np-scrub-track">',
      '    <div class="np-scrub-fill" id="npScrubFill">',
      '      <div class="np-scrub-handle"></div>',
      '    </div>',
      '  </div>',
      '</div>',

      '<div class="np-inner">',

      /* Prev */
      '  <button class="np-btn" id="npPrev" title="Previous">',
      '    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h2v12H6zm3.5 6l8.5 6V6z"/></svg>',
      '  </button>',

      /* Play/Pause */
      '  <button class="np-btn np-play" id="npPlayPause" title="Play / Pause">',
      '    <svg class="np-icon-play" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
      '    <svg class="np-icon-pause" viewBox="0 0 24 24" fill="currentColor" style="display:none"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>',
      '  </button>',

      /* Next */
      '  <button class="np-btn" id="npNext" title="Next">',
      '    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 18h2V6h-2zM6 18l8.5-6L6 6z"/></svg>',
      '  </button>',

      /* Time */
      '  <span class="np-time"><span id="npTimeCurrent">0:00</span> / <span id="npTimeTotal">0:00</span></span>',

      /* Section info */
      '  <div class="np-info">',
      '    <div class="np-label" id="npLabel">Ready</div>',
      '    <div class="np-title" id="npTitle"></div>',
      '  </div>',

      /* Section jump */
      '  <select class="np-section-select" id="npSectionSelect" title="Jump to section"></select>',

      /* Speed */
      '  <div class="np-speed-wrap">',
      '    <button class="np-speed-btn" id="npSpeedBtn" title="Playback speed">1x</button>',
      '    <div class="np-speed-menu" id="npSpeedMenu"></div>',
      '  </div>',

      /* Close */
      '  <button class="np-close" id="npClose" title="Close player">&times;</button>',

      '</div>',
    ].join('\n');

    document.body.appendChild(playerEl);

    // Cache refs
    scrubBar     = document.getElementById('npScrub');
    scrubFill    = document.getElementById('npScrubFill');
    scrubHandle  = scrubFill.querySelector('.np-scrub-handle');
    scrubHover   = document.getElementById('npScrubHover');
    timeCurrentEl = document.getElementById('npTimeCurrent');
    timeTotalEl  = document.getElementById('npTimeTotal');
    labelEl      = document.getElementById('npLabel');
    titleEl      = document.getElementById('npTitle');
    playBtn      = document.getElementById('npPlayPause');
    playIcon     = playBtn.querySelector('.np-icon-play');
    pauseIcon    = playBtn.querySelector('.np-icon-pause');
    speedBtn     = document.getElementById('npSpeedBtn');
    speedMenu    = document.getElementById('npSpeedMenu');
    sectionSelect = document.getElementById('npSectionSelect');

    // Build section dropdown
    config.sections.forEach(function(s, i) {
      var opt = document.createElement('option');
      opt.value = i;
      opt.textContent = s.title;
      sectionSelect.appendChild(opt);
    });

    // Build speed menu
    var speeds = [0.5, 0.75, 1, 1.25, 1.5, 1.75, 2];
    speeds.forEach(function(spd) {
      var btn = document.createElement('button');
      btn.className = 'np-speed-opt' + (spd === 1 ? ' active' : '');
      btn.textContent = spd + 'x';
      btn.dataset.speed = spd;
      speedMenu.appendChild(btn);
    });
  }

  // ── Event wiring ───────────────────────────────────────
  function wireEvents() {
    // Transport
    document.getElementById('npPrev').addEventListener('click', prevSection);
    playBtn.addEventListener('click', togglePlayback);
    document.getElementById('npNext').addEventListener('click', nextSection);
    document.getElementById('npClose').addEventListener('click', closePlayer);

    // Section jump
    sectionSelect.addEventListener('change', function() {
      var idx = parseInt(sectionSelect.value, 10);
      if (idx >= 0 && idx < config.sections.length) {
        playParagraph(idx, 1);
      }
    });

    // Speed menu
    speedBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      speedMenu.classList.toggle('open');
    });
    speedMenu.addEventListener('click', function(e) {
      var opt = e.target.closest('.np-speed-opt');
      if (!opt) return;
      var spd = parseFloat(opt.dataset.speed);
      setSpeed(spd);
      speedMenu.classList.remove('open');
    });
    document.addEventListener('click', function() {
      speedMenu.classList.remove('open');
    });

    // Scrub bar — mouse
    scrubBar.addEventListener('mousedown', scrubStart);
    document.addEventListener('mousemove', scrubMove);
    document.addEventListener('mouseup', scrubEnd);

    // Scrub bar — touch
    scrubBar.addEventListener('touchstart', scrubTouchStart, { passive: false });
    document.addEventListener('touchmove', scrubTouchMove, { passive: false });
    document.addEventListener('touchend', scrubTouchEnd);

    // Scrub hover tooltip
    scrubBar.addEventListener('mousemove', function(e) {
      if (isScrubbing) return;
      var rect = scrubBar.getBoundingClientRect();
      var pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      var loc = sectionFromGlobal(Math.floor(pct * totalParagraphs));
      var s = config.sections[loc.section];
      scrubHover.textContent = s.title + ' · ¶' + loc.paragraph;
      scrubHover.style.left = (pct * 100) + '%';
    });

    // Launch button
    if (config.launchButton) {
      var btn = document.querySelector(config.launchButton);
      if (btn) {
        btn.addEventListener('click', function() {
          btn.classList.remove('pulsing');
          playParagraph(0, 1);
        });
      }
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
      if (!playerEl.classList.contains('visible')) return;
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
      switch(e.key) {
        case ' ':
          e.preventDefault();
          togglePlayback();
          break;
        case 'ArrowLeft':
          if (audio && audio.duration) {
            audio.currentTime = Math.max(0, audio.currentTime - 5);
          }
          break;
        case 'ArrowRight':
          if (audio && audio.duration) {
            audio.currentTime = Math.min(audio.duration, audio.currentTime + 5);
          }
          break;
      }
    });
  }

  // ── Scrub logic ────────────────────────────────────────
  function scrubStart(e) {
    isScrubbing = true;
    scrubBar.classList.add('scrubbing');
    scrubTo(e.clientX);
  }
  function scrubMove(e) {
    if (!isScrubbing) return;
    scrubTo(e.clientX);
  }
  function scrubEnd() {
    if (!isScrubbing) return;
    isScrubbing = false;
    scrubBar.classList.remove('scrubbing');
  }

  function scrubTouchStart(e) {
    e.preventDefault();
    isScrubbing = true;
    scrubBar.classList.add('scrubbing');
    scrubTo(e.touches[0].clientX);
  }
  function scrubTouchMove(e) {
    if (!isScrubbing) return;
    e.preventDefault();
    scrubTo(e.touches[0].clientX);
  }
  function scrubTouchEnd() {
    if (!isScrubbing) return;
    isScrubbing = false;
    scrubBar.classList.remove('scrubbing');
  }

  function scrubTo(clientX) {
    var rect = scrubBar.getBoundingClientRect();
    var pct = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));

    // If scrubbing within current paragraph's time range, just seek
    if (audio && audio.duration && currentSection >= 0) {
      var globalCur = globalParaIndex(currentSection, currentParagraph);
      var paraStart = globalCur / totalParagraphs;
      var paraEnd = (globalCur + 1) / totalParagraphs;

      if (pct >= paraStart && pct < paraEnd) {
        var paraFrac = (pct - paraStart) / (paraEnd - paraStart);
        audio.currentTime = paraFrac * audio.duration;
        updateScrubVisual(pct);
        return;
      }
    }

    // Otherwise, jump to a different paragraph
    var targetGlobal = Math.floor(pct * totalParagraphs);
    if (targetGlobal >= totalParagraphs) targetGlobal = totalParagraphs - 1;
    var loc = sectionFromGlobal(targetGlobal);
    playParagraph(loc.section, loc.paragraph);
    updateScrubVisual(pct);
  }

  function updateScrubVisual(pct) {
    scrubFill.style.width = (pct * 100) + '%';
  }

  // ── Playback ───────────────────────────────────────────
  function playParagraph(sectionIdx, paraNum) {
    if (sectionIdx < 0 || sectionIdx >= config.sections.length) return;
    var s = config.sections[sectionIdx];
    if (paraNum < 1 || paraNum > s.paragraphs) return;

    // Tear down previous
    if (audio) {
      audio.pause();
      audio.removeAttribute('src');
      audio.load();
    }
    cancelAnimationFrame(progressRAF);

    currentSection = sectionIdx;
    currentParagraph = paraNum;

    // Dispatch event for page integration
    document.dispatchEvent(new CustomEvent('narrationStep', {
      detail: { section: s.id, sectionIdx: sectionIdx, paragraph: paraNum }
    }));

    // Highlight & scroll on first paragraph
    if (config.highlightSections && paraNum === 1) {
      highlightSection(s.id);
      scrollToSection(s.id);
    }

    audio = new Audio(audioFile(sectionIdx, paraNum));
    audio.playbackRate = playbackRate;
    playing = true;
    updateUI();
    showPlayer();

    audio.addEventListener('canplay', function handler() {
      audio.removeEventListener('canplay', handler);
      audio.play();
      startProgressLoop();
    });

    audio.addEventListener('ended', function handler() {
      audio.removeEventListener('ended', handler);
      cancelAnimationFrame(progressRAF);
      if (currentParagraph < s.paragraphs) {
        playParagraph(currentSection, currentParagraph + 1);
      } else if (currentSection < config.sections.length - 1) {
        clearHighlight();
        setTimeout(function() { playParagraph(currentSection + 1, 1); }, 600);
      } else {
        playing = false;
        updateUI();
        clearHighlight();
      }
    });

    audio.addEventListener('error', function handler() {
      audio.removeEventListener('error', handler);
      console.warn('NarrationPlayer: audio not found — ' + s.prefix + '-p' + pad(paraNum) + '.mp3');
      cancelAnimationFrame(progressRAF);
      if (currentParagraph < s.paragraphs) {
        setTimeout(function() { playParagraph(currentSection, currentParagraph + 1); }, 200);
      } else if (currentSection < config.sections.length - 1) {
        setTimeout(function() { playParagraph(currentSection + 1, 1); }, 400);
      } else {
        playing = false;
        updateUI();
      }
    });
  }

  function togglePlayback() {
    if (!audio) {
      // First play
      playParagraph(0, 1);
      return;
    }
    if (playing) {
      audio.pause();
      playing = false;
      cancelAnimationFrame(progressRAF);
    } else {
      audio.play();
      playing = true;
      startProgressLoop();
      if (config.highlightSections) highlightSection(config.sections[currentSection].id);
    }
    updateUI();
  }

  function prevSection() {
    if (currentParagraph > 1) {
      playParagraph(currentSection, 1);
    } else if (currentSection > 0) {
      playParagraph(currentSection - 1, 1);
    }
  }

  function nextSection() {
    if (currentSection < config.sections.length - 1) {
      playParagraph(currentSection + 1, 1);
    }
  }

  function setSpeed(spd) {
    playbackRate = spd;
    if (audio) audio.playbackRate = spd;
    speedBtn.textContent = spd + 'x';
    // Update active state
    var opts = speedMenu.querySelectorAll('.np-speed-opt');
    opts.forEach(function(o) {
      o.classList.toggle('active', parseFloat(o.dataset.speed) === spd);
    });
  }

  function closePlayer() {
    if (audio) {
      audio.pause();
      audio.removeAttribute('src');
      audio.load();
      audio = null;
    }
    playing = false;
    currentSection = -1;
    currentParagraph = 0;
    cancelAnimationFrame(progressRAF);
    clearHighlight();
    hidePlayer();
    document.dispatchEvent(new CustomEvent('narrationStop'));
  }

  // ── Progress loop (RAF for smooth scrub) ───────────────
  function startProgressLoop() {
    cancelAnimationFrame(progressRAF);
    function tick() {
      if (!audio || !playing) return;
      var globalIdx = globalParaIndex(currentSection, currentParagraph);
      var paraFrac = (audio.duration && audio.duration > 0)
        ? audio.currentTime / audio.duration : 0;
      var overallPct = (globalIdx + paraFrac) / totalParagraphs;
      updateScrubVisual(overallPct);

      // Update time
      timeCurrentEl.textContent = formatTime(audio.currentTime);
      timeTotalEl.textContent = formatTime(audio.duration);

      progressRAF = requestAnimationFrame(tick);
    }
    progressRAF = requestAnimationFrame(tick);
  }

  // ── UI updates ─────────────────────────────────────────
  function updateUI() {
    if (currentSection < 0) return;
    var s = config.sections[currentSection];
    labelEl.textContent = 'Section ' + (currentSection + 1) + ' of ' + config.sections.length
      + '  ·  ¶' + currentParagraph + '/' + s.paragraphs;
    titleEl.textContent = s.title;
    playIcon.style.display = playing ? 'none' : 'block';
    pauseIcon.style.display = playing ? 'block' : 'none';
    sectionSelect.value = currentSection;
  }

  function showPlayer() {
    playerEl.classList.add('visible');
    document.body.classList.add('np-active');
  }

  function hidePlayer() {
    playerEl.classList.remove('visible');
    document.body.classList.remove('np-active');
    scrubFill.style.width = '0%';
  }

  // ── Section highlighting (optional) ────────────────────
  function clearHighlight() {
    document.querySelectorAll('.section-narrating').forEach(function(el) {
      el.classList.remove('section-narrating');
    });
  }

  function highlightSection(id) {
    clearHighlight();
    var heading = document.getElementById(id);
    if (!heading) return;
    var el = heading;
    while (el) {
      if (el.nodeType === 1) el.classList.add('section-narrating');
      el = el.nextElementSibling;
      if (el && (el.tagName === 'H2' || el.tagName === 'HR')) break;
    }
  }

  function scrollToSection(id) {
    var heading = document.getElementById(id);
    if (!heading) return;
    var rect = heading.getBoundingClientRect();
    var offset = window.pageYOffset + rect.top - 80;
    window.scrollTo({ top: offset, behavior: 'smooth' });
  }

  // ── Public API ─────────────────────────────────────────
  window.NarrationPlayer = {
    init: function(cfg) {
      config = cfg;
      config.highlightSections = cfg.highlightSections !== false;

      // Compute totals
      totalParagraphs = 0;
      sectionOffsets = [];
      config.sections.forEach(function(s) {
        sectionOffsets.push(totalParagraphs);
        totalParagraphs += s.paragraphs;
      });

      injectStyles();
      buildPlayer();
      wireEvents();

      // Auto-dismiss launch button pulse
      if (config.launchButton) {
        setTimeout(function() {
          var btn = document.querySelector(config.launchButton);
          if (btn) btn.classList.remove('pulsing');
        }, 4500);
      }
    },

    start: function() { playParagraph(0, 1); },
    toggle: togglePlayback,
    prev: prevSection,
    next: nextSection,
    close: closePlayer,

    // Jump to a specific section by index or id
    jumpTo: function(sectionIdOrIndex, paragraph) {
      var idx = sectionIdOrIndex;
      if (typeof sectionIdOrIndex === 'string') {
        idx = config.sections.findIndex(function(s) { return s.id === sectionIdOrIndex; });
      }
      playParagraph(idx, paragraph || 1);
    }
  };
})();
