  // ── PARAGRAPH-BASED AUDIO ENGINE ──
  // Each narration paragraph is its own audio file (p01.mp3–p29.mp3).
  // When one ends, the next visual beat triggers and the next file plays.

  const paragraphs = [
    // ── SCENE 1: Establishing — terminals booting ──
    { file: 'audio-segments/paragraphs/p01.mp3', scene: 1, fallbackDuration: 8000,
      onStart: () => {
        const terminals = ['t-clinic', 't-pharmacy', 't-patient'];
        terminals.forEach((id, i) => {
          setTimeout(() => {
            document.getElementById(id).classList.add(
              id === 't-clinic' ? 'glow-clinic' : id === 't-pharmacy' ? 'glow-pharmacy' : 'glow-patient'
            );
            const bodyId = 'tb-' + id.split('-')[1];
            document.querySelectorAll(`#${bodyId} .line`).forEach((line, j) => {
              setTimeout(() => line.classList.add('visible'), j * 80);
            });
          }, i * 600);
        });
      }},

    // p02: "Alex Chen opens their phone..." → question fades in
    { file: 'audio-segments/paragraphs/p02.mp3', scene: 2, fallbackDuration: 5000,
      onStart: () => {
        setTimeout(() => document.getElementById('s2-question').style.opacity = '1', 300);
      }},

    // p03: "That's it. One sentence." → dramatic hold
    { file: 'audio-segments/paragraphs/p03.mp3', scene: 2, fallbackDuration: 5000,
      onStart: () => {}},

    // p04: "Alex's AI assistant doesn't know..." → entities appear
    { file: 'audio-segments/paragraphs/p04.mp3', scene: 2, fallbackDuration: 14000,
      onStart: () => {
        setTimeout(() => document.getElementById('s2-bub1').classList.add('visible'), 500);
        setTimeout(() => {
          const el = document.getElementById('s2-clinic');
          el.style.opacity = '1'; el.style.transform = 'translateY(0)';
        }, 3000);
        setTimeout(() => {
          const el = document.getElementById('s2-pharmacy');
          el.style.opacity = '1'; el.style.transform = 'translateY(0)';
        }, 6000);
        setTimeout(() => {
          document.getElementById('s2-bub1').classList.remove('visible');
          document.getElementById('s2-disconnect').style.opacity = '1';
        }, 9000);
        setTimeout(() => document.getElementById('s2-patient').style.opacity = '1', 11000);
      }},

    // p05: "Here's the problem..." → strangers labels
    { file: 'audio-segments/paragraphs/p05.mp3', scene: 2, fallbackDuration: 7000,
      onStart: () => {
        setTimeout(() => document.getElementById('s2-reach-lines').style.opacity = '1', 500);
        setTimeout(() => document.getElementById('s2-bub2').classList.add('visible'), 1500);
        setTimeout(() => {
          document.getElementById('s2-bub2').classList.remove('visible');
          document.getElementById('s2-strangers').style.opacity = '1';
        }, 5000);
      }},

    // p06: "So how does Alex's assistant..." → title + subtitle
    { file: 'audio-segments/paragraphs/p06.mp3', scene: 2, fallbackDuration: 5000,
      onStart: () => {
        setTimeout(() => document.getElementById('s2-title').style.opacity = '1', 500);
        setTimeout(() => document.getElementById('s2-subtitle').style.opacity = '1', 2000);
      }},

    // p07: "Before any data moves..." → Scene 3 transition
    { file: 'audio-segments/paragraphs/p07.mp3', scene: 3, fallbackDuration: 4000,
      onStart: () => {}},

    // p08: "Each organization has a genesis key..." → genesis keys
    { file: 'audio-segments/paragraphs/p08.mp3', scene: 3, fallbackDuration: 10000,
      onStart: () => { stagger(['kl1', 'kl2', 'kl3'], 400, 300); }},

    // p09: "From each genesis key..." → key hierarchy
    { file: 'audio-segments/paragraphs/p09.mp3', scene: 3, fallbackDuration: 8000,
      onStart: () => { stagger(['klA', 'klB'], 400, 300); }},

    // p10: "When Alex's assistant reaches out..." → connections + bubbles
    { file: 'audio-segments/paragraphs/p10.mp3', scene: 3, fallbackDuration: 12000,
      onStart: () => {
        setTimeout(() => {
          document.getElementById('connPC').classList.add('active');
          setTimeout(() => document.getElementById('pktPC').classList.add('visible'), 800);
        }, 500);
        setTimeout(() => document.getElementById('s3-bub1').classList.add('visible'), 800);
        setTimeout(() => {
          document.getElementById('s3-bub1').classList.remove('visible');
          document.getElementById('s3-bub2').classList.add('visible');
        }, 3000);
        setTimeout(() => {
          document.getElementById('s3-bub2').classList.remove('visible');
          document.getElementById('s3-bub3').classList.add('visible');
        }, 5500);
        setTimeout(() => document.getElementById('s3-bub3').classList.remove('visible'), 8000);
      }},

    // p11: "No central directory..." → pharmacy connection
    { file: 'audio-segments/paragraphs/p11.mp3', scene: 3, fallbackDuration: 7000,
      onStart: () => {
        setTimeout(() => {
          document.getElementById('connPP').classList.add('active');
          setTimeout(() => document.getElementById('pktPP').classList.add('visible'), 800);
        }, 300);
        setTimeout(() => document.getElementById('s3-bub4').classList.add('visible'), 1000);
        setTimeout(() => {
          document.getElementById('s3-bub4').classList.remove('visible');
          document.getElementById('s3-bub5').classList.add('visible');
        }, 3000);
        setTimeout(() => document.getElementById('s3-bub5').classList.remove('visible'), 5500);
      }},

    // p12: "And here's what's crucial..." → policy emphasis
    { file: 'audio-segments/paragraphs/p12.mp3', scene: 3, fallbackDuration: 18000,
      onStart: () => {}},

    // p13: "Now trust is established..." → Scene 4 transition
    { file: 'audio-segments/paragraphs/p13.mp3', scene: 4, fallbackDuration: 3000,
      onStart: () => {}},

    // p14: "Alex's assistant asks the clinic..." → clinic data card
    { file: 'audio-segments/paragraphs/p14.mp3', scene: 4, fallbackDuration: 7000,
      onStart: () => {
        setTimeout(() => document.getElementById('s4-bub1').classList.add('visible'), 300);
        setTimeout(() => document.getElementById('clinicData').classList.add('visible'), 800);
        setTimeout(() => document.getElementById('s4-bub1').classList.remove('visible'), 4000);
      }},

    // p15: "But the clinic doesn't just send data..." → receipt
    { file: 'audio-segments/paragraphs/p15.mp3', scene: 4, fallbackDuration: 12000,
      onStart: () => {
        setTimeout(() => document.getElementById('s4-bub2').classList.add('visible'), 300);
        stagger(['rf1','rf2','rf3','rf4','rf5','rf6','rf7','rf8','rf9','rf10'], 350, 1500);
        setTimeout(() => document.getElementById('s4-bub2').classList.remove('visible'), 8000);
      }},

    // p16: "The same thing happens with the pharmacy..."
    { file: 'audio-segments/paragraphs/p16.mp3', scene: 4, fallbackDuration: 7000,
      onStart: () => {
        setTimeout(() => {
          document.getElementById('pharmacyData').classList.add('visible');
          document.getElementById('s4-bub3').classList.add('visible');
        }, 500);
        setTimeout(() => document.getElementById('s4-bub3').classList.remove('visible'), 5000);
      }},

    // p17: "Now Alex's assistant has both pieces..." → Scene 5
    { file: 'audio-segments/paragraphs/p17.mp3', scene: 5, fallbackDuration: 4000,
      onStart: () => {}},

    // p18: "Your prescription was filled..." → synthesis text
    { file: 'audio-segments/paragraphs/p18.mp3', scene: 5, fallbackDuration: 5000,
      onStart: () => {
        setTimeout(() => document.getElementById('synthAnswer').style.opacity = '1', 300);
      }},

    // p19: "Simple. Conversational." → chain nodes
    { file: 'audio-segments/paragraphs/p19.mp3', scene: 5, fallbackDuration: 10000,
      onStart: () => {
        ['cn1','cn2','cn3','cn4'].forEach((id, i) => {
          setTimeout(() => {
            document.getElementById(id).classList.add('visible');
            if (i > 0) document.getElementById(['ca1','ca2','ca3'][i-1]).classList.add('visible');
          }, i * 800);
        });
        setTimeout(() => document.getElementById('synthProof').style.opacity = '1', 3500);
      }},

    // p20: "Anyone can check this chain..." → checkmarks
    { file: 'audio-segments/paragraphs/p20.mp3', scene: 5, fallbackDuration: 8000,
      onStart: () => {
        ['ck1','ck2','ck3','ck4'].forEach((id, i) => {
          setTimeout(() => document.getElementById(id).classList.add('visible'), i * 500 + 300);
        });
        setTimeout(() => document.getElementById('s5-bub1').classList.add('visible'), 2500);
      }},

    // p21: "This is the part that matters most." → Scene 6
    { file: 'audio-segments/paragraphs/p21.mp3', scene: 6, fallbackDuration: 3000,
      onStart: () => {}},

    // p22: "There's no platform..." → items 1-2
    { file: 'audio-segments/paragraphs/p22.mp3', scene: 6, fallbackDuration: 7000,
      onStart: () => { stagger(['ab1','ab2'], 600, 400); }},

    // p23: "The clinic runs its own server..." → items 3-4
    { file: 'audio-segments/paragraphs/p23.mp3', scene: 6, fallbackDuration: 7000,
      onStart: () => { stagger(['ab3','ab4'], 600, 400); }},

    // p24: "This is what portable trust..." → emotional peak
    { file: 'audio-segments/paragraphs/p24.mp3', scene: 6, fallbackDuration: 8000,
      onStart: () => {}},

    // p25: "The agentic age is coming..."
    { file: 'audio-segments/paragraphs/p25.mp3', scene: 6, fallbackDuration: 8000,
      onStart: () => {}},

    // p26: "ZeroPoint makes the math do the work." → Scene 7
    { file: 'audio-segments/paragraphs/p26.mp3', scene: 7, fallbackDuration: 5000,
      onStart: () => {
        setTimeout(() => document.getElementById('closingTagline').classList.add('visible'), 500);
        setTimeout(() => document.getElementById('closingMark').classList.add('visible'), 500);
      }},

    // p27: "Everything you just saw..." → Scene 8
    { file: 'audio-segments/paragraphs/p27.mp3', scene: 8, fallbackDuration: 5000,
      onStart: () => {
        const t = document.getElementById('ctaTerminal');
        setTimeout(() => { t.style.opacity = '1'; t.style.transform = 'translateY(0)'; }, 400);
      }},

    // p28: "The Trust Triangle is one example..."
    { file: 'audio-segments/paragraphs/p28.mp3', scene: 8, fallbackDuration: 12000,
      onStart: () => {
        setTimeout(() => document.getElementById('ctaText').style.opacity = '1', 500);
      }},

    // p29: "The Trust Triangle is healthcare..." → final
    { file: 'audio-segments/paragraphs/p29.mp3', scene: 8, fallbackDuration: 8000,
      onStart: () => {}},
  ];

  let currentParagraph = 0;
  let audioMode = false;
  let started = false;

  const testAudio = new Audio('audio-segments/paragraphs/p01.mp3');
  testAudio.addEventListener('canplaythrough', () => {
    audioMode = true;
    document.getElementById('startLabel').textContent = 'Click to play with narration';
    document.getElementById('startLabel').style.color = 'var(--green)';
  }, { once: true });
  testAudio.addEventListener('error', () => {
    audioMode = false;
    document.getElementById('startLabel').textContent = 'Click to play (no audio found)';
  }, { once: true });

  function firstParagraphOfScene(scene) {
    return paragraphs.findIndex(p => p.scene === scene);
  }

  function updateProgress() {
    document.getElementById('progressBar').style.width = `${(currentScene / totalScenes) * 100}%`;
    document.getElementById('stepIndicator').textContent = `${currentScene} / ${totalScenes}`;
  }

  function stopCurrentAudio() {
    if (currentAudio) {
      currentAudio.pause();
      currentAudio.currentTime = 0;
      currentAudio.onended = null;
      currentAudio.ontimeupdate = null;
      currentAudio = null;
    }
  }

  function startPresentation() {
    if (started) return;
    started = true;
    document.getElementById('startScreen').style.opacity = '0';
    document.getElementById('startScreen').style.transition = 'opacity 0.5s ease';
    setTimeout(() => {
      document.getElementById('startScreen').style.display = 'none';
      document.getElementById('controls').style.display = 'flex';
      if (audioMode) document.getElementById('audioIndicator').style.display = 'block';
    }, 500);
    if (audioMode) playParagraph(0);
    else showSceneTimerMode(1);
  }

  function playParagraph(idx) {
    if (idx < 0 || idx >= paragraphs.length) return;
    currentParagraph = idx;
    const p = paragraphs[idx];
    if (p.scene !== currentScene) {
      currentScene = p.scene;
      document.querySelectorAll('.kf').forEach(el => el.classList.remove('active'));
      document.getElementById(`kf${currentScene}`).classList.add('active');
      updateProgress();
    }
    if (p.onStart) p.onStart();
    stopCurrentAudio();
    clearTimeout(autoTimer);
    const audio = new Audio(p.file);
    currentAudio = audio;
    audio.onended = () => {
      currentAudio = null;
      if (autoPlay && idx + 1 < paragraphs.length) playParagraph(idx + 1);
    };
    audio.onerror = () => {
      currentAudio = null;
      if (autoPlay) autoTimer = setTimeout(() => playParagraph(idx + 1), p.fallbackDuration);
    };
    audio.play().catch(() => {
      currentAudio = null;
      if (autoPlay) autoTimer = setTimeout(() => playParagraph(idx + 1), p.fallbackDuration);
    });
  }

  const sceneDurations = [8000, 45000, 55000, 30000, 25000, 30000, 5000, 20000];

  function showSceneTimerMode(n) {
    currentScene = Math.max(1, Math.min(n, totalScenes));
    document.querySelectorAll('.kf').forEach(el => el.classList.remove('active'));
    document.getElementById(`kf${currentScene}`).classList.add('active');
    updateProgress();
    animateSceneTimerMode(currentScene);
    scheduleNextTimer();
  }

  function scheduleNextTimer() {
    clearTimeout(autoTimer);
    if (autoPlay) {
      autoTimer = setTimeout(() => {
        if (currentScene < totalScenes) showSceneTimerMode(currentScene + 1);
      }, sceneDurations[currentScene - 1]);
    }
  }

  function animateSceneTimerMode(n) {
    switch(n) {
      case 1: paragraphs[0].onStart(); break;
      case 2:
        paragraphs[1].onStart();
        setTimeout(() => paragraphs[3].onStart(), 4000);
        setTimeout(() => paragraphs[4].onStart(), 20000);
        setTimeout(() => paragraphs[5].onStart(), 35000);
        break;
      case 3:
        paragraphs[7].onStart();
        setTimeout(() => paragraphs[8].onStart(), 5000);
        setTimeout(() => paragraphs[9].onStart(), 10000);
        setTimeout(() => paragraphs[10].onStart(), 25000);
        break;
      case 4:
        paragraphs[13].onStart();
        setTimeout(() => paragraphs[14].onStart(), 8000);
        setTimeout(() => paragraphs[15].onStart(), 18000);
        break;
      case 5:
        paragraphs[17].onStart();
        setTimeout(() => paragraphs[18].onStart(), 4000);
        setTimeout(() => paragraphs[19].onStart(), 12000);
        break;
      case 6:
        paragraphs[21].onStart();
        setTimeout(() => paragraphs[22].onStart(), 8000);
        break;
      case 7: paragraphs[25].onStart(); break;
      case 8:
        paragraphs[26].onStart();
        setTimeout(() => paragraphs[27].onStart(), 5000);
        break;
    }
  }

  function showScene(n) {
    currentScene = Math.max(1, Math.min(n, totalScenes));
    document.querySelectorAll('.kf').forEach(el => el.classList.remove('active'));
    document.getElementById(`kf${currentScene}`).classList.add('active');
    updateProgress();
    if (audioMode) {
      const pIdx = firstParagraphOfScene(currentScene);
      if (pIdx >= 0) playParagraph(pIdx);
    } else {
      animateSceneTimerMode(currentScene);
      scheduleNextTimer();
    }
  }

  function nextScene() {
    stopCurrentAudio(); clearTimeout(autoTimer);
    if (currentScene < totalScenes) showScene(currentScene + 1);
    else showScene(1);
  }

  function prevScene() {
    stopCurrentAudio(); clearTimeout(autoTimer);
    if (currentScene > 1) showScene(currentScene - 1);
  }

  function toggleAuto() {
    autoPlay = !autoPlay;
    document.getElementById('autoBtn').textContent = autoPlay ? '⏸ Pause' : '▶ Play';
    if (!autoPlay) {
      clearTimeout(autoTimer);
      if (currentAudio) currentAudio.pause();
    } else {
      if (audioMode) {
        if (currentAudio) currentAudio.play();
        else playParagraph(currentParagraph);
      } else scheduleNextTimer();
    }
  }

  function stagger(elements, delayMs = 150, startMs = 300) {
    elements.forEach((el, i) => {
      const elem = typeof el === 'string' ? document.getElementById(el) : el;
      if (elem) {
        elem.classList.remove('visible');
        setTimeout(() => elem.classList.add('visible'), startMs + (i * delayMs));
      }
    });
  }