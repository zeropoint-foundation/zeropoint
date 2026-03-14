# Audio Segments — Trust Triangle Narration

Five audio files, one per segment. Render each separately so scene
durations can be matched to actual narration length.

## Rendering notes

- **Pace**: Conversational but deliberate. ~150 wpm for technical sections,
  ~170 wpm for narrative flow. Not rushed, not solemn.
- **Pauses**: Each segment file includes `[pause Xs]` markers. These are
  breathing room for visuals to land. Render as actual silence in the audio.
- **Emphasis**: Words in `*asterisks*` get slight vocal stress, not dramatic.
- **Tone**: Confident explainer, not hype. Think conference keynote, not ad.

## File mapping

| File | Animation Scenes | Est. Duration |
|------|-----------------|---------------|
| `01-setup.txt` | Scenes 1–2 | ~45s |
| `02-introduction.txt` | Scene 3 | ~60s |
| `03-exchange.txt` | Scene 4 | ~35s |
| `04-provenance.txt` | Scenes 5–6 | ~55s |
| `05-closing-cta.txt` | Scenes 7–8 | ~30s |

**Total**: ~3:45–4:15

## After rendering

Drop the audio files (mp3 or wav) into this directory as:
`01-setup.mp3`, `02-introduction.mp3`, etc.

Then update `sceneDurations` in `trust-triangle-animation.html` to match
actual audio lengths. The animation already has `<audio>` elements wired
to auto-play per scene — just uncomment them once the files are in place.
