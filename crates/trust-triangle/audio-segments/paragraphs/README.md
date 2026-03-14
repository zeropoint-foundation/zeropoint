# Per-Paragraph Audio Files

Each paragraph of narration is its own audio file, giving precise control
over animation timing. The animation plays them sequentially — when one
finishes, the next visual beat triggers and the next file plays.

## Rendering Notes
- Pace: ~150 wpm for technical, ~170 wpm for narrative
- Leave ~0.5s natural pause at the end of each file
- Maintain consistent tone/volume across files (same session)

## File → Scene → Visual Event Mapping

| File | Scene | Visual Event | Text (first few words) |
|------|-------|--------------|----------------------|
| `p01.mp3` | 1 | Terminals booting up | "This is the Trust Triangle..." |
| `p02.mp3` | 1→2 | **Transition to Scene 2** — question fades in | "Alex Chen opens their phone..." |
| `p03.mp3` | 2 | Hold on question, dramatic beat | "That's it. One sentence..." |
| `p04.mp3` | 2 | Clinic + Pharmacy entities appear | "Alex's AI assistant doesn't know..." |
| `p05.mp3` | 2 | Disconnect indicator, "strangers" labels | "Here's the problem..." |
| `p06.mp3` | 2 | Reach lines + question marks from patient | "So how does Alex's assistant..." |
| `p07.mp3` | 2→3 | **Transition to Scene 3** — handshake begins | "Before any data moves..." |
| `p08.mp3` | 3 | Genesis keys animate in | "Each organization has what ZeroPoint calls..." |
| `p09.mp3` | 3 | Key hierarchy (genesis→operator→agent) | "From each genesis key, a chain of authority..." |
| `p10.mp3` | 3 | Connection lines draw, cert chain packets | "When Alex's assistant reaches out..." |
| `p11.mp3` | 3 | Triangle fully formed, mutual trust | "No central directory was consulted..." |
| `p12.mp3` | 3 | Policy engine emphasis | "And here's what's crucial..." |
| `p13.mp3` | 3→4 | **Transition to Scene 4** — exchange begins | "Now trust is established..." |
| `p14.mp3` | 4 | Clinic data card fades in | "Alex's assistant asks the clinic..." |
| `p15.mp3` | 4 | Receipt visualization, fields reveal | "But the clinic doesn't just send data..." |
| `p16.mp3` | 4 | Pharmacy data card fades in | "The same thing happens with the pharmacy..." |
| `p17.mp3` | 4→5 | **Transition to Scene 5** — provenance chain | "Now Alex's assistant has both pieces..." |
| `p18.mp3` | 5 | Synthesis answer text fades in | "Your prescription was filled..." |
| `p19.mp3` | 5 | Chain nodes + arrows appear | "Simple. Conversational..." |
| `p20.mp3` | 5 | Verification checkmarks cascade | "Anyone can check this chain..." |
| `p21.mp3` | 5→6 | **Transition to Scene 6** — "What's Not Here" | "This is the part that matters most." |
| `p22.mp3` | 6 | Strikethrough grid items appear | "There's no platform in the middle..." |
| `p23.mp3` | 6 | More grid items + governance line | "The clinic runs its own server..." |
| `p24.mp3` | 6 | Emotional peak — portable trust | "This is what portable trust..." |
| `p25.mp3` | 6 | Closing thought, agentic age | "The agentic age is coming..." |
| `p26.mp3` | 6→7 | **Transition to Scene 7** — tagline | "ZeroPoint makes the math do the work." |
| `p27.mp3` | 7→8 | **Transition to Scene 8** — CTA begins | "Everything you just saw..." |
| `p28.mp3` | 8 | Git clone terminal visible | "The Trust Triangle is one example..." |
| `p29.mp3` | 8 | Final CTA text, URLs visible | "The Trust Triangle is healthcare..." |

## Scene Transitions

Transitions happen at the *start* of specific paragraphs:

| Transition | Trigger |
|-----------|---------|
| Scene 1 → 2 | p02 starts |
| Scene 2 → 3 | p07 starts |
| Scene 3 → 4 | p13 starts |
| Scene 4 → 5 | p17 starts |
| Scene 5 → 6 | p21 starts |
| Scene 6 → 7 | p26 starts |
| Scene 7 → 8 | p27 starts |
