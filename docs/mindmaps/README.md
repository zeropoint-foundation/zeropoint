# docs/mindmaps

Structured mindmap JSONs — one file per topic. Source of truth only; rendered
HTML is not committed (see *Why JSON-only* below).

Renderer: `tools/mindmap-mcp` (see that directory's README for the tool
surface). Default theme is `zp-dark`, matching the ZP web palette pulled from
`zeropoint.global/tools/mindgraph.html`. Render is deterministic — same JSON
+ same theme → identical HTML byte-for-byte.

## Index

| Artifact | Source | Tier |
|---|---|---|
| `ai-companion-architecture-2026-07.json` | Session synthesis (2026-07-23), see handoff | Historical (Tier 3) |
| `companionrank-methodology-2026-07.json` | `companionrank.com/methodology` capture | Historical (Tier 3) |
| `rfab-ai-chat-review-2026-07.json` | `rfab.ai/blog/ai-chat-review` capture | Historical (Tier 3) |
| `butlerian-jihad-ai-girlfriends-2026-07.json` | Collins podcast transcript | Historical (Tier 3) |
| `hot-girl-service-economy-2026-07.json` | Collins podcast transcript | Historical (Tier 3) |

The five above land as Tier-3 historical per
`docs/CANONICAL-CORPUS-INDEX-2026-07.md` conventions — reasoning trail, not
canonical claims. A future mindmap rendered to argue a Tier-2 elaboration
would sit alongside the doc it argues for, not here.

## Why JSON-only

The HTML is a deterministic derivation of `JSON + renderer + theme`.
Committing both duplicates the data path (P4 *every bit counts*) and lets
the derived artifact drift silently the moment the renderer changes. The
JSON is the source; the HTML is a view.

## Regenerating

To rebuild any artifact for viewing:

```bash
cd tools/mindmap-mcp
.venv/bin/python -c "
import json, sys
from mindmap_mcp.core import render_mindmap
slug = 'ai-companion-architecture-2026-07'
mm = json.load(open(f'../../docs/mindmaps/{slug}.json'))
out = f'/tmp/{slug}.html'
open(out, 'w').write(render_mindmap(mm, theme='zp-dark'))
print(out)
"
open /tmp/ai-companion-architecture-2026-07.html
```

Swap the slug for whichever mindmap you want. The tool re-render takes under
a second per mindmap, and every render carries the current toolbar
(theme toggle, PDF/SVG/Markdown/JSON exports).

## Reasoning trail

The AI-companion-architecture arc is documented in
`docs/handoffs/ai-companion-architecture-research-2026-07-23.md`. That
handoff has the full reasoning + four ZP resonances against the substrate's
current elaborations (empirical program, shadow-evaluation primitive,
substrate-blindness heuristics, extension surface).
