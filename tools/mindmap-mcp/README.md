# mindmap-mcp

A structured-mindmap generator + renderer, exposed as an MCP tool. Same shape
as `youtube-transcript-mcp`: a normalized schema, a resilient ladder of
extraction rungs, a rendering surface that has no MCP dependency so ZeroPoint
can consume it directly.

```
extract:   openai → anthropic → local              (LLM ladder — pick whichever's configured)
render:    JSON  →  SVG  →  self-contained HTML    (no CDN, no browser storage, no external fonts)
themes:    zp-dark | zp-light | mylens | mono      (light/dark toggle at runtime — no round-trip)
export:    PDF · SVG · Markdown outline · JSON     (from the rendered artifact's toolbar)
```

The visual language is patterned after MyLens.ai — a central pill, branches
splitting left and right, sub-nodes and leaves fanning outward with smooth
cubic-bezier connectors. Default palette matches the ZeroPoint web surfaces
(pulled from `zeropoint.global/tools/mindgraph.html`): `--bg #0a0a0c`,
`--accent #7eb8da`, `--text-primary #e8e8ec`, Inter font stack. The six
branch colors reuse the palette ZP already uses across its dashboards
(teal `#94e2d5`, coral `#f87171`, saffron `#fbbf24`, lavender `#a78bfa`,
sage `#34d399`, rose `#fb923c`).

**Runtime UI on every rendered HTML:**

- **Theme toggle** (☾/☀) — flips between `zp-dark` and `zp-light` instantly.
  Both palettes ship in the file itself; no CDN, no server round-trip.
- **PDF export** — routes through `window.print()` with a dedicated
  `@media print` stylesheet: toolbar/editor hidden, canvas set to fit
  landscape A4/Letter with 12 mm margins. Users get their OS's Save-as-PDF.
- **SVG export** — the current-theme SVG as a standalone file, ready to
  drop into Figma or a Cloudflare Pages deploy.
- **Markdown outline** — the mindmap flattened into headers-and-bullets:
  `# title / _subtitle_ / ## branch / ### sub / - leaf`. Ideal for pasting
  into notes, blog posts, or a doc.
- **JSON export** — round-trip source for editing the same mindmap elsewhere.
- **Edit JSON** — a slide-out editor. Change anything, press Render, watch
  the tree re-layout live.

## Tools

| Tool | What it does |
|---|---|
| `mindmap_extract` | Extract a structured mindmap from long text (transcript, article, notes) via the LLM ladder. |
| `mindmap_render` | Render a mindmap JSON as self-contained HTML or SVG. Default theme is `zp-dark`; the rendered HTML carries a toolbar for runtime theme toggle + PDF/SVG/Markdown/JSON exports. |
| `mindmap_themes` | List the available themes. |

`mindmap_extract` returns:

```json
{
  "title": "The Hot Girl Service Economy",
  "subtitle": "One sentence about the piece.",
  "center": {"label": "Central thesis", "emoji": "💅"},
  "branches": [
    {
      "label": "Top-level category",
      "emoji": "🌴",
      "color": "teal",
      "children": [
        {
          "label": "Subcategory",
          "children": [{"label": "leaf point ≤40 chars"}]
        }
      ]
    }
  ],
  "footnotes": ["short bullet"],
  "source": "openai",
  "generated_at": "2026-07-23T…Z"
}
```

`mindmap_render` accepts that shape verbatim and produces:

- **`format=html`** — a single self-contained document, no CDN, no browser
  storage. Includes an optional slide-out editor for live JSON tweaking.
- **`format=svg`** — just the SVG element for embedding elsewhere.

## Install (phase 1 — local on APOLLO)

```bash
cd /Users/kenrom/projects/zeropoint/tools/mindmap-mcp

python3 -m venv .venv
.venv/bin/pip install -e .
# optional provider SDKs: .venv/bin/pip install -e ".[openai,anthropic]"
```

Register it with the Claude desktop app so Claude can call it. Edit
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mindmap": {
      "command": "/Users/kenrom/projects/zeropoint/tools/mindmap-mcp/.venv/bin/mindmap-mcp",
      "env": {
        "MMCP_OPENAI_API_KEY": "sk-…",
        "MMCP_OPENAI_MODEL": "gpt-4o-mini"
      }
    }
  }
}
```

Restart the app. `mindmap_render`, `mindmap_extract`, and `mindmap_themes`
then appear to Claude. Any subset of provider env vars is fine — the ladder
degrades to whichever is configured.

Quick sanity check (no MCP client needed):

```bash
.venv/bin/python -c "
from mindmap_mcp.core import render_mindmap
mm = {
  'title':'Demo','subtitle':'A quick smoke test',
  'center':{'label':'ZeroPoint','emoji':'⚙️'},
  'branches':[
    {'label':'Trust','emoji':'🔑','color':'teal','children':[
      {'label':'Signing','children':[{'label':'Ed25519'},{'label':'Genesis-rooted'}]}
    ]},
    {'label':'Ontology','emoji':'🗺️','color':'coral','children':[
      {'label':'Trajectory'},{'label':'Decision'}
    ]},
  ]
}
open('/tmp/mm.html','w').write(render_mindmap(mm))
print('/tmp/mm.html written')
"
open /tmp/mm.html
```

## Composition with youtube-transcript-mcp

The two tools are designed to compose. Typical flow with Claude Desktop:

1. Claude calls `youtube_get_transcript(video=<url>)` — plain text out.
2. Claude calls `mindmap_extract(text=<transcript.text>)` — structured JSON out.
3. Claude calls `mindmap_render(mindmap=<json>, theme='mylens')` — HTML out.
4. Claude sends the HTML to the user with `SendUserFile`.

Neither tool depends on the other at the code level (no imports across
package boundaries) — they compose in the caller's control flow, which
matches ZeroPoint's *one canonical path per substrate concern* discipline
(each tool owns exactly one concern).

## Configuration

All optional — see `.env.example` for the full list. The ones that matter:

- **Extraction rungs** — one or more of `MMCP_OPENAI_API_KEY` /
  `MMCP_ANTHROPIC_API_KEY` / `MMCP_LOCAL_BASE_URL`. Off until set.
- **Renderer defaults** — `MMCP_DEFAULT_THEME`, `MMCP_DEFAULT_WIDTH`,
  `MMCP_DEFAULT_HEIGHT` (currently unused; renderer sizes to content).

## Phase 2 — ZeroPoint integration

Same shape as the transcript tool: the ladder lives in `core.py` /
`renderer.py` / `common.py` with **zero MCP dependency**, so ZeroPoint can
consume it directly:

```python
from mindmap_mcp.core import extract_mindmap, render_mindmap
mm = extract_mindmap(long_text, provider="auto")
html = render_mindmap(mm, theme="brand")   # zeropoint.global-tinted variant
```

The `source` and `generated_at` fields are exactly what a `mindmap:extracted`
receipt would carry. Extraction is *contact*, not *commit* — reaches the
world (or a local model) but shouldn't mutate substrate state until an
operator-signed receipt records it. Natural shape: the render output is the
artifact the receipt cites (per the artifact-library pattern — cheap
proposals, expensive decisions).

## Notes / limitations

- **JSON compliance** varies by model tier. `response_format: json_object` on
  the OpenAI rung keeps the return shape strict; the Anthropic rung falls back
  to defensive stripping if the model wraps in a code block. Local rungs
  (small models) may fail JSON validation more often — the ladder catches
  and moves on to the next rung.
- **Renderer is deterministic and pure** — same JSON in produces byte-identical
  HTML out. Convenient for content-addressed artifacts.
- **No external fonts / CDN loads.** System font stack only (Inter fallback).
  The rendered file works offline, in email, on a printed PDF export.
- **No browser storage.** Editor state lives in the textarea; not persisted
  across reloads. This matches the constraint documented for claude.ai
  artifacts and keeps the file portable to any hosting surface.
- stdio transport logs to **stderr only**, so it never corrupts the JSON-RPC stream.
