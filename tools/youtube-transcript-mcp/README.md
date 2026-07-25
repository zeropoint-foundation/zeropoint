# youtube-transcript-mcp

A resilient MCP tool for fetching YouTube transcripts, built for the reality that
YouTube now blocks the naive transcript path from datacenter/cloud IPs. Instead of
one scraper that fails silently, it runs a **fallback ladder** behind a single tool
and records which rung served each result.

```
cache  →  youtube-transcript-api  →  yt-dlp subtitles  →  managed API  →  local ASR
(free) (free, structured, best)    (free, diff. failure)  (paid, opt-in) (opt-in, whisper)
```

Every rung normalizes to one schema, so callers get identical output regardless of
path — with `source` and `cache_hit` provenance fields telling you where it came from.

## Why a ladder (not just a library)

The thing that broke in the last ~18 months isn't the parsing libraries — it's that
YouTube started blocking datacenter IPs from the `timedtext` endpoint. `youtube-transcript-api`
works on a residential IP and throws `RequestBlocked`/`IpBlocked` from a cloud box.
`yt-dlp` hits the same wall from a different code path (and now PO-token requirements).
So the ladder's rungs fail *independently* — when one is blocked, the next usually isn't —
and the cache means you pay the fetch cost for any (video, language) pair at most once.

## Tools

| Tool | What it does |
|---|---|
| `youtube_get_transcript` | Fetch a transcript. Params: `video`, `languages`, `translate_to`, `use_cache`, `response_format` (`json`/`text`/`markdown`). |
| `youtube_list_transcripts` | List available caption tracks (language, generated?, translatable?). |
| `youtube_cache_info` | Inspect cache stats; optionally clear (all or one video). |

`youtube_get_transcript` (json) returns:

```json
{
  "video_id": "…", "language": "English", "language_code": "en",
  "is_generated": true, "translated_to": null,
  "source": "youtube_transcript_api", "cache_hit": false,
  "segments": [{"start": 0.0, "duration": 3.2, "text": "…"}],
  "text": "full plain transcript …",
  "duration_seconds": 612.4, "fetched_at": "2026-07-21T…Z"
}
```

## Install (phase 1 — local on APOLLO)

Running locally means a residential IP, so the free path just works — no proxy, no keys.

```bash
cd /Users/kenrom/projects/zeropoint/tools/youtube-transcript-mcp

# Isolated venv (recommended so it doesn't touch the ZP toolchain)
python3 -m venv .venv
.venv/bin/pip install -e .
# optional local-ASR rung: .venv/bin/pip install -e ".[asr]"  (also needs ffmpeg)
```

Register it with the Claude desktop app so Claude can call it. Edit
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "youtube-transcript": {
      "command": "/Users/kenrom/projects/zeropoint/tools/youtube-transcript-mcp/.venv/bin/youtube-transcript-mcp"
    }
  }
}
```

Restart the app. The three `youtube_*` tools then appear to Claude. Add any optional
config from `.env.example` as `"env": { … }` in that same block if you enable proxies,
a managed provider, or ASR.

Quick CLI sanity check (no MCP client needed):

```bash
.venv/bin/python -c "from youtube_transcript_mcp.core import get_transcript; \
print(get_transcript('dQw4w9WgXcQ')['text'][:200])"
```

## Configuration

All optional — see `.env.example` for the full list. The ones that matter:

- **Cache location** — `YTMCP_CACHE_DIR` (default `~/.cache/youtube-transcript-mcp/`).
  Point it at `~/ZeroPoint/data/transcripts` to keep it inside the ZP runtime home.
- **Residential proxy** (only for server-side / phase 2) — `YTMCP_WEBSHARE_USERNAME` +
  `YTMCP_WEBSHARE_PASSWORD`, or `YTMCP_HTTP_PROXY`/`YTMCP_HTTPS_PROXY`.
- **Managed backstop** — `YTMCP_MANAGED_API_KEY` (+ `YTMCP_MANAGED_PROVIDER`). Off until set.
- **Local ASR** — `YTMCP_ENABLE_ASR=1` (needs the `[asr]` extra + ffmpeg). Off by default.

## Phase 2 — ZeroPoint integration

The ladder lives in `core.py`/`fetchers.py`/`cache.py` with **zero MCP dependency**, so
ZeroPoint can consume it directly:

```python
from youtube_transcript_mcp.core import get_transcript, list_transcripts
record = get_transcript("https://youtu.be/…", languages=["en"])
```

Two things change when this runs inside ZeroPoint server-side rather than on APOLLO:

1. **IP posture becomes load-bearing.** From `zp-playground` (a datacenter IP) the API and
   yt-dlp rungs will be blocked, so you must either set the Webshare/proxy env vars or enable
   the managed rung. The ladder already degrades to whichever rung can reach YouTube; the
   only decision is which paid path (residential proxy vs managed API) you contract for.
2. **Provenance → chain receipts.** The `source`/`cache_hit`/`fetched_at` fields are exactly
   what a `transcript:fetched` receipt would carry. Fetch is *contact*, not *commit* — a fetch
   reaches the world but shouldn't mutate substrate state until an operator-signed receipt
   records it (P7). Natural shape: the cache write and a signed receipt land together, and the
   normalized record is the artifact the receipt cites.

The Rust side can either shell out to the console script (`youtube-transcript-mcp` over stdio)
or port the ladder; the normalized schema is the contract either way.

## Notes / limitations

- **Translation** is only supported by the API rung (it uses YouTube's own translation). If
  the API rung is blocked, `translate_to` requests fall through to source-language captions.
- **Managed provider adapter** in `fetchers._call_managed_provider()` targets Supadata's shape
  as a template — verify the current request/response format against your provider before
  relying on it. Any error there is treated as a normal rung failure.
- **ASR** ignores `translate_to` (it produces source-language text) and needs `ffmpeg` on PATH.
- stdio transport logs to **stderr only**, so it never corrupts the JSON-RPC stream.
