# AI Landscape — YouTube Source Channels

Read each morning by the `zp-ai-landscape-sweep` scheduled task. One channel per
line, `<channel_id> # <channel name>`. Lines starting with `#` are ignored.

Every ID below was verified by fetching its RSS feed and confirming the returned
channel title — not taken from a search result or a handle. Handles are not
channel IDs and the legacy `?user=` form is unreliable: `?user=houseofel`
resolves to an unrelated channel called "McCoy Ink".

## Why channel IDs and not the subscription feed

The sweep is unattended and must not depend on a logged-in browser. Ken uses
Comet, so the Chrome MCP is unavailable, and computer-use grants browsers
read-tier only — visible in screenshots, not drivable. A browser-driven scrape
of the subscriptions page would break silently the first time a layout changed
or a session expired, and a research task that fails quietly is worse than one
that never ran.

Per-channel RSS at `https://www.youtube.com/feeds/videos.xml?channel_id=<ID>`
needs no auth, no session and no browser. It returns new uploads with video IDs,
which the `youtube-transcript` MCP then turns into transcripts.

The cost is that this list is curated rather than automatic — it does not track
subscription changes. That is a fair trade for a task that has to work every
morning without supervision, and it also means the list is a deliberate
statement of which voices are worth a daily read, which a raw subscription dump
is not.

## Finding a channel ID

The `@handle` in a URL is not the channel ID. Either:

- Open the channel, view source, and search for `"channelId":"UC…"`, or
- Visit `https://www.youtube.com/@handle` and check the RSS link in the page
  head, or
- Try `https://www.youtube.com/feeds/videos.xml?user=<handle>` — works for
  older accounts only.

Channel IDs always begin `UC` and are 24 characters.

## Channels

UC0C-17n9iuUQPylguM1d-lQ  # AI News & Strategy Daily | Nate B Jones
UCsoc5Ad-fC7wWie2PH4rPcw  # House of El: AI
UCJ52xpIoq5aKaIU_ZP40-nQ  # House of El
UCvxm0qTrGN_1LMYgUaftWyQ  # Peter H. Diamandis (Moonshots)

<!-- Add below, one per line: UC…  # Channel Name -->

### Why these four

Named by the operator 2026-08-11 as default transcript pulls. Two are close to
the lens's centre and two are wider on purpose:

- **Nate B Jones** — daily AI news and strategy, ~1,000 videos since May 2024.
  Highest expected signal density per fetch; likely the workhorse.
- **House of El: AI** — AI explained by a computer-science PhD building in
  finance. Analytical rather than announcement-driven.
- **House of El** — the same author on geopolitics, currencies and how systems
  are built and for whom. Off the AI beat, and the closest thing here to the
  sovereignty and trust questions ZeroPoint exists to answer. Adjacent-domain
  framing is often where a lens earns its keep.
- **Peter H. Diamandis (Moonshots)** — long-horizon technology framing. Lowest
  density, longest range; good for the *noted for pattern* section rather than
  load-bearing items.

The two House of El channels are distinct: `@HouseofEl-AI` (2025, AI) and
`@HouseofEl` (2020, geopolitics). Both verified separately.

## Notes on curation

Worth pruning as well as adding. A channel that has not produced a load-bearing
item in two months is costing a transcript fetch a day for nothing — the same
signal-density argument the log itself is built on. The log records which source
produced each entry, so the evidence for pruning accumulates on its own.
