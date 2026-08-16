# AI Landscape — Sources

Read each morning by the `zp-ai-landscape-sweep` scheduled task.

## This file is a floor, not a ceiling

**Operator direction, 2026-08-13:** the sources named here are the ones that get
checked *by default*. They are not the extent of the sweep. Every run should cast
wider than this file — the channel list below is a guaranteed minimum, and §
"Widening classes" names the ground to cover beyond it.

The failure this guards against is a sweep that quietly narrows to its own
bookmark list and starts reporting the same four voices' opinions as though they
were the landscape. A curated default plus a mandate to range is the shape that
survives; a fixed list alone is not.

---

## Default YouTube channels

One channel per line, `<channel_id> # <channel name>`. Lines starting with `#`
are ignored.

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

---

## Widening classes

Ground the sweep should cover beyond the defaults. Not a checklist to exhaust
every run — a map of where to range, weighted by what the lens is for. A run that
only ever returns items from the default channels and the first page of a search
has not swept.

### 1. Non-English primary text — highest value, most neglected

Earned the hard way on 2026-08-13: three independent English summaries of one CAC
document each supplied a detail the Chinese original does not contain — an
effective date, a tiering axis, a pre-deployment requirement. All three were in a
ZeroPoint steering brief before the original was read.

- **China** — `cac.gov.cn` (CAC), MIIT, NDRC, TC260 standards drafts. Expert
  commentary (专家解读) and press Q&A (答记者问) pages are usually published
  alongside the instrument itself and are often more legible than the text.
- **EU** — EUR-Lex, the AI Office, EDPB, national DPAs. French and German
  regulatory commentary frequently precedes English coverage.
- **Japan / Korea** — METI, PIPC, and the Korean AI Basic Act ecosystem.
- **Rule:** if an item turns on the content of a non-English instrument, read the
  instrument. Otherwise label the item as resting on translation.

### 2. Standards and specification venues

Where the actual protocols land, usually months before commentary notices.

- IETF datatracker (agent identity, delegation, OAuth extensions), W3C, C2PA /
  CAWG, Linux Foundation projects (x402 Foundation), DIF, OpenID Foundation.
- NIST (AI RMF and successors), ISO/IEC JTC 1/SC 42.
- **Watch for name collisions** — 2026-08-13 turned up two unrelated "AIP"s, the
  IETF Agent Identity Protocol and China's state-backed Agent Interconnection
  Protocol. Disambiguate on every mention.

### 3. Preprints

arXiv `cs.CR`, `cs.AI`, `cs.MA`, `cs.SE`. Agent identity, delegation, sandbox
escape, capability control, verifiable inference. Preprints surfaced the AIP
drafts before any trade coverage.

### 4. Vendor engineering blogs beyond the frontier labs

The default weighting toward Anthropic / OpenAI / Google / Meta is right but
incomplete. Liquid AI's LFM2.5 release was a load-bearing item on 2026-08-13 and
appears on no list anywhere. Also: Mistral, Qwen/Alibaba, DeepSeek, Moonshot,
Zhipu, Cohere, Together, Groq, Cerebras, Hugging Face, Ollama, llama.cpp.

### 5. Release and artifact signals

Often the earliest honest signal, because it is the thing itself rather than an
announcement about it.

- GitHub releases and changelogs for substrate-adjacent projects.
- Hugging Face model cards and licence changes — a licence shift is a strategic
  move and rarely gets its own press release.

### 6. Security disclosure channels

CVE / NVD, vendor security advisories, CISA, conference proceedings (Black Hat,
DEF CON, USENIX Security, IEEE S&P). Agent sandbox escapes, MCP supply chain,
prompt injection with real consequence.

### 7. Regulatory and legal primary text, non-EU/China

US Federal Register, state legislatures (CA, NY, TX, IL — Illinois SB315 landed
2026-07 and was found only via a vendor blog), UK (DSIT, Ofcom, ICO), Canada,
India, Brazil, Singapore IMDA.

### 8. Deliberately off-beat

The `House of El` geopolitics channel is on the default list on purpose — it is
off the AI beat and closest to the sovereignty questions ZeroPoint exists to
answer. Generalise that: adjacent-domain framing is often where a lens earns its
keep. Payments infrastructure, identity and KYC, supply-chain provenance in other
industries, energy and compute markets, insurance and liability.

---

## Promotion — how this list grows

When a run finds a load-bearing item from a source **not** on this list, name the
source in the log entry and add a line to "Candidate sources" below. A source
that produces two load-bearing items should be promoted into the defaults.

Symmetrically, per "Notes on curation", a default that produces nothing for two
months is a pruning candidate. The list should churn. A sources file that has not
changed in a quarter is either perfectly curated or not being read — and the
second is far more likely.

### Candidate sources

<!-- Append: `- <source>  # <date first hit>, <what it produced>` -->

- liquid.ai engineering blog  # 2026-08-13, LFM2.5-2.6B on-device agent release,
  verified at source after an aggregator got the hardware claim wrong
- cac.gov.cn (incl. 专家解读 / 答记者问 pages)  # 2026-08-13, the Implementation
  Opinions original — three English summaries had each invented a detail
- IETF datatracker agent-identity drafts  # 2026-08-13, three competing drafts
  sharing the AIP acronym; pre-convergence signal
- anthropic.com/research (Frontier Red Team posts)  # 2026-08-13, the multiagent
  turf-war / collusion / epistemics study — measured evidence for the absence ZP
  is built on, with a prescribed direction that is mechanism design rather than
  identity. Distinct from red.anthropic.com, which carries the cyber work.
- Hugging Face model cards and licence files  # 2026-08-13, MiniMax H3's
  territory exclusion of US/EU/UK/Korea — a licence clause, surfaced by no
  announcement anywhere
- docs.cloud.google.com product docs (GA / Preview status labels)  # 2026-08-13,
  Agent Identity GA vs Agent Gateway Private Preview — vendor docs separated
  shipped from announced where the announcements did not
- developer.nvidia.com / blogs.nvidia.com (engineering + technical blogs)  #
  2026-08-14, NVIDIA-verified agent skills (signed capability artifacts, skill
  cards, OpenSSF Model Signing) and the SAFE RFC; NVIDIA's own deployment blog
  also settled the Qwen3.8-Max release question two prior sweeps left open
- IETF datatracker  # 2026-08-14, SECOND load-bearing item
  (draft-reece-wimse-cross-org-delegation, R1-R9 requirements) after the AIP
  drafts on 2026-08-13 — **promotion candidate for the default list**
- news.cn / 人民邮电报 and china.com.cn / 央视新闻 (Chinese-language state
  outlets)  # 2026-08-15, TWO load-bearing items in one run — the GB/Z 185-2026
  agent-interconnection standard series with 2,000+ 智能体身份码 issued, and the
  20263116-Q-252 mandatory agent-security standard plan. Both read in the
  original; English search coverage collapsed 指导性 (guidance) into "standard"
  and would have produced a wrong item. **Promotion candidate for the defaults.**
- eips.ethereum.org / ERC-8004 + on-chain agent registries  # 2026-08-15,
  Trustless Agents live on mainnet since Jan 2026 with ERC-721-based agent
  identity — an entire lineage this log had never once mentioned
- arXiv bibliographies as a traversal surface (not a source, a method)  #
  2026-08-15, produced four of the run's items; following one preprint's
  reference list outperformed every seed-term search
- fidoalliance.org (Agentic AI focus area + working groups)  # 2026-08-16, the
  Agentic Authentication TWG and Payments TWG, with Google AP2 and Mastercard
  Verifiable Intent as founding contributions — a whole standards body absent
  from five prior entries, found by blind-spot grep rather than by search
- anthropic.com/news + support.claude.com  # 2026-08-16, the SynthID-Text-derived
  text watermark and C2PA file credentials, applied worldwide; the two pages
  carry different details and both were needed. Distinct from
  anthropic.com/research, already listed for the Frontier Red Team work
- ox.security/research-news  # 2026-08-16, the MCP STDIO command-injection full
  disclosure — closed a structural claim three prior sweeps had left unverified,
  and its "Rejected Disclosures" list was the load-bearing part
- IETF datatracker  # 2026-08-16, THIRD load-bearing item (the eleven-draft
  agent-authorization field, and DAAP's hash-chain/cascade-revocation schemas).
  **Past the promotion bar — move into the defaults.**
- stdaily.com / secrss.com (Chinese-language standards coverage)  # 2026-08-16,
  carry the GB/Z 185-2026 series announcement in the original; no new item this
  run, recorded as reachable primaries for future Chinese-language legs
