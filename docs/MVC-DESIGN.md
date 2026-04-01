# Minimum Viable Credentials (MVC) — Design Document

## Problem

ZeroPoint's configure engine treats every variable in a tool's `.env.example` as equally
important. A project like PentAGI lists 80+ env vars spanning a dozen providers, but it
can run fully with just an Anthropic key and a local Ollama instance. The current system
reports "missing 34 credential(s)" and skips the tool entirely.

Users should store their API keys once during onboard. Every tool they install should
just work — autoconfigured with whatever providers they have, no `.env` editing ever again.

## Core Concept: Capabilities, Not Variables

The engine stops thinking in env vars and starts thinking in **capabilities** — abstract
roles that a provider can fill. A tool declares which capabilities it needs. The engine
resolves each capability to whichever provider the user actually has keys for.

---

## 1. Capability Taxonomy

### 1.1 Language & Reasoning

| Capability | Description | Example Providers |
|---|---|---|
| `reasoning_llm` | Frontier-class model for complex tasks — planning, analysis, multi-step reasoning, long-context synthesis | Claude Opus/Sonnet, GPT-4o, Gemini Pro, DeepSeek-R1 |
| `fast_llm` | Lightweight model for high-volume, low-latency tasks — classification, extraction, formatting, routing | Claude Haiku, GPT-4o-mini, Gemma 3, Qwen 3 |
| `code_llm` | Code-specialized model for generation, review, debugging, refactoring | Claude Sonnet, GPT-4o, DeepSeek-Coder, Codestral |
| `long_context_llm` | 100K+ token context for large document processing, codebase analysis, transcript summarization | Claude (200K), Gemini (1M+), GPT-4o (128K) |

### 1.2 Vision & Image

| Capability | Description | Example Providers |
|---|---|---|
| `vision` | Image understanding — OCR, scene description, diagram parsing, visual Q&A | Claude, GPT-4o, Gemini, LLaVA (local) |
| `image_gen` | Image creation from text prompts — illustrations, diagrams, concept art, UI mockups | DALL-E 3, Stable Diffusion (local), Midjourney, Flux, Ideogram |
| `image_edit` | Inpainting, outpainting, style transfer, background removal on existing images | DALL-E edit, Stable Diffusion img2img, Adobe Firefly |

### 1.3 Audio

| Capability | Description | Example Providers |
|---|---|---|
| `tts` | Text-to-speech — narration, voice interfaces, accessibility | OpenAI TTS, ElevenLabs, Google Cloud TTS, Coqui (local), Bark (local) |
| `asr` | Automatic speech recognition — transcription, real-time dictation, meeting notes | OpenAI Whisper, Deepgram, Google Speech, Whisper.cpp (local) |
| `audio_gen` | Music and sound effect generation — scoring, ambient audio, sound design | Suno, Udio, MusicGen (local), AudioCraft (local) |
| `voice_clone` | Voice cloning and custom voice synthesis from reference samples | ElevenLabs, Coqui, RVC (local) |

### 1.4 Video & 3D

| Capability | Description | Example Providers |
|---|---|---|
| `video_gen` | Video generation from text or image prompts — clips, animations, storyboards | Sora (OpenAI), Runway Gen-3, Pika, Kling, Veo (Google) |
| `video_edit` | Video manipulation — trimming, compositing, style transfer, frame interpolation | Runway, Pika, Descript |
| `video_understanding` | Video analysis — scene detection, action recognition, temporal Q&A, surveillance | Gemini (native), GPT-4o (frame sampling), Twelve Labs |
| `3d_gen` | 3D model and scene generation from text or images | Meshy, Tripo, Point-E, Shap-E, Luma AI |

### 1.5 Retrieval & Search

| Capability | Description | Example Providers |
|---|---|---|
| `embedding` | Vector embeddings for semantic search, RAG, clustering, similarity | OpenAI Embeddings, Voyage, Nomic, Ollama (local), Cohere Embed |
| `web_search` | Real-time web search for current information, fact-checking, research | Tavily, Serper, Perplexity, DuckDuckGo (free), Brave Search |
| `reranking` | Result reranking for improved retrieval precision in RAG pipelines | Cohere Rerank, Jina Rerank, Voyage Rerank |

### 1.6 Infrastructure

| Capability | Description | Example Providers |
|---|---|---|
| `database` | Relational database for persistent structured storage, migrations, queries | PostgreSQL, MySQL, SQLite (local) |
| `vector_db` | Vector database for embedding storage, ANN search, metadata filtering | ChromaDB (local), Qdrant (local), Pinecone, Weaviate, Milvus |
| `graph_db` | Graph database for relationship modeling, knowledge graphs, traversal queries | Neo4j, Memgraph, ArangoDB |
| `cache` | In-memory cache for session state, rate limiting, pub/sub, queues | Redis, Valkey, KeyDB, Memcached |
| `object_storage` | Binary/file storage for uploads, media assets, backups, model weights | S3, Cloudflare R2, GCS, MinIO (local) |
| `message_queue` | Async message passing for task orchestration, event-driven workflows | RabbitMQ, Kafka, NATS, Redis Streams |

### 1.7 Observability & Auth

| Capability | Description | Example Providers |
|---|---|---|
| `observability` | LLM call tracing, cost tracking, prompt versioning, evaluation dashboards | Langfuse, LangSmith, Helicone, Lunary, Braintrust |
| `auth_oauth` | OAuth2 social login — Google, GitHub, Microsoft identity federation | Google OAuth, GitHub OAuth, Auth0, Clerk |
| `auth_api` | API authentication and key management for tool-to-tool communication | Custom tokens, JWT, gateway auth |

### 1.8 Specialized Agent Capabilities

| Capability | Description | Example Providers |
|---|---|---|
| `browser` | Headless browser automation for web scraping, form filling, testing | Browserbase, Playwright (local), Puppeteer (local), Steel |
| `code_execution` | Sandboxed code execution for dynamic tool use, data analysis, REPL | E2B, Modal, local Docker, Jupyter kernel |
| `file_conversion` | Document format conversion — PDF, DOCX, spreadsheets, presentations | LibreOffice (local), Pandoc (local), CloudConvert |
| `email` | Email sending, receiving, parsing for notifications and communication | SendGrid, Resend, Postmark, SMTP (local) |
| `ledger` | Distributed ledger for receipts, attestation anchoring, audit trails | Hedera, Ethereum (L2), Solana |

---

## 2. Provider Capability Matrix

Each provider in the vault satisfies one or more capabilities. This is the resolution
table the engine uses to match what the user has to what the tool needs.

```toml
# Encoded in providers-default.toml as new `capabilities` field

[[providers]]
id = "openai"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "long_context_llm",
                 "vision", "image_gen", "image_edit", "tts", "asr",
                 "embedding", "video_gen"]

[[providers]]
id = "anthropic"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "long_context_llm",
                 "vision"]

[[providers]]
id = "gemini"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "long_context_llm",
                 "vision", "video_understanding", "embedding", "video_gen"]

[[providers]]
id = "deepseek"
capabilities = ["reasoning_llm", "code_llm"]

[[providers]]
id = "groq"
capabilities = ["reasoning_llm", "fast_llm"]  # inference-only, not a model provider

[[providers]]
id = "ollama"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "vision",
                 "embedding"]  # depends on pulled models

[[providers]]
id = "together"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "image_gen",
                 "embedding"]

[[providers]]
id = "replicate"
capabilities = ["image_gen", "video_gen", "audio_gen", "3d_gen", "tts", "asr"]

[[providers]]
id = "elevenlabs"  # new provider entry needed
capabilities = ["tts", "voice_clone"]

[[providers]]
id = "runway"  # new
capabilities = ["video_gen", "video_edit"]

[[providers]]
id = "suno"  # new
capabilities = ["audio_gen"]

[[providers]]
id = "tavily"
capabilities = ["web_search"]

[[providers]]
id = "serper"
capabilities = ["web_search"]

[[providers]]
id = "hedera"
capabilities = ["ledger"]
```

---

## 3. Tool Manifest: `.zp-configure.toml`

Lives alongside `.env.example` in each tool's directory. Declares what the tool
actually needs vs. what it can optionally use.

### 3.1 Format

```toml
# .zp-configure.toml — PentAGI
[tool]
name = "PentAGI"
version = "0.1"
description = "Autonomous pentesting agent with research, coding, and reporting"

# ── Required capabilities ──────────────────────────────────
# ALL of these must be satisfied for the tool to be configurable.
# Each entry is a capability ID. The engine picks the best available
# provider from the user's vault.

[[required]]
capability = "reasoning_llm"
# Which env vars this capability fills (mapped from .env.example)
env_vars = ["OPENAI_API_KEY", "OPENAI_BASE_URL"]
# Optional: prefer a specific provider if available
prefer = ["anthropic", "openai"]
# Optional: model hint for the capability
model_env = "OPENAI_MODELS"
model_default = "claude-sonnet-4-20250514"

[[required]]
capability = "embedding"
env_vars = ["EMBEDDING_KEY", "EMBEDDING_URL"]
prefer = ["ollama"]  # local-first
model_env = "EMBEDDING_MODEL"
model_default = "nomic-embed-text"

[[required]]
capability = "database"
env_vars = ["POSTGRES_PASSWORD", "POSTGRES_USER", "POSTGRES_DB", "DATABASE_URL"]
# database has a special "local" provider — ZP can spin up a container
local_default = true

# ── Optional capabilities ──────────────────────────────────
# These enrich the tool but it runs fine without them.
# The engine configures them if the user has the keys, skips cleanly if not.

[[optional]]
capability = "web_search"
env_vars = ["TAVILY_API_KEY"]
prefer = ["tavily", "serper"]
fallback_env = "DUCKDUCKGO_ENABLED"
fallback_value = "true"

[[optional]]
capability = "image_gen"
env_vars = ["OPENAI_API_KEY"]  # shared with reasoning_llm
note = "Uses the same OpenAI key as reasoning; only needs DALL-E model access"

[[optional]]
capability = "tts"
env_vars = ["TTS_OPENAI_API_KEY", "TTS_OPENAI_BASE_URL"]
prefer = ["openai", "qwen"]

[[optional]]
capability = "asr"
env_vars = ["ASR_OPENAI_API_KEY", "ASR_OPENAI_BASE_URL"]
prefer = ["openai", "qwen"]

[[optional]]
capability = "observability"
env_vars = ["LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST"]
prefer = ["langfuse"]

[[optional]]
capability = "auth_oauth"
env_vars = ["OAUTH_GOOGLE_CLIENT_ID", "OAUTH_GOOGLE_CLIENT_SECRET"]
prefer = ["google"]

[[optional]]
capability = "graph_db"
env_vars = ["NEO4J_PASSWORD", "NEO4J_USER"]
prefer = ["neo4j"]

[[optional]]
capability = "browser"
env_vars = ["BROWSERBASE_API_KEY", "BROWSERBASE_PROJECT_ID"]
prefer = ["browserbase"]
```

### 3.2 Key Design Decisions

**`env_vars` is explicit, not inferred.** The manifest tells the engine exactly which
`.env.example` variables a capability fills. No regex guessing. This is the source of
truth for "this var means reasoning_llm, not a separate provider requirement."

**`prefer` orders provider selection.** If the user has both Anthropic and OpenAI keys,
`prefer = ["anthropic", "openai"]` picks Anthropic. Without `prefer`, the engine picks
whichever the user stored first (vault insertion order).

**`model_env` + `model_default` handle model selection.** When the engine resolves
`reasoning_llm` to Anthropic, it also knows to set `OPENAI_MODELS=claude-sonnet-4-20250514`
and rewrite `OPENAI_BASE_URL` to the Anthropic-compatible endpoint (or ZP proxy).

**`fallback_env` / `fallback_value` for graceful degradation.** If no `web_search`
provider is available, set `DUCKDUCKGO_ENABLED=true` as a free fallback.

**`local_default = true` for infrastructure.** Database and vector_db capabilities
can be satisfied by local containers. ZP can offer to `docker compose up` the
required services.

---

## 4. Resolution Algorithm

```
resolve_tool(manifest, vault, provider_catalog):

  1. For each [[required]] entry:
     a. Find providers in vault that satisfy entry.capability
     b. Sort by entry.prefer order (preferred first), then vault insertion order
     c. Pick the first available provider
     d. If NO provider satisfies → tool is NOT configurable, report clearly:
        "PentAGI requires reasoning_llm — add an API key for: Anthropic, OpenAI, or Gemini"
     e. Map provider's vault_ref → entry.env_vars in the output .env
     f. If entry.model_env specified → set model_default (or provider's recommended model)
     g. If entry uses a proxiable provider → rewrite base_url to ZP proxy endpoint

  2. For each [[optional]] entry:
     a. Same resolution as required, but on failure:
        - If fallback_env specified → write fallback_value
        - Else → comment out the env vars with "# Optional: [capability] not configured"
     b. Track as "enrichment" in configure output

  3. For remaining .env.example vars NOT claimed by any manifest entry:
     a. Match against builtin_patterns() for defaults (URLs, toggles, usernames)
     b. Unmatched vars → preserve template value with comment

  4. Write .env with clear sections:
     # ── Required: reasoning_llm (resolved: anthropic) ──
     OPENAI_API_KEY=${vault:anthropic/api_key}
     OPENAI_BASE_URL=https://api.anthropic.com/v1
     OPENAI_MODELS=claude-sonnet-4-20250514

     # ── Optional: web_search (resolved: tavily) ──
     TAVILY_API_KEY=${vault:tavily/api_key}

     # ── Optional: tts (not configured) ──
     # TTS_OPENAI_API_KEY=
     # TTS_OPENAI_BASE_URL=

  5. Return MVC report:
     {
       status: "ready" | "missing_required" | "needs_attention" | "partial",
       confidence: "high" | "medium" | "low",
       required_satisfied: ["reasoning_llm", "embedding", "database"],
       required_missing: [],
       optional_configured: ["web_search", "image_gen"],
       optional_skipped: ["tts", "asr", "observability", "auth_oauth", "graph_db"],
       providers_used: {"anthropic": ["reasoning_llm", "image_gen"], "ollama": ["embedding"]},
       attention_items: [],   // vars/capabilities the engine couldn't resolve honestly
       source: "manifest" | "inferred",
     }
```

### 4.1 Confidence Tiers

Every resolution produces a confidence level that governs how the engine behaves:

**`high` — Configured (manifest-declared, all required satisfied)**
The tool has a `.zp-configure.toml`, every required capability resolved to a known
provider, and env var mappings are explicit. The engine writes the `.env` automatically.
No human review needed.

**`medium` — Configured with caveats (inferred or partially ambiguous)**
Either the tool has no manifest (capabilities were inferred from `.env.example`), or
some vars matched patterns but the mapping was ambiguous (e.g., a var could serve two
capabilities). The engine writes the `.env` but flags specific caveats:
```
CONFIG  PentAGI (inferred — no manifest)
        ✓ reasoning_llm → anthropic
        ✓ embedding → ollama
        ⚠ CUSTOM_INFERENCE_URL — not recognized, preserved from template
        Caveat: configuration was inferred. Run `zp configure manifest` to lock it in.
```

**`low` — Needs attention (engine hit its knowledge boundary)**
The engine encountered something it can't resolve honestly. This is NOT a failure —
it's the engine being transparent. Causes include:

- Env vars that look like credentials but match no known pattern
- A capability the manifest references that isn't in the taxonomy
- A provider-specific requirement the engine can't generalize
  (e.g., "must be GPT-4o specifically, not just any reasoning LLM")
- A `.env.example` with internal/proprietary service URLs that need manual entry
- Conflicting signals (var name suggests one provider, but value template suggests another)

The engine reports exactly what it couldn't resolve and why:
```
ATTENTION  IronClaw
           ✓ reasoning_llm → anthropic
           ✗ NEARAI_CUSTOM_ENDPOINT — no pattern match, looks like a credential
           ✗ INTERNAL_AUTH_TOKEN — unknown service, cannot resolve
           → 2 variable(s) need manual review. Run `zp configure review ironclaw`
```

The engine NEVER guesses on `low` confidence items. It preserves the template value,
comments it clearly, and surfaces it to the user. A wrong guess that breaks a tool's
boot sequence is worse than asking for help.

### 4.2 Confidence Escalation

Confidence flows upward over time:

1. First scan: no manifest → `low` or `medium` (inferred)
2. User runs `zp configure manifest --path ./pentagi` → generates draft manifest
3. User reviews, commits manifest → future scans are `high`
4. Community/tool author ships `.zp-configure.toml` in repo → `high` for everyone

The `needs_attention` items also feed back into the pattern registry. If the engine
sees `NEARAI_CUSTOM_ENDPOINT` across multiple tools, that's a signal to add a pattern
for it. The system learns from its own uncertainty.

---

## 5. Manifest Discovery: Bootstrapping Without Manifests

Not every tool will ship with a `.zp-configure.toml`. For tools that don't have one,
the engine falls back to heuristic inference:

### 5.1 Capability Inference from `.env.example`

```
infer_capabilities(env_template, pattern_registry, provider_catalog):

  1. Parse all vars from .env.example
  2. Match each var against builtin_patterns()
  3. Group matched vars by provider
  4. For each provider group:
     a. Look up provider in catalog → get capabilities list
     b. If provider has reasoning_llm AND this tool has multiple LLM provider vars,
        classify as ONE reasoning_llm requirement (not N separate requirements)
  5. Vars matching ApiKey/Password/Secret → required capabilities
  6. Vars matching Url/Model/Toggle/Config → defaults (not capabilities)
  7. Heuristic: if 3+ LLM providers appear, tool needs reasoning_llm (any one of them)
  8. Heuristic: if embedding vars appear, tool needs embedding
  9. Heuristic: if postgres vars appear, tool needs database
```

### 5.2 Manifest Generation

The engine can also GENERATE a draft `.zp-configure.toml` for a scanned tool:

```
zp configure manifest --path ~/projects/pentagi
```

This analyzes the `.env.example`, applies the heuristics above, and produces a draft
manifest that the user (or tool author) can review and refine. Over time, as manifests
get committed to tool repos, the heuristic path becomes the minority case.

---

## 6. Provider Cross-Compatibility

Many tools hardcode `OPENAI_API_KEY` but actually work with any OpenAI-compatible API.
The engine needs to know which providers expose OpenAI-compatible endpoints:

```toml
# In providers-default.toml
[[providers]]
id = "anthropic"
openai_compatible = false  # needs header translation
openai_proxy = true        # ZP proxy handles translation

[[providers]]
id = "groq"
openai_compatible = true   # native /v1/chat/completions

[[providers]]
id = "together"
openai_compatible = true

[[providers]]
id = "ollama"
openai_compatible = true   # /api/chat and /v1/chat/completions

[[providers]]
id = "deepseek"
openai_compatible = true
```

When the engine resolves `reasoning_llm` for a tool that uses `OPENAI_API_KEY`:
- If provider is OpenAI → direct key injection
- If provider is openai_compatible (Groq, Together, etc.) → inject their key + rewrite base_url
- If provider is NOT compatible (Anthropic) → inject key + set base_url to ZP proxy
  (which translates OpenAI format ↔ Anthropic format transparently)

This is where the proxy route we just re-enabled becomes essential. ZP proxy acts as
a universal adapter, making any provider look like OpenAI to tools that only speak that
protocol.

---

## 7. Aggregator Deluxe Mode

### 7.1 The Problem Aggregators Solve

Most tools list env vars for 5-10 individual LLM providers. The user doesn't need all
of them — they need ONE that satisfies each capability. But aggregators go further:
a single API key covers multiple capabilities AND brings intelligent routing, fallback,
and cost optimization that individual provider keys don't offer.

### 7.2 Aggregator Classification

Aggregators are providers that expose a unified API endpoint fronting multiple upstream
models. They get a special `aggregator` field in the provider catalog:

```toml
[[providers]]
id = "abacus"
name = "Abacus.ai"
category = "aggregator"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "long_context_llm",
                 "vision", "image_gen", "embedding"]
openai_compatible = true
aggregator = true
routing = "intelligent"  # RouteLLM — auto-selects best model per request
coverage = "GPT-4o, Claude, Gemini, Llama, Mistral, and more"

[[providers]]
id = "openrouter"
name = "OpenRouter"
category = "aggregator"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "long_context_llm",
                 "vision", "image_gen", "tts", "embedding"]
openai_compatible = true
aggregator = true
routing = "explicit"  # user specifies model per request via model field
coverage = "200+ models across OpenAI, Anthropic, Google, Meta, Mistral, and more"

[[providers]]
id = "together"
name = "Together AI"
category = "llm"
capabilities = ["reasoning_llm", "fast_llm", "code_llm", "image_gen", "embedding"]
openai_compatible = true
aggregator = false  # single provider, but broad capability coverage
```

### 7.3 Resolution Modes

When the engine resolves capabilities for a tool, it operates in one of three modes:

**Standard mode** — each capability maps to the best individual provider available.
PentAGI might get Anthropic for reasoning, Ollama for embedding, Tavily for search.
This is the default when the user has individual provider keys.

**Deluxe mode** — an aggregator key satisfies ALL compatible capabilities through a
single endpoint. When the engine detects an aggregator in the vault, it evaluates
whether that aggregator covers all (or most) of the tool's required capabilities.
If it does, the engine offers deluxe configuration:

```
PentAGI                          [Configure: Standard]  [Configure: Deluxe]

Standard mode:
├── reasoning_llm → Anthropic
├── fast_llm      → Groq
├── embedding     → Ollama (local)
└── web_search    → Tavily

Deluxe mode (Abacus.ai RouteLLM):
├── reasoning_llm → Abacus.ai (auto-routes to best model)
├── fast_llm      → Abacus.ai (auto-routes to fastest model)
├── embedding     → Abacus.ai
└── web_search    → Tavily (not covered by aggregator)
    ⚡ Single key, intelligent routing, automatic fallback
```

**Hybrid mode** — aggregator covers most capabilities, individual providers fill gaps.
This happens naturally when deluxe mode can't cover everything (e.g., Abacus doesn't
do web search, so Tavily still fills that role).

### 7.4 Deluxe Mode Resolution Algorithm

```
resolve_deluxe(manifest, vault, provider_catalog):

  1. Find all aggregator providers in vault
  2. For each aggregator:
     a. Count how many of the tool's required capabilities it covers
     b. Score = covered_required / total_required
     c. If score >= 0.8 → candidate for deluxe mode
  3. If candidates exist:
     a. Pick the aggregator with highest coverage score
     b. Map all covered capabilities to the aggregator
     c. For uncovered capabilities → fall back to standard resolution
     d. If aggregator.routing == "intelligent":
        - model_env vars can be left empty or set to "auto"
        - The aggregator's routing layer picks the best model per request
     e. If aggregator.routing == "explicit":
        - model_env vars get mapped to specific models available on the platform
        - e.g., OPENAI_MODELS="anthropic/claude-sonnet-4-20250514" (OpenRouter format)
  4. Return deluxe MVC report with:
     - aggregator_used: "abacus"
     - aggregator_coverage: ["reasoning_llm", "fast_llm", "code_llm", "embedding"]
     - standard_fallback: ["web_search"]  // capabilities the aggregator doesn't cover
     - mode: "deluxe" | "hybrid"
```

### 7.5 Env Var Mapping in Deluxe Mode

In deluxe mode, the engine maps multiple provider-specific env vars to the single
aggregator endpoint. For PentAGI with Abacus.ai:

```env
# ── Deluxe: Abacus.ai RouteLLM (intelligent routing) ──
# All LLM capabilities routed through Abacus.ai
OPENAI_API_KEY=${vault:abacus/api_key}
OPENAI_BASE_URL=https://api.abacus.ai/v0/openai
OPENAI_MODELS=auto

# Abacus covers reasoning, fast, code, vision, embedding
# All these point to the same key — routing is handled server-side
ANTHROPIC_API_KEY=                    # not needed in deluxe mode
DEEPSEEK_API_KEY=                     # not needed in deluxe mode
EMBEDDING_KEY=${vault:abacus/api_key}
EMBEDDING_URL=https://api.abacus.ai/v0/openai
EMBEDDING_MODEL=auto

# ── Standard fallback (not covered by aggregator) ──
TAVILY_API_KEY=${vault:tavily/api_key}
DUCKDUCKGO_ENABLED=true
```

### 7.6 Manifest Support

The `.zp-configure.toml` can express aggregator preferences:

```toml
[tool]
name = "PentAGI"

# Prefer deluxe mode when available — lets the aggregator handle routing
prefer_aggregator = true

# Or pin to a specific aggregator
# prefer_aggregator = "abacus"

# Or disable deluxe entirely — always use individual providers
# prefer_aggregator = false
```

### 7.7 Onboard UI for Deluxe

When an aggregator is detected in the vault, the onboard configure step surfaces it:

```
╔═══════════════════════════════════════════════════════════╗
║  ⚡ Deluxe mode available                                ║
║                                                           ║
║  Your Abacus.ai key can power all LLM capabilities       ║
║  across 3 tools with intelligent model routing.           ║
║                                                           ║
║  PentAGI   — 5/6 capabilities covered                    ║
║  OpenMAIC  — 3/3 capabilities covered                    ║
║  IronClaw  — 2/4 capabilities covered                    ║
║                                                           ║
║  [Configure All in Deluxe]    [Use Standard Instead]      ║
╚═══════════════════════════════════════════════════════════╝
```

This is a powerful onboarding moment: the user stores ONE aggregator key, and ZP
configures their entire tool ecosystem through it.

---

## 8. Onboard Integration

The MVC system changes the onboard configure step from "did you store all 34 keys?"
to a capability-aware readiness assessment:

### Step 7 (Configure) — New Flow

```
1. Scan tools in ~/projects
2. For each tool with .zp-configure.toml:
   a. Evaluate required capabilities against vault
   b. Show: "PentAGI — Ready (reasoning: Anthropic, embedding: Ollama, db: local)"
   c. Or: "OpenMAIC — Needs: reasoning_llm (add Anthropic, OpenAI, or Gemini key)"
3. For each tool WITHOUT manifest:
   a. Run heuristic inference
   b. Show with lower confidence: "IronClaw — Likely ready (inferred: reasoning_llm ✓)"
4. One-click configure: write all .env files for ready tools
5. Show enrichment opportunities: "Add a Tavily key to enable web search in PentAGI"
```

### Onboard UI Changes

The configure card shifts from a wall of red "missing" badges to a capability checklist,
grouped by confidence tier:

```
PentAGI                          confidence: high    [Configure]
├── ✅ reasoning_llm → Anthropic (Claude Sonnet)
├── ✅ embedding     → Ollama (nomic-embed-text)
├── ✅ database      → PostgreSQL (local)
├── ✅ web_search    → Tavily
├── ⬜ tts           → not configured (optional)
├── ⬜ asr           → not configured (optional)
├── ⬜ observability → not configured (optional)
└── ⬜ browser       → not configured (optional)

IronClaw                         confidence: medium   [Configure]
├── ✅ reasoning_llm → Anthropic (Claude Sonnet)
├── ⚠️ NEARAI_MODEL  → preserved from template (unrecognized)
└── ℹ️ Inferred from .env.example — run `zp configure manifest` to lock in

deploy-tool                      confidence: low      [Review]
├── ✅ reasoning_llm → Anthropic (Claude Sonnet)
├── ❓ INTERNAL_AUTH_TOKEN → unknown service, needs manual entry
├── ❓ STAGING_DB_URL     → looks like a connection string, not in vault
└── ℹ️ 2 variable(s) need your attention before configuring
```

The key UX shift: tools at `high` and `medium` confidence get a **[Configure]** button
that writes the `.env` immediately. Tools at `low` confidence get a **[Review]** button
that opens an interactive resolution flow where the user can provide values for the
unknowns — and those values feed back into the vault for future tools.

---

## 9. Implementation Phases

### Phase A: Capability Registry (engine-level)
- Add `Capability` enum to `zp-engine`
- Add `capabilities` field to `providers-default.toml`
- Add `openai_compatible` and `openai_proxy` fields
- Provider resolution: given a capability + vault contents, return best provider

### Phase B: Manifest Format
- Define `.zp-configure.toml` schema (serde deserialization)
- Write manifests for known tools: PentAGI, IronClaw, OpenMAIC
- Manifest discovery in `analyze_tool()` — check for manifest before falling back

### Phase C: Resolution Engine
- Replace `analyze_tool()` logic with capability-aware resolution
- New `resolve_tool()` function implementing the algorithm above
- Update `run_auto()` to use MVC reports instead of raw missing counts
- Proxy URL rewriting for non-OpenAI providers filling OpenAI-shaped vars

### Phase D: Heuristic Fallback
- Capability inference from `.env.example` when no manifest exists
- `zp configure manifest` command to generate draft manifests
- Confidence scoring for inferred vs declared capabilities

### Phase E: Onboard UI
- Update onboard configure step to show capability tree
- Enrichment suggestions ("add X key to unlock Y in Z tool")
- Provider preference UI (let user set preferred provider per capability globally)

---

## 10. New Providers Needed

The current `providers-default.toml` needs entries for providers that satisfy
capabilities not yet covered:

| Provider | Capabilities | Priority |
|---|---|---|
| ElevenLabs | `tts`, `voice_clone` | High — best TTS quality |
| Deepgram | `asr` | Medium — alternative to Whisper |
| Runway | `video_gen`, `video_edit` | Medium |
| Suno | `audio_gen` | Low — niche |
| Udio | `audio_gen` | Low — niche |
| Meshy | `3d_gen` | Low — niche |
| Luma AI | `3d_gen`, `video_gen` | Low |
| Browserbase | `browser` | High — PentAGI uses it |
| E2B | `code_execution` | Medium |
| Pinecone | `vector_db` | Medium |
| Qdrant | `vector_db` | Medium — self-hostable |
| Twelve Labs | `video_understanding` | Low — specialized |
| Jina | `embedding`, `reranking`, `web_search` | Medium — versatile |
| Cohere | `reasoning_llm`, `embedding`, `reranking` | Already exists, add capabilities |
| SendGrid | `email` | Low |
| Resend | `email` | Low |
| Flux (via Replicate/Together) | `image_gen` | Covered by existing providers |
| Stable Diffusion (local) | `image_gen` | Special — local runtime detection |

---

## 11. Findings from Real-World Manifest Writing

Five tools analyzed: PentAGI (375 env vars), OpenMAIC (124), IronClaw (197),
zp-hedera (12), and Agent Zero (researched from public docs). Each surfaced
design issues that refine the manifest format and taxonomy.

### 11.1 New Concepts Discovered

**Backend selector pattern (IronClaw)**
Some tools use a single env var (e.g., `LLM_BACKEND=anthropic`) to select which
provider is active, then only that provider's vars matter. The manifest needs a
`backend_groups` concept — the engine sets the selector and populates only the
selected group. This is distinct from PentAGI/OpenMAIC where all provider vars
exist simultaneously and only one needs a real key.

**Config vars (Agent Zero)**
Agent Zero uses `A0_SET_*` prefix vars that aren't credentials but configure
which provider/model to use. The manifest needs `config_vars` alongside `env_vars`
to express "when you resolve this capability, also set these config vars."

**Auto-generatable secrets (PentAGI)**
Many env vars that look like credentials are actually deployment secrets that should
be randomly generated, not stored in vault. PentAGI has ~14 of these (salts, internal
passwords, encryption keys for bundled services). The manifest `[auto_generate]` section
handles this — the engine generates random values on first configure and stores them
locally.

**Shared capabilities (OpenMAIC, Agent Zero)**
When one API key satisfies multiple capabilities (e.g., OpenAI key covers reasoning,
TTS, ASR, and embedding), the manifest uses `shared_with` to express this. The engine
resolves the primary capability first, then propagates the same provider to shared
capabilities without consuming additional vault entries.

**Provider override blocks**
Every tool needed `[[provider_overrides]]` — when the engine resolves a capability
to a specific provider, it needs to know exactly which env vars to set and what
values to use. This is the most tool-specific part of the manifest and can't be
inferred from `.env.example` alone.

### 11.2 New Capabilities Needed in Taxonomy

| Capability | Discovered In | Description |
|---|---|---|
| `pdf_processing` | OpenMAIC | AI-powered document parsing/extraction (UnPDF, MinerU) — distinct from `file_conversion` |
| `messaging_slack` | IronClaw | Slack bot integration (bot token + app token + signing secret) |
| `messaging_telegram` | IronClaw | Telegram bot integration |
| `messaging_signal` | IronClaw | Signal messenger integration |
| `messaging_webhook` | IronClaw | HTTP webhook server for custom integrations |

The messaging capabilities are a new category — **communication channels**. They're
not AI capabilities but they ARE credential-bearing integrations that the engine
should know about. They always land in `needs_attention` tier since they require
app creation in external developer consoles.

### 11.3 API Key Naming Patterns Discovered

| Tool | Pattern | Example |
|---|---|---|
| PentAGI | `{PROVIDER}_API_KEY` | `ANTHROPIC_API_KEY` |
| PentAGI | `{PREFIX}_{PROVIDER}_KEY` | `OPEN_AI_KEY` (note: underscore in OPEN_AI) |
| OpenMAIC | `{PROVIDER}_API_KEY` | `OPENAI_API_KEY` |
| OpenMAIC | `{CAPABILITY}_{PROVIDER}_API_KEY` | `TTS_OPENAI_API_KEY`, `VIDEO_KLING_API_KEY` |
| IronClaw | `{PROVIDER}_API_KEY` | `ANTHROPIC_API_KEY` |
| IronClaw | `LLM_API_KEY` (generic) | Used with `openai_compatible` backend |
| Agent Zero | `API_KEY_{PROVIDER}` | `API_KEY_OPENAI` (reversed order!) |

The reversed pattern in Agent Zero (`API_KEY_OPENAI` vs `OPENAI_API_KEY`) means
the builtin_patterns() regex needs to handle both orderings. Current patterns
only match `OPENAI_API_KEY` style.

### 11.4 MVC Summary by Tool

| Tool | Required Capabilities | Min Keys | Total Env Vars | Ratio |
|---|---|---|---|---|
| PentAGI | reasoning_llm, embedding, database | 1 (LLM) + local | 375 | 0.3% |
| OpenMAIC | reasoning_llm | 1 | 124 | 0.8% |
| IronClaw | reasoning_llm, database | 1 (LLM) + local | 197 | 0.5% |
| zp-hedera | ledger | 2 (ID + key) | 12 | 16.7% |
| Agent Zero | reasoning_llm | 1 | ~30 | 3.3% |

The ratio column is striking: PentAGI needs 1 actual API key out of 375 env vars.
That's 0.3% signal in 99.7% noise. This is exactly why MVC exists — to extract
that signal.

### 11.5 Manifest Format Additions

Based on these findings, the manifest schema needs:

```toml
# Backend selector pattern (IronClaw)
[[required]]
capability = "reasoning_llm"
env_vars = ["LLM_BACKEND"]       # the selector var
[[required.backend_groups]]      # per-backend var sets
backend = "anthropic"
env_vars = ["ANTHROPIC_API_KEY", "ANTHROPIC_MODEL"]

# Config vars (Agent Zero)
[[required]]
capability = "reasoning_llm"
config_vars = { A0_SET_chat_model_provider = "${provider}" }

# Auto-generatable secrets
[auto_generate]
secrets = ["COOKIE_SIGNING_SALT", "LANGFUSE_SALT", ...]

# Shared capabilities
[[optional]]
capability = "tts"
shared_with = "reasoning_llm"    # reuses same provider + key

# Provider overrides with also_set
[[provider_overrides]]
provider = "openai"
env_map = { OPENAI_API_KEY = "${vault:openai/api_key}" }
also_set = { DEFAULT_MODEL = "openai:gpt-4o" }
shares = ["tts", "asr", "embedding"]

# Attention flags for needs_attention items
[[optional]]
capability = "messaging_slack"
attention = "Requires creating a Slack app at api.slack.com"
```
