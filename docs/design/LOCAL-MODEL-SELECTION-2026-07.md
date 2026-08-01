# Local Model Selection — APOLLO (M4 Pro Mini) + PI5 (2026-07)

**Decision record + benchmark plan. Analysis input, not a canonical elaboration.** Records which local models ZeroPoint will benchmark on the named fleet nodes, why, and the license posture. Does not amend KEEL. Composes with `HARDWARE-ROLE-SEPARATION-2026-07` (canonical two-role topology — closed the Regent-vs-Sentinel node question in this doc at line 20 on 2026-07-27), `INFERENCE-ROUTING-DISCIPLINE-2026-07`, `AI-LANDSCAPE-SIGNAL-2026-07` (the latency-floor framing), `MULTI-DEVICE-OPERATION-2026-07` (every device a scoped Genesis delegation), and `DEPENDENCY-POSTURE` (license-capture risk). Companion harness: `tools/local-model-bench/zp_local_model_bench.py`.

## Named hardware targets

Reference these names, not "the Mini" or "a Pi" — abstract references are how fleet roles get mixed up.

| Node | Hardware | RAM / bandwidth | Form (SUBSTRATE-FORM) | Inference role | Runtime |
|---|---|---|---|---|---|
| **APOLLO** | M4 Pro Mac Mini | 64GB / ~273GB/s | Appliance — rally compute target | Resident high-inference (near-realtime) + mondo streaming (non-realtime) | **MLX** |
| **PI5** | Raspberry Pi 5 (8GB) | 8GB / ~17GB/s LPDDR4X, CPU-only (Cortex-A76 @ 2.4GHz) | Edge / Sovereign floor — always-on | Router classifier + lightweight precedent/edge cognition | **llama.cpp / GGUF** |

**APOLLO** budget: ~48–56GB for weights+KV after `sudo sysctl iogpu.wired_limit_mb=57344` (leaving ~6–8GB for the OS). Hosts the Qwen resident + fast tiers and the GLM-5.2 streaming track.

**PI5 (8GB)** — after the OS, ~6–6.5GB is usable, so *capacity* isn't the limit up to ~4B; **CPU-bound speed is** (Cortex-A76 @ 2.4GHz, ~17GB/s). So PI5's realistic role is the **router classifier + light precedent work**, not the fast-SLM tier — Qwen3-4B stays on APOLLO. Clear-license fit: **Qwen3-0.6B** as the classifier (snappy), **Qwen3-1.7B** for light edge cognition. Note this is exactly where Liquid's **LFM2.5-230M** shines most — ~42 tok/s under 1GB on a Pi 5, purpose-built for on-device classification/extraction — so the always-on-classifier slot is the single strongest case for electing Tier B; **Qwen3-0.6B** is the sovereign-default substitute.

**Runtime split (important):** the MLX harness (`zp_local_model_bench.py`) is **APOLLO-only** — MLX needs Apple Silicon/Metal. **PI5 benchmarking is a separate llama.cpp/GGUF track** — same five measures, different runtime — to be scaffolded when PI5 joins the loop.

**Topology decision (closed 2026-07-27 per `HARDWARE-ROLE-SEPARATION-2026-07.md`):** APOLLO is the **Regent-role sovereign** — the always-on Regent presence with its own Genesis, held by Secure Enclave, hosting the LLM inference and adapter workload. PI5 is the **Sentinel-role sovereign** — network-adjacent to the router, allowlist enforcement, destination monitoring, chain-anchored egress attestation. The pivot away from "PI5 as always-on Regent" was made because PI5 inference throughput on 3B–4B models (~7–9 tok/s at Q4_K_M) is a poor fit for the Regent role, while it is genuinely well-suited to the Sentinel role (cheap sustained pattern matching, NEON-accelerated hashing/regex). PI5's model shortlist in this doc is therefore downshifted: a small classifier (Qwen3-0.6B or Liquid LFM2.5-230M if Tier B is elected) is sufficient for Sentinel-role work; the "light edge cognition" tier (Qwen3-1.7B) is deferred as an optional add-on rather than a primary target. LoRA and X-LoRA adapter workloads live on APOLLO (see §"Adapter workflow" below and the forthcoming Regent adapter design doc). `MULTI-DEVICE-OPERATION` (Regent-follows-operator) governs the Regent's rally behavior on APOLLO; the Sentinel does not need to follow the operator — it stays at the network boundary.

### Adapter workflow on APOLLO

Regent-role adapter work — LoRA fine-tuning ceremony, adapter loading, hot-swap primitives, X-LoRA experimentation — lives on APOLLO because the M4 Pro's 64GB unified memory and Metal backend support: (a) multiple adapters loaded concurrently via S-LoRA-style batching; (b) X-LoRA token-level blending as research prototype; (c) on-device shadow-evaluation of candidate adapters against controls; (d) sub-100ms hot-swap latency for adapter transitions. None of these are feasible on PI5. The adapter artifact format (LoRAAdapter = safetensors + provenance manifest + Ed25519 signature envelope), `FineTuningAuthorization` two-phase ceremony, and load/swap primitives are specified in `REGENT-ADAPTER-WORKFLOW-2026-07.md`; this doc's contribution is naming APOLLO as their target hardware.

## Selection criteria

The local model's job in ZeroPoint is narrow and specific: reason over the chain/ontology, emit **structured output** (receipt schemas, JSON envelopes), and **dispatch tools** reliably — under a license that doesn't compromise the sovereignty thesis. So the filters were: permissive license, MLX-native, strong tool-use/instruction-following + reasoning/coding, and fits 64GB at 4-bit with context headroom.

## License posture — two tiers, not a blanket exclusion

Decision (2026-07-21, revised): **tier by who decides, rather than hard-exclude.** A blanket license exclusion over-corrects — it throws away genuine technical advantage (notably Liquid's edge efficiency) that an informed operator might rightly want. The sovereign move is not to forbid, but to keep the *default* clean and make anything else an *explicit operator election*. This is bounded operator sovereignty (KEEL Part VIII): the substrate ships sovereign-clean; the operator may trade a license constraint for capability with eyes open, and that election is a recorded admission decision (composes with QUARANTINE-PLANE admission and LICENSING-AND-INTEGRITY).

**Tier A — Reference / shipped default: clear-license only (Apache-2.0 / MIT).** This is what the reference implementation lists and what ships as the sovereign default. No strings. Resident tiers = **Qwen (Apache-2.0)**; mondo tier = **GLM (MIT)**.

**Tier B — Operator-electable: license-gated, documented, opt-in.** Not in the reference stack; benchmarkable and available with the license terms surfaced so the election is informed:

- **Liquid AI LFM2.5** (LFM2.5-8B-A1B, LFM2.5-230M) — *the strongest edge/SLM tech in the field*: MLX-native, ~1.5B active, IFEval 91.84, BFCL v3 64.79, <6GB, purpose-built for on-device tool-calling; the 230M runs on a Pi 5. Ships under the **LFM Open License v1.0** (revenue-gated commercial threshold + use terms), so it is operator-electable, not default. An operator who clears the license terms gets the best fast/edge tier available.
- **Meta Llama 4 Scout** (109B/17B, 10M context) — Llama 4 Community License. Electable for extreme-context experiments.
- **Google Gemma** — Gemma license terms. Electable.

The benchmark harness encodes exactly this split: the clear-license set runs by default; `--include-license-gated` opts into Tier B with a printed license banner.

## The shortlist (clear-license)

Mapped to the horizon × capability routing tiers. Exact `mlx-community` tags evolve — prefer the newest 4-bit Instruct build present on HF at pull time; the repos below are the safe floor.

| Tier / role | Model | License | Shape | ~4-bit size | Why |
|---|---|---|---|---|---|
| **Resident — general/tool-use workhorse** | Qwen3.6-35B-A3B-Instruct (floor: Qwen3-30B-A3B-Instruct) | Apache-2.0 | MoE, ~3B active | ~18–20GB | Best clean reasoning + tool-use that fits; small active → fast on 273GB/s |
| **Resident — coding/agentic** | Qwen3-Coder-30B-A3B-Instruct | Apache-2.0 | MoE, ~3B active | ~18GB | Coding + tool-dispatch specialist; verified MLX 4-bit build exists |
| **Fast SLM / precedent rung** | Qwen3-4B-Instruct | Apache-2.0 | dense ~4B | ~2.5GB | Cheap, fast; precedent-shaped work, structured emission (clean substitute for Liquid) |
| **Router classifier / edge** | Qwen3-1.7B (or 0.6B) | Apache-2.0 | dense | ~1–1.2GB | The substrate-side SLM-vs-LLM classifier; also the Pi/Edge-Form floor |
| **Mondo — streaming only** | GLM-5.2 | MIT | MoE 744B/40B active | ~370GB on SSD | Frontier open coding; MIT (no distribution fragility). Colibri-streamed, latency-tolerant. Separate track (not MLX-resident). |

Note the pattern: every resident pick is **small-active MoE** — the architecture that's ideal for mid-bandwidth UMA (big capability, tiny per-token bandwidth read).

**GLM-5.2 defensive-inference proof point (added 2026-07-31).** CNBC piece by Deirdre Bosa (`youtube.com/watch?v=lWMebfCc5f4`) reports that in July 2026, when Hugging Face investigated an OpenAI closed-model rogue incident, closed frontier models could not perform the forensic investigation because their own guardrails prevented it — Hugging Face turned to GLM-5.2 (the open-weight model already in this doc's mondo tier), which succeeded. Bosa's framing: "a closed American model caused the incident, and a Chinese open weight model helped defend against it." Real-world corroboration of GLM-5.2's usefulness for the specific class of security-adjacent inference where closed-model guardrails cut against the operator's investigative interest. Does not change GLM's Tier A / MIT positioning in this doc — reinforces the mondo tier selection with an external incident that's now mainstream-financial-media-canonical. Composition note: informs `INFERENCE-ROUTING-DISCIPLINE-2026-07` on the guardrail-cuts-against-operator failure mode that argues for open-weight availability at the mondo tier.

### Operator-electable (Tier B — license-gated, opt-in)

Not shipped in the reference stack; benchmarkable via `--include-license-gated`. Listed so the election is informed, not hidden.

| Role | Model | License | Shape | ~4-bit size | Why elect it |
|---|---|---|---|---|---|
| Fast SLM / edge | LFM2.5-8B-A1B | LFM Open License v1.0 (revenue-gated) | MoE, ~1.5B active | ~5GB | Best fast-tier tech: IFEval 91.84, strong BFCL, <6GB, MLX-native |
| Classifier / Pi-edge | LFM2.5-230M | LFM Open License v1.0 | dense 230M | ~1GB | Runs on a Pi 5; strong data-extraction/routing for its size |
| Extreme context | Llama 4 Scout | Llama 4 Community | MoE 109B/17B | ~55–60GB | 10M-token context (tight fit, prefill-bound) |

## Expected on APOLLO (to be replaced by measured numbers)

Ballparks only — the harness exists to replace these with real numbers from APOLLO:

- Qwen3.x-30/35B-A3B (≈3B active, ~1.5GB read/token @ int4) → decode plausibly **40–90 tok/s** (memory-bound ceiling higher; real-world lower from overhead).
- Qwen3-4B dense (~2.5GB/token) → **50–90 tok/s**.
- Qwen3-1.7B → **triple digits**.
- **Prefill** at long context is the real unknown and Apple's weak spot — the harness measures it explicitly at 2k/8k/32k(/128k). This is the number that actually gates whole-chain reflection.

## Benchmark methodology — five measures

For each model, the harness (`zp_local_model_bench.py`) captures exactly what the routing needs:

1. **Decode tok/s** (warm, resident) — interactive-speed number.
2. **Prefill tok/s across context lengths** (2k → 8k → 32k → optional 128k) — the whole-chain-reflection bottleneck; also surfaces the KV-headroom ceiling (OOM at a length = your effective context limit on 64GB).
3. **Structured-output / tool-call reliability** — a ZeroPoint-shaped eval: emit a valid receipt-schema JSON, and produce a well-formed tool call. Scored pass/fail. This is the go/no-go for Regent's job.
4. **Peak memory** — weights + KV at each context vs the ~48–56GB budget.
5. **Quant-degradation sanity** — two representative tasks (summarize a chain fragment into ontology entities; precedent-match a finding). Outputs captured to file for human review — this is the int4-degradation check flagged as poke #6 in the horizon-routing critique.

## Pull commands (clear-license only)

Prerequisites on the Mini:

```bash
python3 -m venv ~/.venvs/zpbench && source ~/.venvs/zpbench/bin/activate
pip install -U mlx-lm huggingface_hub
sudo sysctl iogpu.wired_limit_mb=57344   # let ~56GB go to weights+KV
```

Pull the resident + fast tiers (confirm the newest `mlx-community` 4-bit Instruct tag; these are safe floors):

```bash
hf download mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit
hf download mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit      # or Qwen3.6-35B-A3B-Instruct-4bit if present
hf download mlx-community/Qwen3-4B-Instruct-2507-4bit
hf download mlx-community/Qwen3-1.7B-4bit
```

Mondo tier (separate, streaming track — only if the SSD has ~370GB free): GLM-5.2 int4 weights for Colibri, per the Colibri repo's fetch instructions. Not part of the MLX harness.

Operator-electable (Tier B — only if you choose to clear the license terms):

```bash
hf download LiquidAI/LFM2.5-8B-A1B-MLX-4bit    # confirm the actual MLX tag
hf download LiquidAI/LFM2.5-230M-MLX-4bit
python zp_local_model_bench.py --include-license-gated
```

## Open decisions

- **Qwen3.6-35B-A3B vs Qwen3-30B-A3B** for the general tier — take the newer if its MLX build is up at pull time; both Apache, both fit.
- **GLM-5.2 streaming** — deferred until the resident tier is characterized and SSD headroom confirmed.
- Liquid is now Tier B (operator-electable), not excluded — elect it if you clear the LFM license terms; it becomes reference-eligible only if Liquid relicenses to Apache/MIT.
