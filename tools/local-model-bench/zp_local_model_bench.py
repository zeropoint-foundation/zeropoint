#!/usr/bin/env python3
"""ZeroPoint local-model benchmark harness (Apple Silicon / MLX).

Measures the five things ZeroPoint's inference routing actually cares about, per model —
tuned to the flagship use cases (UC-1 research synthesis, UC-3 private-doc QA):
  1. decode tok/s (warm)
  2. UC-1 feasibility curve: prefill tok/s AND whether a real needle-synthesis still succeeds
     at each corpus-scale context length (the whole-chain-reflection ceiling)
  3. structured-output / tool-call reliability incl. uc1_synthesis (Regent's real job) — pass/fail
  4. peak memory (weights + KV vs the 48-56GB budget)
  5. quant-degradation sanity: UC-1 ontology extraction + UC-3 grounded private-doc QA,
     captured with expected answers for a fast human grade

Clear-license models only (Apache-2.0 / MIT). Edit MODELS below or pass --models.

Design notes:
  - I (the author) could not run this on Apple hardware before delivery, so it is written
    defensively: mlx imports are lazy, per-model failures are isolated, and stats are read
    with getattr fallbacks in case the installed mlx-lm API differs. Sanity-run and report
    any API drift; fixes are cheap.
  - Prefill 128k on a 64GB box may OOM with a 30B model — that's a *result* (your effective
    context ceiling), not a crash to fear. Each measure is wrapped so one failure is recorded
    and the run continues.

Usage:
  pip install -U mlx-lm huggingface_hub
  sudo sysctl iogpu.wired_limit_mb=57344     # let ~56GB go to weights+KV
  python zp_local_model_bench.py                       # all models, default contexts
  python zp_local_model_bench.py --models qwen3-4b     # subset by id
  python zp_local_model_bench.py --contexts 2048,8192  # override prefill lengths
  python zp_local_model_bench.py --decode-tokens 256   # decode sample length

Target node is named via --target (default APOLLO, the M4 Pro Mac Mini); PI5 uses a
separate llama.cpp/GGUF track, not this MLX harness.

Outputs (next to this script; <base> = <target>-<stamp>):
  results/bench-<base>.json   full structured results (includes target + contexts)
  results/bench-<base>.md     human-readable comparison table
  results/samples-<base>.txt  captured generations for quant-degradation review
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Model registry — CLEAR-LICENSE ONLY (Apache-2.0 / MIT).
# Confirm the newest mlx-community 4-bit Instruct tag at pull time; these are safe floors.
# ---------------------------------------------------------------------------
MODELS: List[Dict[str, str]] = [
    {
        "id": "qwen3-30b-a3b",
        "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
        "tier": "resident-general",
        "license": "Apache-2.0",
        "note": "General/tool-use workhorse. Swap to Qwen3.6-35B-A3B-Instruct-4bit if present.",
    },
    {
        "id": "qwen3-coder-30b-a3b",
        "repo": "mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit",
        "tier": "resident-coder",
        "license": "Apache-2.0",
        "note": "Coding/agentic tool-dispatch specialist.",
    },
    {
        "id": "qwen3-4b",
        "repo": "mlx-community/Qwen3-4B-Instruct-2507-4bit",
        "tier": "fast-slm",
        "license": "Apache-2.0",
        "note": "Precedent rung / structured emission.",
    },
    {
        "id": "qwen3-1.7b",
        "repo": "mlx-community/Qwen3-1.7B-4bit",
        "tier": "classifier-edge",
        "license": "Apache-2.0",
        "note": "Router classifier / Pi-edge floor.",
    },
]

# ---------------------------------------------------------------------------
# LICENSE-GATED models — NOT in the clear-license reference set. Operator-electable only.
# These carry non-Apache/MIT licenses (Liquid's LFM Open License v1.0 is revenue-gated).
# Admitting one is an explicit operator decision (bounded operator sovereignty): superb
# edge tech, license strings attached. Enable with --include-license-gated.
# Confirm the current MLX 4-bit tag at pull time (LiquidAI or mlx-community build).
# ---------------------------------------------------------------------------
LICENSE_GATED_MODELS: List[Dict[str, str]] = [
    {
        "id": "lfm2.5-8b-a1b",
        "repo": "LiquidAI/LFM2.5-8B-A1B-MLX-4bit",
        "tier": "fast-slm (electable)",
        "license": "LFM Open License v1.0 (revenue-gated)",
        "note": "Liquid edge MoE (~1.5B active): IFEval 91.84, strong BFCL, <6GB. Best fast-tier tech if license clears.",
    },
    {
        "id": "lfm2.5-230m",
        "repo": "LiquidAI/LFM2.5-230M-MLX-4bit",
        "tier": "classifier-edge (electable)",
        "license": "LFM Open License v1.0 (revenue-gated)",
        "note": "230M edge / router-classifier; runs on a Pi 5. Confirm MLX tag.",
    },
]

# Corpus-scale ladder for UC-1 (research-synthesis reflection). A source + a few design docs
# lands in the 16k-64k range; 65536 probes the wall. Add 131072 to find the hard ceiling (may OOM).
DEFAULT_CONTEXTS = [4096, 16384, 32768, 65536]
DEFAULT_DECODE_TOKENS = 256

# Per-model operating config, applied BEFORE measurement (a model + its prompts are an
# atomic pair, per INFERENCE-ROUTING-DISCIPLINE). These emission-style evals (structured
# output, tool calls, classification, synthesis) want terse output as the CORRECT operating
# point for every model, so thinking is disabled: Instruct-2507 models ignore the flag;
# hybrid/thinking models (e.g. Qwen3-1.7B) get thinking off so they do not burn the token
# budget reasoning out loud. Override per model via a "chat_kwargs" key in a MODELS entry.
EVAL_CHAT_KWARGS = {"enable_thinking": False}


# ---------------------------------------------------------------------------
# ZeroPoint-shaped structured-output / tool-call eval.
# Each case: (name, chat messages, checker(text) -> bool).
# ---------------------------------------------------------------------------
def _extract_json(text: str) -> Optional[Any]:
    """Pull the first JSON object/array out of a model response (handles code fences)."""
    if not text:
        return None
    t = text.strip()
    if "```" in t:
        # take the largest fenced block
        parts = t.split("```")
        candidates = [p[4:] if p.lower().startswith("json") else p for p in parts]
        candidates = [c.strip() for c in candidates if "{" in c or "[" in c]
        for c in sorted(candidates, key=len, reverse=True):
            try:
                return json.loads(c)
            except Exception:
                continue
    # fall back to first { .. } span
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(t[start : end + 1])
        except Exception:
            return None
    return None


def _check_receipt(text: str) -> bool:
    obj = _extract_json(text)
    if not isinstance(obj, dict):
        return False
    required = {"receipt_type", "video_id", "segments", "source"}
    return required.issubset(set(obj.keys()))


def _check_tool_call(text: str) -> bool:
    obj = _extract_json(text)
    if not isinstance(obj, dict):
        return False
    if obj.get("name") != "youtube_get_transcript":
        return False
    args = obj.get("arguments")
    return isinstance(args, dict) and "video" in args


def _check_enum(text: str) -> bool:
    # classifier-style: must answer exactly one of the allowed tokens
    t = (text or "").strip().lower()
    # accept the first word being the verdict
    first = t.split()[0].strip(".,:'\"") if t.split() else ""
    return first in {"slm", "llm"}


def _check_synthesis(text: str) -> bool:
    # UC-1 short synthesis: valid JSON with a confirm/contradict/update relation + a target.
    obj = _extract_json(text)
    if not isinstance(obj, dict):
        return False
    rel = str(obj.get("relation", "")).lower()
    has_target = any(k in obj for k in ("target", "doc", "section"))
    return rel in {"updates", "confirms", "contradicts"} and has_target


STRUCTURED_CASES: List[Dict[str, Any]] = [
    {
        "name": "receipt_json",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Emit ONLY a JSON object (no prose) for a transcript receipt with exactly "
                    "these keys: receipt_type (string 'transcript:fetched'), video_id (string), "
                    "segments (integer), source (string). Use video_id 'abc123XYZ01', 61 segments, "
                    "source 'youtube_transcript_api'."
                ),
            }
        ],
        "check": _check_receipt,
    },
    {
        "name": "tool_call_json",
        "messages": [
            {
                "role": "user",
                "content": (
                    "You can call a tool `youtube_get_transcript(video: string)`. The user says: "
                    "'get me the transcript of https://youtu.be/dQw4w9WgXcQ'. Respond ONLY with a "
                    "JSON object: {\"name\": <tool>, \"arguments\": {\"video\": <value>}}."
                ),
            }
        ],
        "check": _check_tool_call,
    },
    {
        "name": "route_classifier",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Classify whether this task should route to a small local model (answer 'SLM') "
                    "or a frontier model (answer 'LLM'). Answer with ONE word only.\n"
                    "Task: 'Re-run the same structured extraction we've done 40 times on a new "
                    "receipt of an already-known class.'"
                ),
            }
        ],
        "check": _check_enum,
    },
    {
        # UC-1 flagship, short form: does a new source confirm/contradict/update an existing doc?
        "name": "uc1_synthesis",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Existing design note: 'DEPENDENCY-POSTURE — a local inference backend is a "
                    "strategic hedge, not yet built.' New finding: 'a frontier open model now runs "
                    "locally on commodity hardware.' Emit ONLY JSON (no prose): "
                    "{\"target\": <doc name>, \"relation\": \"updates|confirms|contradicts\", \"why\": <short>}."
                ),
            }
        ],
        "check": _check_synthesis,
    },
]

# Captured for human review (quant-degradation eyeball). Each carries an `expect` so you can
# grade groundedness at a glance. UC-1 (ontology extraction) + UC-3 (private-doc grounded QA).
QUALITY_PROMPTS: List[Dict[str, str]] = [
    {
        "name": "uc1_ontology_extract",
        "content": (
            "From this chain fragment, list the entities as JSON with keys "
            "trajectories, decisions, insights (arrays of short strings):\n"
            "'Operator declared an inference envelope authorizing two models; substrate "
            "recorded a served-model receipt; a divergence receipt fired when the router "
            "served a cheaper tier; operator flagged the divergence for review.'"
        ),
        "expect": "decisions include the envelope declaration; insights/trajectory note the routing divergence + operator flag.",
    },
    {
        "name": "uc3_grounded_qa",
        "content": (
            "PRIVATE DOCUMENT (answer ONLY from this text; do not use outside knowledge):\n"
            "'Master Services Agreement. Section 4.2: Fees are net-45. Section 9.1: Either party "
            "may terminate for convenience with 60 days written notice. Section 12: Governing law "
            "is Delaware.'\n\n"
            "QUESTION: How many days notice is required to terminate for convenience, and under "
            "which section? Answer in one sentence, citing the section."
        ),
        "expect": "60 days, Section 9.1. (Wrong number or fabricated section = int4 degradation on grounded retrieval.)",
    },
]


# ---------------------------------------------------------------------------
# Stats extraction (defensive across mlx-lm versions)
# ---------------------------------------------------------------------------
def _stat(resp: Any, *names: str) -> Optional[float]:
    for n in names:
        v = getattr(resp, n, None)
        if v is not None:
            try:
                return float(v)
            except Exception:
                pass
    return None


@dataclass
class ModelResult:
    id: str
    repo: str
    tier: str
    license: str
    loaded: bool = False
    load_error: Optional[str] = None
    load_seconds: Optional[float] = None
    decode_tps: Optional[float] = None
    peak_memory_gb: Optional[float] = None
    prefill: Dict[str, Any] = field(default_factory=dict)   # ctx_len -> {prompt_tokens, prefill_tps, peak_gb, error}
    structured: Dict[str, bool] = field(default_factory=dict)
    structured_score: Optional[str] = None
    samples: Dict[str, str] = field(default_factory=dict)


def _peak_gb() -> Optional[float]:
    try:
        import mlx.core as mx
        # API moved across versions; try the known spellings.
        for getter in ("get_peak_memory",):
            fn = getattr(mx, getter, None)
            if fn:
                return round(fn() / (1024 ** 3), 2)
        metal = getattr(mx, "metal", None)
        if metal and hasattr(metal, "get_peak_memory"):
            return round(metal.get_peak_memory() / (1024 ** 3), 2)
    except Exception:
        return None
    return None


def _reset_peak() -> None:
    try:
        import mlx.core as mx
        for name in ("reset_peak_memory",):
            fn = getattr(mx, name, None)
            if fn:
                fn()
                return
        metal = getattr(mx, "metal", None)
        if metal and hasattr(metal, "reset_peak_memory"):
            metal.reset_peak_memory()
    except Exception:
        pass


def _run_prompt(model, tokenizer, messages, max_tokens, chat_kwargs=None):
    """Run one generation; return (text, prompt_tps, gen_tps, prompt_tokens)."""
    from mlx_lm import stream_generate

    ck = dict(chat_kwargs or {})
    try:
        prompt = tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, tokenize=False, **ck
        )
    except Exception:
        prompt = tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, tokenize=False
        )
    text_parts: List[str] = []
    last = None
    manual_t0 = time.time()
    first_token_t: Optional[float] = None
    n_gen = 0
    for resp in stream_generate(model, tokenizer, prompt, max_tokens=max_tokens):
        if first_token_t is None:
            first_token_t = time.time()
        seg = getattr(resp, "text", None)
        if seg:
            text_parts.append(seg)
        n_gen += 1
        last = resp
    t_end = time.time()

    prompt_tps = _stat(last, "prompt_tps")
    gen_tps = _stat(last, "generation_tps")
    prompt_tokens = _stat(last, "prompt_tokens")

    # Manual fallbacks if the version doesn't expose stats.
    if prompt_tokens is None:
        try:
            prompt_tokens = float(len(tokenizer.encode(prompt)))
        except Exception:
            prompt_tokens = None
    if prompt_tps is None and prompt_tokens and first_token_t:
        dt = first_token_t - manual_t0
        prompt_tps = prompt_tokens / dt if dt > 0 else None
    if gen_tps is None and first_token_t and n_gen > 1:
        dt = t_end - first_token_t
        gen_tps = (n_gen - 1) / dt if dt > 0 else None

    return "".join(text_parts), prompt_tps, gen_tps, prompt_tokens


def _make_corpus_prompt(tokenizer, target_tokens: int):
    """UC-1 corpus-scale reflection probe.

    Builds a synthetic 'design corpus' (~target_tokens) with a planted SECTION 7 on inference
    sourcing, then asks a real synthesis question: which section does a new external finding
    update? Returns (messages, checker) where checker(text) -> bool tests whether the model
    located the right section AND emitted the synthesis *at that context length*. So each
    prefill step measures not just throughput but whether reflection still works at length.
    """
    topics = [
        "chain integrity", "quarantine plane", "circuit breaker", "kinship primitives",
        "media provenance", "hardware genesis", "observation plane", "recovery ceremony",
        "peer trust anchor", "household composition", "genesis rotation", "shadow evaluation",
    ]

    def _toklen(s: str) -> int:
        try:
            return len(tokenizer.encode(s))
        except Exception:
            return max(1, len(s) // 4)

    def _section(n: int, topic: str) -> str:
        return (
            f"SECTION {n} — {topic.upper()}: the substrate records each action as a signed receipt "
            f"on an append-only chain anchored to the operator's Genesis root; officers observe and "
            f"report while the Regent reasons over composed context regarding {topic}. "
        )

    needle = (
        "SECTION 7 — INFERENCE SOURCING: the substrate routes cognition across local, rallied, and "
        "cloud sources decoupled from Form; the practical floor for local frontier inference is "
        "treated as empirically unknown and measured, not assumed. "
    )
    question = (
        "\n\nQUESTION: A new external finding says: 'a 744B open Mixture-of-Experts model now runs "
        "on a commodity laptop via disk streaming, so local frontier capability is possible but "
        "latency-bound.' Which SECTION does this finding most directly update? Answer ONLY as JSON: "
        "{\"section\": <int>, \"relation\": \"updates|confirms|contradicts\"}."
    )

    parts: List[str] = []
    ti = 0
    for n in range(1, 7):          # sections 1..6
        parts.append(_section(n, topics[ti % len(topics)])); ti += 1
    parts.append(needle)           # section 7 = the needle
    n = 8
    q_tokens = _toklen(question)
    body = "".join(parts)
    # pad with further sections until we approach the target (keeps the needle mid-context)
    while _toklen(body) < max(0, target_tokens - q_tokens):
        body += _section(n, topics[ti % len(topics)]); n += 1; ti += 1

    messages = [{"role": "user", "content": body + question}]

    def checker(text: str) -> bool:
        obj = _extract_json(text)
        if isinstance(obj, dict):
            try:
                if int(obj.get("section")) == 7:
                    return True
            except Exception:
                pass
        t = (text or "").lower()
        return ('"section": 7' in t) or ("section 7" in t) or ("inference sourcing" in t)

    return messages, checker


def benchmark_model(spec: Dict[str, str], contexts: List[int], decode_tokens: int,
                    samples_out: List[str]) -> ModelResult:
    res = ModelResult(id=spec["id"], repo=spec["repo"], tier=spec["tier"], license=spec["license"])
    ck = {**EVAL_CHAT_KWARGS, **spec.get("chat_kwargs", {})}
    from mlx_lm import load

    # --- load ---
    try:
        _reset_peak()
        t0 = time.time()
        model, tokenizer = load(spec["repo"])
        res.load_seconds = round(time.time() - t0, 1)
        res.loaded = True
    except Exception as e:
        res.load_error = f"{type(e).__name__}: {e}"
        return res

    # --- decode tok/s (short prompt, warm) ---
    try:
        _reset_peak()
        _txt, _ptps, gtps, _pt = _run_prompt(
            model, tokenizer,
            [{"role": "user", "content": "Write two sentences about append-only audit logs."}],
            max_tokens=decode_tokens,
            chat_kwargs=ck,
        )
        res.decode_tps = round(gtps, 1) if gtps else None
        res.peak_memory_gb = _peak_gb()
    except Exception as e:
        res.samples["_decode_error"] = f"{type(e).__name__}: {e}"

    # --- prefill across contexts, carrying a real UC-1 needle-synthesis task ---
    for ctx in contexts:
        entry: Dict[str, Any] = {}
        try:
            _reset_peak()
            msgs, checker = _make_corpus_prompt(tokenizer, ctx)
            txt, ptps, _g, ptoks = _run_prompt(model, tokenizer, msgs, max_tokens=96, chat_kwargs=ck)
            entry["prompt_tokens"] = int(ptoks) if ptoks else None
            entry["prefill_tps"] = round(ptps, 1) if ptps else None
            entry["peak_gb"] = _peak_gb()
            entry["synthesis_ok"] = bool(checker(txt))   # UC-1: did reflection still work at this length?
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {e}"  # OOM here == your effective ceiling
        res.prefill[str(ctx)] = entry

    # --- structured-output / tool-call reliability ---
    passed = 0
    for case in STRUCTURED_CASES:
        try:
            txt, _p, _g, _t = _run_prompt(model, tokenizer, case["messages"], max_tokens=512, chat_kwargs=ck)
            ok = bool(case["check"](txt))
        except Exception as e:
            ok = False
            txt = f"<error: {type(e).__name__}: {e}>"
        res.structured[case["name"]] = ok
        passed += int(ok)
        samples_out.append(f"[{res.id}] structured/{case['name']} -> {'PASS' if ok else 'FAIL'}\n{txt}\n")
    res.structured_score = f"{passed}/{len(STRUCTURED_CASES)}"

    # --- quant-degradation sanity (UC-1 ontology + UC-3 grounded QA; captured for human review) ---
    for q in QUALITY_PROMPTS:
        try:
            txt, _p, _g, _t = _run_prompt(
                model, tokenizer, [{"role": "user", "content": q["content"]}],
                max_tokens=400, chat_kwargs=ck,
            )
        except Exception as e:
            txt = f"<error: {type(e).__name__}: {e}>"
        res.samples[q["name"]] = txt
        expect = q.get("expect")
        header = f"[{res.id}] quality/{q['name']}"
        if expect:
            header += f"\n  EXPECT: {expect}"
        samples_out.append(f"{header}\n{txt}\n")

    # free the model before the next one (single-box memory discipline)
    try:
        del model, tokenizer
        import mlx.core as mx
        clr = getattr(mx, "clear_cache", None)
        if clr:
            clr()
    except Exception:
        pass

    return res


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def render_markdown(results: List[ModelResult], contexts: List[int], stamp: str, target: str) -> str:
    lines = [
        f"# ZeroPoint local-model benchmark — {target} — {stamp}",
        "",
        f"Target node: **{target}** (Apple Silicon / MLX). Default set is clear-license only; "
        "`--include-license-gated` appends operator-electable (Tier B) models. "
        "Emission evals run with thinking disabled - each model at its correct operating point.",
        "",
        "## Summary",
        "",
        "| model | tier | license | load s | decode tok/s | peak GB | structured | notes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        if not r.loaded:
            lines.append(f"| {r.id} | {r.tier} | {r.license} | — | — | — | — | LOAD FAIL: {r.load_error} |")
            continue
        lines.append(
            f"| {r.id} | {r.tier} | {r.license} | {r.load_seconds} | "
            f"{r.decode_tps or '—'} | {r.peak_memory_gb or '—'} | {r.structured_score or '—'} | |"
        )
    # prefill table = UC-1 feasibility curve: prefill tok/s / peak GB / did synthesis still work
    lines += [
        "",
        "## UC-1 feasibility by context length (prefill tok/s / peak GB / synthesis✓)",
        "",
        "Each cell carries a real needle-synthesis task at that context length. `✓/✗` = did the "
        "model locate the right corpus section and answer. Where `✗` appears or the cell OOMs is "
        "your whole-chain-reflection ceiling — the number that decides UC-1's feasibility on this node.",
        "",
    ]
    header = "| model | " + " | ".join(f"{c}" for c in contexts) + " |"
    sep = "|---|" + "---|" * len(contexts)
    lines += [header, sep]
    for r in results:
        if not r.loaded:
            continue
        cells = []
        for c in contexts:
            e = r.prefill.get(str(c), {})
            if e.get("error"):
                cells.append("OOM/err")
            else:
                tps = e.get("prefill_tps")
                pk = e.get("peak_gb")
                mark = "✓" if e.get("synthesis_ok") else "✗"
                cells.append(f"{tps or '—'} / {pk if pk else '—'}GB / {mark}")
        lines.append(f"| {r.id} | " + " | ".join(cells) + " |")
    # structured detail
    lines += ["", "## Structured-output / tool-call detail", ""]
    case_names = [c["name"] for c in STRUCTURED_CASES]
    lines += ["| model | " + " | ".join(case_names) + " |", "|---|" + "---|" * len(case_names)]
    for r in results:
        if not r.loaded:
            continue
        cells = ["✓" if r.structured.get(n) else "✗" for n in case_names]
        lines.append(f"| {r.id} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "## Reading the results (ZeroPoint routing implications)",
        "",
        "- **decode tok/s** — is this tier interactive (realtime horizon) or background-only?",
        "- **UC-1 feasibility curve** — the length where `✓` flips to `✗` (or OOMs) is APOLLO's "
        "whole-chain-reflection ceiling, i.e. how much corpus the flagship use case can actually "
        "reason over on this node. This is the single most decision-relevant number.",
        "- **structured/tool (incl. uc1_synthesis)** — a model that can't hold this is not a "
        "Regent-emission candidate, regardless of speed.",
        "- **peak GB** — headroom against the ~48–56GB budget; watch it climb with context (KV cache).",
        "- **samples file (uc1_ontology + uc3_grounded_qa)** — read against each task's EXPECT line; "
        "a wrong number or fabricated section on UC-3 is int4 grounded-retrieval degradation, quietly.",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="ZeroPoint local-model benchmark (MLX).")
    ap.add_argument("--models", default="", help="comma-separated model ids to run (default: all)")
    ap.add_argument("--contexts", default="", help="comma-separated prefill context lengths")
    ap.add_argument("--decode-tokens", type=int, default=DEFAULT_DECODE_TOKENS)
    ap.add_argument("--stamp", default="latest", help="output filename stamp (Date.now unavailable in some envs)")
    ap.add_argument("--include-license-gated", action="store_true",
                    help="also benchmark license-gated (non-Apache/MIT) models, e.g. Liquid LFM2.5 — operator-electable, not the reference set")
    ap.add_argument("--target", default="APOLLO",
                    help="named fleet node this run is measuring (default APOLLO, the M4 Pro Mac Mini). "
                         "PI5 uses a separate llama.cpp/GGUF track, not this MLX harness.")
    args = ap.parse_args()

    contexts = (
        [int(x) for x in args.contexts.split(",") if x.strip()]
        if args.contexts
        else list(DEFAULT_CONTEXTS)
    )
    pool = list(MODELS)
    if args.include_license_gated:
        print("NOTE: including LICENSE-GATED models (non-Apache/MIT, e.g. Liquid LFM Open License). "
              "These are operator-electable, NOT part of the clear-license reference set.", file=sys.stderr)
        pool += LICENSE_GATED_MODELS
    wanted = {m.strip() for m in args.models.split(",") if m.strip()}
    specs = [m for m in pool if (not wanted or m["id"] in wanted)]
    if not specs:
        known = [m["id"] for m in pool]
        print(f"No models matched {wanted}. Known ids: {known}"
              " (add --include-license-gated for Liquid options.)", file=sys.stderr)
        return 2

    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[ModelResult] = []
    samples: List[str] = []
    for spec in specs:
        print(f"==> benchmarking {spec['id']} ({spec['repo']})", file=sys.stderr)
        try:
            results.append(benchmark_model(spec, contexts, args.decode_tokens, samples))
        except Exception as e:
            print(f"    fatal for {spec['id']}: {e}", file=sys.stderr)
            traceback.print_exc()
            r = ModelResult(id=spec["id"], repo=spec["repo"], tier=spec["tier"], license=spec["license"])
            r.load_error = f"fatal: {type(e).__name__}: {e}"
            results.append(r)

    stamp = args.stamp
    base = f"{args.target}-{stamp}"
    (out_dir / f"bench-{base}.json").write_text(
        json.dumps(
            {"target": args.target, "stamp": stamp, "contexts": contexts,
             "results": [asdict(r) for r in results]},
            indent=2,
        ),
        encoding="utf-8",
    )
    (out_dir / f"bench-{base}.md").write_text(
        render_markdown(results, contexts, stamp, args.target), encoding="utf-8"
    )
    (out_dir / f"samples-{base}.txt").write_text("\n".join(samples), encoding="utf-8")

    print(f"\nWrote:\n  {out_dir/f'bench-{base}.json'}\n  {out_dir/f'bench-{base}.md'}\n  {out_dir/f'samples-{base}.txt'}",
          file=sys.stderr)
    # echo the markdown so it's visible immediately
    print("\n" + (out_dir / f"bench-{base}.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
