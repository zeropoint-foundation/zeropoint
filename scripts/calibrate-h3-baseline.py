#!/usr/bin/env python3
"""
calibrate-h3-baseline.py — populate [entropy_baseline] in a model dossier.

Runs a calibration battery of prompts against a served model, collects
per-chosen-token log-probabilities from each response, computes the mean
and standard deviation of -log P(chosen) across the battery, and writes
the result into models/<family>/model_dossier.toml so
zp_emission_coherence's H3 (token entropy anomaly) heuristic has a
baseline to compare against.

H3 spec: REGENT-DOOM-LOOP-DETECTION-2026-07.md §Heuristic 3.
Dossier field: [entropy_baseline] per MODEL-DOSSIER-2026-07 schema.
Loader: crates/zp-regent/src/routing.rs::DossierCorpus::entropy_baselines()
        wired into loop_runner.rs via zp-server/src/regent.rs (commit
        56cda86, 2026-08-01).

# Backend

Ollama's OpenAI-compat endpoint at /v1/chat/completions supports
`logprobs=true` and returns per-token log-probabilities in
response.choices[0].logprobs.content. This script uses that endpoint.
Other backends (llama.cpp server, vLLM, MLX with the OpenAI wrapper)
expose the same OpenAI logprobs shape and will work with `--endpoint`.

MLX raw (mlx_lm.generate) also exposes per-token logprobs but through a
different API; not supported here to keep the script HTTP-only.

# Determinism

Sampling is fixed to `temperature=0.0` for baseline calibration —
greedy decoding produces the most reproducible surprise distribution
per prompt. Non-zero temperatures inflate surprise variance and would
make the baseline a moving target.

# Corpus

Defaults to scripts/parity-corpora/starter-24.jsonl (24 prompts across
chat / code / math / reasoning / tool_dispatch / other workload classes).
Point --corpus at any JSONL with `text` and `max_tokens` fields for
larger batteries.

# Usage

    # Dry run against Ollama's default endpoint — no writes
    python3 scripts/calibrate-h3-baseline.py --model qwen3:8b --dry-run

    # Real run: populates models/qwen3/model_dossier.toml
    python3 scripts/calibrate-h3-baseline.py --model qwen3:8b --family qwen3

    # Custom endpoint / corpus
    python3 scripts/calibrate-h3-baseline.py --model qwen3:8b --family qwen3 \\
        --endpoint http://localhost:11434 \\
        --corpus scripts/parity-corpora/starter-24.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ── HTTP client ────────────────────────────────────────────────────────

def call_completion(endpoint: str, model: str, prompt: str, max_tokens: int,
                    timeout: int) -> dict:
    """Call the OpenAI-compat /v1/chat/completions with logprobs enabled.

    Returns the raw response JSON. Raises on HTTP error, network error,
    or non-200 status.
    """
    url = endpoint.rstrip("/") + "/v1/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.0,
        "logprobs": True,
        "top_logprobs": 1,
        "stream": False,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_chosen_logprobs(response: dict) -> list[float] | None:
    """Extract per-chosen-token log-probabilities from a chat response.

    Expected OpenAI shape:
        response.choices[0].logprobs.content = [
            {"token": "hello", "logprob": -0.34, "top_logprobs": [...]},
            ...
        ]

    Returns None if the response doesn't carry logprobs (backend
    doesn't support them, or returned empty). Non-numeric logprob
    values are silently skipped.
    """
    try:
        content = response["choices"][0]["logprobs"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
    if not content:
        return None
    out = []
    for tok in content:
        lp = tok.get("logprob")
        if isinstance(lp, (int, float)) and math.isfinite(lp):
            out.append(float(lp))
    return out or None


# ── Statistics ────────────────────────────────────────────────────────

def response_mean_surprise(logprobs: list[float]) -> float:
    """Mean per-token surprise for a single response.

    Surprise = -log P(chosen). Log-probs are non-positive
    (P in [0, 1] → log P ≤ 0), so surprise is non-negative.
    """
    return sum(-lp for lp in logprobs) / len(logprobs)


# ── Dossier writer ────────────────────────────────────────────────────

def write_baseline(
    dossier_path: Path,
    mean: float,
    std_dev: float,
    prompt_count: int,
    battery_receipt: str,
    calibrated_at: str,
    target_variant: str,
) -> None:
    """Update the dossier's [entropy_baseline] fields in place.

    Regex-based edit — parses each `key = value` line in the
    [entropy_baseline] section and replaces the numeric/string values.
    Preserves surrounding comments and TOML structure exactly.

    Rejects if the dossier lacks an [entropy_baseline] section.
    """
    import re

    text = dossier_path.read_text()
    if "[entropy_baseline]" not in text:
        raise SystemExit(
            f"{dossier_path} lacks an [entropy_baseline] section — "
            f"add the schema first (see commit 56cda86 for the shape)."
        )

    def replace_field(text: str, field: str, new_value: str) -> str:
        # Match `field = <anything until end-of-line>` inside
        # [entropy_baseline] section. Non-greedy up to first newline.
        # Match must respect the section boundary — we scope by
        # extracting the section, editing, and re-inserting.
        pat = re.compile(rf"^({re.escape(field)}\s*=\s*)([^\n#]+?)(\s*(?:#.*)?)$",
                         re.MULTILINE)
        return pat.sub(rf"\g<1>{new_value}\g<3>", text, count=1)

    # Scope the edits: extract [entropy_baseline] block, edit, splice back.
    section_start = text.index("[entropy_baseline]")
    # Section ends at next `\n[` (next top-level section header) or EOF.
    section_end_rel = text[section_start + 1:].find("\n[")
    section_end = (section_start + 1 + section_end_rel) if section_end_rel >= 0 else len(text)
    before = text[:section_start]
    section = text[section_start:section_end]
    after = text[section_end:]

    section = replace_field(section, "state", '"calibrated"')
    section = replace_field(section, "target_variant", f'"{target_variant}"')
    section = replace_field(section, "mean", f"{mean:.6f}")
    section = replace_field(section, "std_dev", f"{std_dev:.6f}")
    section = replace_field(section, "battery_prompt_count", str(prompt_count))
    section = replace_field(section, "battery_receipt", f'"{battery_receipt}"')
    section = replace_field(section, "calibrated_at", f'"{calibrated_at}"')

    dossier_path.write_text(before + section + after)


# ── Main ──────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--model", required=True,
                    help='Model identifier the server understands, e.g. "qwen3:8b".')
    ap.add_argument("--family", default=None,
                    help='Dossier family (subdirectory under models/). '
                         'If omitted, writes nothing — prints results only.')
    ap.add_argument("--target-variant", default=None,
                    help='Value written to entropy_baseline.target_variant. '
                         'Defaults to --model.')
    ap.add_argument("--endpoint", default="http://localhost:11434",
                    help="Base URL of the OpenAI-compat server (default Ollama).")
    ap.add_argument("--corpus", default="scripts/parity-corpora/starter-24.jsonl",
                    help="JSONL calibration corpus.")
    ap.add_argument("--repo-root", default=".",
                    help="Path to the repo root (models/ + scripts/ resolved from here).")
    ap.add_argument("--timeout", type=int, default=180,
                    help="Per-request timeout in seconds (default 180).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compute + print results; do NOT write to any dossier.")
    ap.add_argument("--verbose", action="store_true",
                    help="Print per-response surprise as calibration runs.")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    corpus_path = repo_root / args.corpus
    if not corpus_path.exists():
        print(f"corpus not found: {corpus_path}", file=sys.stderr)
        return 2

    target_variant = args.target_variant or args.model

    prompts = [json.loads(line) for line in corpus_path.read_text().splitlines() if line.strip()]
    if not prompts:
        print(f"corpus empty: {corpus_path}", file=sys.stderr)
        return 2

    print(f"calibrating H3 baseline for {args.model} against {args.endpoint}")
    print(f"corpus: {corpus_path} ({len(prompts)} prompts)")
    print(f"target_variant: {target_variant}")
    print()

    per_response_surprises: list[float] = []
    per_class_surprises: dict[str, list[float]] = defaultdict(list)
    dropped: list[tuple[str, str]] = []
    start = time.time()

    for i, prompt in enumerate(prompts, 1):
        pid = prompt.get("id", f"prompt-{i}")
        wc = prompt.get("workload_class", "unknown")
        text = prompt.get("text", "")
        max_toks = prompt.get("max_tokens", 128)
        if not text:
            dropped.append((pid, "empty text"))
            continue
        try:
            resp = call_completion(
                args.endpoint, args.model, text, max_toks, args.timeout
            )
        except urllib.error.URLError as e:
            dropped.append((pid, f"HTTP error: {e}"))
            print(f"  [{i}/{len(prompts)}] {pid} ({wc}) DROPPED — {e}", file=sys.stderr)
            continue
        except Exception as e:
            dropped.append((pid, f"error: {e}"))
            print(f"  [{i}/{len(prompts)}] {pid} ({wc}) DROPPED — {e}", file=sys.stderr)
            continue

        logprobs = extract_chosen_logprobs(resp)
        if not logprobs:
            dropped.append((pid, "no logprobs in response — backend may not support them"))
            print(f"  [{i}/{len(prompts)}] {pid} ({wc}) DROPPED — no logprobs "
                  "(backend doesn't support them for this model)",
                  file=sys.stderr)
            continue

        surprise = response_mean_surprise(logprobs)
        per_response_surprises.append(surprise)
        per_class_surprises[wc].append(surprise)
        if args.verbose:
            print(f"  [{i}/{len(prompts)}] {pid} ({wc}) surprise={surprise:.4f} "
                  f"tokens={len(logprobs)}")

    elapsed = time.time() - start
    if not per_response_surprises:
        print(f"\nno usable responses collected — cannot compute baseline.", file=sys.stderr)
        print(f"dropped: {len(dropped)} — first few:", file=sys.stderr)
        for pid, reason in dropped[:5]:
            print(f"  {pid}: {reason}", file=sys.stderr)
        return 3

    mean = statistics.fmean(per_response_surprises)
    std_dev = statistics.stdev(per_response_surprises) if len(per_response_surprises) > 1 else 0.0

    # Battery hash — content-addressed identity for the calibration input.
    # Lets a future receipt point at exactly this corpus+model+endpoint
    # combination for auditability.
    battery_content = json.dumps({
        "model": args.model,
        "target_variant": target_variant,
        "endpoint": args.endpoint,
        "corpus_path": str(corpus_path.relative_to(repo_root)),
        "prompt_ids": [p.get("id") for p in prompts],
    }, sort_keys=True).encode()
    battery_hash = hashlib.blake2b(battery_content, digest_size=16).hexdigest()
    battery_receipt = f"regent:calibration:h3:{battery_hash}"
    calibrated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print()
    print(f"── H3 baseline for {args.model} ────────────────────────")
    print(f"  mean surprise      : {mean:.6f}")
    print(f"  std_dev            : {std_dev:.6f}")
    print(f"  responses used     : {len(per_response_surprises)}/{len(prompts)}")
    print(f"  dropped            : {len(dropped)}")
    print(f"  elapsed            : {elapsed:.1f}s")
    print(f"  battery_receipt    : {battery_receipt}")
    print(f"  calibrated_at      : {calibrated_at}")
    print()
    if per_class_surprises:
        print("── Per workload class (informational — not stored yet) ─")
        for wc, vals in sorted(per_class_surprises.items()):
            m = statistics.fmean(vals)
            s = statistics.stdev(vals) if len(vals) > 1 else 0.0
            print(f"  {wc:16s} n={len(vals):2d}  mean={m:.4f}  std={s:.4f}")

    if args.dry_run:
        print("\n[dry-run] not writing to any dossier.")
        return 0

    if not args.family:
        print("\nno --family given; not writing to any dossier. Pass --family qwen3 "
              "(or similar) to persist the baseline.")
        return 0

    dossier_path = repo_root / "models" / args.family / "model_dossier.toml"
    if not dossier_path.exists():
        print(f"\ndossier not found: {dossier_path}", file=sys.stderr)
        return 4
    write_baseline(
        dossier_path=dossier_path,
        mean=mean,
        std_dev=std_dev,
        prompt_count=len(per_response_surprises),
        battery_receipt=battery_receipt,
        calibrated_at=calibrated_at,
        target_variant=target_variant,
    )
    print(f"\nwrote baseline to {dossier_path}")
    print("regenerate connections.json if you want the maturity number to update.")
    print()
    print("suggested receipt emission (chain-anchors the calibration run):")
    print(f"  zp chain emit {battery_receipt} "
          f'--detail "model={args.model}, mean={mean:.4f}, std_dev={std_dev:.4f}, '
          f'n={len(per_response_surprises)}, corpus_hash={battery_hash}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
