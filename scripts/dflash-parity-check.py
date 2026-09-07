#!/usr/bin/env python3
"""
dflash-parity-check.py — byte-identical parity attestation for a DFlash drafter.

Runs the **acceleration-ablation shadow scenario** per
`docs/design/SHADOW-EVALUATION-PRIMITIVE-2026-07.md` §Context 1 — same prompt,
same seed, drafter-active vs drafter-inactive, byte-by-byte compare. Produces
the `substrate:characterization:validated` receipt required by
`docs/design/MODEL-DOSSIER-2026-07.md` §"Bootstrap ceremony" to promote a
drafter's dossier state from `not_yet_trained` to `active`.

## Requirements

- macOS on Apple Silicon (MLX runtime).
- dflash-mlx installed (see `scripts/install-dflash-mlx.sh`).
- The target model weights cached (first launch of `dflash serve --model X`
  pulls them; subsequent runs use cache).

## Usage

```
# Full parity run against qwen3:8b + its DFlash drafter, using the default
# corpus in scripts/parity-corpora/starter-200.jsonl:
python3 scripts/dflash-parity-check.py \\
  --target Qwen/Qwen3-8B \\
  --drafter z-lab/Qwen3-8B-DFlash-b16 \\
  --corpus scripts/parity-corpora/starter-200.jsonl

# Dry run — validate script + corpus without loading the model:
python3 scripts/dflash-parity-check.py --dry-run \\
  --target Qwen/Qwen3-8B --corpus scripts/parity-corpora/starter-200.jsonl

# Small smoke run with 3 prompts:
python3 scripts/dflash-parity-check.py \\
  --target Qwen/Qwen3-8B --drafter z-lab/Qwen3-8B-DFlash-b16 \\
  --corpus scripts/parity-corpora/starter-200.jsonl --limit 3
```

Report lands at
`models/<family>/drafters/parity-report-<UTC-timestamp>-<corpus-hash>.json` by
default; override with `--out`. The report file IS the evidence input for
`substrate:characterization:validated` — sign it via your normal receipt-
emission path.

## Pass criterion

Every prompt in the corpus must produce byte-identical output on both the
baseline (target-alone) path and the accelerated (target+drafter) path. Any
divergence blocks drafter promotion until root-caused (see
MODEL-DOSSIER §"Bootstrap ceremony").

## Adapter shape

This script is adapter-based to avoid hard-coding one particular dflash-mlx
API surface. Two callables are required:

- `baseline_generate(model_id, prompt, max_tokens, seed) -> List[int]` —
  returns the token IDs the target would emit un-accelerated.
- `accelerated_generate(model_id, drafter_id, prompt, max_tokens, seed) ->
  List[int]` — returns the token IDs from the target+drafter path.

The default adapters use `dflash_mlx` in-process (models loaded once,
reused). If your dflash-mlx version exposes a different API surface, swap
the adapter functions marked ADAPTER-SEAM.

## Determinism

Uses greedy decoding (`temperature=0.0`) so both paths are deterministic
functions of the input prompt. Seed argument is passed through in case the
runtime uses it for tie-breaking; for greedy at temp=0, seed shouldn't
matter, but we pass it explicitly for reproducibility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional, Callable, Any


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


@dataclass
class Prompt:
    """One prompt in the parity corpus."""

    id: str
    """Stable identifier — used for reporting divergences."""

    text: str
    """The prompt text to send to the model."""

    workload_class: str = "chat"
    """One of the classes MODEL-DOSSIER tracks per-workload acceptance rate
    against: chat | math | code | reasoning | tool_dispatch | other."""

    max_tokens: int = 128
    """Max tokens to generate. Longer = more surface area for divergence
    but slower. 128 is a reasonable balance for parity testing."""


def load_corpus(path: Path) -> list[Prompt]:
    """Load a JSONL corpus of prompts. One JSON object per line."""
    prompts: list[Prompt] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw or raw.startswith("//") or raw.startswith("#"):
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"{path}:{lineno}: invalid JSON — {e}"
                ) from e
            if "text" not in obj:
                raise ValueError(
                    f"{path}:{lineno}: missing required field 'text'"
                )
            prompts.append(
                Prompt(
                    id=obj.get("id", f"line-{lineno}"),
                    text=obj["text"],
                    workload_class=obj.get("workload_class", "chat"),
                    max_tokens=int(obj.get("max_tokens", 128)),
                )
            )
    return prompts


def hash_corpus(prompts: list[Prompt]) -> str:
    """Deterministic SHA-256 of the corpus contents."""
    h = hashlib.sha256()
    for p in prompts:
        # Sorted keys and no extra whitespace for stable hashing.
        payload = json.dumps(
            {
                "id": p.id,
                "text": p.text,
                "workload_class": p.workload_class,
                "max_tokens": p.max_tokens,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        h.update(payload.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Adapters — the runtime-dependent seam
# ---------------------------------------------------------------------------
#
# These are the two callables the parity check consumes. Defaults use
# dflash-mlx in-process. If your dflash-mlx version has a different API
# surface, swap these — the rest of the script is API-agnostic.


class AdapterError(RuntimeError):
    """Raised when an adapter can't complete its call."""


def _import_dflash_mlx():
    """Lazy import; raise AdapterError if not available."""
    try:
        import dflash_mlx  # type: ignore
    except ImportError as e:
        raise AdapterError(
            "dflash_mlx not importable. Run scripts/install-dflash-mlx.sh "
            "and activate the venv at .venvs/dflash-mlx before running "
            "this script.\n"
            f"underlying error: {e}"
        ) from e
    return dflash_mlx


# Model cache — load-once-per-run.
_MODEL_CACHE: dict[str, Any] = {}


def _load_target(model_id: str) -> Any:
    """Load the target model once per run and cache it.

    ADAPTER-SEAM: adjust the actual load call to match your dflash-mlx
    version's API. Common shapes seen in the ecosystem:

    - `dflash_mlx.load(model_id)` → (model, tokenizer)
    - `dflash_mlx.load_model(model_id)` and separately `.load_tokenizer(...)`
    - `mlx_lm.load(model_id)` for the pure-baseline path
    """
    cache_key = f"target:{model_id}"
    if cache_key in _MODEL_CACHE:
        return _MODEL_CACHE[cache_key]
    dflash_mlx = _import_dflash_mlx()
    # ADAPTER-SEAM: replace with actual dflash-mlx load call.
    if hasattr(dflash_mlx, "load"):
        loaded = dflash_mlx.load(model_id)
    elif hasattr(dflash_mlx, "load_model"):
        loaded = dflash_mlx.load_model(model_id)
    else:
        raise AdapterError(
            f"dflash_mlx has neither .load() nor .load_model() — "
            f"check your dflash-mlx version and update this adapter. "
            f"Available top-level attrs: {sorted(vars(dflash_mlx))[:20]}"
        )
    _MODEL_CACHE[cache_key] = loaded
    return loaded


def _load_drafter(target_id: str, drafter_id: str) -> Any:
    """Load the drafter checkpoint once per run and cache it."""
    cache_key = f"drafter:{target_id}:{drafter_id}"
    if cache_key in _MODEL_CACHE:
        return _MODEL_CACHE[cache_key]
    dflash_mlx = _import_dflash_mlx()
    # ADAPTER-SEAM: replace with actual drafter-load call.
    if hasattr(dflash_mlx, "load_drafter"):
        loaded = dflash_mlx.load_drafter(drafter_id)
    elif hasattr(dflash_mlx, "load"):
        loaded = dflash_mlx.load(drafter_id)
    else:
        raise AdapterError(
            f"dflash_mlx has no drafter-load entry point — "
            f"check your dflash-mlx version and update this adapter."
        )
    _MODEL_CACHE[cache_key] = loaded
    return loaded


def baseline_generate(
    model_id: str, prompt: str, max_tokens: int, seed: int
) -> tuple[list[int], float]:
    """Target-alone generation. Returns (token_ids, elapsed_seconds).

    ADAPTER-SEAM: the actual generation call depends on the runtime's API.
    Reference shapes:

    - `mlx_lm.generate(model, tokenizer, prompt, max_tokens=..., temp=0.0)`
    - `dflash_mlx.generate(model, tokenizer, prompt, ..., use_drafter=False)`
    """
    loaded = _load_target(model_id)
    dflash_mlx = _import_dflash_mlx()
    t0 = time.perf_counter()
    # ADAPTER-SEAM: replace with actual generate call.
    if hasattr(dflash_mlx, "generate"):
        result = dflash_mlx.generate(
            loaded,
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=0.0,
            seed=seed,
            use_drafter=False,
        )
    else:
        raise AdapterError(
            "dflash_mlx.generate not found — update baseline_generate "
            "adapter for your version."
        )
    elapsed = time.perf_counter() - t0
    token_ids = _extract_token_ids(result)
    return token_ids, elapsed


def accelerated_generate(
    model_id: str, drafter_id: str, prompt: str, max_tokens: int, seed: int
) -> tuple[list[int], float]:
    """Target+drafter generation. Returns (token_ids, elapsed_seconds)."""
    loaded = _load_target(model_id)
    drafter = _load_drafter(model_id, drafter_id)
    dflash_mlx = _import_dflash_mlx()
    t0 = time.perf_counter()
    # ADAPTER-SEAM: replace with actual accelerated call.
    if hasattr(dflash_mlx, "generate"):
        result = dflash_mlx.generate(
            loaded,
            drafter=drafter,
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=0.0,
            seed=seed,
            use_drafter=True,
        )
    else:
        raise AdapterError(
            "dflash_mlx.generate not found — update accelerated_generate "
            "adapter for your version."
        )
    elapsed = time.perf_counter() - t0
    token_ids = _extract_token_ids(result)
    return token_ids, elapsed


def _extract_token_ids(result: Any) -> list[int]:
    """Normalize whatever the runtime returns into a list of int token IDs.

    ADAPTER-SEAM: adjust for your dflash-mlx version's return shape.
    """
    # Common shapes:
    if isinstance(result, list) and result and isinstance(result[0], int):
        return list(result)
    if hasattr(result, "token_ids"):
        return list(result.token_ids)
    if isinstance(result, dict) and "token_ids" in result:
        return list(result["token_ids"])
    if hasattr(result, "tolist"):  # numpy / mlx array
        return list(result.tolist())
    raise AdapterError(
        f"unable to extract token IDs from result of type {type(result)}"
    )


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


@dataclass
class Divergence:
    prompt_id: str
    workload_class: str
    first_position: int
    baseline_token_at_position: int
    accelerated_token_at_position: int
    baseline_length: int
    accelerated_length: int


@dataclass
class PromptResult:
    prompt_id: str
    workload_class: str
    baseline_length: int
    accelerated_length: int
    identical: bool
    baseline_elapsed_s: float
    accelerated_elapsed_s: float
    divergence: Optional[Divergence] = None


def compare_outputs(
    prompt: Prompt,
    baseline_tokens: list[int],
    accelerated_tokens: list[int],
    baseline_elapsed: float,
    accelerated_elapsed: float,
) -> PromptResult:
    """Byte-identical comparison at token granularity."""
    identical = baseline_tokens == accelerated_tokens
    divergence: Optional[Divergence] = None
    if not identical:
        first = min(len(baseline_tokens), len(accelerated_tokens))
        for i in range(first):
            if baseline_tokens[i] != accelerated_tokens[i]:
                first = i
                break
        divergence = Divergence(
            prompt_id=prompt.id,
            workload_class=prompt.workload_class,
            first_position=first,
            baseline_token_at_position=(
                baseline_tokens[first] if first < len(baseline_tokens) else -1
            ),
            accelerated_token_at_position=(
                accelerated_tokens[first]
                if first < len(accelerated_tokens)
                else -1
            ),
            baseline_length=len(baseline_tokens),
            accelerated_length=len(accelerated_tokens),
        )
    return PromptResult(
        prompt_id=prompt.id,
        workload_class=prompt.workload_class,
        baseline_length=len(baseline_tokens),
        accelerated_length=len(accelerated_tokens),
        identical=identical,
        baseline_elapsed_s=baseline_elapsed,
        accelerated_elapsed_s=accelerated_elapsed,
        divergence=divergence,
    )


# ---------------------------------------------------------------------------
# Receipt shape (per MODEL-DOSSIER §"Unified receipt schema")
# ---------------------------------------------------------------------------


@dataclass
class ParityReport:
    """The evidence payload for a substrate:characterization:validated receipt."""

    receipt_type: str = "substrate:characterization:validated"
    characterization_form: str = "drafter"
    lifecycle_state: str = "validated"  # ready for operator ratification → active

    target: dict[str, str] = field(default_factory=dict)
    drafter: dict[str, str] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    parity: dict[str, Any] = field(default_factory=dict)
    per_prompt: list[dict[str, Any]] = field(default_factory=list)
    divergences: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--target",
        required=True,
        help="Target model identifier (HF hub ID or local path).",
    )
    p.add_argument(
        "--drafter",
        default=None,
        help="Drafter checkpoint (HF hub ID). If omitted, dflash-mlx's "
        "auto-resolution is used for registered targets.",
    )
    p.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="JSONL file of prompts. One JSON object per line with fields: "
        "id (optional), text (required), workload_class (optional, "
        "default 'chat'), max_tokens (optional, default 128).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Run only the first N prompts (smoke testing).",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Random seed passed to both paths for tie-breaking. Greedy "
        "decoding at temp=0 should be deterministic regardless.",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the parity report here. Default: "
        "models/<derived-family>/drafters/parity-report-<ts>-<hash>.json",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Load and hash the corpus, validate the environment, but "
        "don't invoke the runtime. Useful for verifying setup.",
    )
    p.add_argument(
        "--min-prompts",
        type=int,
        default=200,
        help="Warn if the corpus has fewer prompts than this (MODEL-DOSSIER "
        "recommends N >= 200 for validation-grade evidence). Default: 200.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Emit per-prompt progress to stderr.",
    )
    return p.parse_args()


def preflight() -> list[str]:
    """Return a list of preflight warnings/errors. Empty = all good."""
    issues: list[str] = []
    if platform.system() != "Darwin":
        issues.append(
            f"WARNING: MLX requires macOS; detected {platform.system()}. "
            "The runtime will refuse to load. Dry-run still works."
        )
    if platform.machine() != "arm64":
        issues.append(
            f"WARNING: MLX requires Apple Silicon (arm64); detected "
            f"{platform.machine()}."
        )
    if sys.version_info < (3, 10):
        issues.append(
            f"WARNING: dflash-mlx requires Python >= 3.10; running "
            f"{sys.version_info.major}.{sys.version_info.minor}."
        )
    return issues


def default_output_path(target: str, corpus_hash: str) -> Path:
    """Derive a sensible default output path from the target model ID."""
    # Best-effort family derivation from the target — after last / or :,
    # then before any -/_ variant suffix.
    stem = target.split("/")[-1].split(":")[-1].lower()
    family = stem.split("-")[0].split("_")[0]
    # Common shorthand: "qwen3", "qwen3.6", "gemma4"
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return Path(
        f"models/{family}/drafters/parity-report-{ts}-{corpus_hash[:12]}.json"
    )


def main() -> int:
    args = parse_args()

    # Preflight ------------------------------------------------------
    issues = preflight()
    for i in issues:
        print(i, file=sys.stderr)

    # Corpus load & hash --------------------------------------------
    if not args.corpus.is_file():
        print(f"error: corpus not found: {args.corpus}", file=sys.stderr)
        return 2
    try:
        prompts = load_corpus(args.corpus)
    except ValueError as e:
        print(f"error: corpus parse: {e}", file=sys.stderr)
        return 2
    if args.limit is not None:
        prompts = prompts[: args.limit]
    if not prompts:
        print("error: corpus contained zero prompts", file=sys.stderr)
        return 2
    corpus_hash = hash_corpus(prompts)
    print(
        f"corpus: {args.corpus} — {len(prompts)} prompts, sha256 "
        f"{corpus_hash[:16]}",
        file=sys.stderr,
    )
    if len(prompts) < args.min_prompts:
        print(
            f"WARNING: corpus has {len(prompts)} prompts; MODEL-DOSSIER "
            f"recommends >= {args.min_prompts} for validation-grade evidence. "
            f"Report will still be produced but should be re-run with a "
            f"larger corpus before drafter promotion.",
            file=sys.stderr,
        )

    # Dry-run: report and exit --------------------------------------
    if args.dry_run:
        print(
            f"\n[dry-run] target: {args.target}, drafter: "
            f"{args.drafter or '(auto-resolve)'}",
            file=sys.stderr,
        )
        print(f"[dry-run] would run {len(prompts)} prompt pairs", file=sys.stderr)
        print(
            f"[dry-run] output would land at: "
            f"{args.out or default_output_path(args.target, corpus_hash)}",
            file=sys.stderr,
        )
        print("[dry-run] no runtime invoked; exiting 0", file=sys.stderr)
        return 0

    # Full run -------------------------------------------------------
    if args.drafter is None:
        print(
            "note: --drafter not specified; relying on dflash-mlx "
            "auto-resolution for the target.",
            file=sys.stderr,
        )

    results: list[PromptResult] = []
    baseline_total = 0.0
    accel_total = 0.0
    started_at = time.time()

    try:
        for idx, p in enumerate(prompts, start=1):
            if args.verbose:
                print(
                    f"[{idx}/{len(prompts)}] {p.id} ({p.workload_class}) ...",
                    file=sys.stderr,
                    end=" ",
                    flush=True,
                )
            baseline_tokens, baseline_elapsed = baseline_generate(
                args.target, p.text, p.max_tokens, args.seed
            )
            accel_tokens, accel_elapsed = accelerated_generate(
                args.target,
                args.drafter,  # None allowed — adapter handles auto-resolve
                p.text,
                p.max_tokens,
                args.seed,
            )
            res = compare_outputs(
                p, baseline_tokens, accel_tokens, baseline_elapsed, accel_elapsed
            )
            results.append(res)
            baseline_total += baseline_elapsed
            accel_total += accel_elapsed
            if args.verbose:
                mark = "OK " if res.identical else "!! "
                print(
                    f"{mark}baseline {baseline_elapsed:.2f}s / "
                    f"accel {accel_elapsed:.2f}s",
                    file=sys.stderr,
                )
    except AdapterError as e:
        print(f"\nADAPTER ERROR: {e}", file=sys.stderr)
        print(
            "\nThis is a runtime-integration issue. Update the ADAPTER-SEAM "
            "functions in this script to match your dflash-mlx version's "
            "API, then re-run. See the module docstring.",
            file=sys.stderr,
        )
        return 3
    except KeyboardInterrupt:
        print("\ninterrupted by operator; partial run.", file=sys.stderr)
        return 130

    # Aggregate ------------------------------------------------------
    ok = sum(1 for r in results if r.identical)
    diverged = sum(1 for r in results if not r.identical)
    total_baseline_tokens = sum(r.baseline_length for r in results)
    total_accel_tokens = sum(r.accelerated_length for r in results)
    baseline_tps = (
        total_baseline_tokens / baseline_total if baseline_total > 0 else 0.0
    )
    accel_tps = (
        total_accel_tokens / accel_total if accel_total > 0 else 0.0
    )
    speedup = accel_tps / baseline_tps if baseline_tps > 0 else 0.0
    parity_pass = diverged == 0

    # Build receipt --------------------------------------------------
    report = ParityReport(
        target={
            "model_id": args.target,
            "version": "",  # populate from provider if known
            "weights_hash": "",  # populate if local weights hash available
        },
        drafter={
            "id": args.drafter or "(auto-resolved by dflash-mlx)",
            "checkpoint_hash": "",
        },
        evidence={
            "corpus_source": str(args.corpus),
            "corpus_hash": corpus_hash,
            "corpus_prompt_count": len(prompts),
            "seed": args.seed,
            "greedy": True,
        },
        provenance={
            "produced_by": "scripts/dflash-parity-check.py",
            "produced_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)
            ),
            "host_platform": platform.platform(),
            "python_version": sys.version.split()[0],
        },
        parity={
            "pass": parity_pass,
            "prompts_run": len(results),
            "byte_identical_count": ok,
            "divergence_count": diverged,
            "baseline_tokens_total": total_baseline_tokens,
            "accelerated_tokens_total": total_accel_tokens,
            "baseline_tokens_per_sec": round(baseline_tps, 2),
            "accelerated_tokens_per_sec": round(accel_tps, 2),
            "measured_speedup": round(speedup, 2),
        },
        per_prompt=[asdict(r) for r in results],
        divergences=[
            asdict(r.divergence) for r in results if r.divergence is not None
        ],
    )

    # Write ----------------------------------------------------------
    out = args.out or default_output_path(args.target, corpus_hash)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        f.write("\n")

    # Summary --------------------------------------------------------
    print()
    print(f"wrote {out}")
    print(f"  parity      : {'PASS' if parity_pass else 'FAIL'}")
    print(f"  prompts     : {ok}/{len(results)} byte-identical")
    if diverged:
        print(f"  divergences : {diverged} — see report for first-position details")
    print(f"  speedup     : {speedup:.2f}x ({accel_tps:.1f} tok/s accelerated, "
          f"{baseline_tps:.1f} tok/s baseline)")
    print()
    if parity_pass and len(prompts) >= args.min_prompts:
        print(
            "This report is the evidence payload for a "
            "substrate:characterization:validated receipt. Emit and sign it "
            "via your normal receipt path to promote drafter state from "
            "'not_yet_trained' to 'active' in the model_dossier.toml."
        )
    elif parity_pass:
        print(
            f"NOTE: report shows parity PASS but corpus had "
            f"{len(prompts)} < {args.min_prompts} prompts. Re-run with a "
            f"larger corpus before drafter promotion."
        )
    else:
        print(
            "PARITY FAIL: drafter should NOT be promoted. Investigate "
            "divergences and re-train/re-quantize as needed."
        )

    return 0 if parity_pass else 4


if __name__ == "__main__":
    sys.exit(main())
