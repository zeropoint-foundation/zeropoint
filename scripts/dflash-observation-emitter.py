#!/usr/bin/env python3
"""
dflash-observation-emitter.py — polls dflash-mlx's /metrics endpoint and emits
`observation:inference:drafter_acceptance` events to a JSONL stream.

Realizes OBSERVATION-PLANE-2026-07 §"Inference telemetry" (Surface 7) as a
lightweight Python sidecar. Substrate-side receipt-emission (converting these
JSONL events into `ReceiptType::ObservationClaim` chain receipts with
`observation_type = "inference:drafter_acceptance"`) is a separate wiring
step — this script produces the evidence stream that Rust will consume.

## Design

- **Polling, not proxying.** The `dflash serve` process exposes acceptance
  metrics via `POST /metrics` per its documented telemetry surface. We poll
  this endpoint at a configurable interval, compute the delta between
  successive samples, and aggregate into rolling windows. No MITM, no
  library-level patching of dflash-mlx — the poller works against any
  reachable `dflash serve` instance including remote ones.

- **Rolling windows, dossier-declared threshold.** Every window boundary
  (default: every 1000 tokens OR every 60 seconds, whichever crosses first)
  emits one `observation:inference:drafter_acceptance` event. When the
  windowed mean acceptance rate drops below `--drift-threshold`, a
  `substrate:characterization:drift_suspected` event is also emitted.
  Substrate-side, the threshold value ought to be pulled from the dossier's
  `[drafter.acceptance_rate].drift_threshold` field; here we take it as a
  CLI arg with the same default (0.55) as the TOML template.

- **JSONL output.** One event per line, appended to
  `<out-dir>/drafter_acceptance-<utc>.jsonl` (rotated daily by default).
  Substrate-side reader tails this file and converts to chain receipts.

## Requirements

- Python 3.10+.
- A running `dflash serve` reachable at `--server-url` (default
  `http://127.0.0.1:8000`).
- Standard-library only — no runtime dependencies to install.

## Usage

```
# Foreground (Ctrl-C to stop):
python3 scripts/dflash-observation-emitter.py \\
  --target Qwen/Qwen3-8B \\
  --drafter z-lab/Qwen3-8B-DFlash-b16

# Dry run — validate connectivity and metrics-endpoint shape without
# writing any events:
python3 scripts/dflash-observation-emitter.py --dry-run \\
  --target Qwen/Qwen3-8B --drafter z-lab/Qwen3-8B-DFlash-b16

# Point at a specific server, tighter window, higher drift threshold:
python3 scripts/dflash-observation-emitter.py \\
  --target Qwen/Qwen3-8B --drafter z-lab/Qwen3-8B-DFlash-b16 \\
  --server-url http://127.0.0.1:8001 \\
  --window-tokens 500 --window-seconds 30 \\
  --drift-threshold 0.60
```

## Metrics-endpoint adapter

The exact JSON shape returned by `POST /metrics` is documented as including
`tokens_per_cycle`, `cycles`, adaptive block counters, and CopySpec counters.
The precise field names may vary across dflash-mlx versions. The
`parse_metrics()` function is the seam — adjust for your version's actual
response shape if the smoke test flags a mismatch.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Metrics-endpoint adapter (ADAPTER-SEAM)
# ---------------------------------------------------------------------------


@dataclass
class MetricsSnapshot:
    """Substrate-independent snapshot derived from a /metrics response.

    Field semantics:
    - `total_target_tokens` — total tokens the target model has committed
      to output across all requests since server start. Monotonic-increasing.
    - `total_drafted_tokens` — total tokens the drafter proposed (accepted
      + rejected combined). Monotonic-increasing.
    - `total_accepted_tokens` — total drafter proposals accepted. Monotonic.

    Rolling acceptance rate over a window is:
        (accepted_delta) / (drafted_delta)

    Rolling speedup over a window (approx) is:
        (target_delta + accepted_delta) / target_delta
      = 1 + accepted_delta / target_delta

    If the actual /metrics response uses different field names, adjust
    `parse_metrics()` — everything downstream reads only the normalized
    snapshot.
    """

    total_target_tokens: int
    total_drafted_tokens: int
    total_accepted_tokens: int
    server_uptime_s: float
    raw: dict  # keep the original payload for provenance


def fetch_metrics(server_url: str, timeout: float = 5.0) -> dict:
    """POST /metrics and return the parsed JSON body."""
    url = server_url.rstrip("/") + "/metrics"
    req = urllib.request.Request(
        url,
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return json.loads(body.decode("utf-8"))


def parse_metrics(payload: dict) -> MetricsSnapshot:
    """
    ADAPTER-SEAM. Convert dflash-mlx's /metrics response into a
    MetricsSnapshot. The dflash-mlx docs describe fields including
    `tokens_per_cycle`, `cycles`, adaptive block counters, and CopySpec
    counters. Actual field names may differ across versions.

    Preferred normalized shape (versions >= 0.1.7):
        {
          "tokens": {
            "target_total": <int>,   # target model output tokens
            "drafted_total": <int>,  # drafter proposals (all)
            "accepted_total": <int>  # drafter proposals accepted
          },
          "uptime_s": <float>
        }

    Fallback: probe common alternative field names.
    """
    # Preferred shape.
    if "tokens" in payload and isinstance(payload["tokens"], dict):
        t = payload["tokens"]
        return MetricsSnapshot(
            total_target_tokens=int(t.get("target_total", 0)),
            total_drafted_tokens=int(t.get("drafted_total", 0)),
            total_accepted_tokens=int(t.get("accepted_total", 0)),
            server_uptime_s=float(payload.get("uptime_s", 0.0)),
            raw=payload,
        )

    # Fallback shape: flat keys with common aliases.
    aliases_target = ["target_tokens", "total_target_tokens", "target_output_tokens"]
    aliases_drafted = ["drafted_tokens", "total_drafted_tokens", "draft_tokens"]
    aliases_accepted = ["accepted_tokens", "total_accepted_tokens"]

    def first_present(keys: list[str], default: int = 0) -> int:
        for k in keys:
            if k in payload:
                return int(payload[k])
        return default

    return MetricsSnapshot(
        total_target_tokens=first_present(aliases_target),
        total_drafted_tokens=first_present(aliases_drafted),
        total_accepted_tokens=first_present(aliases_accepted),
        server_uptime_s=float(payload.get("uptime_s", 0.0)),
        raw=payload,
    )


# ---------------------------------------------------------------------------
# Window aggregation
# ---------------------------------------------------------------------------


@dataclass
class WindowState:
    """Rolling window between two MetricsSnapshots."""

    start_wall_utc: str
    start_uptime_s: float
    start_snapshot: MetricsSnapshot
    end_wall_utc: Optional[str] = None
    end_uptime_s: Optional[float] = None
    end_snapshot: Optional[MetricsSnapshot] = None

    def close(self, wall_utc: str, snap: MetricsSnapshot) -> None:
        self.end_wall_utc = wall_utc
        self.end_uptime_s = snap.server_uptime_s
        self.end_snapshot = snap

    def acceptance_rate(self) -> Optional[float]:
        if self.end_snapshot is None:
            return None
        drafted_delta = (
            self.end_snapshot.total_drafted_tokens
            - self.start_snapshot.total_drafted_tokens
        )
        accepted_delta = (
            self.end_snapshot.total_accepted_tokens
            - self.start_snapshot.total_accepted_tokens
        )
        if drafted_delta <= 0:
            return None
        return accepted_delta / drafted_delta

    def target_tokens_in_window(self) -> int:
        if self.end_snapshot is None:
            return 0
        return (
            self.end_snapshot.total_target_tokens
            - self.start_snapshot.total_target_tokens
        )

    def drafted_tokens_in_window(self) -> int:
        if self.end_snapshot is None:
            return 0
        return (
            self.end_snapshot.total_drafted_tokens
            - self.start_snapshot.total_drafted_tokens
        )

    def duration_s(self) -> float:
        if self.end_uptime_s is None:
            return 0.0
        return self.end_uptime_s - self.start_uptime_s


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


def build_acceptance_event(
    target: str,
    drafter: Optional[str],
    window: WindowState,
) -> dict:
    """Build one observation:inference:drafter_acceptance JSONL event.

    Shape matches MODEL-DOSSIER §"Continuous drift signal" and
    OBSERVATION-PLANE §"Inference telemetry". Rust-side receipt-emission
    will map these fields onto `ClaimMetadata::Observation` with
    observation_type = "inference:drafter_acceptance" plus per-field
    extensions under `zp.observation.inference.*`.
    """
    return {
        "event_type": "observation:inference:drafter_acceptance",
        "target_model_id": target,
        "drafter_id": drafter or "(auto-resolved by dflash-mlx)",
        "window": {
            "start_wall_utc": window.start_wall_utc,
            "end_wall_utc": window.end_wall_utc,
            "duration_s": round(window.duration_s(), 3),
        },
        "target_tokens_in_window": window.target_tokens_in_window(),
        "drafted_tokens_in_window": window.drafted_tokens_in_window(),
        "mean_acceptance_rate": (
            round(window.acceptance_rate(), 4)
            if window.acceptance_rate() is not None
            else None
        ),
        # Position-wise curve requires per-token accept/reject stream which
        # isn't exposed by /metrics. Placeholder for the substrate-side hook
        # once dflash-mlx exposes it (or a patched build does). Consumers
        # should treat null/empty as "not-yet-available."
        "position_wise_acceptance_curve": None,
        # Workload-class breakdown requires per-request classification which
        # also isn't observable from /metrics. Same treatment as above.
        "workload_class_breakdown": None,
    }


def build_drift_event(
    target: str,
    drafter: Optional[str],
    window: WindowState,
    threshold: float,
) -> dict:
    """Build one substrate:characterization:drift_suspected event."""
    rate = window.acceptance_rate()
    return {
        "event_type": "substrate:characterization:drift_suspected",
        "characterization_form": "drafter",
        "target_model_id": target,
        "drafter_id": drafter or "(auto-resolved by dflash-mlx)",
        "trigger": "drafter_acceptance_below_threshold",
        "observed_mean_acceptance_rate": (
            round(rate, 4) if rate is not None else None
        ),
        "declared_threshold": threshold,
        "window": {
            "start_wall_utc": window.start_wall_utc,
            "end_wall_utc": window.end_wall_utc,
            "duration_s": round(window.duration_s(), 3),
        },
    }


class Emitter:
    """Append-only JSONL writer with daily rotation."""

    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._current_date = ""
        self._file = None

    def _rotate_if_needed(self) -> None:
        today = time.strftime("%Y%m%d", time.gmtime())
        if today != self._current_date:
            if self._file:
                self._file.close()
            path = self.out_dir / f"drafter_acceptance-{today}.jsonl"
            # Line-buffered so events flush quickly even without close.
            self._file = path.open("a", encoding="utf-8", buffering=1)
            self._current_date = today

    def emit(self, event: dict) -> None:
        self._rotate_if_needed()
        assert self._file is not None
        self._file.write(json.dumps(event, ensure_ascii=False) + "\n")

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None


# ---------------------------------------------------------------------------
# Main poll loop
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--target",
        required=True,
        help="Target model identifier — recorded in every emitted event.",
    )
    p.add_argument(
        "--drafter",
        default=None,
        help="Drafter checkpoint identifier — recorded in every emitted event. "
        "If omitted, events note '(auto-resolved by dflash-mlx)'.",
    )
    p.add_argument(
        "--server-url",
        default="http://127.0.0.1:8000",
        help="dflash serve base URL. Default: http://127.0.0.1:8000",
    )
    p.add_argument(
        "--poll-interval-s",
        type=float,
        default=5.0,
        help="Seconds between /metrics polls. Default: 5.0",
    )
    p.add_argument(
        "--window-tokens",
        type=int,
        default=1000,
        help="Emit an event when the window has accumulated at least N drafted "
        "tokens. Default: 1000 (matches MODEL-DOSSIER schema).",
    )
    p.add_argument(
        "--window-seconds",
        type=float,
        default=60.0,
        help="Emit an event when the window has been open at least N seconds, "
        "even if --window-tokens hasn't been reached. Default: 60.0",
    )
    p.add_argument(
        "--drift-threshold",
        type=float,
        default=0.55,
        help="Emit substrate:characterization:drift_suspected when the "
        "windowed acceptance rate drops below this value. Default: 0.55 "
        "(matches the model_dossier.toml template default).",
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=Path.home() / "projects" / "zeropoint" / ".observations" / "inference",
        help="Where to write JSONL event files. Default: "
        "~/projects/zeropoint/.observations/inference/",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch /metrics once, print the parsed snapshot, and exit "
        "without opening the emitter file.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Log each poll to stderr.",
    )
    return p.parse_args()


def dry_run(args: argparse.Namespace) -> int:
    """Fetch once, verify shape, print, exit."""
    print(f"[dry-run] fetching {args.server_url}/metrics ...", file=sys.stderr)
    try:
        payload = fetch_metrics(args.server_url, timeout=10.0)
    except urllib.error.URLError as e:
        print(f"[dry-run] FAILED to reach server: {e}", file=sys.stderr)
        print(
            "  Ensure 'dflash serve --model ...' is running and reachable "
            "at the given URL.",
            file=sys.stderr,
        )
        return 2
    except Exception as e:
        print(f"[dry-run] FAILED: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    print("[dry-run] /metrics raw payload:", file=sys.stderr)
    print(json.dumps(payload, indent=2), file=sys.stderr)

    try:
        snap = parse_metrics(payload)
    except Exception as e:
        print(
            f"\n[dry-run] parse_metrics FAILED: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        print(
            "  Adjust the parse_metrics() ADAPTER-SEAM for your dflash-mlx "
            "version's response shape.",
            file=sys.stderr,
        )
        return 3

    print("\n[dry-run] parsed snapshot:", file=sys.stderr)
    print(f"  target tokens total    : {snap.total_target_tokens}", file=sys.stderr)
    print(f"  drafted tokens total   : {snap.total_drafted_tokens}", file=sys.stderr)
    print(f"  accepted tokens total  : {snap.total_accepted_tokens}", file=sys.stderr)
    print(f"  server uptime          : {snap.server_uptime_s:.1f}s", file=sys.stderr)

    if snap.total_drafted_tokens == 0:
        print(
            "\n[dry-run] NOTE: drafter has not been observed yet (drafted "
            "tokens = 0). Send at least one completion request to the server "
            "and re-run to see non-zero counts.",
            file=sys.stderr,
        )
    else:
        approx_rate = (
            snap.total_accepted_tokens / snap.total_drafted_tokens
            if snap.total_drafted_tokens > 0
            else 0.0
        )
        print(
            f"\n[dry-run] lifetime acceptance rate (approx): "
            f"{approx_rate:.2%}",
            file=sys.stderr,
        )

    print("\n[dry-run] shape OK; ready to run without --dry-run.", file=sys.stderr)
    return 0


def main() -> int:
    args = parse_args()

    if args.dry_run:
        return dry_run(args)

    emitter = Emitter(args.out_dir)
    print(
        f"dflash-observation-emitter: polling {args.server_url}/metrics every "
        f"{args.poll_interval_s}s, writing to {args.out_dir}",
        file=sys.stderr,
    )

    # Graceful shutdown on SIGTERM/SIGINT.
    stop = False

    def _handle_signal(signum, frame):
        nonlocal stop
        stop = True
        print(
            f"\nreceived signal {signum}; finishing current window and exiting",
            file=sys.stderr,
        )

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    current_window: Optional[WindowState] = None
    consecutive_errors = 0
    total_polls = 0
    total_events = 0
    total_drift_events = 0

    try:
        while not stop:
            try:
                payload = fetch_metrics(args.server_url, timeout=args.poll_interval_s * 2)
                snap = parse_metrics(payload)
                consecutive_errors = 0
                total_polls += 1
            except urllib.error.URLError as e:
                consecutive_errors += 1
                if consecutive_errors == 1 or consecutive_errors % 12 == 0:
                    print(
                        f"warning: /metrics unreachable "
                        f"(consecutive={consecutive_errors}): {e}",
                        file=sys.stderr,
                    )
                time.sleep(args.poll_interval_s)
                continue
            except Exception as e:
                consecutive_errors += 1
                print(
                    f"error: parse failure "
                    f"(consecutive={consecutive_errors}): "
                    f"{type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                time.sleep(args.poll_interval_s)
                continue

            now_utc = utc_now()

            if current_window is None:
                current_window = WindowState(
                    start_wall_utc=now_utc,
                    start_uptime_s=snap.server_uptime_s,
                    start_snapshot=snap,
                )
                if args.verbose:
                    print(
                        f"[{now_utc}] opened window; target={snap.total_target_tokens} "
                        f"drafted={snap.total_drafted_tokens} "
                        f"accepted={snap.total_accepted_tokens}",
                        file=sys.stderr,
                    )
                time.sleep(args.poll_interval_s)
                continue

            # Close the window if either boundary is met.
            drafted_delta = snap.total_drafted_tokens - current_window.start_snapshot.total_drafted_tokens
            elapsed = snap.server_uptime_s - current_window.start_uptime_s
            should_close = (
                drafted_delta >= args.window_tokens
                or elapsed >= args.window_seconds
            )

            if should_close:
                current_window.close(now_utc, snap)

                event = build_acceptance_event(
                    args.target, args.drafter, current_window
                )
                emitter.emit(event)
                total_events += 1

                rate = current_window.acceptance_rate()
                if rate is not None and rate < args.drift_threshold:
                    drift = build_drift_event(
                        args.target, args.drafter, current_window, args.drift_threshold
                    )
                    emitter.emit(drift)
                    total_drift_events += 1
                    print(
                        f"[{now_utc}] DRIFT SUSPECTED — rate {rate:.2%} < "
                        f"threshold {args.drift_threshold:.2%}",
                        file=sys.stderr,
                    )

                if args.verbose:
                    rate_str = f"{rate:.2%}" if rate is not None else "(no data)"
                    print(
                        f"[{now_utc}] emitted acceptance window "
                        f"drafted={drafted_delta} rate={rate_str} "
                        f"duration={elapsed:.1f}s",
                        file=sys.stderr,
                    )

                # Start a fresh window from this snapshot.
                current_window = WindowState(
                    start_wall_utc=now_utc,
                    start_uptime_s=snap.server_uptime_s,
                    start_snapshot=snap,
                )

            time.sleep(args.poll_interval_s)

    finally:
        emitter.close()
        print(
            f"\nshutdown: {total_polls} polls, {total_events} acceptance events, "
            f"{total_drift_events} drift events emitted.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
