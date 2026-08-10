"""Minimal Ollama chat client with throughput metering."""
import time
import requests

import config


class Metrics:
    """Accumulates decode throughput across the run."""

    def __init__(self):
        self.calls = 0
        self.eval_tokens = 0
        self.eval_seconds = 0.0
        self.prompt_tokens = 0
        self.wall_seconds = 0.0

    def record(self, payload, wall):
        self.calls += 1
        self.wall_seconds += wall
        self.eval_tokens += payload.get("eval_count", 0) or 0
        self.prompt_tokens += payload.get("prompt_eval_count", 0) or 0
        # Ollama reports durations in nanoseconds.
        self.eval_seconds += (payload.get("eval_duration", 0) or 0) / 1e9

    @property
    def decode_tps(self):
        if self.eval_seconds <= 0:
            return 0.0
        return self.eval_tokens / self.eval_seconds

    @property
    def effective_tps(self):
        """Tokens per second of wall clock -- what you actually feel."""
        if self.wall_seconds <= 0:
            return 0.0
        return self.eval_tokens / self.wall_seconds

    def summary(self):
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "eval_tokens": self.eval_tokens,
            "decode_tokens_per_sec": round(self.decode_tps, 2),
            "effective_tokens_per_sec_wall": round(self.effective_tps, 2),
            "total_wall_seconds": round(self.wall_seconds, 1),
        }


METRICS = Metrics()

_MOCK_PARAS = [
    "Restrict the credential to the narrowest scope that satisfies the "
    "operation. Rotate on any change of operator. Record the rotation.",
    "The control fails open under partition, which means a caller that cannot "
    "reach the authority proceeds as though it had been granted permission; "
    "the remedy is to invert the default so that unreachable authority denies.",
    "- Unbounded retry on the auth path.\n- No ceiling. No jitter.\n"
    "- Fix: cap attempts, then fail closed.",
]


def chat(system, user, seed=None):
    """One-shot chat completion. Returns the assistant text."""
    if config.MOCK:
        time.sleep(0.01)
        idx = (seed or 0) % len(_MOCK_PARAS)
        return _MOCK_PARAS[idx]

    body = {
        "model": config.MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "think": config.THINK,
        "options": {
            "num_ctx": config.NUM_CTX,
            "temperature": config.TEMPERATURE,
        },
    }
    if seed is not None:
        body["options"]["seed"] = seed

    t0 = time.time()
    r = requests.post(
        f"{config.OLLAMA_URL}/api/chat",
        json=body,
        timeout=config.REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    payload = r.json()
    METRICS.record(payload, time.time() - t0)
    return payload["message"]["content"].strip()
