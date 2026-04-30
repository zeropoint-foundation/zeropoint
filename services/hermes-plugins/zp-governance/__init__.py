"""
zp-governance Hermes plugin — Stage 1 dispatch gate.

On every tool call Hermes attempts, POST a small request to
ZeroPoint's /api/v1/gate/tool-call. If ZP denies, return a block
directive to Hermes so the tool never fires. Each decision (allow or
block) is journaled as a receipt in ZP's external-receipts stream.

Design decisions:

* **Fail-open.** If ZP is unreachable (timeout, connection refused),
  the plugin allows the tool call and logs a warning. A blocked
  governance layer must not silently halt Hermes — the operator would
  never notice, and the right posture when the substrate is degraded
  is visibility, not stoppage. Hard-block policy is an operator
  opt-in (set ZP_GATE_FAIL_CLOSED=1).

* **Synchronous.** The `pre_tool_call` hook is synchronous by design
  (the tool dispatcher waits for the hook result). Budget: 2s total
  including connect + read. Past that, fail-open with a timeout note.

* **Minimal payload.** Tool name + args hash (not args themselves) +
  thread/run IDs. Args are not forwarded — the gate policy decides by
  tool class, not by args content. If per-arg gating is needed, that's
  a policy-engine concern for a future stage.

Configuration (environment variables, all optional):

  ZP_URL                http://127.0.0.1:17010   base URL
  ZP_SESSION_TOKEN      (read from ~/ZeroPoint/session.json if unset)
  ZP_GATE_FAIL_CLOSED   0 | 1                    fail-open (default) vs. fail-closed
  ZP_GATE_TIMEOUT_MS    2000                     total wall-clock budget
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("zp-governance")

_DEFAULT_ZP_URL = "http://127.0.0.1:17010"
_DEFAULT_TIMEOUT_MS = 2000
_SESSION_FILE = Path.home() / "ZeroPoint" / "session.json"


def _zp_url() -> str:
    return os.environ.get("ZP_URL", _DEFAULT_ZP_URL).rstrip("/")


def _session_token() -> Optional[str]:
    tok = os.environ.get("ZP_SESSION_TOKEN", "").strip()
    if tok:
        return tok
    try:
        d = json.loads(_SESSION_FILE.read_text())
        v = d.get("token")
        return v if isinstance(v, str) and v else None
    except Exception:
        return None


def _fail_closed() -> bool:
    return os.environ.get("ZP_GATE_FAIL_CLOSED", "0").strip() in ("1", "true", "yes")


def _timeout_seconds() -> float:
    try:
        ms = int(os.environ.get("ZP_GATE_TIMEOUT_MS", str(_DEFAULT_TIMEOUT_MS)))
    except ValueError:
        ms = _DEFAULT_TIMEOUT_MS
    return max(0.1, ms / 1000.0)


def _args_hash(args: Any) -> str:
    """Stable short hash of args. Full args are NOT forwarded to the gate —
    this is an identity hint for receipt metadata, not a policy input."""
    try:
        payload = json.dumps(args, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        payload = repr(args)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def _pre_tool_call(
    tool_name: str,
    args: Optional[dict] = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_unused: Any,
) -> Optional[dict]:
    """Called before every tool dispatch. Return a block-directive dict to
    stop the tool, None/anything else to allow."""
    url = _zp_url() + "/api/v1/gate/tool-call"
    body = json.dumps({
        "tool_name": tool_name,
        "args_hash": _args_hash(args),
        "thread_id": session_id or None,
        "run_id": task_id or None,
        "agent": "hermes",
    }).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    token = _session_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=_timeout_seconds()) as resp:
            raw = resp.read()
            elapsed_ms = int((time.monotonic() - start) * 1000)
            try:
                decision = json.loads(raw.decode("utf-8"))
            except Exception:
                log.warning("zp-governance: gate returned non-JSON (%dms); failing open", elapsed_ms)
                return None
            if decision.get("allow"):
                log.debug("zp-governance: allow %s (%dms)", tool_name, elapsed_ms)
                return None
            reason = decision.get("reason") or "blocked by ZeroPoint governance"
            log.info("zp-governance: BLOCK %s — %s (%dms)", tool_name, reason, elapsed_ms)
            return {"action": "block", "message": f"[ZeroPoint gate] {reason}"}
    except urllib.error.HTTPError as e:
        log.warning("zp-governance: HTTP %d from gate; %s", e.code, "failing closed" if _fail_closed() else "failing open")
        if _fail_closed():
            return {"action": "block", "message": f"[ZeroPoint gate] unreachable (HTTP {e.code})"}
        return None
    except Exception as e:
        log.warning("zp-governance: gate unreachable (%s); %s", e, "failing closed" if _fail_closed() else "failing open")
        if _fail_closed():
            return {"action": "block", "message": f"[ZeroPoint gate] unreachable ({e})"}
        return None


def _post_tool_call(
    tool_name: str,
    args: Optional[dict] = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_unused: Any,
) -> None:
    """Observe memory-tool writes and fire a ZP observation receipt.

    Stage 2 pass-through (per docs/design/zp-hermes-interfaces.md
    Interface 1): every `memory` tool write auto-accepts; ZP records a
    signed receipt with a content hash, so the audit chain witnesses
    what the substrate committed. Hermes's actual memory file on disk
    stays where it is — this is observation, not interception.

    Only `memory` tool calls are forwarded; everything else already
    flowed through the pre_tool_call gate for Stage 1 governance.

    Fail-open: observation failure doesn't halt the agent. A degraded
    substrate must not silently stop Hermes from writing to its own
    memory. (Same posture as the gate — set ZP_GATE_FAIL_CLOSED=1 to
    invert, though "hard-fail on memory observation" is a poor default
    even for strict operators.)"""
    if tool_name != "memory" or not isinstance(args, dict):
        return
    action = args.get("action")
    if action not in ("add", "replace", "remove"):
        return
    target = args.get("target") or "MEMORY"
    content = args.get("content")
    content = content if isinstance(content, str) else None

    url = _zp_url() + "/api/v1/memory/observe"
    body = json.dumps({
        "action": action,
        "target": target,
        "content": content,
        "thread_id": session_id or None,
        "run_id": task_id or None,
        "tool_call_id": tool_call_id or None,
        "agent": "hermes",
    }).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    token = _session_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_timeout_seconds()) as resp:
            resp.read()
        log.debug("zp-governance: memory observed — action=%s target=%s", action, target)
    except Exception as e:
        log.warning("zp-governance: memory observation failed (%s) — continuing", e)


def register(ctx) -> None:
    """Hermes plugin entry point. Wires the ZP governance hooks."""
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("post_tool_call", _post_tool_call)
    log.info(
        "zp-governance plugin registered — pre_tool_call gate + post_tool_call memory observer wired to %s",
        _zp_url(),
    )
