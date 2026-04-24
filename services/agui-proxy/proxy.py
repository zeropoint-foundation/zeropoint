"""
ZeroPoint AG-UI Governance Proxy

Sits between Hermes (agent) and its dashboard (frontend).
Every AG-UI event passes through ZeroPoint's receipt system.

Usage:
    uvicorn proxy:app --host 127.0.0.1 --port 8900
"""

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse

from ag_ui.core import Event
from pydantic import TypeAdapter
from config import ProxyConfig
from governance import GovernanceGate

# AG-UI's `Event` is a discriminated `Annotated[Union[...]]`, not a model
# class — so `Event.model_validate()` raises. Use a TypeAdapter instead.
_EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(Event)

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("zp-agui-proxy")

# ── Config & State ─────────────────────────────────────────────────
config = ProxyConfig()
gate: GovernanceGate = None  # initialized in lifespan
upstream_client: httpx.AsyncClient = None
zp_client: Optional[httpx.AsyncClient] = None
zp_session_token: Optional[str] = None


def _load_zp_session_token(path_str: str) -> Optional[str]:
    """
    Read the ZP session token from disk. Env var `ZP_SESSION_TOKEN` wins if
    set, then `ZP_SESSION_FILE`, then the configured path. None means the
    proxy will skip credential injection (degrades to no-creds).
    """
    if t := os.environ.get("ZP_SESSION_TOKEN"):
        return t
    p = Path(os.environ.get("ZP_SESSION_FILE", path_str)).expanduser()
    try:
        d = json.loads(p.read_text())
        token = d.get("token")
        if isinstance(token, str) and token:
            return token
    except Exception as e:
        log.warning(f"Could not read ZP session token from {p}: {e}")
    return None


async def _fetch_credentials() -> dict[str, str]:
    """
    Fetch the configured provider credentials from ZeroPoint.
    Returns a map of `provider -> api_key_value`. Missing credentials are
    silently skipped (the upstream may not need them).
    """
    if not config.inject_credentials or zp_client is None or not zp_session_token:
        return {}
    out: dict[str, str] = {}
    auth = {"Authorization": f"Bearer {zp_session_token}"}
    for provider in config.inject_credentials:
        try:
            r = await zp_client.get(f"/api/v1/credentials/{provider}", headers=auth)
            if r.status_code == 200:
                v = r.json().get("value")
                if isinstance(v, str) and v:
                    out[provider] = v
            elif r.status_code == 404:
                pass  # provider not in vault — that's fine
            else:
                log.warning(
                    f"ZP credentials/{provider} returned HTTP {r.status_code}"
                )
        except httpx.HTTPError as e:
            log.warning(f"Could not fetch credentials/{provider}: {e}")
    return out


@asynccontextmanager
async def lifespan(app: FastAPI):
    global gate, upstream_client, zp_client, zp_session_token
    gate = GovernanceGate(config)
    upstream_client = httpx.AsyncClient(
        base_url=config.hermes_url,
        timeout=httpx.Timeout(connect=5.0, read=300.0, write=5.0, pool=5.0),
    )
    zp_client = httpx.AsyncClient(base_url=config.zeropoint_url, timeout=5.0)
    zp_session_token = _load_zp_session_token(config.zp_session_file)
    cred_state = (
        f"{len(config.inject_credentials)} provider(s) configured, token "
        + ("loaded" if zp_session_token else "MISSING — skipping injection")
    )
    log.info(
        "Governance proxy online — "
        f"listening on {config.proxy_host}:{config.proxy_port}, "
        f"upstream={config.hermes_url}, "
        f"zeropoint={config.zeropoint_url}, "
        f"credential injection: {cred_state}"
    )
    yield
    await gate.close()
    await upstream_client.aclose()
    if zp_client is not None:
        await zp_client.aclose()
    log.info("Governance proxy shut down")


app = FastAPI(
    title="ZeroPoint AG-UI Governance Proxy",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Hermes dashboard origin — tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Cockpit ────────────────────────────────────────────────────────
# Serve the Hermes-generated cockpit from disk, same-origin with /agent so
# its SSE POSTs carry cookies + don't need CORS. Read-on-request so the
# next Hermes regeneration is live without a proxy restart. no-cache so
# the browser doesn't pin a stale version during iteration.

COCKPIT_PATH = Path(__file__).parent / "cockpit.html"
ABACUS_PATH = Path(__file__).parent / "abacus.html"

# The two journals the abacus reads. Proxy-local journal (per-event SSE
# receipts) and ZP-server journal (gate decisions + external receipts
# posted by forwarders). Normalized into a single event stream for render.
PROXY_JOURNAL = Path(os.environ.get("AGUI_PROXY_RECEIPT_JOURNAL", "/tmp/agui-receipts.jsonl"))
ZP_EXTERNAL_JOURNAL = Path.home() / "ZeroPoint" / "logs" / "external-receipts.jsonl"


@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/cockpit", status_code=307)


@app.get("/cockpit", response_class=HTMLResponse)
async def cockpit():
    try:
        html = COCKPIT_PATH.read_text()
    except FileNotFoundError:
        return HTMLResponse(
            content=(
                "<!DOCTYPE html><html><body style='font-family:monospace;padding:2em'>"
                "<h1>No cockpit on disk</h1>"
                "<p>Ask Hermes to build one, then save to "
                f"<code>{COCKPIT_PATH}</code>.</p></body></html>"
            ),
            status_code=404,
        )
    return HTMLResponse(
        content=html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


# ── Abacus ─────────────────────────────────────────────────────────
# The receipt-stream visualizer. Reads both journals, groups beads by
# claim-type category onto horizontal wires, time flows left → right.
# See docs/design/zp-visual-language.md for the visual grammar.

@app.get("/abacus", response_class=HTMLResponse)
async def abacus_page():
    try:
        html = ABACUS_PATH.read_text()
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>abacus.html not on disk</h1>",
            status_code=404,
        )
    return HTMLResponse(
        content=html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


# Claim-type → wire assignment. Five horizontal rails, palette aligned to
# the cockpit's accent vocabulary.
# - lifecycle: session / run / step boundaries
# - content:   assistant message body
# - tool:      tool calls (use) + gate decisions (governance)
# - telemetry: agent.* classifier customs
# - other:     anything unmapped, for visibility rather than silence
_WIRE_MAP: dict[str, str] = {
    "session.begin": "lifecycle", "session.seal": "lifecycle", "session.fault": "lifecycle",
    "step.begin": "lifecycle", "step.seal": "lifecycle",
    "message.begin": "content", "message.stream": "content", "message.seal": "content",
    "action.request": "tool", "action.params": "tool",
    "action.execute": "tool", "action.result": "tool",
    "state.snapshot": "tool", "state.mutation": "tool", "state.messages": "tool",
    "gate.tool_call.allowed": "gate", "gate.tool_call.blocked": "gate",
    "event.ping": "other", "event.unknown": "other", "event.raw": "other", "event.custom": "other",
    "activity.snapshot": "telemetry", "activity.delta": "telemetry",
    "reasoning.begin": "telemetry", "reasoning.seal": "telemetry",
    "reasoning.message.begin": "telemetry", "reasoning.message.stream": "telemetry",
    "reasoning.message.seal": "telemetry", "reasoning.encrypted": "telemetry",
}


def _wire_for(claim_type: str) -> str:
    if claim_type in _WIRE_MAP:
        return _WIRE_MAP[claim_type]
    if claim_type.startswith("agent."):
        return "telemetry"
    if claim_type.startswith("gate."):
        return "gate"
    return "other"


@app.get("/journal")
async def journal(limit: int = 5000):
    """
    Normalized merge of the two receipt journals for the abacus renderer.
    Returns events sorted by timestamp ascending. Schema per event:
      { receipt_id, timestamp (ms), claim_type, wire, source, approved,
        event_type, metadata, reason }
    """
    out: list[dict] = []

    def _load(path: Path, source: str) -> None:
        if not path.exists():
            return
        try:
            with path.open() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    ts = r.get("timestamp")
                    if not isinstance(ts, (int, float)):
                        continue
                    ct = r.get("claim_type") or "event.unknown"
                    out.append({
                        "receipt_id": r.get("receipt_id"),
                        "timestamp": int(ts),
                        "claim_type": ct,
                        "wire": _wire_for(ct),
                        "source": source,
                        "approved": r.get("approved"),
                        "event_type": r.get("event_type"),
                        "metadata": r.get("metadata") or {},
                        "reason": r.get("reason"),
                    })
        except OSError as e:
            log.warning(f"journal: could not read {path}: {e}")

    _load(PROXY_JOURNAL, "proxy")
    _load(ZP_EXTERNAL_JOURNAL, "zp")

    out.sort(key=lambda e: e["timestamp"])
    # Trim head if over limit — keep most recent `limit` events.
    if len(out) > limit:
        out = out[-limit:]

    return {
        "count": len(out),
        "events": out,
        "wires": ["lifecycle", "content", "tool", "gate", "telemetry", "other"],
    }


# ── Health ─────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "proxy": "zp-agui-governance",
        "upstream": config.hermes_url,
        "zeropoint": config.zeropoint_url,
        "governance": gate.stats if gate else {},
    }


# ── AG-UI Proxy Endpoint ──────────────────────────────────────────

@app.post("/agent")
async def proxy_agent(request: Request):
    """
    Main proxy endpoint. Receives RunAgentInput from the dashboard,
    forwards to Hermes, intercepts the SSE stream, governs each event,
    and re-emits approved events to the dashboard.
    """
    # 1. Read the incoming RunAgentInput
    body = await request.body()
    headers = {
        "content-type": "application/json",
        "accept": "text/event-stream",
    }

    # 1a. Fetch vault-stored provider credentials and add as X-Provider-Key-*
    # headers. The bridge will read these and inject as env vars on the agent
    # subprocess. The proxy is the credential boundary — credentials never
    # reach the dashboard, never go on disk, never appear in receipts.
    creds = await _fetch_credentials()
    for provider, value in creds.items():
        headers[f"X-Provider-Key-{provider}"] = value

    log.info(
        f"Proxying agent run to Hermes — injecting {len(creds)} credential(s): "
        f"{', '.join(creds.keys()) or 'none'}"
    )

    # 2. Forward to Hermes as a streaming request
    try:
        hermes_req = upstream_client.build_request(
            "POST",
            "/agent",  # Hermes AG-UI endpoint
            content=body,
            headers=headers,
        )
        hermes_resp = await upstream_client.send(hermes_req, stream=True)
    except httpx.HTTPError as e:
        log.error(f"Failed to reach Hermes: {e}")
        return Response(
            content=json.dumps({"error": f"Upstream unreachable: {e}"}),
            status_code=502,
            media_type="application/json",
        )

    # 3. Stream governed events back to the dashboard
    async def governed_stream() -> AsyncGenerator[bytes, None]:
        async for line in hermes_resp.aiter_lines():
            if not line.startswith("data: "):
                # Pass through SSE formatting (empty lines, comments)
                yield f"{line}\n".encode()
                continue

            raw_json = line[6:]  # strip "data: "

            # Parse the AG-UI event
            try:
                event_data = json.loads(raw_json)
                event = _EVENT_ADAPTER.validate_python(event_data)
            except Exception as e:
                # Unparseable event — log and pass through
                log.warning(f"Unparseable event, passing through: {e}")
                yield f"{line}\n\n".encode()
                continue

            # Governance gate
            approved, reason = await gate.evaluate(event)

            # Stamp receipt (async, non-blocking on the stream)
            await gate.stamp_receipt(event, approved, reason)

            if approved:
                # Forward to dashboard
                yield f"data: {raw_json}\n\n".encode()

                if config.log_all_events:
                    log.info(f"APPROVED [{event.type}]")
            else:
                # Blocked — emit a governance event instead
                blocked_event = {
                    "type": "CUSTOM",
                    "name": "zeropoint.governance.blocked",
                    "value": {
                        "original_type": event.type,
                        "reason": reason,
                        "timestamp": int(time.time() * 1000),
                    },
                }
                yield f"data: {json.dumps(blocked_event)}\n\n".encode()

                if config.log_blocked_events:
                    log.warning(f"BLOCKED [{event.type}]: {reason}")

        await hermes_resp.aclose()

    return StreamingResponse(
        governed_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-ZeroPoint-Governed": "true",
        },
    )


# ── Governance Admin ───────────────────────────────────────────────

@app.get("/governance/stats")
async def governance_stats():
    """Current governance statistics."""
    return gate.stats if gate else {}


@app.post("/governance/block/{event_type}")
async def block_event_type(event_type: str):
    """Add an event type to the deny list at runtime."""
    if event_type not in config.blocked_event_types:
        config.blocked_event_types.append(event_type)
        log.info(f"Added '{event_type}' to deny list")
    return {"blocked": config.blocked_event_types}


@app.delete("/governance/block/{event_type}")
async def unblock_event_type(event_type: str):
    """Remove an event type from the deny list."""
    if event_type in config.blocked_event_types:
        config.blocked_event_types.remove(event_type)
        log.info(f"Removed '{event_type}' from deny list")
    return {"blocked": config.blocked_event_types}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.proxy_host, port=config.proxy_port)
