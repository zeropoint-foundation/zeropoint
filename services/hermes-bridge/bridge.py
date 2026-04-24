"""
Hermes AG-UI Bridge

Wraps Hermes Agent (a one-shot Python CLI) as an AG-UI HTTP service.

Architecture:
    Dashboard ─POST RunAgentInput─▶ AG-UI Proxy :17020
                                          │
                                          ▼
                        This bridge :17030  POST /agent
                                          │
                                          ▼
                    spawn: <hermes_venv>/python run_agent.py --query ... --model ...
                                          │
                                          ▼
                        stdout lines streamed as
                        TextMessageContentEvent
                                          │
                                          ▼
                        RunFinishedEvent on clean exit,
                        RunErrorEvent on non-zero

This makes Hermes a governable tenant: one HTTP request = one agent run = one
chain of AG-UI events. Each invocation is a session the proxy can stamp with
ZeroPoint receipts.
"""

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("hermes-bridge")

# ── Config (env-driven, sensible defaults) ─────────────────────────
HERMES_PATH = os.environ.get("HERMES_PATH", "/Users/kenrom/projects/hermes")
HERMES_PYTHON = os.environ.get(
    "HERMES_PYTHON", os.path.join(HERMES_PATH, ".venv", "bin", "python")
)
HERMES_DEFAULT_MODEL = os.environ.get("HERMES_DEFAULT_MODEL", "claude-haiku-4-5")
# Setting a base_url with hostname `api.anthropic.com` makes run_agent.py
# auto-select its `anthropic_messages` api_mode (the native /v1/messages
# adapter). Without this it defaults to /chat/completions and 404s against
# Anthropic's domain. Override per request via forwardedProps.base_url.
HERMES_DEFAULT_BASE_URL = os.environ.get(
    "HERMES_DEFAULT_BASE_URL", "https://api.anthropic.com"
)
HERMES_MAX_TURNS = int(os.environ.get("HERMES_MAX_TURNS", "5"))
BRIDGE_HOST = os.environ.get("BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "17030"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "Hermes bridge online — %s:%d → hermes=%s python=%s default_model=%s",
        BRIDGE_HOST,
        BRIDGE_PORT,
        HERMES_PATH,
        HERMES_PYTHON,
        HERMES_DEFAULT_MODEL,
    )
    if not os.path.exists(HERMES_PYTHON):
        log.warning("HERMES_PYTHON %s not found — Hermes runs will fail", HERMES_PYTHON)
    if not os.path.exists(os.path.join(HERMES_PATH, "run_agent.py")):
        log.warning("run_agent.py not found at HERMES_PATH=%s", HERMES_PATH)
    yield
    log.info("Hermes bridge shutting down")


app = FastAPI(title="Hermes AG-UI Bridge", version="0.1.0", lifespan=lifespan)


# ── Helpers ────────────────────────────────────────────────────────

def now_ms() -> int:
    return int(time.time() * 1000)


def sse(event_dict: dict) -> bytes:
    """Encode a dict as one SSE `data:` frame."""
    return f"data: {json.dumps(event_dict)}\n\n".encode()


def extract_user_query(body: dict) -> Optional[str]:
    """
    Pull the most recent user message text out of a RunAgentInput-shaped body.
    Tolerant of shape variations — falls back to top-level `query` if present.
    """
    if isinstance(body.get("query"), str):
        return body["query"]

    messages = body.get("messages") or []
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role and role != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str) and content.strip():
            return content
        # AG-UI sometimes uses list-of-parts content
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    text = part.get("text") or part.get("value")
                    if isinstance(text, str) and text.strip():
                        return text
    return None


def _hint(body: dict, key: str) -> Optional[str]:
    fwd = body.get("forwardedProps") or {}
    if isinstance(fwd, dict):
        v = fwd.get(key)
        if isinstance(v, str) and v.strip():
            return v
    v = body.get(key)
    if isinstance(v, str) and v.strip():
        return v
    return None


def extract_model(body: dict) -> Optional[str]:
    return _hint(body, "model") or (HERMES_DEFAULT_MODEL or None)


def extract_base_url(body: dict) -> Optional[str]:
    return _hint(body, "base_url") or (HERMES_DEFAULT_BASE_URL or None)


# ── Health ─────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "hermes-bridge",
        "hermes_path": HERMES_PATH,
        "hermes_python": HERMES_PYTHON,
        "hermes_python_exists": os.path.exists(HERMES_PYTHON),
        "default_model": HERMES_DEFAULT_MODEL,
        "max_turns": HERMES_MAX_TURNS,
    }


# ── Main /agent endpoint ───────────────────────────────────────────

@app.post("/agent")
async def agent(request: Request):
    """
    Translate an AG-UI RunAgentInput into a Hermes invocation and stream the
    result as AG-UI events. One request = one Hermes run.
    """
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(
            {"error": f"Invalid JSON: {e}"}, status_code=400
        )
    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "Body must be a JSON object"}, status_code=400
        )

    thread_id = body.get("thread_id") or str(uuid.uuid4())
    run_id = body.get("run_id") or str(uuid.uuid4())
    message_id = str(uuid.uuid4())

    query = extract_user_query(body)
    if not query:
        return JSONResponse(
            {"error": "No user message text found in RunAgentInput"},
            status_code=400,
        )
    model = extract_model(body)
    base_url = extract_base_url(body)

    # Provider credentials forwarded by the AG-UI proxy as X-Provider-Key-<name>.
    # We translate to the conventional <NAME>_API_KEY env var the agent reads.
    # Hermes treats GOOGLE_API_KEY and GEMINI_API_KEY as aliases, so for "google"
    # we set both to widen compatibility.
    injected_env: dict[str, str] = {}
    for raw_key, raw_val in request.headers.items():
        if not raw_key.lower().startswith("x-provider-key-"):
            continue
        provider = raw_key[len("x-provider-key-"):].strip()
        if not provider or not raw_val:
            continue
        env_name = f"{provider.upper()}_API_KEY"
        injected_env[env_name] = raw_val
        if provider.lower() == "google":
            injected_env["GEMINI_API_KEY"] = raw_val

    log.info(
        "Run %s thread=%s model=%s query=%r injected=%s",
        run_id,
        thread_id,
        model,
        query[:120] + ("..." if len(query) > 120 else ""),
        list(injected_env.keys()) or "none",
    )

    async def stream() -> AsyncGenerator[bytes, None]:
        # 1. RunStartedEvent
        yield sse(
            {
                "type": "RUN_STARTED",
                "threadId": thread_id,
                "runId": run_id,
                "timestamp": now_ms(),
            }
        )

        # 2. TextMessageStartEvent (single assistant message bracketing the run)
        yield sse(
            {
                "type": "TEXT_MESSAGE_START",
                "messageId": message_id,
                "role": "assistant",
                "timestamp": now_ms(),
            }
        )

        # 3. Spawn Hermes. Pass --model and --base_url when set so run_agent.py
        # can route to the right API surface (api.anthropic.com triggers the
        # Anthropic-native messages adapter; api.openai.com triggers chat
        # completions, etc.).
        cmd = [
            HERMES_PYTHON,
            "run_agent.py",
            "--query",
            query,
            "--max_turns",
            str(HERMES_MAX_TURNS),
        ]
        if model:
            cmd.extend(["--model", model])
        if base_url:
            cmd.extend(["--base_url", base_url])
        # Bridge env + injected provider creds. Inherit current env so PATH,
        # HOME, etc. carry through; overlay credentials on top.
        spawn_env = {**os.environ, **injected_env}

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=HERMES_PATH,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=spawn_env,
            )
        except Exception as e:
            yield sse(
                {
                    "type": "RUN_ERROR",
                    "threadId": thread_id,
                    "runId": run_id,
                    "message": f"Failed to spawn Hermes: {e}",
                    "timestamp": now_ms(),
                }
            )
            return

        # 4. Stream stdout lines as text deltas
        assert proc.stdout is not None
        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace")
                yield sse(
                    {
                        "type": "TEXT_MESSAGE_CONTENT",
                        "messageId": message_id,
                        "delta": text,
                        "timestamp": now_ms(),
                    }
                )
        except Exception as e:
            log.exception("Stream interrupted")
            yield sse(
                {
                    "type": "RUN_ERROR",
                    "threadId": thread_id,
                    "runId": run_id,
                    "message": f"Stream error: {e}",
                    "timestamp": now_ms(),
                }
            )
            try:
                proc.kill()
            except Exception:
                pass
            return

        rc = await proc.wait()
        log.info("Run %s exited rc=%d", run_id, rc)

        # 5. Close the assistant message
        yield sse(
            {
                "type": "TEXT_MESSAGE_END",
                "messageId": message_id,
                "timestamp": now_ms(),
            }
        )

        # 6. Run terminator
        if rc == 0:
            yield sse(
                {
                    "type": "RUN_FINISHED",
                    "threadId": thread_id,
                    "runId": run_id,
                    "timestamp": now_ms(),
                }
            )
        else:
            yield sse(
                {
                    "type": "RUN_ERROR",
                    "threadId": thread_id,
                    "runId": run_id,
                    "message": f"Hermes exited with code {rc}",
                    "timestamp": now_ms(),
                }
            )

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Hermes-Bridge": "0.1.0",
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=BRIDGE_HOST, port=BRIDGE_PORT)
