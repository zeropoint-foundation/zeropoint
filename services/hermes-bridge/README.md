# Hermes AG-UI Bridge

Wraps Hermes Agent (Nous Research) as an AG-UI HTTP service so the AG-UI
governance proxy can route governed agent runs to it.

## Why this exists

Hermes is a one-shot Python CLI (`python run_agent.py --query ... --model ...`),
not a long-running server. ZeroPoint's tile/port model assumes services that
bind a port. The bridge inverts that: it IS the long-running service. Each
inbound `POST /agent` becomes one Hermes invocation.

## Architecture

```
Dashboard --POST RunAgentInput--> AG-UI Proxy :17020
                                       |
                                       v
                            this bridge :17030  POST /agent
                                       |
                                       v
              spawn: <hermes_venv>/python run_agent.py --query ... --model ...
                                       |
                                       v
                          stdout lines -> TextMessageContentEvent
                          rc == 0      -> RunFinishedEvent
                          rc != 0      -> RunErrorEvent
```

Each request is a complete AG-UI session: `RunStartedEvent`,
`TextMessageStartEvent`, a stream of `TextMessageContentEvent` deltas,
`TextMessageEndEvent`, then `RunFinishedEvent` or `RunErrorEvent`.

## Configuration

Environment variables (with defaults):

| Var | Default | Purpose |
|---|---|---|
| `HERMES_PATH` | `/Users/kenrom/projects/hermes` | Hermes repo root |
| `HERMES_PYTHON` | `$HERMES_PATH/.venv/bin/python` | Interpreter to spawn |
| `HERMES_DEFAULT_MODEL` | `gemini-2.5-flash` | Used when request doesn't specify |
| `HERMES_MAX_TURNS` | `5` | `--max_turns` passed to Hermes |
| `BRIDGE_HOST` | `127.0.0.1` | Bind address |
| `BRIDGE_PORT` | `17030` | Bind port (matches AG-UI proxy upstream) |

## Run

```bash
cd ~/projects/zeropoint/services/hermes-bridge
pip install -r requirements.txt
python bridge.py
```

## Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Bridge state + Hermes prereq check |
| `/agent` | POST | RunAgentInput → SSE stream of AG-UI events |

## Notes

- Stderr is merged into stdout so Hermes warnings/errors appear in the text
  stream (the dashboard renders them as part of the assistant message).
- `model` can come from `forwardedProps.model` or top-level `model`; falls back
  to `HERMES_DEFAULT_MODEL`.
- `query` comes from the last user message in `messages`, or top-level `query`.
- One request = one process. No state retained between runs.
