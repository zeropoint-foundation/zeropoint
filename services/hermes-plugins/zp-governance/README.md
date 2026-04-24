# zp-governance — Hermes plugin for ZeroPoint's Stage 1 gate

Intercepts every Hermes tool dispatch at the `pre_tool_call` hook, consults ZeroPoint's `/api/v1/gate/tool-call` endpoint, and blocks the dispatch if ZP denies. Every decision (allow or block) is journaled as an external receipt in ZP.

This is the implementation of Stage 1 of the ZP × Hermes integration plan. See `docs/design/zp-hermes-interfaces.md` in the ZeroPoint repo for the full architecture.

## Install

The plugin already lives at `~/.hermes/plugins/zp-governance/`. To enable:

```bash
hermes plugins enable zp-governance
```

Or add to `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - zp-governance
```

Verify:

```bash
hermes plugins list | grep zp-governance
```

## Configuration

Environment variables, all optional:

| Var | Default | Purpose |
|-----|---------|---------|
| `ZP_URL` | `http://127.0.0.1:17010` | ZP server base URL |
| `ZP_SESSION_TOKEN` | read from `~/ZeroPoint/session.json` | bearer token for auth |
| `ZP_GATE_FAIL_CLOSED` | `0` (fail-open) | set to `1` for hard-fail when ZP unreachable |
| `ZP_GATE_TIMEOUT_MS` | `2000` | per-call budget (connect + read) |

Fail-open is the default posture on purpose: a degraded governance layer should not silently halt Hermes. Operators who want strict enforcement opt in via `ZP_GATE_FAIL_CLOSED=1`.

## Policy

ZP-side policy lives at `~/ZeroPoint/gate-policy.json`:

```json
{
  "deny_tool_names": ["terminal", "execute_code"]
}
```

Missing file or missing key → allow everything. Matches are case-sensitive exact tool names. Future policy expressions (capability grants, WASM modules, envelope consumption for `browser_*`) slot in at the ZP endpoint without changes to this plugin.

## Receipt stream

Every gate decision lands in `~/ZeroPoint/logs/external-receipts.jsonl`:

```json
{"receipt_id":"rcpt-...","timestamp":...,"claim_type":"gate.tool_call.allowed","approved":true,"metadata":{"tool_name":"...","args_hash":"...","thread_id":"...","run_id":"...","agent":"hermes"}}
{"receipt_id":"rcpt-...","timestamp":...,"claim_type":"gate.tool_call.blocked","approved":false,"reason":"tool 'terminal' is on the gate-policy deny list","metadata":{...}}
```

Two new claim types on the abacus: `gate.tool_call.allowed` and `gate.tool_call.blocked`. Both wire into the same receipt journal the AG-UI proxy already writes to.
