# zeropoint — Python SDK

A pure-Python HTTP client for [ZeroPoint](https://zeropoint.global)'s
governance gate. Lets Python agent frameworks (CrewAI, LangGraph,
OpenHands, Cline, …) participate in ZeroPoint governance without
writing Rust.

## What this is

A typed, async-native HTTP client. It talks to a running `zp-server`
(default `http://localhost:3120`) and returns Pydantic models for every
response.

## What this is *not*

- **Not** an FFI binding to the Rust core. There is no Rust in this
  package; `pip install zeropoint` does not require a compiler.
- **Not** a re-implementation of ZeroPoint's chain or signing logic.
  Receipt generation, Ed25519 signing, and chain verification all stay
  server-side in Rust where they belong. This SDK calls
  `verify_chain()` and reads the report; it does not verify locally.
- **Not** a way to bypass governance. The gate decision happens on the
  server. This SDK is the integration surface that lets your agent
  *participate* in governance.

The SDK's value proposition is integration convenience.

## Install

```sh
pip install zeropoint
```

Or, from a local checkout:

```sh
cd zeropoint-py
pip install -e ".[dev]"
```

Requires Python 3.10 or newer. Runtime dependencies are `httpx>=0.27`
and `pydantic>=2.0` — nothing else.

## Quickstart

```python
from zeropoint import ZeroPointClient

with ZeroPointClient() as zp:
    # Liveness check
    health = zp.health()
    print(health.status)

    # Governance gate — ask the server whether this action is allowed
    result = zp.governance.evaluate(
        action="write",
        tool="ironclaw",
        parameters={"path": "/tmp/x"},
        trust_tier=1,
    )
    if not result.allowed:
        raise SystemExit(f"denied: {result.denial_reason}")
    print(f"allowed; receipt={result.receipt_id}, "
          f"reversibility={result.reversibility}")
```

Async usage mirrors the sync API:

```python
import asyncio
from zeropoint import AsyncZeroPointClient

async def main():
    async with AsyncZeroPointClient() as zp:
        head = await zp.receipts.chain_head()
        print(head.entry_hash)

asyncio.run(main())
```

## Configuration

```python
ZeroPointClient(
    base_url="http://localhost:3120",  # default
    api_key=None,                       # optional bearer token
    timeout=30.0,                       # per-request seconds
)
```

When `api_key` is set, every request carries
`Authorization: Bearer <key>`.

## API reference

Module docstrings carry the full reference; the high-level shape:

| Sub-namespace        | Endpoint                                        | Method                              |
|----------------------|-------------------------------------------------|-------------------------------------|
| (top-level)          | `GET  /api/v1/health`                           | `client.health()`                   |
| (top-level)          | `GET  /api/v1/version`                          | `client.version()`                  |
| (top-level)          | `GET  /api/v1/identity`                         | `client.identity()`                 |
| (top-level)          | `GET  /api/v1/stats`                            | `client.stats()`                    |
| `client.governance`  | `POST /api/v1/gate/tool-call`                   | `.evaluate(...)`                    |
| `client.governance`  | `GET  /api/v1/policy/rules`                     | `.policy_rules()`                   |
| `client.receipts`    | `POST /api/v1/receipts/generate`                | `.generate(receipt_type, claims)`   |
| `client.receipts`    | `POST /api/v1/receipts`                         | `.submit_external(receipt)`         |
| `client.receipts`    | `GET  /api/v1/audit/chain-head`                 | `.chain_head()`                     |
| `client.receipts`    | `GET  /api/v1/audit/entries`                    | `.chain_entries(limit, offset)`     |
| `client.receipts`    | `GET  /api/v1/audit/verify`                     | `.verify_chain()`                   |
| `client.tools`       | `GET  /api/v1/tools`                            | `.list_tools()`                     |
| `client.tools`       | `POST /api/v1/tools/register`                   | `.register(name, manifest)`         |
| `client.tools`       | `POST /api/v1/tools/launch`                     | `.launch(tool_name)`                |
| `client.tools`       | `POST /api/v1/tools/stop`                       | `.stop(tool_name)`                  |
| `client.tools`       | `POST /api/v1/tools/{name}/preflight`           | `.preflight(tool_name)`             |
| `client.security`    | `GET  /api/v1/security/posture`                 | `.posture()`                        |
| `client.security`    | `GET  /api/v1/security/topology`                | `.topology()`                       |

Every response is a typed Pydantic model. Use `result.to_dict()` or
`result.to_json()` for serialization.

## Errors

```python
from zeropoint import (
    ZeroPointError,        # base
    ConnectionError,       # transport-level (cannot reach server)
    AuthenticationError,   # 401 / 403
    GovernanceError,       # gate denial (when raise_on_deny=True)
    ChainError,            # chain verification failed (when raise_on_failure=True)
)
```

Every exception carries `status_code` and `body` when the failure
originated server-side.

By default, governance denials and chain-verification failures return
typed result objects rather than raising — agent frameworks should be
free to inspect `result.allowed` and branch. Pass `raise_on_deny=True`
or `raise_on_failure=True` to opt into raising.

## Development

```sh
cd zeropoint-py
pip install -e ".[dev]"
pytest tests/ -k "not integration"
```

Integration tests (marked `@pytest.mark.integration`) expect a running
`zp-server` and are skipped by the default invocation.

## License

Apache-2.0.
