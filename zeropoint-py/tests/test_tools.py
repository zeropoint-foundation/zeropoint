"""Unit tests for the tools sub-namespace (d)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from zeropoint import (
    AuthenticationError,
    LaunchResult,
    PreflightResult,
    StopResult,
    Tool,
    ZeroPointClient,
)


# ── success — typed response parsing ─────────────────────────────────


@respx.mock
def test_list_tools_returns_typed_list(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/tools").mock(
        return_value=httpx.Response(
            200,
            json={
                "tools": [
                    {
                        "name": "ironclaw",
                        "canonicalized": True,
                        "configured": True,
                        "launched": True,
                        "port": 3210,
                        "reversibility": "irreversible",
                        "scan_verdict": "clean",
                    },
                    {"name": "search", "canonicalized": True},
                ]
            },
        )
    )
    tools = client.tools.list_tools()
    assert len(tools) == 2
    assert all(isinstance(t, Tool) for t in tools)
    assert tools[0].launched is True
    assert tools[1].launched is False  # default


@respx.mock
def test_launch_and_stop_return_typed_results(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.post(f"{base_url}/api/v1/tools/launch").mock(
        return_value=httpx.Response(
            200,
            json={"name": "ironclaw", "launched": True, "port": 3210, "pid": 4242},
        )
    )
    respx.post(f"{base_url}/api/v1/tools/stop").mock(
        return_value=httpx.Response(
            200, json={"name": "ironclaw", "stopped": True}
        )
    )
    launch = client.tools.launch("ironclaw")
    stop = client.tools.stop("ironclaw")
    assert isinstance(launch, LaunchResult)
    assert launch.port == 3210
    assert isinstance(stop, StopResult)
    assert stop.stopped is True


@respx.mock
def test_preflight_returns_checks(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.post(f"{base_url}/api/v1/tools/ironclaw/preflight").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "ironclaw",
                "passed": True,
                "checks": [
                    {"check": "env", "status": "pass"},
                    {"check": "port", "status": "pass"},
                ],
            },
        )
    )
    pre = client.tools.preflight("ironclaw")
    assert isinstance(pre, PreflightResult)
    assert pre.passed is True
    assert len(pre.checks) == 2
    assert pre.checks[0].check == "env"


# ── error response handling ──────────────────────────────────────────


@respx.mock
def test_list_tools_403_raises_authentication_error(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/tools").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )
    with pytest.raises(AuthenticationError) as excinfo:
        client.tools.list_tools()
    assert excinfo.value.status_code == 403


@respx.mock
def test_register_404_raises_zp_error_with_body(
    client: ZeroPointClient, base_url: str
) -> None:
    from zeropoint import ZeroPointError

    respx.post(f"{base_url}/api/v1/tools/register").mock(
        return_value=httpx.Response(404, json={"error": "endpoint not found"})
    )
    with pytest.raises(ZeroPointError) as excinfo:
        client.tools.register("nope", {"tool": {"name": "nope"}})
    assert excinfo.value.status_code == 404
    assert excinfo.value.body == {"error": "endpoint not found"}


# ── request payload / construction ───────────────────────────────────


@respx.mock
def test_register_sends_name_and_manifest_in_body(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.post(f"{base_url}/api/v1/tools/register").mock(
        return_value=httpx.Response(
            200, json={"name": "ironclaw", "canonicalized": True}
        )
    )
    manifest = {"tool": {"name": "ironclaw"}, "capabilities": {"reversibility": "irreversible"}}
    client.tools.register("ironclaw", manifest)
    body = json.loads(route.calls[0].request.content)
    assert body == {"name": "ironclaw", "manifest": manifest}


@respx.mock
def test_preflight_path_includes_tool_name(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.post(f"{base_url}/api/v1/tools/my-tool/preflight").mock(
        return_value=httpx.Response(
            200, json={"name": "my-tool", "passed": True}
        )
    )
    client.tools.preflight("my-tool")
    assert route.called
    assert route.calls[0].request.url.path == "/api/v1/tools/my-tool/preflight"


@respx.mock
def test_launch_sends_name_in_body(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.post(f"{base_url}/api/v1/tools/launch").mock(
        return_value=httpx.Response(
            200, json={"name": "ironclaw", "launched": True}
        )
    )
    client.tools.launch("ironclaw")
    body = json.loads(route.calls[0].request.content)
    assert body == {"name": "ironclaw"}
