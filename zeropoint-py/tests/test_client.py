"""Unit tests for the top-level client (a) — health/version/identity/stats."""

from __future__ import annotations

import httpx
import pytest
import respx

from zeropoint import (
    AuthenticationError,
    HealthResponse,
    IdentityResponse,
    StatsResponse,
    VersionResponse,
    ZeroPointError,
    ZeroPointClient,
)
from zeropoint.exceptions import ConnectionError as ZpConnectionError


# ── (a) success — typed response parsing ─────────────────────────────


@respx.mock
def test_health_success(client: ZeroPointClient, base_url: str) -> None:
    respx.get(f"{base_url}/api/v1/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "ok",
                "uptime_seconds": 1234.5,
                "version": "0.1.0",
            },
        )
    )

    result = client.health()
    assert isinstance(result, HealthResponse)
    assert result.status == "ok"
    assert result.uptime_seconds == 1234.5
    assert result.version == "0.1.0"
    # `to_dict` survives the round-trip.
    d = result.to_dict()
    assert d["status"] == "ok"


@respx.mock
def test_version_returns_typed_model(client: ZeroPointClient, base_url: str) -> None:
    respx.get(f"{base_url}/api/v1/version").mock(
        return_value=httpx.Response(
            200,
            json={"version": "0.7.3", "commit": "abc123", "build": "release"},
        )
    )
    v = client.version()
    assert isinstance(v, VersionResponse)
    assert v.version == "0.7.3"
    assert v.commit == "abc123"


@respx.mock
def test_identity_and_stats_parse_minimal_payloads(
    client: ZeroPointClient, base_url: str
) -> None:
    """Fields are optional — empty server response is still well-formed."""
    respx.get(f"{base_url}/api/v1/identity").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(f"{base_url}/api/v1/stats").mock(
        return_value=httpx.Response(
            200, json={"entries_total": 401, "tools_governed": 7}
        )
    )

    ident = client.identity()
    assert isinstance(ident, IdentityResponse)
    assert ident.operator is None  # not populated, but parses

    stats = client.stats()
    assert isinstance(stats, StatsResponse)
    assert stats.entries_total == 401
    assert stats.tools_governed == 7


# ── (b) error response handling ──────────────────────────────────────


@respx.mock
def test_health_401_raises_authentication_error(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/health").mock(
        return_value=httpx.Response(401, json={"error": "missing api key"})
    )
    with pytest.raises(AuthenticationError) as excinfo:
        client.health()
    assert excinfo.value.status_code == 401
    assert excinfo.value.body == {"error": "missing api key"}


@respx.mock
def test_health_500_raises_zeropoint_error(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/health").mock(
        return_value=httpx.Response(500, text="internal server error")
    )
    with pytest.raises(ZeroPointError) as excinfo:
        client.health()
    assert excinfo.value.status_code == 500
    # Body falls back to the raw text when JSON decoding fails.
    assert excinfo.value.body == "internal server error"


@respx.mock
def test_transport_failure_raises_zp_connection_error(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/health").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    with pytest.raises(ZpConnectionError) as excinfo:
        client.health()
    assert excinfo.value.status_code is None
    assert "could not reach zp-server" in excinfo.value.message


# ── (c) request payload / construction ───────────────────────────────


def test_constructor_normalizes_trailing_slash() -> None:
    """Trailing slashes on base_url shouldn't double up in URLs."""
    c = ZeroPointClient(base_url="http://localhost:3120/")
    try:
        assert c._base_url == "http://localhost:3120"
    finally:
        c.close()


def test_constructor_sets_authorization_header_when_api_key_given() -> None:
    c = ZeroPointClient(base_url="http://localhost:3120", api_key="secret-token")
    try:
        # httpx.Client exposes default headers via `.headers`.
        assert c._httpx.headers["Authorization"] == "Bearer secret-token"
        assert c._httpx.headers["User-Agent"].startswith("zeropoint-py/")
    finally:
        c.close()


@respx.mock
def test_health_uses_get_and_targets_correct_path(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.get(f"{base_url}/api/v1/health").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )
    client.health()
    assert route.called
    # Verb + path are what we promised.
    assert route.calls[0].request.method == "GET"
    assert route.calls[0].request.url.path == "/api/v1/health"
