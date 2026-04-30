"""Unit tests for the security sub-namespace (e)."""

from __future__ import annotations

import httpx
import pytest
import respx

from zeropoint import (
    SecurityPosture,
    Topology,
    TopologyNode,
    ZeroPointClient,
    ZeroPointError,
)


# ── success — typed response parsing ─────────────────────────────────


@respx.mock
def test_posture_returns_typed_security_posture(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/security/posture").mock(
        return_value=httpx.Response(
            200,
            json={
                "posture": "balanced",
                "trust_tier": "Tier1",
                "sovereignty_mode": "touch_id",
                "auth_required": True,
                "findings": ["api_key not rotated in 90d"],
            },
        )
    )
    p = client.security.posture()
    assert isinstance(p, SecurityPosture)
    assert p.posture == "balanced"
    assert p.auth_required is True
    assert p.findings == ["api_key not rotated in 90d"]


@respx.mock
def test_topology_returns_self_and_peers(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/security/topology").mock(
        return_value=httpx.Response(
            200,
            json={
                "self_node": {
                    "name": "apollo",
                    "role": "primary",
                    "address": "192.168.1.152",
                    "reputation": 1.0,
                },
                "peers": [
                    {"name": "artemis", "role": "peer", "reputation": 0.95},
                    {"name": "playground", "role": "peer", "reputation": 0.9},
                ],
            },
        )
    )
    topo = client.security.topology()
    assert isinstance(topo, Topology)
    assert isinstance(topo.self_node, TopologyNode)
    assert topo.self_node.name == "apollo"
    assert len(topo.peers) == 2
    assert topo.peers[0].reputation == 0.95


@respx.mock
def test_topology_handles_no_peers(client: ZeroPointClient, base_url: str) -> None:
    """Empty topology — single-node deployment — must still parse."""
    respx.get(f"{base_url}/api/v1/security/topology").mock(
        return_value=httpx.Response(200, json={})
    )
    topo = client.security.topology()
    assert isinstance(topo, Topology)
    assert topo.self_node is None
    assert topo.peers == []


# ── error response handling ──────────────────────────────────────────


@respx.mock
def test_posture_500_raises_zeropoint_error(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/security/posture").mock(
        return_value=httpx.Response(500, text="boom")
    )
    with pytest.raises(ZeroPointError) as excinfo:
        client.security.posture()
    assert excinfo.value.status_code == 500
    assert excinfo.value.body == "boom"


# ── request construction ─────────────────────────────────────────────


@respx.mock
def test_posture_uses_get_and_correct_path(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.get(f"{base_url}/api/v1/security/posture").mock(
        return_value=httpx.Response(200, json={"posture": "permissive"})
    )
    client.security.posture()
    assert route.called
    assert route.calls[0].request.method == "GET"
    assert route.calls[0].request.url.path == "/api/v1/security/posture"


@respx.mock
def test_topology_uses_get_and_correct_path(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.get(f"{base_url}/api/v1/security/topology").mock(
        return_value=httpx.Response(200, json={})
    )
    client.security.topology()
    assert route.called
    assert route.calls[0].request.url.path == "/api/v1/security/topology"
