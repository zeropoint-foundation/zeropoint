"""Unit tests for the governance sub-namespace (b)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from zeropoint import (
    EvaluationResult,
    GovernanceError,
    PolicyRule,
    ZeroPointClient,
)


# ── success — typed response parsing ─────────────────────────────────


@respx.mock
def test_evaluate_allowed_returns_evaluation_result(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.post(f"{base_url}/api/v1/gate/tool-call").mock(
        return_value=httpx.Response(
            200,
            json={
                "allowed": True,
                "receipt_id": "rcpt-abc123",
                "denial_reason": None,
                "reversibility": "reversible",
            },
        )
    )
    result = client.governance.evaluate(
        action="read",
        tool="search",
        parameters={"q": "trust"},
        trust_tier=1,
    )
    assert isinstance(result, EvaluationResult)
    assert result.allowed is True
    assert result.receipt_id == "rcpt-abc123"
    assert result.reversibility == "reversible"


@respx.mock
def test_policy_rules_returns_list_of_typed_rules(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.get(f"{base_url}/api/v1/policy/rules").mock(
        return_value=httpx.Response(
            200,
            json={
                "rules": [
                    {
                        "rule_id": "R-001",
                        "name": "no_shell_eval",
                        "severity": "critical",
                        "enabled": True,
                    },
                    {"rule_id": "R-002", "name": "fs_scope", "enabled": False},
                ]
            },
        )
    )
    rules = client.governance.policy_rules()
    assert len(rules) == 2
    assert all(isinstance(r, PolicyRule) for r in rules)
    assert rules[0].rule_id == "R-001"
    assert rules[1].enabled is False


# ── error response handling ──────────────────────────────────────────


@respx.mock
def test_evaluate_denied_with_raise_on_deny_raises_governance_error(
    client: ZeroPointClient, base_url: str
) -> None:
    respx.post(f"{base_url}/api/v1/gate/tool-call").mock(
        return_value=httpx.Response(
            200,
            json={
                "allowed": False,
                "denial_reason": "irreversible action requires tier ≥ 1",
                "reversibility": "irreversible",
            },
        )
    )
    with pytest.raises(GovernanceError) as excinfo:
        client.governance.evaluate(
            action="delete",
            tool="ironclaw",
            parameters={"id": 42},
            trust_tier=0,
            raise_on_deny=True,
        )
    assert excinfo.value.denial_reason == "irreversible action requires tier ≥ 1"


@respx.mock
def test_evaluate_denied_without_raise_returns_typed_result(
    client: ZeroPointClient, base_url: str
) -> None:
    """Default behavior is to surface denial as a typed result, not raise.

    Agent frameworks should be free to inspect ``allowed=False`` and
    branch — raising should be opt-in.
    """
    respx.post(f"{base_url}/api/v1/gate/tool-call").mock(
        return_value=httpx.Response(
            200,
            json={
                "allowed": False,
                "denial_reason": "some reason",
                "reversibility": "unknown",
            },
        )
    )
    result = client.governance.evaluate(
        action="delete",
        tool="ironclaw",
        parameters={},
        trust_tier=0,
    )
    assert result.allowed is False
    assert result.denial_reason == "some reason"


# ── request payload / construction ───────────────────────────────────


@respx.mock
def test_evaluate_sends_expected_json_body(
    client: ZeroPointClient, base_url: str
) -> None:
    route = respx.post(f"{base_url}/api/v1/gate/tool-call").mock(
        return_value=httpx.Response(200, json={"allowed": True})
    )
    client.governance.evaluate(
        action="write",
        tool="ironclaw",
        parameters={"path": "/tmp/x", "bytes": 64},
        trust_tier=2,
    )
    assert route.called
    body = json.loads(route.calls[0].request.content)
    assert body == {
        "action": "write",
        "tool": "ironclaw",
        "parameters": {"path": "/tmp/x", "bytes": 64},
        "trust_tier": 2,
    }
