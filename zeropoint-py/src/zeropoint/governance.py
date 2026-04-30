"""Governance-gate API surface.

This module talks to ``POST /api/v1/gate/tool-call`` and
``GET /api/v1/policy/rules``. The gate decision lives **server-side** —
this module never makes its own allow/deny decision. It just calls the
server and surfaces the typed result.

The sync :class:`GovernanceAPI` and async :class:`AsyncGovernanceAPI`
share request and response shapes; only the transport differs.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

import httpx

from . import _http
from .exceptions import GovernanceError
from .models import EvaluationResult, PolicyRule

if TYPE_CHECKING:
    from .client import AsyncZeroPointClient, ZeroPointClient


def _build_evaluate_payload(
    action: str,
    tool: str,
    parameters: dict[str, Any],
    trust_tier: int,
) -> dict[str, Any]:
    """The wire format for ``POST /api/v1/gate/tool-call``.

    Centralized so sync and async variants stay in lock-step.
    """
    return {
        "action": action,
        "tool": tool,
        "parameters": parameters,
        "trust_tier": trust_tier,
    }


def _parse_evaluation(payload: Any, *, raise_on_deny: bool) -> EvaluationResult:
    """Validate the response and optionally raise on denial.

    Centralized so both clients have identical denial semantics.
    """
    result = EvaluationResult.model_validate(payload)
    if raise_on_deny and not result.allowed:
        raise GovernanceError(
            "governance gate denied action",
            denial_reason=result.denial_reason,
            status_code=200,  # the *server* answered cleanly
            body=payload,
        )
    return result


class GovernanceAPI:
    """Sync governance-gate operations.

    Instances are usually accessed via ``client.governance`` rather than
    constructed directly.
    """

    def __init__(self, client: "ZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.Client:
        return self._client._httpx  # noqa: SLF001 — intentional cross-class access

    def evaluate(
        self,
        action: str,
        tool: str,
        parameters: dict[str, Any],
        trust_tier: int = 0,
        *,
        raise_on_deny: bool = False,
    ) -> EvaluationResult:
        """Evaluate a tool call against the governance gate.

        Args:
            action: The action label (e.g. ``"read"``, ``"write"``).
            tool: Tool name as canonicalized in the substrate.
            parameters: Action-specific parameters; passed through.
            trust_tier: 0 / 1 / 2. Defaults to 0 (least privilege).
            raise_on_deny: If True, raise :class:`GovernanceError` when
                the server returns ``allowed=False``. Default is False
                so callers can branch on the typed result.
        """
        url = f"{self._client._base_url}/api/v1/gate/tool-call"  # noqa: SLF001
        try:
            resp = self._http_client.post(
                url,
                json=_build_evaluate_payload(action, tool, parameters, trust_tier),
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return _parse_evaluation(resp.json(), raise_on_deny=raise_on_deny)

    def policy_rules(self) -> list[PolicyRule]:
        """List policy rules currently configured on the server."""
        url = f"{self._client._base_url}/api/v1/policy/rules"  # noqa: SLF001
        try:
            resp = self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        payload = resp.json()
        # Accept either a bare array or `{ "rules": [...] }`.
        items = payload.get("rules", payload) if isinstance(payload, dict) else payload
        return [PolicyRule.model_validate(item) for item in items]


class AsyncGovernanceAPI:
    """Async twin of :class:`GovernanceAPI`."""

    def __init__(self, client: "AsyncZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.AsyncClient:
        return self._client._httpx  # noqa: SLF001

    async def evaluate(
        self,
        action: str,
        tool: str,
        parameters: dict[str, Any],
        trust_tier: int = 0,
        *,
        raise_on_deny: bool = False,
    ) -> EvaluationResult:
        url = f"{self._client._base_url}/api/v1/gate/tool-call"  # noqa: SLF001
        try:
            resp = await self._http_client.post(
                url,
                json=_build_evaluate_payload(action, tool, parameters, trust_tier),
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return _parse_evaluation(resp.json(), raise_on_deny=raise_on_deny)

    async def policy_rules(self) -> list[PolicyRule]:
        url = f"{self._client._base_url}/api/v1/policy/rules"  # noqa: SLF001
        try:
            resp = await self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        payload = resp.json()
        items = payload.get("rules", payload) if isinstance(payload, dict) else payload
        return [PolicyRule.model_validate(item) for item in items]


__all__ = ["GovernanceAPI", "AsyncGovernanceAPI"]
