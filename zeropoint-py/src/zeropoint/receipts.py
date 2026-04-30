"""Receipt operations.

Receipt generation, external submission, chain inspection, and
verification. Verification logic stays **server-side** (Rust) — this
module is just the typed view of what the server reports.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

import httpx

from . import _http
from .exceptions import ChainError
from .models import (
    AuditEntry,
    ChainHead,
    Receipt,
    ReceiptAck,
    VerifyResult,
)

if TYPE_CHECKING:
    from .client import AsyncZeroPointClient, ZeroPointClient


def _parse_verify(payload: Any, *, raise_on_failure: bool) -> VerifyResult:
    """Centralize VerifyResult parsing + optional raising.

    The chain verification result has the same shape regardless of
    whether the SDK runs sync or async, so we keep the parsing here.
    """
    result = VerifyResult.model_validate(payload)
    if raise_on_failure and not result.passed:
        raise ChainError(
            "chain verification failed",
            status_code=200,
            body=payload,
        )
    return result


class ReceiptsAPI:
    """Sync receipt operations."""

    def __init__(self, client: "ZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.Client:
        return self._client._httpx  # noqa: SLF001

    def generate(self, receipt_type: str, claims: dict[str, Any]) -> Receipt:
        """Ask the server to generate and sign a receipt of ``receipt_type``."""
        url = f"{self._client._base_url}/api/v1/receipts/generate"  # noqa: SLF001
        try:
            resp = self._http_client.post(
                url,
                json={"receipt_type": receipt_type, "claims": claims},
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return Receipt.model_validate(resp.json())

    def submit_external(self, receipt: dict[str, Any]) -> ReceiptAck:
        """Submit an externally-generated receipt for inclusion in the chain."""
        url = f"{self._client._base_url}/api/v1/receipts"  # noqa: SLF001
        try:
            resp = self._http_client.post(url, json=receipt)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return ReceiptAck.model_validate(resp.json())

    def chain_head(self) -> ChainHead:
        """Return the current chain head (latest sealed entry hash)."""
        url = f"{self._client._base_url}/api/v1/audit/chain-head"  # noqa: SLF001
        try:
            resp = self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return ChainHead.model_validate(resp.json())

    def chain_entries(self, limit: int = 100, offset: int = 0) -> list[AuditEntry]:
        """Page through audit entries, most-recent-first."""
        url = f"{self._client._base_url}/api/v1/audit/entries"  # noqa: SLF001
        try:
            resp = self._http_client.get(
                url,
                params={"limit": limit, "offset": offset},
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        payload = resp.json()
        items = payload.get("entries", payload) if isinstance(payload, dict) else payload
        return [AuditEntry.model_validate(item) for item in items]

    def verify_chain(self, *, raise_on_failure: bool = False) -> VerifyResult:
        """Ask the server to re-verify the audit chain.

        Verification logic lives in Rust on the server. The SDK only
        consumes the report.
        """
        url = f"{self._client._base_url}/api/v1/audit/verify"  # noqa: SLF001
        try:
            resp = self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return _parse_verify(resp.json(), raise_on_failure=raise_on_failure)


class AsyncReceiptsAPI:
    """Async twin of :class:`ReceiptsAPI`."""

    def __init__(self, client: "AsyncZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.AsyncClient:
        return self._client._httpx  # noqa: SLF001

    async def generate(self, receipt_type: str, claims: dict[str, Any]) -> Receipt:
        url = f"{self._client._base_url}/api/v1/receipts/generate"  # noqa: SLF001
        try:
            resp = await self._http_client.post(
                url,
                json={"receipt_type": receipt_type, "claims": claims},
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return Receipt.model_validate(resp.json())

    async def submit_external(self, receipt: dict[str, Any]) -> ReceiptAck:
        url = f"{self._client._base_url}/api/v1/receipts"  # noqa: SLF001
        try:
            resp = await self._http_client.post(url, json=receipt)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return ReceiptAck.model_validate(resp.json())

    async def chain_head(self) -> ChainHead:
        url = f"{self._client._base_url}/api/v1/audit/chain-head"  # noqa: SLF001
        try:
            resp = await self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return ChainHead.model_validate(resp.json())

    async def chain_entries(self, limit: int = 100, offset: int = 0) -> list[AuditEntry]:
        url = f"{self._client._base_url}/api/v1/audit/entries"  # noqa: SLF001
        try:
            resp = await self._http_client.get(
                url,
                params={"limit": limit, "offset": offset},
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        payload = resp.json()
        items = payload.get("entries", payload) if isinstance(payload, dict) else payload
        return [AuditEntry.model_validate(item) for item in items]

    async def verify_chain(self, *, raise_on_failure: bool = False) -> VerifyResult:
        url = f"{self._client._base_url}/api/v1/audit/verify"  # noqa: SLF001
        try:
            resp = await self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return _parse_verify(resp.json(), raise_on_failure=raise_on_failure)


__all__ = ["ReceiptsAPI", "AsyncReceiptsAPI"]
