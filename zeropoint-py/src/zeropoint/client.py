"""Sync and async ZeroPoint HTTP clients.

The two classes mirror each other: :class:`ZeroPointClient` for blocking
callers and :class:`AsyncZeroPointClient` for ``asyncio``-based ones.
Both expose the same sub-namespaces (``client.governance``,
``client.receipts``, ``client.tools``, ``client.security``) and the
same direct methods (``health``, ``version``, ``identity``, ``stats``).

The "sync wraps async via httpx" line in the spec is honored by using
``httpx.Client`` for the sync surface and ``httpx.AsyncClient`` for the
async one — both share the same underlying httpx core, just with
different transports. There is no event-loop trickery and no thread
pool: sync stays sync, async stays async.

Both clients support context-manager usage::

    with ZeroPointClient() as zp:
        zp.health()

    async with AsyncZeroPointClient() as zp:
        await zp.health()
"""

from __future__ import annotations

from typing import Optional

import httpx

from . import _http
from .governance import AsyncGovernanceAPI, GovernanceAPI
from .models import (
    HealthResponse,
    IdentityResponse,
    StatsResponse,
    VersionResponse,
)
from .receipts import AsyncReceiptsAPI, ReceiptsAPI
from .security import AsyncSecurityAPI, SecurityAPI
from .tools import AsyncToolsAPI, ToolsAPI

DEFAULT_BASE_URL = "http://localhost:3120"
DEFAULT_TIMEOUT_SECONDS = 30.0


class ZeroPointClient:
    """Synchronous HTTP client for the ZeroPoint governance gate.

    Args:
        base_url: Where zp-server is listening. Default
            ``http://localhost:3120``.
        api_key: Optional bearer token. Sent as ``Authorization: Bearer
            <key>`` on every request.
        timeout: Per-request timeout in seconds.
        transport: Optional ``httpx.BaseTransport`` for testing
            (e.g. ``respx.MockTransport`` or ``httpx.MockTransport``).
            When ``None`` the default httpx transport is used.

    Example::

        from zeropoint import ZeroPointClient

        with ZeroPointClient() as zp:
            health = zp.health()
            result = zp.governance.evaluate(
                action="read",
                tool="search_docs",
                parameters={"query": "trust triangle"},
                trust_tier=1,
            )
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: Optional[str] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self._base_url = _http.normalize_base_url(base_url)
        self._api_key = api_key
        self._httpx = httpx.Client(
            headers=_http.build_headers(api_key),
            timeout=timeout,
            transport=transport,
        )
        # Sub-namespaces
        self.governance = GovernanceAPI(self)
        self.receipts = ReceiptsAPI(self)
        self.tools = ToolsAPI(self)
        self.security = SecurityAPI(self)

    # ── Lifecycle ────────────────────────────────────────────────────

    def close(self) -> None:
        """Release the underlying httpx connection pool."""
        self._httpx.close()

    def __enter__(self) -> "ZeroPointClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ── Direct endpoints ─────────────────────────────────────────────

    def health(self) -> HealthResponse:
        """``GET /api/v1/health``."""
        return self._get("/api/v1/health", HealthResponse)

    def version(self) -> VersionResponse:
        """``GET /api/v1/version``."""
        return self._get("/api/v1/version", VersionResponse)

    def identity(self) -> IdentityResponse:
        """``GET /api/v1/identity``."""
        return self._get("/api/v1/identity", IdentityResponse)

    def stats(self) -> StatsResponse:
        """``GET /api/v1/stats``."""
        return self._get("/api/v1/stats", StatsResponse)

    # ── Internal ─────────────────────────────────────────────────────

    def _get(self, path: str, model_cls):
        """Generic GET → typed model. Used for the simple readonly endpoints."""
        url = f"{self._base_url}{path}"
        try:
            resp = self._httpx.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return model_cls.model_validate(resp.json())


class AsyncZeroPointClient:
    """Async twin of :class:`ZeroPointClient`.

    Identical surface; awaitable methods. See :class:`ZeroPointClient`
    for argument semantics.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: Optional[str] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self._base_url = _http.normalize_base_url(base_url)
        self._api_key = api_key
        self._httpx = httpx.AsyncClient(
            headers=_http.build_headers(api_key),
            timeout=timeout,
            transport=transport,
        )
        self.governance = AsyncGovernanceAPI(self)
        self.receipts = AsyncReceiptsAPI(self)
        self.tools = AsyncToolsAPI(self)
        self.security = AsyncSecurityAPI(self)

    async def aclose(self) -> None:
        """Release the underlying httpx async connection pool."""
        await self._httpx.aclose()

    async def __aenter__(self) -> "AsyncZeroPointClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def health(self) -> HealthResponse:
        return await self._get("/api/v1/health", HealthResponse)

    async def version(self) -> VersionResponse:
        return await self._get("/api/v1/version", VersionResponse)

    async def identity(self) -> IdentityResponse:
        return await self._get("/api/v1/identity", IdentityResponse)

    async def stats(self) -> StatsResponse:
        return await self._get("/api/v1/stats", StatsResponse)

    async def _get(self, path: str, model_cls):
        url = f"{self._base_url}{path}"
        try:
            resp = await self._httpx.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return model_cls.model_validate(resp.json())


__all__ = ["ZeroPointClient", "AsyncZeroPointClient", "DEFAULT_BASE_URL"]
