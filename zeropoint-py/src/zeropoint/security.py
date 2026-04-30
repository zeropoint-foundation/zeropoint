"""Security posture and topology endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from . import _http
from .models import SecurityPosture, Topology

if TYPE_CHECKING:
    from .client import AsyncZeroPointClient, ZeroPointClient


class SecurityAPI:
    """Sync security-posture queries."""

    def __init__(self, client: "ZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.Client:
        return self._client._httpx  # noqa: SLF001

    def posture(self) -> SecurityPosture:
        """Server's self-reported security posture."""
        url = f"{self._client._base_url}/api/v1/security/posture"  # noqa: SLF001
        try:
            resp = self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return SecurityPosture.model_validate(resp.json())

    def topology(self) -> Topology:
        """Mesh topology — self node plus known peers."""
        url = f"{self._client._base_url}/api/v1/security/topology"  # noqa: SLF001
        try:
            resp = self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return Topology.model_validate(resp.json())


class AsyncSecurityAPI:
    """Async twin of :class:`SecurityAPI`."""

    def __init__(self, client: "AsyncZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.AsyncClient:
        return self._client._httpx  # noqa: SLF001

    async def posture(self) -> SecurityPosture:
        url = f"{self._client._base_url}/api/v1/security/posture"  # noqa: SLF001
        try:
            resp = await self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return SecurityPosture.model_validate(resp.json())

    async def topology(self) -> Topology:
        url = f"{self._client._base_url}/api/v1/security/topology"  # noqa: SLF001
        try:
            resp = await self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return Topology.model_validate(resp.json())


__all__ = ["SecurityAPI", "AsyncSecurityAPI"]
