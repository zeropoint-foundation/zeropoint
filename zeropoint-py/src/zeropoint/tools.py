"""Tool lifecycle: list, register, launch, stop, preflight."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

import httpx

from . import _http
from .models import LaunchResult, PreflightResult, StopResult, Tool

if TYPE_CHECKING:
    from .client import AsyncZeroPointClient, ZeroPointClient


class ToolsAPI:
    """Sync tool-lifecycle operations."""

    def __init__(self, client: "ZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.Client:
        return self._client._httpx  # noqa: SLF001

    def list_tools(self) -> list[Tool]:
        """List every governed tool the server knows about."""
        url = f"{self._client._base_url}/api/v1/tools"  # noqa: SLF001
        try:
            resp = self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        payload = resp.json()
        items = payload.get("tools", payload) if isinstance(payload, dict) else payload
        return [Tool.model_validate(item) for item in items]

    def register(self, name: str, manifest: dict[str, Any]) -> Tool:
        """Register a new tool with the server, supplying its manifest."""
        url = f"{self._client._base_url}/api/v1/tools/register"  # noqa: SLF001
        try:
            resp = self._http_client.post(
                url,
                json={"name": name, "manifest": manifest},
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return Tool.model_validate(resp.json())

    def launch(self, tool_name: str) -> LaunchResult:
        """Launch a registered tool. Server allocates the port and starts the process."""
        url = f"{self._client._base_url}/api/v1/tools/launch"  # noqa: SLF001
        try:
            resp = self._http_client.post(url, json={"name": tool_name})
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return LaunchResult.model_validate(resp.json())

    def stop(self, tool_name: str) -> StopResult:
        """Stop a running tool."""
        url = f"{self._client._base_url}/api/v1/tools/stop"  # noqa: SLF001
        try:
            resp = self._http_client.post(url, json={"name": tool_name})
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return StopResult.model_validate(resp.json())

    def preflight(self, tool_name: str) -> PreflightResult:
        """Run preflight checks for ``tool_name``."""
        url = f"{self._client._base_url}/api/v1/tools/{tool_name}/preflight"  # noqa: SLF001
        try:
            resp = self._http_client.post(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return PreflightResult.model_validate(resp.json())


class AsyncToolsAPI:
    """Async twin of :class:`ToolsAPI`."""

    def __init__(self, client: "AsyncZeroPointClient") -> None:
        self._client = client

    @property
    def _http_client(self) -> httpx.AsyncClient:
        return self._client._httpx  # noqa: SLF001

    async def list_tools(self) -> list[Tool]:
        url = f"{self._client._base_url}/api/v1/tools"  # noqa: SLF001
        try:
            resp = await self._http_client.get(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        payload = resp.json()
        items = payload.get("tools", payload) if isinstance(payload, dict) else payload
        return [Tool.model_validate(item) for item in items]

    async def register(self, name: str, manifest: dict[str, Any]) -> Tool:
        url = f"{self._client._base_url}/api/v1/tools/register"  # noqa: SLF001
        try:
            resp = await self._http_client.post(
                url,
                json={"name": name, "manifest": manifest},
            )
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return Tool.model_validate(resp.json())

    async def launch(self, tool_name: str) -> LaunchResult:
        url = f"{self._client._base_url}/api/v1/tools/launch"  # noqa: SLF001
        try:
            resp = await self._http_client.post(url, json={"name": tool_name})
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return LaunchResult.model_validate(resp.json())

    async def stop(self, tool_name: str) -> StopResult:
        url = f"{self._client._base_url}/api/v1/tools/stop"  # noqa: SLF001
        try:
            resp = await self._http_client.post(url, json={"name": tool_name})
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return StopResult.model_validate(resp.json())

    async def preflight(self, tool_name: str) -> PreflightResult:
        url = f"{self._client._base_url}/api/v1/tools/{tool_name}/preflight"  # noqa: SLF001
        try:
            resp = await self._http_client.post(url)
        except httpx.HTTPError as e:
            raise _http.wrap_transport_error(e) from e
        _http.raise_for_status(resp)
        return PreflightResult.model_validate(resp.json())


__all__ = ["ToolsAPI", "AsyncToolsAPI"]
