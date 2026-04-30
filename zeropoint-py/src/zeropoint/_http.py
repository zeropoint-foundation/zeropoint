"""Shared HTTP plumbing for sync and async clients.

The two public client classes (:class:`zeropoint.client.ZeroPointClient`
and :class:`zeropoint.client.AsyncZeroPointClient`) differ only in their
underlying httpx transport. The error-mapping logic — which HTTP status
turns into which SDK exception — is identical, so it lives here as
free functions.

Network exceptions from httpx (``ConnectError``, ``TimeoutException``,
``ReadError``, …) all funnel into :class:`~zeropoint.exceptions.ConnectionError`.
HTTP 401/403 become :class:`~zeropoint.exceptions.AuthenticationError`.
Other 4xx/5xx become :class:`~zeropoint.exceptions.ZeroPointError` with
``status_code`` and ``body`` populated.

Callers that need domain-specific error mapping (governance denials,
chain failures) wrap the result themselves.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .exceptions import (
    AuthenticationError,
    ConnectionError as ZpConnectionError,
    ZeroPointError,
)


def _safe_body(response: httpx.Response) -> Optional[Any]:
    """Best-effort decode the response body as JSON, falling back to text."""
    try:
        return response.json()
    except (ValueError, httpx.DecodingError):
        try:
            return response.text
        except Exception:  # pragma: no cover — exotic encoding failures
            return None


def raise_for_status(response: httpx.Response) -> None:
    """Map an HTTP error response onto a typed SDK exception.

    No-op on 2xx. Caller is responsible for parsing the body into a
    Pydantic model on success.
    """
    if response.is_success:
        return

    body = _safe_body(response)
    status = response.status_code

    if status in (401, 403):
        raise AuthenticationError(
            f"server rejected request with HTTP {status}",
            status_code=status,
            body=body,
        )

    raise ZeroPointError(
        f"server returned HTTP {status}",
        status_code=status,
        body=body,
    )


def wrap_transport_error(exc: httpx.HTTPError) -> ZpConnectionError:
    """Convert any httpx transport-level error into our ConnectionError."""
    return ZpConnectionError(
        f"could not reach zp-server: {exc}",
        status_code=None,
        body=None,
    )


def normalize_base_url(base_url: str) -> str:
    """Trim any trailing slash so endpoint joins are predictable."""
    return base_url.rstrip("/")


def build_headers(api_key: Optional[str]) -> dict[str, str]:
    """Construct default headers, including ``Authorization`` when set."""
    headers = {
        "Accept": "application/json",
        "User-Agent": "zeropoint-py/0.1.0",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers
