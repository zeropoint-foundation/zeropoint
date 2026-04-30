"""Typed exceptions raised by the ZeroPoint Python SDK.

Every exception carries the HTTP status code and response body when the
failure originated from the server. Network-level failures (connection
refused, timeout) raise :class:`ConnectionError` with ``status_code=None``.
"""

from __future__ import annotations

from typing import Any, Optional


class ZeroPointError(Exception):
    """Base class for every error raised by the SDK.

    Attributes:
        message: Human-readable explanation of the failure.
        status_code: The HTTP status code returned by the server, or
            ``None`` for client-side / network failures.
        body: The raw response body, parsed as JSON when possible. May
            be ``None`` if the server returned no body or the response
            could not be decoded.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        body: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.body = body

    def __repr__(self) -> str:  # pragma: no cover — trivial
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"status_code={self.status_code!r}, body={self.body!r})"
        )


class ConnectionError(ZeroPointError):
    """The SDK could not reach the zp-server.

    Raised when httpx fails to establish a connection, the request times
    out, or the response is otherwise unparseable. Distinct from
    :class:`AuthenticationError`, which means the server *was* reached
    and answered 401/403.

    Note: this name shadows the built-in ``ConnectionError`` inside this
    module. Import it as ``from zeropoint.exceptions import
    ConnectionError as ZpConnectionError`` if a name collision matters.
    """


class AuthenticationError(ZeroPointError):
    """The server rejected the request as unauthenticated or unauthorized.

    Maps to HTTP 401 and 403. Check the SDK constructor's ``api_key``
    argument and the server's auth posture (``zp doctor`` reports it).
    """


class GovernanceError(ZeroPointError):
    """The governance gate denied an action.

    Raised by :meth:`zeropoint.governance.GovernanceAPI.evaluate` (and
    its async twin) when ``allowed=False``. The denial reason from the
    server is exposed both as :attr:`denial_reason` and inside
    :attr:`body` for callers that want the full response.
    """

    def __init__(
        self,
        message: str,
        *,
        denial_reason: Optional[str] = None,
        status_code: Optional[int] = None,
        body: Optional[Any] = None,
    ) -> None:
        super().__init__(message, status_code=status_code, body=body)
        self.denial_reason = denial_reason


class ChainError(ZeroPointError):
    """Audit-chain verification failed.

    Raised by :meth:`zeropoint.receipts.ReceiptsAPI.verify_chain` when
    the server reports any verification rule violation (P1, P2, M3, M4,
    S1). The full report is in :attr:`body`.
    """


__all__ = [
    "ZeroPointError",
    "ConnectionError",
    "AuthenticationError",
    "GovernanceError",
    "ChainError",
]
