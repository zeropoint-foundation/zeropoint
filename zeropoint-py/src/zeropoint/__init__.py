"""ZeroPoint — Python SDK for the ZeroPoint governance gate.

A pure-Python HTTP client. No FFI, no Rust bindings, no signing logic
in Python. The chain, the signatures, and the verification all stay
server-side in Rust where they belong; this SDK just makes the
governance gate accessible from Python agent code with typed responses
and proper error handling.

Quickstart::

    from zeropoint import ZeroPointClient

    with ZeroPointClient() as zp:
        health = zp.health()
        result = zp.governance.evaluate(
            action="write",
            tool="ironclaw",
            parameters={"file": "/tmp/foo"},
            trust_tier=1,
        )
        if not result.allowed:
            raise SystemExit(f"denied: {result.denial_reason}")

The async surface mirrors the sync surface with awaitable methods; see
:class:`AsyncZeroPointClient`.
"""

from .client import (
    DEFAULT_BASE_URL,
    AsyncZeroPointClient,
    ZeroPointClient,
)
from .exceptions import (
    AuthenticationError,
    ChainError,
    ConnectionError,
    GovernanceError,
    ZeroPointError,
)
from .models import (
    AuditEntry,
    ChainHead,
    EvaluationResult,
    HealthResponse,
    IdentityResponse,
    LaunchResult,
    PolicyRule,
    PreflightCheck,
    PreflightResult,
    Receipt,
    ReceiptAck,
    SecurityPosture,
    StatsResponse,
    StopResult,
    Tool,
    Topology,
    TopologyNode,
    VerifyResult,
    VersionResponse,
    ZpModel,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "DEFAULT_BASE_URL",
    "ZeroPointClient",
    "AsyncZeroPointClient",
    # Exceptions
    "ZeroPointError",
    "ConnectionError",
    "AuthenticationError",
    "GovernanceError",
    "ChainError",
    # Models
    "ZpModel",
    "HealthResponse",
    "VersionResponse",
    "IdentityResponse",
    "StatsResponse",
    "EvaluationResult",
    "PolicyRule",
    "Receipt",
    "ReceiptAck",
    "ChainHead",
    "AuditEntry",
    "VerifyResult",
    "Tool",
    "LaunchResult",
    "StopResult",
    "PreflightCheck",
    "PreflightResult",
    "SecurityPosture",
    "TopologyNode",
    "Topology",
]
