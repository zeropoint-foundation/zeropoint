"""Pydantic v2 models for every request and response on the ZP HTTP API.

Models are intentionally permissive: ``model_config = ConfigDict(extra="allow")``
so that server-side fields the SDK doesn't yet know about don't break
deserialization. The same forward-compat principle ZP uses elsewhere —
unknown beads are still readable.

Every model inherits from :class:`ZpModel`, which adds :meth:`to_dict`
and :meth:`to_json` convenience wrappers around Pydantic's
``model_dump`` and ``model_dump_json``.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ZpModel(BaseModel):
    """Base for every SDK model.

    Permissive on extra fields so a newer server can add response keys
    without breaking older SDK clients. Strict on type validation:
    a server returning a string where the SDK expects an int still
    raises ``ValidationError``.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain ``dict`` (Pydantic ``model_dump``)."""
        return self.model_dump(mode="python")

    def to_json(self) -> str:
        """Serialize to a JSON string (Pydantic ``model_dump_json``)."""
        return self.model_dump_json()


# ─────────────────────────────────────────────────────────────────────
# Health / version / identity / stats
# ─────────────────────────────────────────────────────────────────────


class HealthResponse(ZpModel):
    """``GET /api/v1/health`` — server liveness."""

    status: str
    uptime_seconds: Optional[float] = None
    version: Optional[str] = None


class VersionResponse(ZpModel):
    """``GET /api/v1/version`` — build metadata."""

    version: str
    commit: Optional[str] = None
    build: Optional[str] = None


class IdentityResponse(ZpModel):
    """``GET /api/v1/identity`` — operator identity exposed by the server."""

    operator: Optional[str] = None
    operator_public_key: Optional[str] = None
    genesis_public_key: Optional[str] = None
    sovereignty_mode: Optional[str] = None
    trust_tier: Optional[str] = None


class StatsResponse(ZpModel):
    """``GET /api/v1/stats`` — coarse counters from the audit chain."""

    entries_total: Optional[int] = None
    receipts_signed: Optional[int] = None
    tools_governed: Optional[int] = None
    canon_entities: Optional[int] = None


# ─────────────────────────────────────────────────────────────────────
# Governance
# ─────────────────────────────────────────────────────────────────────


class EvaluationResult(ZpModel):
    """Result of ``POST /api/v1/gate/tool-call``.

    The four spec-mandated fields are ``allowed``, ``receipt_id``,
    ``denial_reason``, and ``reversibility``. Anything else the server
    returns lands in the model's extras (still accessible via
    ``model_dump``).
    """

    allowed: bool
    receipt_id: Optional[str] = None
    denial_reason: Optional[str] = None
    reversibility: Optional[str] = None


class PolicyRule(ZpModel):
    """A single policy rule from ``GET /api/v1/policy/rules``."""

    rule_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: bool = True


# ─────────────────────────────────────────────────────────────────────
# Receipts
# ─────────────────────────────────────────────────────────────────────


class Receipt(ZpModel):
    """A signed receipt as returned by ``POST /api/v1/receipts/generate``.

    The server holds the signing key — Python never signs. This model is
    the parsed view of what the server signed.
    """

    id: str
    receipt_type: str = Field(alias="receipt_type")
    content_hash: Optional[str] = None
    signature: Optional[str] = None
    signer_public_key: Optional[str] = None
    parent_receipt_id: Optional[str] = None
    created_at: Optional[str] = None
    claims: Optional[dict[str, Any]] = None


class ReceiptAck(ZpModel):
    """Acknowledgement for ``POST /api/v1/receipts`` (external receipt submission)."""

    accepted: bool
    receipt_id: Optional[str] = None
    entry_hash: Optional[str] = None
    rejection_reason: Optional[str] = None


class ChainHead(ZpModel):
    """``GET /api/v1/audit/chain-head``."""

    entry_hash: str
    sequence: Optional[int] = None
    timestamp: Optional[str] = None


class AuditEntry(ZpModel):
    """One entry from ``GET /api/v1/audit/entries``."""

    entry_hash: str
    prev_hash: Optional[str] = None
    timestamp: str
    actor: Optional[str] = None
    action: Optional[dict[str, Any]] = None
    receipt: Optional[dict[str, Any]] = None


class VerifyResult(ZpModel):
    """``GET /api/v1/audit/verify`` — chain verification report.

    Mirrors ``zp_verify::VerifyReport`` but only the fields the SDK
    typically reads. The full report stays in ``extras`` for callers
    that want it.
    """

    passed: bool
    entries_checked: int = 0
    signature_checks: int = 0
    signature_failures: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    rules_checked: list[str] = Field(default_factory=list)
    chain_head: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────────────


class Tool(ZpModel):
    """A governed tool as listed by ``GET /api/v1/tools``."""

    name: str
    canonicalized: bool = False
    configured: bool = False
    launched: bool = False
    port: Optional[int] = None
    reversibility: Optional[str] = None
    scan_verdict: Optional[str] = None


class LaunchResult(ZpModel):
    """``POST /api/v1/tools/launch`` outcome."""

    name: str
    launched: bool
    port: Optional[int] = None
    pid: Optional[int] = None
    detail: Optional[str] = None


class StopResult(ZpModel):
    """``POST /api/v1/tools/stop`` outcome."""

    name: str
    stopped: bool
    detail: Optional[str] = None


class PreflightCheck(ZpModel):
    """A single check inside :class:`PreflightResult`."""

    check: str
    status: str
    detail: Optional[str] = None


class PreflightResult(ZpModel):
    """``POST /api/v1/tools/{tool}/preflight`` outcome."""

    name: str
    passed: bool
    checks: list[PreflightCheck] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────
# Security
# ─────────────────────────────────────────────────────────────────────


class SecurityPosture(ZpModel):
    """``GET /api/v1/security/posture``."""

    posture: str
    trust_tier: Optional[str] = None
    sovereignty_mode: Optional[str] = None
    auth_required: bool = False
    findings: list[str] = Field(default_factory=list)


class TopologyNode(ZpModel):
    """A node entry inside :class:`Topology`."""

    name: str
    role: Optional[str] = None
    address: Optional[str] = None
    reputation: Optional[float] = None


class Topology(ZpModel):
    """``GET /api/v1/security/topology``."""

    self_node: Optional[TopologyNode] = None
    peers: list[TopologyNode] = Field(default_factory=list)


__all__ = [
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
