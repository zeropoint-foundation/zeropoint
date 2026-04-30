"""
ZeroPoint Network Sentinel for ASUS Merlin Routers.

A Python-based governance service implementing ZeroPoint's cryptographic primitives
for network access control, DNS governance, and anomaly detection on ASUS Merlin
routers running on ARM 32-bit architecture with Python 3.11 via Entware.

Core Concepts (mapped from Rust ZeroPoint primitives):
- PolicyContext: Decision context with action, trust_tier, channel
- PolicyDecision: Enum of Allow, Block, Warn, Review, Sanitize
- AuditEntry: Hash-chained audit trail with Blake3 hashing
- GateResult: Result of gate evaluation with decision and trust metrics
- Guard: Rate limiting and blocklist enforcement
- GovernanceGate: Orchestrates the decision pipeline

License: ZeroPoint Open Foundation
Author: ZeroPoint Labs
"""

__version__ = "0.1.0"
__author__ = "ZeroPoint Labs"

from zp_sentinel.gate import GovernanceGate, Guard, PolicyEngine, PolicyContext, PolicyDecision
from zp_sentinel.audit import AuditStore, AuditEntry
from zp_sentinel.config import Config

__all__ = [
    "GovernanceGate",
    "Guard",
    "PolicyEngine",
    "PolicyContext",
    "PolicyDecision",
    "AuditStore",
    "AuditEntry",
    "Config",
]
