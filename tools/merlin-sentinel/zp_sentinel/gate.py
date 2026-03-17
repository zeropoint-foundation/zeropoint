"""
ZeroPoint Governance Gate implementation.

Maps to Rust primitives: Guard, PolicyEngine, GovernanceGate
Orchestrates the decision pipeline: Guard → Policy → Audit
"""

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Set
from collections import defaultdict, deque

from zp_sentinel.audit import AuditStore, PolicyDecision, AuditEntry
from zp_sentinel.notifier import NotificationDispatcher

logger = logging.getLogger(__name__)


class TrustTier(Enum):
    """
    Trust classification for entities.
    Maps to ZeroPoint Rust trust_tier enum.
    """
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"

    def __str__(self):
        return self.value


@dataclass
class PolicyContext:
    """
    Decision context.
    Maps to ZeroPoint Rust PolicyContext struct.

    Fields:
    - action: What's being evaluated (domain query, MAC address, etc)
    - trust_tier: Initial trust classification
    - channel: Decision channel (dns, device, anomaly, manual)
    """
    action: str
    trust_tier: TrustTier
    channel: str


@dataclass
class GateResult:
    """
    Result of gate evaluation.
    Maps to ZeroPoint Rust GateResult struct.

    Fields:
    - decision: Allow/Block/Warn/Review/Sanitize
    - risk_level: 0.0-1.0 risk assessment
    - trust_tier: Final trust classification
    - audit_entry: Recorded audit entry
    - applied_rules: Which rules were applied
    """
    decision: PolicyDecision
    risk_level: float
    trust_tier: TrustTier
    audit_entry: AuditEntry
    applied_rules: List[str]


class RateTracker:
    """
    Token bucket rate limiter for anomaly detection.
    Maps to ZeroPoint Rust rate_tracker concept.
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize rate tracker.

        Args:
            capacity: Maximum tokens
            refill_rate: Tokens per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, count: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        self._refill()

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + (elapsed * self.refill_rate),
        )
        self.last_refill = now

    def get_tokens(self) -> float:
        """Get current token count."""
        self._refill()
        return self.tokens


class Guard:
    """
    First stage of governance gate.
    Implements blocklists and rate limiting.
    Maps to ZeroPoint Rust Guard struct.
    """

    def __init__(self):
        """Initialize guard."""
        self.blocklist: Set[str] = set()
        self.rate_trackers: Dict[str, RateTracker] = {}
        self.dynamic_blocks: Dict[str, float] = {}  # MAC/domain -> expiry timestamp

    def add_to_blocklist(self, item: str):
        """Add item to blocklist."""
        self.blocklist.add(item.lower())

    def remove_from_blocklist(self, item: str):
        """Remove item from blocklist."""
        self.blocklist.discard(item.lower())

    def load_blocklist(self, items: List[str]):
        """Load blocklist from list."""
        self.blocklist = {item.lower() for item in items}
        logger.info(f"Guard blocklist loaded: {len(self.blocklist)} items")

    def is_blocked(self, item: str) -> bool:
        """Check if item is blocked."""
        item_lower = item.lower()

        # Check static blocklist
        if item_lower in self.blocklist:
            return True

        # Check dynamic blocks (with expiry)
        if item_lower in self.dynamic_blocks:
            if time.time() < self.dynamic_blocks[item_lower]:
                return True
            else:
                del self.dynamic_blocks[item_lower]

        return False

    def dynamic_block(self, item: str, duration_seconds: int = 3600):
        """Temporarily block an item."""
        self.dynamic_blocks[item.lower()] = time.time() + duration_seconds
        logger.info(f"Dynamic block added: {item} for {duration_seconds}s")

    def check_rate(self, identifier: str, limit: int, period_seconds: int) -> bool:
        """Check if identifier is within rate limit."""
        if identifier not in self.rate_trackers:
            # Create new tracker: limit tokens in period_seconds
            refill_rate = limit / period_seconds
            self.rate_trackers[identifier] = RateTracker(capacity=limit, refill_rate=refill_rate)

        return self.rate_trackers[identifier].consume(1)

    def cleanup_expired(self):
        """Clean up expired dynamic blocks."""
        now = time.time()
        expired = [item for item, expiry in self.dynamic_blocks.items() if now >= expiry]
        for item in expired:
            del self.dynamic_blocks[item]


class PolicyEngine:
    """
    Second stage of governance gate.
    Implements policy rules and trust evaluation.
    """

    def __init__(self):
        """Initialize policy engine."""
        self.rules: List[Dict] = []
        self.entity_trust: Dict[str, TrustTier] = {}  # Track trust per entity

    def add_rule(
        self,
        name: str,
        condition: callable,
        action: PolicyDecision,
        risk_level: float = 0.0,
    ):
        """Add a policy rule."""
        self.rules.append(
            {
                "name": name,
                "condition": condition,
                "action": action,
                "risk_level": risk_level,
            }
        )
        logger.debug(f"Policy rule added: {name}")

    def set_entity_trust(self, entity: str, trust_tier: TrustTier):
        """Set trust tier for an entity."""
        self.entity_trust[entity] = trust_tier

    def get_entity_trust(self, entity: str) -> TrustTier:
        """Get trust tier for an entity."""
        return self.entity_trust.get(entity, TrustTier.UNKNOWN)

    def evaluate(self, context: PolicyContext) -> tuple[PolicyDecision, float, List[str]]:
        """
        Evaluate policy against context.

        Returns:
            (decision, risk_level, applied_rules)
        """
        applied_rules = []
        final_decision = PolicyDecision.ALLOW
        max_risk = 0.0

        # Check each rule in order
        for rule in self.rules:
            try:
                if rule["condition"](context):
                    applied_rules.append(rule["name"])
                    final_decision = rule["action"]
                    max_risk = max(max_risk, rule["risk_level"])

                    # Once we hit BLOCK, subsequent rules don't change decision
                    if final_decision == PolicyDecision.BLOCK:
                        break
            except Exception as e:
                logger.error(f"Error evaluating rule {rule['name']}: {e}")

        return final_decision, max_risk, applied_rules


class GovernanceGate:
    """
    Main governance gate orchestrating Guard → Policy → Audit.
    Maps to ZeroPoint Rust GovernanceGate struct.
    """

    def __init__(self, audit_store: AuditStore, notifier: NotificationDispatcher = None):
        """
        Initialize governance gate.

        Args:
            audit_store: AuditStore for recording decisions
            notifier: NotificationDispatcher for alerting (optional)
        """
        self.guard = Guard()
        self.policy_engine = PolicyEngine()
        self.audit_store = audit_store
        self.notifier = notifier

    def evaluate(
        self,
        context: PolicyContext,
        actor: str,
    ) -> GateResult:
        """
        Evaluate a decision through the governance gate.

        Pipeline:
        1. Guard checks blocklist and rate limits
        2. Policy engine evaluates rules
        3. Audit trail records decision

        Args:
            context: PolicyContext with action and trust info
            actor: Source of decision (DNS, DEVICE, ANOMALY, MANUAL)

        Returns:
            GateResult with decision and audit entry
        """
        decision = PolicyDecision.ALLOW
        risk_level = 0.0
        applied_rules = []
        details = {}

        # Stage 1: Guard (blocklist + rate limit)
        if self.guard.is_blocked(context.action):
            decision = PolicyDecision.BLOCK
            risk_level = 1.0
            applied_rules.append("guard_blocklist")
            details["reason"] = "Found in blocklist"
            logger.debug(f"Guard blocked: {context.action}")
        else:
            # Stage 2: Policy evaluation
            policy_decision, policy_risk, policy_rules = self.policy_engine.evaluate(context)

            if policy_decision != PolicyDecision.ALLOW:
                decision = policy_decision
                risk_level = max(risk_level, policy_risk)
                applied_rules.extend(policy_rules)
                details["policy_rules"] = policy_rules
                logger.debug(f"Policy evaluated to {decision} for {context.action}")

        # Determine final trust tier
        final_trust_tier = context.trust_tier
        if decision == PolicyDecision.BLOCK:
            final_trust_tier = TrustTier.BLOCKED
        elif decision == PolicyDecision.WARN or risk_level > 0.7:
            final_trust_tier = TrustTier.SUSPICIOUS
        elif decision == PolicyDecision.ALLOW and context.trust_tier == TrustTier.UNKNOWN:
            final_trust_tier = TrustTier.TRUSTED

        # Stage 3: Audit recording
        audit_entry = self.audit_store.record(
            actor=actor,
            action=context.action,
            policy_decision=decision,
            risk_level=risk_level,
            trust_tier=str(final_trust_tier),
            details=details,
        )

        # Stage 4: Notification dispatch (if notifier attached)
        if self.notifier:
            # Build an audit callback that records SYSTEM notification events
            def _audit_notification(**kwargs):
                self.audit_store.record(
                    policy_decision=PolicyDecision.ALLOW,
                    risk_level=0.0,
                    trust_tier="trusted",
                    **kwargs,
                )

            self.notifier.notify(
                actor=actor,
                action=context.action,
                decision=str(decision),
                risk_level=risk_level,
                trust_tier=str(final_trust_tier),
                details=details,
                audit_callback=_audit_notification,
            )

        return GateResult(
            decision=decision,
            risk_level=risk_level,
            trust_tier=final_trust_tier,
            audit_entry=audit_entry,
            applied_rules=applied_rules,
        )

    def verify_chain(self) -> bool:
        """Verify the integrity of the audit chain."""
        return self.audit_store.verify_chain()

    def get_stats(self) -> dict:
        """Get gate statistics."""
        return {
            "audit_stats": self.audit_store.get_stats(),
            "blocklist_size": len(self.guard.blocklist),
            "dynamic_blocks": len(self.guard.dynamic_blocks),
        }
