"""
ZeroPoint Notification Dispatcher.

Routes governance gate decisions to appropriate notification channels
based on risk level and configuration. The act of notifying is itself
a governed, auditable event in the hash chain.

Channels (progressive):
1. Syslog  — always on by default, writes to router system log
2. File    — always on by default, appends to alerts.log
3. Webhook — opt-in, POST to Ntfy/Pushover/Slack/generic endpoint

Design: "Observable by default" — silent mode is an explicit opt-in,
not the other way around.
"""

import json
import logging
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, List, Callable

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """
    Risk severity tiers.
    Maps gate risk_level float to named tiers for routing.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @staticmethod
    def from_float(risk: float) -> "RiskLevel":
        """Convert 0.0-1.0 risk float to named tier."""
        if risk >= 0.9:
            return RiskLevel.CRITICAL
        elif risk >= 0.7:
            return RiskLevel.HIGH
        elif risk >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def __ge__(self, other):
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return order.index(self) >= order.index(other)

    def __gt__(self, other):
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return order.index(self) > order.index(other)

    def __le__(self, other):
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return order.index(self) <= order.index(other)

    def __lt__(self, other):
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return order.index(self) < order.index(other)


# Risk level labels for display
RISK_ICONS = {
    RiskLevel.LOW: "○",
    RiskLevel.MEDIUM: "◐",
    RiskLevel.HIGH: "●",
    RiskLevel.CRITICAL: "⊘",
}

RISK_TAGS = {
    RiskLevel.LOW: "LOG",
    RiskLevel.MEDIUM: "ALERT",
    RiskLevel.HIGH: "PUSH",
    RiskLevel.CRITICAL: "PUSH+REPEAT",
}


@dataclass
class NotificationEvent:
    """
    A notification dispatched by the sentinel.

    This is distinct from the audit entry — it records that the
    operator was *told* about something, not just that it happened.
    """
    timestamp: str
    risk_level: RiskLevel
    actor: str
    action: str
    decision: str
    summary: str
    details: Dict
    channels_sent: List[str] = field(default_factory=list)


class NotificationDispatcher:
    """
    Routes gate decisions to notification channels based on risk level.

    Sits between the GovernanceGate evaluation and the audit recording.
    Every notification dispatched is itself recorded in the audit trail
    as a SYSTEM/notification event.
    """

    def __init__(
        self,
        alert_file: str = "/opt/var/zp-sentinel/alerts.log",
        webhook_url: str = "",
        webhook_topic: str = "zp-sentinel",
        webhook_priority: str = "default",
        min_level: str = "medium",
        syslog_enabled: bool = True,
        file_enabled: bool = True,
        silent: bool = False,
        cooldown_seconds: int = 30,
        critical_repeat_seconds: int = 300,
    ):
        """
        Initialize notification dispatcher.

        Args:
            alert_file: Path to alerts log file
            webhook_url: Webhook endpoint URL (empty = disabled)
            webhook_topic: Topic/channel for webhook (Ntfy topic, etc.)
            webhook_priority: Default webhook priority
            min_level: Minimum risk level to trigger any notification
            syslog_enabled: Write to router syslog via logger command
            file_enabled: Append to alert file
            silent: Override — suppress all notifications (explicit opt-in)
            cooldown_seconds: Min seconds between duplicate notifications
            critical_repeat_seconds: Repeat interval for unacked critical alerts
        """
        self.alert_file = alert_file
        self.webhook_url = webhook_url
        self.webhook_topic = webhook_topic
        self.webhook_priority = webhook_priority
        self.min_level = RiskLevel(min_level)
        self.syslog_enabled = syslog_enabled
        self.file_enabled = file_enabled
        self.silent = silent
        self.cooldown_seconds = cooldown_seconds
        self.critical_repeat_seconds = critical_repeat_seconds

        # Deduplication: action -> last notification timestamp
        self._cooldown_tracker: Dict[str, float] = {}

        # Unacked critical alerts for repeat
        self._critical_alerts: Dict[str, NotificationEvent] = {}

        # Stats
        self.notifications_sent = 0
        self.notifications_suppressed = 0

        # Ensure alert directory exists
        Path(alert_file).parent.mkdir(parents=True, exist_ok=True)

        mode = "silent" if silent else f"active (min_level={min_level})"
        logger.info(f"Notification dispatcher initialized: {mode}")

    def notify(
        self,
        actor: str,
        action: str,
        decision: str,
        risk_level: float,
        trust_tier: str,
        details: Dict,
        audit_callback: Optional[Callable] = None,
    ) -> Optional[NotificationEvent]:
        """
        Evaluate whether a gate decision warrants notification,
        and dispatch to appropriate channels.

        Args:
            actor: Event source (DNS, DEVICE, ANOMALY, etc.)
            action: What was evaluated
            decision: Gate decision (allow, block, warn, review)
            risk_level: 0.0-1.0 risk assessment
            trust_tier: Trust classification
            details: Event details dict
            audit_callback: Optional callback to record notification in audit trail

        Returns:
            NotificationEvent if notification was sent, None if suppressed
        """
        if self.silent:
            return None

        risk_tier = RiskLevel.from_float(risk_level)

        # Below minimum threshold — no notification
        if risk_tier < self.min_level:
            return None

        # Cooldown deduplication — don't spam about the same thing
        cooldown_key = f"{actor}:{action}:{decision}"
        now = time.time()

        if cooldown_key in self._cooldown_tracker:
            elapsed = now - self._cooldown_tracker[cooldown_key]
            if elapsed < self.cooldown_seconds:
                self.notifications_suppressed += 1
                return None

        self._cooldown_tracker[cooldown_key] = now

        # Build notification
        summary = self._build_summary(actor, action, decision, risk_tier, details)

        event = NotificationEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_level=risk_tier,
            actor=actor,
            action=action,
            decision=decision,
            summary=summary,
            details=details,
        )

        # Dispatch to channels
        if self.syslog_enabled:
            self._send_syslog(event)
            event.channels_sent.append("syslog")

        if self.file_enabled:
            self._send_file(event)
            event.channels_sent.append("file")

        if self.webhook_url and risk_tier >= RiskLevel.HIGH:
            success = self._send_webhook(event)
            if success:
                event.channels_sent.append("webhook")

        # Track critical alerts for repeat
        if risk_tier == RiskLevel.CRITICAL:
            self._critical_alerts[cooldown_key] = event

        self.notifications_sent += 1

        # Record the notification itself as an audit event
        if audit_callback:
            try:
                audit_callback(
                    actor="SYSTEM",
                    action=f"notification:{actor}:{action}",
                    details={
                        "notification_type": "alert",
                        "risk_level": risk_tier.value,
                        "channels": event.channels_sent,
                        "summary": summary,
                        "original_decision": decision,
                    },
                )
            except Exception as e:
                logger.error(f"Failed to audit notification: {e}")

        logger.info(
            f"Notification sent [{risk_tier.value}] → {event.channels_sent}: {summary}"
        )

        return event

    def check_critical_repeats(self, audit_callback: Optional[Callable] = None):
        """
        Check for unacked critical alerts that need repeat notification.
        Call this periodically from the monitor loop.
        """
        if self.silent or not self._critical_alerts:
            return

        now = time.time()
        for key, event in list(self._critical_alerts.items()):
            elapsed = now - self._cooldown_tracker.get(key, 0)
            if elapsed >= self.critical_repeat_seconds:
                # Resend
                event.summary = f"[REPEAT] {event.summary}"
                if self.syslog_enabled:
                    self._send_syslog(event)
                if self.webhook_url:
                    self._send_webhook(event)
                self._cooldown_tracker[key] = now

                logger.warning(f"Critical alert repeated: {event.summary}")

    def ack_critical(self, action_pattern: str) -> int:
        """
        Acknowledge critical alerts matching a pattern.
        Stops repeat notifications for those alerts.

        Args:
            action_pattern: Substring to match against alert action

        Returns:
            Number of alerts acknowledged
        """
        acked = 0
        for key in list(self._critical_alerts.keys()):
            if action_pattern in key:
                del self._critical_alerts[key]
                acked += 1

        if acked > 0:
            logger.info(f"Acknowledged {acked} critical alert(s) matching '{action_pattern}'")

        return acked

    def _build_summary(
        self,
        actor: str,
        action: str,
        decision: str,
        risk_tier: RiskLevel,
        details: Dict,
    ) -> str:
        """Build human-readable notification summary."""
        icon = RISK_ICONS.get(risk_tier, "?")
        tag = RISK_TAGS.get(risk_tier, "INFO")

        # Build contextual message
        if actor == "DNS":
            if decision == "block":
                msg = f"Blocked DNS query: {action}"
            elif "dga" in str(details.get("type", "")).lower():
                msg = f"Suspicious domain pattern: {action}"
            else:
                msg = f"DNS event: {action} → {decision}"
        elif actor == "DEVICE":
            if "new_device" in str(details.get("type", "")):
                msg = f"New device on network: {action}"
            elif decision == "block":
                msg = f"Blocked device: {action}"
            else:
                msg = f"Device event: {action} → {decision}"
        elif actor == "ANOMALY":
            anomaly_type = details.get("type", "unknown")
            rate = details.get("current_rate", "N/A")
            msg = f"Anomaly detected: {anomaly_type} (rate: {rate})"
        else:
            msg = f"{actor}: {action} → {decision}"

        return f"{icon} [{tag}] {msg}"

    def _send_syslog(self, event: NotificationEvent):
        """Write notification to router syslog via logger command."""
        try:
            # Map risk level to syslog priority
            priority_map = {
                RiskLevel.LOW: "info",
                RiskLevel.MEDIUM: "notice",
                RiskLevel.HIGH: "warning",
                RiskLevel.CRITICAL: "crit",
            }
            priority = priority_map.get(event.risk_level, "info")

            subprocess.run(
                [
                    "logger",
                    "-t", "zp-sentinel",
                    "-p", f"daemon.{priority}",
                    event.summary,
                ],
                timeout=5,
                capture_output=True,
            )
        except FileNotFoundError:
            # logger command not available — fall back to writing syslog directly
            try:
                with open("/tmp/syslog.log", "a") as f:
                    f.write(f"{event.timestamp} zp-sentinel: {event.summary}\n")
            except Exception as e:
                logger.debug(f"Syslog fallback failed: {e}")
        except Exception as e:
            logger.debug(f"Syslog send failed: {e}")

    def _send_file(self, event: NotificationEvent):
        """Append notification to alert file."""
        try:
            line = (
                f"{event.timestamp} | {event.risk_level.value:8s} | "
                f"{event.actor:8s} | {event.decision:8s} | "
                f"{event.summary}\n"
            )

            with open(self.alert_file, "a") as f:
                f.write(line)
        except Exception as e:
            logger.error(f"Failed to write alert file: {e}")

    def _send_webhook(self, event: NotificationEvent) -> bool:
        """
        Send notification via webhook (Ntfy, Pushover, or generic).
        Uses urllib to avoid external dependencies on the router.
        """
        if not self.webhook_url:
            return False

        try:
            # Ntfy format (also works as generic webhook)
            payload = {
                "topic": self.webhook_topic,
                "title": f"ZP Sentinel [{event.risk_level.value.upper()}]",
                "message": event.summary,
                "priority": self._ntfy_priority(event.risk_level),
                "tags": [event.actor.lower(), event.decision],
                "timestamp": event.timestamp,
                "extras": {
                    "action": event.action,
                    "details": event.details,
                },
            }

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status < 300:
                    logger.debug(f"Webhook sent: {resp.status}")
                    return True
                else:
                    logger.warning(f"Webhook returned {resp.status}")
                    return False

        except urllib.error.URLError as e:
            logger.warning(f"Webhook failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return False

    @staticmethod
    def _ntfy_priority(risk: RiskLevel) -> int:
        """Map risk level to Ntfy priority (1-5)."""
        return {
            RiskLevel.LOW: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.HIGH: 4,
            RiskLevel.CRITICAL: 5,
        }.get(risk, 3)

    def get_recent_alerts(self, limit: int = 50) -> List[str]:
        """Read recent alerts from the alert file."""
        try:
            path = Path(self.alert_file)
            if not path.exists():
                return []

            with open(path, "r") as f:
                lines = f.readlines()

            return lines[-limit:]
        except Exception as e:
            logger.error(f"Failed to read alerts: {e}")
            return []

    def get_stats(self) -> Dict:
        """Get notification dispatcher statistics."""
        return {
            "mode": "silent" if self.silent else "active",
            "min_level": self.min_level.value,
            "syslog": self.syslog_enabled,
            "file": self.file_enabled,
            "webhook": bool(self.webhook_url),
            "notifications_sent": self.notifications_sent,
            "notifications_suppressed": self.notifications_suppressed,
            "active_critical_alerts": len(self._critical_alerts),
        }
