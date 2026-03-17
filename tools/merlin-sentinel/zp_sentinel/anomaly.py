"""
Traffic anomaly detection and analysis.

Monitors for unusual patterns:
- DNS query spikes
- New unknown devices
- Port scan attempts
- Unusual traffic patterns

Evaluates anomalies through the governance gate and logs warnings.
"""

import logging
import time
from typing import List, Dict, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass

from zp_sentinel.gate import GovernanceGate, PolicyContext, TrustTier, PolicyDecision

logger = logging.getLogger(__name__)


@dataclass
class TimeWindow:
    """Sliding time window for rate tracking."""
    window_size_seconds: int
    max_events: int

    def __post_init__(self):
        self.events: deque = deque()

    def add_event(self, timestamp: float):
        """Add event to window."""
        now = time.time()
        # Remove events outside window
        while self.events and (now - self.events[0]) > self.window_size_seconds:
            self.events.popleft()
        self.events.append(now)

    def event_count(self) -> int:
        """Get event count in window."""
        now = time.time()
        # Clean up old events
        while self.events and (now - self.events[0]) > self.window_size_seconds:
            self.events.popleft()
        return len(self.events)

    def is_exceeded(self) -> bool:
        """Check if event count exceeds threshold."""
        return self.event_count() >= self.max_events


class AnomalyDetector:
    """
    Detects traffic anomalies and evaluates them through governance gate.
    """

    def __init__(self, gate: GovernanceGate):
        """
        Initialize anomaly detector.

        Args:
            gate: GovernanceGate for policy evaluation
        """
        self.gate = gate

        # Tracking windows
        self.dns_query_window = TimeWindow(window_size_seconds=60, max_events=200)
        self.device_connection_window = TimeWindow(window_size_seconds=300, max_events=10)
        self.port_scan_window = TimeWindow(window_size_seconds=60, max_events=20)

        # Historical data
        self.dns_query_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )  # domain -> timestamps
        self.new_devices: deque = deque(maxlen=100)  # Recently seen new devices
        self.port_scans: deque = deque(maxlen=100)  # Potential port scans

        # Stats
        self.alerts_raised = 0

    def check_dns_spike(self) -> Optional[Dict]:
        """
        Check for DNS query spike anomaly.

        Returns:
            Anomaly dict if spike detected, None otherwise
        """
        current_rate = self.dns_query_window.event_count()

        # Spike if we have > 200 queries per minute
        if current_rate > 200:
            alert = {
                "type": "dns_spike",
                "severity": "high",
                "current_rate": current_rate,
                "threshold": 200,
                "timestamp": time.time(),
            }

            self._evaluate_anomaly(alert, "DNS query spike detected")
            return alert

        return None

    def check_device_spike(self) -> Optional[Dict]:
        """
        Check for rapid device connection anomaly.

        Returns:
            Anomaly dict if spike detected, None otherwise
        """
        current_rate = self.device_connection_window.event_count()

        # Spike if we have > 10 new devices in 5 minutes
        if current_rate > 10:
            alert = {
                "type": "device_spike",
                "severity": "high",
                "current_rate": current_rate,
                "threshold": 10,
                "timestamp": time.time(),
            }

            self._evaluate_anomaly(alert, "Device connection spike detected")
            return alert

        return None

    def check_port_scan(self) -> Optional[Dict]:
        """
        Check for potential port scan anomaly.

        Returns:
            Anomaly dict if scan detected, None otherwise
        """
        current_rate = self.port_scan_window.event_count()

        # Potential scan if > 20 connection attempts per minute
        if current_rate > 20:
            alert = {
                "type": "port_scan",
                "severity": "medium",
                "current_rate": current_rate,
                "threshold": 20,
                "timestamp": time.time(),
            }

            self._evaluate_anomaly(alert, "Potential port scan detected")
            return alert

        return None

    def check_domain_entropy(self, domains: List[str]) -> Optional[Dict]:
        """
        Check for high-entropy domain queries (potential DGA detection).

        Args:
            domains: List of recently queried domains

        Returns:
            Anomaly dict if high entropy detected, None otherwise
        """
        if not domains or len(domains) < 10:
            return None

        # Calculate entropy of domain names
        unique_first_chars = len(set(d[0] for d in domains if d))
        unique_tlds = len(set(d.split(".")[-1] for d in domains))

        entropy_score = (unique_first_chars + unique_tlds) / len(domains)

        # High entropy threshold: 0.8 (most domains have similar prefixes and TLDs)
        if entropy_score > 0.8:
            alert = {
                "type": "high_entropy_domains",
                "severity": "medium",
                "entropy_score": entropy_score,
                "threshold": 0.8,
                "sample_domains": domains[:5],
                "timestamp": time.time(),
            }

            self._evaluate_anomaly(
                alert, f"High-entropy domain queries detected (entropy: {entropy_score:.2f})"
            )
            return alert

        return None

    def check_external_recursion(self, queries: List[Dict]) -> Optional[Dict]:
        """
        Check for recursive queries from external sources (potential DNS amplification).

        Args:
            queries: List of query dicts with source_ip

        Returns:
            Anomaly dict if external recursion detected, None otherwise
        """
        external_count = sum(
            1 for q in queries if not self._is_local_ip(q.get("source_ip", ""))
        )

        if external_count > 0 and len(queries) > 0:
            ratio = external_count / len(queries)

            if ratio > 0.1:  # More than 10% from external
                alert = {
                    "type": "external_recursion",
                    "severity": "high",
                    "external_ratio": ratio,
                    "external_count": external_count,
                    "threshold_ratio": 0.1,
                    "timestamp": time.time(),
                }

                self._evaluate_anomaly(
                    alert, f"External DNS recursion detected ({ratio:.1%})"
                )
                return alert

        return None

    def add_dns_query(self, domain: str):
        """Record DNS query for analysis."""
        self.dns_query_window.add_event(time.time())
        self.dns_query_history[domain].append(time.time())

    def add_device_connection(self, mac: str):
        """Record device connection for analysis."""
        self.device_connection_window.add_event(time.time())
        self.new_devices.append((mac, time.time()))

    def add_port_scan_attempt(self, source_ip: str):
        """Record potential port scan attempt for analysis."""
        self.port_scan_window.add_event(time.time())
        self.port_scans.append((source_ip, time.time()))

    def _evaluate_anomaly(self, alert: Dict, description: str):
        """Evaluate anomaly through governance gate."""
        try:
            action = f"{alert['type']}:{alert.get('current_rate', 'N/A')}"

            context = PolicyContext(
                action=action,
                trust_tier=TrustTier.SUSPICIOUS,
                channel="anomaly",
            )

            gate_result = self.gate.evaluate(context, actor="ANOMALY")

            logger.warning(
                f"Anomaly detected: {description} "
                f"→ {gate_result.decision} (risk: {gate_result.risk_level:.2f})"
            )

            self.alerts_raised += 1

        except Exception as e:
            logger.error(f"Error evaluating anomaly: {e}")

    @staticmethod
    def _is_local_ip(ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            octets = list(map(int, ip.split(".")))
            if len(octets) != 4:
                return False

            # Check private ranges
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            if octets[0] == 127:  # loopback
                return True

            return False
        except Exception:
            return False

    def get_stats(self) -> Dict:
        """Get anomaly detector statistics."""
        return {
            "alerts_raised": self.alerts_raised,
            "dns_query_rate": self.dns_query_window.event_count(),
            "device_connection_rate": self.device_connection_window.event_count(),
            "port_scan_rate": self.port_scan_window.event_count(),
            "tracked_domains": len(self.dns_query_history),
        }
