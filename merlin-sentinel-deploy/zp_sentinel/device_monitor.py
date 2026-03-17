"""
Device access control and DHCP lease monitoring.

Monitors DHCP leases and new device connections, evaluates device admission
through the governance gate. Blocks known-bad MAC addresses.
"""

import logging
import os
import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

from zp_sentinel.gate import GovernanceGate, PolicyContext, TrustTier, PolicyDecision
from zp_sentinel.config import DeviceConfig

logger = logging.getLogger(__name__)


@dataclass
class DHCPLease:
    """DHCP lease record."""
    expiry_time: int
    mac_address: str
    ip_address: str
    hostname: str
    client_id: Optional[str] = None


class DHCPLeaseParser:
    """
    Parses dnsmasq/udhcpc DHCP lease files.
    Format: expiry_time mac_address ip_address hostname [client_id]
    """

    @staticmethod
    def parse_file(lease_file: str) -> Dict[str, DHCPLease]:
        """
        Parse DHCP lease file.

        Returns:
            Dict mapping MAC address to DHCPLease
        """
        leases = {}

        if not os.path.exists(lease_file):
            logger.warning(f"DHCP lease file not found: {lease_file}")
            return leases

        try:
            with open(lease_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) < 4:
                        continue

                    try:
                        lease = DHCPLease(
                            expiry_time=int(parts[0]),
                            mac_address=parts[1].lower(),
                            ip_address=parts[2],
                            hostname=parts[3] if parts[3] != "*" else "unknown",
                            client_id=parts[4] if len(parts) > 4 else None,
                        )
                        leases[lease.mac_address] = lease
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse lease line: {line} ({e})")

        except Exception as e:
            logger.error(f"Error reading DHCP lease file: {e}")

        return leases


class DeviceMonitor:
    """
    Monitors device connections and DHCP activity.
    Evaluates device admission through governance gate.
    """

    def __init__(self, config: DeviceConfig, gate: GovernanceGate):
        """
        Initialize device monitor.

        Args:
            config: DeviceConfig with DHCP lease path and MAC blocklist
            gate: GovernanceGate for policy evaluation
        """
        self.config = config
        self.gate = gate
        self.known_devices: Dict[str, Dict] = {}
        self.blocked_macs: set = set()

        # Load initial MAC blocklist from config
        self._load_mac_blocklist()

        # Initialize gate's guard with MAC blocklist
        for mac in self.blocked_macs:
            self.gate.guard.add_to_blocklist(mac)

    def _load_mac_blocklist(self):
        """Load MAC blocklist from config."""
        self.blocked_macs = {mac.lower() for mac in self.config.mac_blocklist}
        logger.info(f"MAC blocklist loaded: {len(self.blocked_macs)} addresses")

    def monitor_dhcp(self) -> Tuple[int, List[dict]]:
        """
        Monitor DHCP leases for new devices.

        Returns:
            (devices_processed, decisions) tuple
        """
        leases = DHCPLeaseParser.parse_file(self.config.dhcp_lease_file)

        decisions = []
        new_devices = []

        for mac, lease in leases.items():
            if mac not in self.known_devices:
                # New device detected
                decision = self._evaluate_device_admission(mac, lease)
                decisions.append(decision)
                new_devices.append(mac)

                # Mark as known
                self.known_devices[mac] = {
                    "lease": lease,
                    "first_seen": datetime.now().isoformat(),
                    "decision": decision,
                }

        if new_devices:
            logger.info(f"Device monitor: detected {len(new_devices)} new device(s)")

        return (len(leases), decisions)

    def _evaluate_device_admission(self, mac: str, lease: DHCPLease) -> dict:
        """
        Evaluate device admission through governance gate.

        Returns:
            Decision dict
        """
        mac_lower = mac.lower()
        is_blocked = mac_lower in self.blocked_macs

        # Determine initial trust tier
        if is_blocked:
            trust_tier = TrustTier.BLOCKED
        else:
            trust_tier = TrustTier.UNKNOWN

        # Create policy context
        action = f"{mac}:{lease.hostname}"
        context = PolicyContext(
            action=action,
            trust_tier=trust_tier,
            channel="device",
        )

        # Evaluate through gate
        gate_result = self.gate.evaluate(context, actor="DEVICE")

        decision = {
            "timestamp": gate_result.audit_entry.timestamp,
            "mac_address": mac,
            "ip_address": lease.ip_address,
            "hostname": lease.hostname,
            "decision": str(gate_result.decision),
            "is_blocked": is_blocked,
            "risk_level": gate_result.risk_level,
            "trust_tier": str(gate_result.trust_tier),
            "audit_id": gate_result.audit_entry.id,
        }

        if gate_result.decision == PolicyDecision.BLOCK:
            logger.warning(f"Device blocked: {mac} ({lease.hostname}) - {lease.ip_address}")
        else:
            logger.info(f"Device admitted: {mac} ({lease.hostname}) - {lease.ip_address}")

        return decision

    def block_mac(self, mac: str) -> bool:
        """
        Block a MAC address.

        Returns:
            True if successfully added to blocklist
        """
        mac_lower = mac.lower()

        if not self._validate_mac(mac):
            logger.error(f"Invalid MAC address: {mac}")
            return False

        if mac_lower in self.blocked_macs:
            logger.warning(f"MAC already blocked: {mac}")
            return False

        self.blocked_macs.add(mac_lower)
        self.gate.guard.add_to_blocklist(mac_lower)

        logger.warning(f"MAC blocked: {mac}")

        return True

    def unblock_mac(self, mac: str) -> bool:
        """
        Unblock a MAC address.

        Returns:
            True if successfully removed from blocklist
        """
        mac_lower = mac.lower()

        if mac_lower not in self.blocked_macs:
            logger.warning(f"MAC not in blocklist: {mac}")
            return False

        self.blocked_macs.discard(mac_lower)
        self.gate.guard.remove_from_blocklist(mac_lower)

        logger.info(f"MAC unblocked: {mac}")

        return True

    @staticmethod
    def _validate_mac(mac: str) -> bool:
        """Validate MAC address format."""
        mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(mac_pattern, mac))

    def get_devices(self) -> List[dict]:
        """Get list of known devices."""
        devices = []

        for mac, device_info in self.known_devices.items():
            lease = device_info["lease"]
            devices.append(
                {
                    "mac_address": mac,
                    "ip_address": lease.ip_address,
                    "hostname": lease.hostname,
                    "blocked": mac.lower() in self.blocked_macs,
                    "first_seen": device_info["first_seen"],
                    "decision": device_info["decision"],
                }
            )

        return sorted(devices, key=lambda x: x["first_seen"], reverse=True)

    def get_stats(self) -> dict:
        """Get device monitor statistics."""
        blocked_count = sum(
            1 for mac in self.known_devices.keys() if mac.lower() in self.blocked_macs
        )

        return {
            "total_known_devices": len(self.known_devices),
            "blocked_devices": blocked_count,
            "allowed_devices": len(self.known_devices) - blocked_count,
            "blocklist_size": len(self.blocked_macs),
        }
