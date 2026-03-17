"""
ZeroPoint Network Sentinel - Main entry point and CLI.

Provides argument parsing, service management, and CLI commands:
- status: show sentinel health
- audit: show recent audit entries
- verify: verify audit chain integrity
- devices: list known devices
- block: block a MAC address
- unblock: unblock a MAC address
- monitor: run continuous monitoring loop
"""

import logging
import logging.handlers
import argparse
import sys
import time
import json
import os
import signal
from typing import Optional

from zp_sentinel.config import Config
from zp_sentinel.gate import GovernanceGate
from zp_sentinel.audit import AuditStore, PolicyDecision
from zp_sentinel.dns_monitor import DNSMonitor
from zp_sentinel.device_monitor import DeviceMonitor
from zp_sentinel.anomaly import AnomalyDetector
from zp_sentinel.notifier import NotificationDispatcher
from zp_sentinel.mesh import MeshClient, MeshConfig as MeshClientConfig

logger = logging.getLogger(__name__)


class Sentinel:
    """Main sentinel service."""

    def __init__(self, config_path: str):
        """Initialize sentinel service."""
        self.config = Config.load(config_path)
        self._setup_logging()

        logger.info("Initializing ZeroPoint Network Sentinel")

        # Initialize audit store
        self.audit_store = AuditStore(self.config.audit.db_path)

        # Initialize notification dispatcher
        nc = self.config.notifications
        self.notifier = NotificationDispatcher(
            alert_file=nc.alert_file,
            webhook_url=nc.webhook_url,
            webhook_topic=nc.webhook_topic,
            webhook_priority=nc.webhook_priority,
            min_level=nc.min_level,
            syslog_enabled=nc.syslog,
            file_enabled=nc.file,
            silent=nc.silent,
            cooldown_seconds=nc.cooldown_seconds,
            critical_repeat_seconds=nc.critical_repeat_seconds,
        )

        # Initialize governance gate (with notifier)
        self.gate = GovernanceGate(self.audit_store, notifier=self.notifier)

        # Initialize monitors
        self.dns_monitor = DNSMonitor(self.config.dns, self.gate)
        self.device_monitor = DeviceMonitor(self.config.device, self.gate)
        self.anomaly_detector = AnomalyDetector(self.gate)

        # Initialize mesh client for trust mesh participation
        mesh_cfg = self.config.mesh
        self.mesh = MeshClient(
            config=MeshClientConfig(
                core_url=mesh_cfg.core_url,
                core_ws_url=mesh_cfg.core_ws_url,
                key_path=mesh_cfg.key_path,
                component_name=mesh_cfg.component_name,
                heartbeat_interval_sec=mesh_cfg.heartbeat_interval_sec,
                heartbeat_threshold=mesh_cfg.heartbeat_threshold,
                auto_register=mesh_cfg.auto_register,
                protocol_version=mesh_cfg.protocol_version,
                advertise_address=mesh_cfg.advertise_address,
                advertise_port=mesh_cfg.advertise_port,
            ),
            stats_provider=self._get_stats_tuple,
        )

        # Auto-register with Core if configured
        if mesh_cfg.auto_register and mesh_cfg.core_url:
            if self.mesh.register():
                self.mesh.start_heartbeat()

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("Sentinel initialized successfully")

    def _setup_logging(self):
        """Setup logging to file and console."""
        log_level = getattr(logging, self.config.service.log_level, logging.INFO)

        # File handler with rotation
        os.makedirs(os.path.dirname(self.config.service.log_file), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            self.config.service.log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        file_handler.setLevel(log_level)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)

        # Formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down")
        self.shutdown()
        sys.exit(0)

    def monitor(self, interval: Optional[int] = None):
        """Run continuous monitoring loop."""
        if interval is None:
            interval = self.config.service.monitor_interval

        logger.info(f"Starting monitoring loop (interval: {interval}s)")

        try:
            while True:
                # Monitor DNS
                dns_count, dns_decisions = self.dns_monitor.monitor_log()
                if dns_count > 0:
                    logger.debug(f"DNS: processed {dns_count} queries")
                    # Check for DNS spike
                    for decision in dns_decisions:
                        self.anomaly_detector.add_dns_query(decision["domain"])
                    self.anomaly_detector.check_dns_spike()

                # Monitor DHCP
                device_count, device_decisions = self.device_monitor.monitor_dhcp()
                if device_count > 0:
                    logger.debug(f"Devices: processed {device_count} leases")
                    # Check for device spike
                    for decision in device_decisions:
                        self.anomaly_detector.add_device_connection(decision["mac_address"])
                    self.anomaly_detector.check_device_spike()

                # Check anomalies
                dns_spike = self.anomaly_detector.check_dns_spike()
                device_spike = self.anomaly_detector.check_device_spike()
                port_scan = self.anomaly_detector.check_port_scan()

                # Check for critical alerts needing repeat
                self.notifier.check_critical_repeats()

                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Monitoring interrupted")
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}", exc_info=True)
        finally:
            self.shutdown()

    def _get_stats_tuple(self):
        """Provide stats to the mesh client for heartbeat reporting."""
        return (
            self.gate.get_stats(),
            self.dns_monitor.get_stats(),
            self.device_monitor.get_stats(),
            self.anomaly_detector.get_stats(),
        )

    def shutdown(self):
        """Shutdown sentinel service."""
        logger.info("Shutting down sentinel")
        self.mesh.stop()
        self.audit_store.close()

    def cmd_status(self):
        """Show sentinel status."""
        stats = {
            "service": {
                "config_file": "loaded",
                "audit_db": self.config.audit.db_path,
                "log_file": self.config.service.log_file,
            },
            "mesh": self.mesh.get_status(),
            "gate": self.gate.get_stats(),
            "notifications": self.notifier.get_stats(),
            "dns_monitor": self.dns_monitor.get_stats(),
            "device_monitor": self.device_monitor.get_stats(),
            "anomaly_detector": self.anomaly_detector.get_stats(),
        }

        print(json.dumps(stats, indent=2))

    def cmd_audit(self, limit: int = 50, actor: Optional[str] = None):
        """Show recent audit entries."""
        if actor:
            entries = self.audit_store.get_by_actor(actor, limit=limit)
            print(f"Recent audit entries from {actor}:")
        else:
            entries = self.audit_store.get_recent(limit=limit)
            print(f"Recent audit entries (last {limit}):")

        for entry in entries:
            details = entry.details
            print(
                f"  [{entry.id}] {entry.timestamp} | {entry.actor} → {entry.policy_decision} | "
                f"{entry.action[:40]} | risk={entry.risk_level:.2f}"
            )

    def cmd_verify(self) -> bool:
        """Verify audit chain integrity."""
        print("Verifying audit chain integrity...")
        is_valid = self.audit_store.verify_chain()

        if is_valid:
            print("✓ Audit chain is valid")
            return True
        else:
            print("✗ Audit chain is BROKEN")
            return False

    def cmd_devices(self):
        """List known devices."""
        devices = self.device_monitor.get_devices()

        print(f"Known devices ({len(devices)}):")
        for device in devices:
            status = "BLOCKED" if device["blocked"] else "allowed"
            print(
                f"  {device['mac_address']} | {device['ip_address']:15} | "
                f"{device['hostname']:20} | {status}"
            )

    def cmd_alerts(self, limit: int = 50):
        """Show recent alert notifications."""
        alerts = self.notifier.get_recent_alerts(limit=limit)

        if not alerts:
            print("No alerts recorded yet.")
            return

        print(f"Recent alerts (last {limit}):")
        for line in alerts:
            print(f"  {line.rstrip()}")

        # Show active critical alerts
        stats = self.notifier.get_stats()
        if stats["active_critical_alerts"] > 0:
            print(f"\n⊘ {stats['active_critical_alerts']} active critical alert(s) — use 'ack <pattern>' to acknowledge")

    def cmd_ack(self, pattern: str):
        """Acknowledge critical alerts matching pattern."""
        count = self.notifier.ack_critical(pattern)

        if count > 0:
            # Record ack in audit trail
            self.audit_store.record(
                actor="MANUAL",
                action=f"ack_alert:{pattern}",
                policy_decision=PolicyDecision.ALLOW,
                risk_level=0.0,
                trust_tier="trusted",
                details={"alerts_acknowledged": count, "pattern": pattern},
            )
            print(f"✓ Acknowledged {count} critical alert(s) matching '{pattern}'")
        else:
            print(f"No active critical alerts matching '{pattern}'")

    def cmd_block(self, mac: str) -> bool:
        """Block a MAC address — audit + notify."""
        success = self.device_monitor.block_mac(mac)

        if success:
            # Record in audit trail
            self.audit_store.record(
                actor="MANUAL",
                action=f"block_mac:{mac}",
                policy_decision=PolicyDecision.BLOCK,
                risk_level=1.0,
                trust_tier="blocked",
                details={"reason": "manual_block"},
            )
            # Notify directly — manual blocks are always high-severity
            self.notifier.notify(
                actor="MANUAL",
                action=f"block_mac:{mac}",
                decision="block",
                risk_level=1.0,
                trust_tier="blocked",
                details={"reason": "manual_block"},
            )
            print(f"✓ MAC blocked: {mac}")
        else:
            print(f"✗ Failed to block MAC: {mac}")

        return success

    def cmd_unblock(self, mac: str) -> bool:
        """Unblock a MAC address — audit + notify."""
        success = self.device_monitor.unblock_mac(mac)

        if success:
            # Record in audit trail
            self.audit_store.record(
                actor="MANUAL",
                action=f"unblock_mac:{mac}",
                policy_decision=PolicyDecision.ALLOW,
                risk_level=0.0,
                trust_tier="trusted",
                details={"reason": "manual_unblock"},
            )
            print(f"✓ MAC unblocked: {mac}")
        else:
            print(f"✗ Failed to unblock MAC: {mac}")

        return success


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ZeroPoint Network Sentinel for ASUS Merlin Routers",
        epilog="Use 'zp-sentinel <command> --help' for command-specific help",
    )

    parser.add_argument(
        "-c",
        "--config",
        default="/opt/etc/zp-sentinel.toml",
        help="Path to configuration file (default: /opt/etc/zp-sentinel.toml)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # status command
    subparsers.add_parser("status", help="Show sentinel status")

    # audit command
    audit_parser = subparsers.add_parser("audit", help="Show audit entries")
    audit_parser.add_argument("-n", "--limit", type=int, default=50, help="Number of entries")
    audit_parser.add_argument("-a", "--actor", help="Filter by actor (DNS/DEVICE/ANOMALY/MANUAL)")

    # verify command
    subparsers.add_parser("verify", help="Verify audit chain integrity")

    # devices command
    subparsers.add_parser("devices", help="List known devices")

    # alerts command
    alerts_parser = subparsers.add_parser("alerts", help="Show recent alert notifications")
    alerts_parser.add_argument("-n", "--limit", type=int, default=50, help="Number of alerts")

    # ack command
    ack_parser = subparsers.add_parser("ack", help="Acknowledge critical alerts")
    ack_parser.add_argument("pattern", help="Pattern to match against alert actions")

    # block command
    block_parser = subparsers.add_parser("block", help="Block a MAC address")
    block_parser.add_argument("mac", help="MAC address to block")

    # unblock command
    unblock_parser = subparsers.add_parser("unblock", help="Unblock a MAC address")
    unblock_parser.add_argument("mac", help="MAC address to unblock")

    # monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Run monitoring loop")
    monitor_parser.add_argument("-i", "--interval", type=int, help="Monitor interval in seconds")

    args = parser.parse_args()

    # Check for config file
    if not os.path.exists(args.config):
        print(f"Error: Configuration file not found: {args.config}")
        sys.exit(1)

    # Initialize sentinel
    sentinel = Sentinel(args.config)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Execute command
    if args.command == "status":
        sentinel.cmd_status()
    elif args.command == "audit":
        sentinel.cmd_audit(limit=args.limit, actor=args.actor)
    elif args.command == "verify":
        is_valid = sentinel.cmd_verify()
        sys.exit(0 if is_valid else 1)
    elif args.command == "alerts":
        sentinel.cmd_alerts(limit=args.limit)
    elif args.command == "ack":
        sentinel.cmd_ack(args.pattern)
    elif args.command == "devices":
        sentinel.cmd_devices()
    elif args.command == "block":
        success = sentinel.cmd_block(args.mac)
        sys.exit(0 if success else 1)
    elif args.command == "unblock":
        success = sentinel.cmd_unblock(args.mac)
        sys.exit(0 if success else 1)
    elif args.command == "monitor":
        sentinel.monitor(interval=args.interval)
    else:
        parser.print_help()
        sys.exit(0)

    sentinel.shutdown()


if __name__ == "__main__":
    main()
