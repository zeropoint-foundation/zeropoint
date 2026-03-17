"""
Configuration loader for ZeroPoint Network Sentinel.

Reads TOML configuration files and provides a unified config interface.
Uses tomli (Python 3.11 backport) for TOML parsing.
"""

import logging
import os
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    import tomllib
except ImportError:
    import tomli as tomllib

logger = logging.getLogger(__name__)


@dataclass
class DNSConfig:
    """DNS monitoring configuration."""
    log_path: str
    blocklist_urls: List[str]
    blocklist_cache_path: str
    rate_limit_qps: int = 100  # Queries per second threshold for anomaly


@dataclass
class DeviceConfig:
    """Device access control configuration."""
    dhcp_lease_file: str
    mac_blocklist: List[str]
    rate_limit_connections_per_minute: int = 10


@dataclass
class AuditConfig:
    """Audit trail configuration."""
    db_path: str
    max_entries_memory: int = 10000


@dataclass
class NotificationConfig:
    """Notification dispatcher configuration."""
    alert_file: str = "/opt/var/zp-sentinel/alerts.log"
    webhook_url: str = ""
    webhook_topic: str = "zp-sentinel"
    webhook_priority: str = "default"
    min_level: str = "medium"  # low, medium, high, critical
    syslog: bool = True
    file: bool = True
    silent: bool = False
    cooldown_seconds: int = 30
    critical_repeat_seconds: int = 300


@dataclass
class MeshConfig:
    """Mesh registration and heartbeat configuration."""
    core_url: str = ""                          # ZeroPoint Core HTTP URL
    core_ws_url: str = ""                       # ZeroPoint Core WebSocket URL
    key_path: str = "/opt/var/zp-sentinel/identity.key"
    component_name: str = "ZP Sentinel"
    heartbeat_interval_sec: int = 30
    heartbeat_threshold: int = 3
    auto_register: bool = True
    protocol_version: str = "0.1.0"
    advertise_address: str = ""
    advertise_port: int = 0


@dataclass
class ServiceConfig:
    """Service-level configuration."""
    pid_file: str = "/opt/var/run/zp-sentinel.pid"
    log_file: str = "/opt/var/log/zp-sentinel.log"
    log_level: str = "INFO"
    monitor_interval: int = 5  # Polling interval in seconds
    zp_server_url: Optional[str] = None  # @deprecated — use [mesh] core_url instead


@dataclass
class Config:
    """Complete sentinel configuration."""
    dns: DNSConfig
    device: DeviceConfig
    audit: AuditConfig
    notifications: NotificationConfig
    mesh: MeshConfig
    service: ServiceConfig

    @staticmethod
    def load(config_path: str) -> "Config":
        """Load configuration from TOML file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")

        logger.info(f"Loading configuration from {config_path}")

        with open(config_path, "rb") as f:
            data = tomllib.load(f)

        # Parse sections
        dns_config = DNSConfig(**data.get("dns", {}))
        device_config = DeviceConfig(**data.get("device", {}))
        audit_config = AuditConfig(**data.get("audit", {}))
        notification_config = NotificationConfig(**data.get("notifications", {}))
        mesh_config = MeshConfig(**data.get("mesh", {}))
        service_config = ServiceConfig(**data.get("service", {}))

        # Create directories if they don't exist
        for path in [
            audit_config.db_path,
            service_config.log_file,
            dns_config.blocklist_cache_path,
            notification_config.alert_file,
        ]:
            directory = os.path.dirname(path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                logger.info(f"Created directory: {directory}")

        config = Config(
            dns=dns_config,
            device=device_config,
            audit=audit_config,
            notifications=notification_config,
            mesh=mesh_config,
            service=service_config,
        )

        logger.info(f"Configuration loaded successfully")
        return config

    def to_dict(self) -> dict:
        """Convert config to dictionary for logging/debugging."""
        return {
            "dns": asdict(self.dns),
            "device": asdict(self.device),
            "audit": asdict(self.audit),
            "service": asdict(self.service),
        }
