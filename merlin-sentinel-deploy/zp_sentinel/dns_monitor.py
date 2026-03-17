"""
DNS query monitoring and governance.

Monitors dnsmasq query logs and evaluates each query through the governance gate.
Blocks queries to domains on the blocklist, allows others.
"""

import logging
import os
import json
from typing import Optional, List, Tuple
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

from zp_sentinel.gate import GovernanceGate, PolicyContext, TrustTier, PolicyDecision
from zp_sentinel.config import DNSConfig

logger = logging.getLogger(__name__)


class BlocklistManager:
    """
    Manages DNS blocklists in Steven Black hosts-style format.
    Downloads and caches blocklists from URLs.
    """

    def __init__(self, config: DNSConfig):
        """
        Initialize blocklist manager.

        Args:
            config: DNSConfig with blocklist URLs and cache path
        """
        self.config = config
        self.blocklist: set = set()
        self._load_blocklist()

    def _load_blocklist(self):
        """Load blocklist from cache or download."""
        cache_file = self.config.blocklist_cache_path

        # Try to load from cache first
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r") as f:
                    self.blocklist = set(line.strip() for line in f if line.strip())
                logger.info(f"Loaded {len(self.blocklist)} entries from blocklist cache")
                return
            except Exception as e:
                logger.warning(f"Failed to load blocklist cache: {e}")

        # Download from URLs
        self._download_blocklists()

    def _download_blocklists(self):
        """Download blocklists from configured URLs."""
        Path(self.config.blocklist_cache_path).parent.mkdir(parents=True, exist_ok=True)

        for url in self.config.blocklist_urls:
            try:
                logger.info(f"Downloading blocklist from {url}")
                response = urlopen(url, timeout=10)
                content = response.read().decode("utf-8")

                # Parse Steven Black hosts format
                for line in content.split("\n"):
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    # Format: 0.0.0.0 domain.com
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1].lower()
                        self.blocklist.add(domain)

            except URLError as e:
                logger.error(f"Failed to download blocklist from {url}: {e}")
            except Exception as e:
                logger.error(f"Error processing blocklist from {url}: {e}")

        # Cache the downloaded blocklist
        try:
            with open(self.config.blocklist_cache_path, "w") as f:
                for domain in sorted(self.blocklist):
                    f.write(f"{domain}\n")
            logger.info(f"Cached {len(self.blocklist)} entries to {self.config.blocklist_cache_path}")
        except Exception as e:
            logger.error(f"Failed to cache blocklist: {e}")

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blocklist."""
        domain_lower = domain.lower()
        if domain_lower in self.blocklist:
            return True

        # Check wildcard subdomains: if example.com is blocked, *.example.com is blocked
        parts = domain_lower.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocklist:
                return True

        return False

    def reload(self):
        """Reload blocklist from URLs."""
        self.blocklist.clear()
        self._download_blocklists()

    def get_stats(self) -> dict:
        """Get blocklist statistics."""
        return {
            "total_entries": len(self.blocklist),
            "cache_file": self.config.blocklist_cache_path,
        }


class DNSQueryLog:
    """
    Parses dnsmasq query log format.
    Format: dnsmasq[pid]: query[protocol] domain from address
    Example: dnsmasq[1234]: query[A] google.com from 192.168.1.100
    """

    @staticmethod
    def parse_line(line: str) -> Optional[Tuple[str, str, str]]:
        """
        Parse a dnsmasq log line.

        Returns:
            (domain, protocol, source_ip) or None if parsing fails
        """
        try:
            # Format: dnsmasq[pid]: query[protocol] domain from address
            if "query[" not in line:
                return None

            # Extract protocol
            protocol_start = line.find("query[") + 6
            protocol_end = line.find("]", protocol_start)
            protocol = line[protocol_start:protocol_end]

            # Extract domain and source
            rest = line[protocol_end + 2:].strip()
            parts = rest.split(" from ")
            if len(parts) != 2:
                return None

            domain = parts[0].strip()
            source_ip = parts[1].strip()

            return (domain, protocol, source_ip)

        except Exception as e:
            logger.debug(f"Failed to parse DNS log line: {e}")
            return None


class DNSMonitor:
    """
    Monitors dnsmasq query log and evaluates queries through governance gate.
    """

    def __init__(self, config: DNSConfig, gate: GovernanceGate):
        """
        Initialize DNS monitor.

        Args:
            config: DNSConfig with log path and rate limits
            gate: GovernanceGate for policy evaluation
        """
        self.config = config
        self.gate = gate
        self.blocklist_manager = BlocklistManager(config)
        self.query_rate_tracker = {}  # domain -> query count
        self.file_position = 0

    def _get_or_create_rate_tracker(self, domain: str) -> int:
        """Get query count for domain."""
        return self.query_rate_tracker.get(domain, 0)

    def _increment_query_count(self, domain: str):
        """Increment query count for domain."""
        self.query_rate_tracker[domain] = self._get_or_create_rate_tracker(domain) + 1

    def monitor_log(self) -> Tuple[int, List[dict]]:
        """
        Monitor dnsmasq log file for new queries.

        Returns:
            (queries_processed, decisions) tuple
        """
        if not os.path.exists(self.config.log_path):
            logger.warning(f"DNS log file not found: {self.config.log_path}")
            return (0, [])

        decisions = []

        try:
            with open(self.config.log_path, "r") as f:
                # Seek to last known position
                if self.file_position > 0:
                    f.seek(self.file_position)

                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parsed = DNSQueryLog.parse_line(line)
                    if not parsed:
                        continue

                    domain, protocol, source_ip = parsed

                    # Evaluate query through gate
                    decision = self._evaluate_query(domain, protocol, source_ip)
                    decisions.append(decision)

                # Save position for next read
                self.file_position = f.tell()

            logger.debug(f"DNS monitor: processed {len(decisions)} queries")
            return (len(decisions), decisions)

        except Exception as e:
            logger.error(f"Error monitoring DNS log: {e}")
            return (0, [])

    def _evaluate_query(self, domain: str, protocol: str, source_ip: str) -> dict:
        """
        Evaluate a DNS query through the governance gate.

        Returns:
            Decision dict with query info and result
        """
        # Check if domain is in blocklist
        is_blocked = self.blocklist_manager.is_blocked(domain)

        # Check query rate
        self._increment_query_count(domain)
        query_count = self._get_or_create_rate_tracker(domain)
        rate_exceeded = query_count > self.config.rate_limit_qps

        # Create policy context
        trust_tier = TrustTier.BLOCKED if is_blocked else TrustTier.TRUSTED
        context = PolicyContext(
            action=domain,
            trust_tier=trust_tier,
            channel="dns",
        )

        # Evaluate through gate
        gate_result = self.gate.evaluate(context, actor="DNS")

        decision = {
            "timestamp": gate_result.audit_entry.timestamp,
            "domain": domain,
            "protocol": protocol,
            "source_ip": source_ip,
            "decision": str(gate_result.decision),
            "is_blocked": is_blocked,
            "rate_exceeded": rate_exceeded,
            "risk_level": gate_result.risk_level,
            "trust_tier": str(gate_result.trust_tier),
            "audit_id": gate_result.audit_entry.id,
        }

        if gate_result.decision == PolicyDecision.BLOCK:
            logger.info(f"DNS block: {domain} (reason: {str(gate_result.applied_rules)})")
        else:
            logger.debug(f"DNS allow: {domain}")

        return decision

    def get_stats(self) -> dict:
        """Get DNS monitor statistics."""
        total_queries = sum(self.query_rate_tracker.values())
        return {
            "total_queries": total_queries,
            "unique_domains": len(self.query_rate_tracker),
            "blocklist": self.blocklist_manager.get_stats(),
        }
