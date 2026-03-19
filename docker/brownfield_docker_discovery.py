"""
Brownfield Docker Discovery — Agent Zero Detection Module

Scans the host environment for Agent Zero installations (containerized or bare-process)
and reports them as governed AI tool surfaces for the `zp secure` wizard.

Detection strategies:
  1. Docker: inspect running containers for A0 image names, entrypoints, and env vars
  2. Bare-process: scan filesystem for agent-zero project directories
  3. Port: check if A0's default web UI port (50080) is in use
  4. ZP deployment: check for existing .zp-bare-process/agent_zero/deployment.json

Each detected instance is returned as an AiToolSurface with metadata for the
Adaptation Wizard's Phase 1 (Discovery) → Phase 2 (Survey/Classification).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class DetectionSource(Enum):
    """How the Agent Zero instance was discovered."""
    DOCKER_CONTAINER = "docker_container"
    BARE_PROCESS = "bare_process"
    FILESYSTEM = "filesystem"
    NETWORK_PORT = "network_port"
    ZP_DEPLOYMENT = "zp_deployment"


class GovernanceState(Enum):
    """Current governance posture of the detected instance."""
    UNMANAGED = "unmanaged"        # No ZP governance at all
    PERMISSIVE = "permissive"      # ZP present but not enforcing
    AUDIT = "audit"                # Logging but not blocking
    STRICT = "strict"              # Full governance enforced


@dataclass
class AgentZeroInstance:
    """A discovered Agent Zero installation."""
    source: DetectionSource
    instance_id: str
    version: Optional[str] = None
    location: Optional[str] = None           # filesystem path or container ID
    docker_image: Optional[str] = None
    docker_container_id: Optional[str] = None
    docker_container_name: Optional[str] = None
    web_ui_port: Optional[int] = None
    ssh_port: Optional[int] = None
    governance_state: GovernanceState = GovernanceState.UNMANAGED
    deployment_id: Optional[str] = None
    model_providers: list[str] = field(default_factory=list)
    api_keys_detected: list[str] = field(default_factory=list)  # provider names only, never keys
    has_memory_data: bool = False
    has_knowledge_data: bool = False
    risk_factors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source.value,
            "instance_id": self.instance_id,
            "version": self.version,
            "location": self.location,
            "docker_image": self.docker_image,
            "docker_container_id": self.docker_container_id,
            "docker_container_name": self.docker_container_name,
            "web_ui_port": self.web_ui_port,
            "ssh_port": self.ssh_port,
            "governance_state": self.governance_state.value,
            "deployment_id": self.deployment_id,
            "model_providers": self.model_providers,
            "api_keys_detected": self.api_keys_detected,
            "has_memory_data": self.has_memory_data,
            "has_knowledge_data": self.has_knowledge_data,
            "risk_factors": self.risk_factors,
            "metadata": self.metadata,
        }


# ─── Docker fingerprints ────────────────────────────────────────────

# Image names / patterns that indicate Agent Zero
A0_IMAGE_PATTERNS = [
    r"frdel/agent-zero",
    r"agent.?zero",
    r"a0[-_]?docker",
    r"ghcr\.io/.*agent.?zero",
]

# Entrypoint / command patterns
A0_ENTRYPOINT_PATTERNS = [
    r"run_ui\.py",
    r"python.*run_ui",
    r"/a0/",
]

# Environment variables that confirm A0
A0_ENV_MARKERS = [
    "AGENT_ZERO_ROOT",
    "A0_SET_",
    "ZP_FRAMEWORK_ID=agent_zero",
]

# Filesystem markers (for bare-process / local installs)
A0_FS_MARKERS = [
    "run_ui.py",
    "agent.py",
    "initialize.py",
    "models.py",
    "python/helpers/settings.py",
    "conf/model_providers.yaml",
]

# Default ports
A0_DEFAULT_WEB_PORT = 50080
A0_DEFAULT_SSH_PORT = 55022


def discover_all(
    search_paths: Optional[list[str]] = None,
    check_docker: bool = True,
    check_ports: bool = True,
    check_zp_deployments: bool = True,
) -> list[AgentZeroInstance]:
    """
    Run all detection strategies and return deduplicated Agent Zero instances.

    Args:
        search_paths: Filesystem paths to scan for A0 installations.
                      Defaults to common locations.
        check_docker: Whether to inspect running Docker containers.
        check_ports: Whether to probe default A0 ports.
        check_zp_deployments: Whether to check for existing ZP deployment records.

    Returns:
        List of discovered AgentZeroInstance objects.
    """
    instances: list[AgentZeroInstance] = []
    seen_ids: set[str] = set()

    if check_docker and _docker_available():
        for inst in _discover_docker():
            if inst.instance_id not in seen_ids:
                instances.append(inst)
                seen_ids.add(inst.instance_id)

    if search_paths is None:
        search_paths = _default_search_paths()

    for path in search_paths:
        for inst in _discover_filesystem(path):
            if inst.instance_id not in seen_ids:
                instances.append(inst)
                seen_ids.add(inst.instance_id)

    if check_ports:
        for inst in _discover_ports():
            if inst.instance_id not in seen_ids:
                instances.append(inst)
                seen_ids.add(inst.instance_id)

    if check_zp_deployments:
        for inst in _discover_zp_deployments(search_paths):
            if inst.instance_id not in seen_ids:
                instances.append(inst)
                seen_ids.add(inst.instance_id)

    # Enrich instances with risk analysis
    for inst in instances:
        _assess_risk(inst)

    return instances


# ─── Docker detection ────────────────────────────────────────────────

def _docker_available() -> bool:
    """Check if Docker CLI is available and daemon is running."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _discover_docker() -> list[AgentZeroInstance]:
    """Inspect running Docker containers for Agent Zero signatures."""
    instances = []

    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return instances
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return instances

    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            container = json.loads(line)
        except json.JSONDecodeError:
            continue

        image = container.get("Image", "")
        container_id = container.get("ID", "")
        container_name = container.get("Names", "")
        ports_str = container.get("Ports", "")

        # Check image name against known patterns
        is_a0 = any(re.search(pat, image, re.IGNORECASE) for pat in A0_IMAGE_PATTERNS)

        # If image doesn't match, inspect the container for deeper signals
        if not is_a0 and container_id:
            is_a0 = _inspect_container_for_a0(container_id)

        if not is_a0:
            continue

        # Parse port mappings
        web_port = _extract_port(ports_str, 80) or _extract_port(ports_str, A0_DEFAULT_WEB_PORT)
        ssh_port = _extract_port(ports_str, 22) or _extract_port(ports_str, A0_DEFAULT_SSH_PORT)

        inst = AgentZeroInstance(
            source=DetectionSource.DOCKER_CONTAINER,
            instance_id=f"docker:{container_id[:12]}",
            location=f"container:{container_id[:12]}",
            docker_image=image,
            docker_container_id=container_id[:12],
            docker_container_name=container_name,
            web_ui_port=web_port,
            ssh_port=ssh_port,
        )

        # Try to get version from container
        _enrich_from_docker(inst)
        instances.append(inst)

    return instances


def _inspect_container_for_a0(container_id: str) -> bool:
    """Deep inspect a container for A0 signatures (entrypoint, env, workdir)."""
    try:
        result = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return False

        inspect_data = json.loads(result.stdout)
        if not inspect_data:
            return False

        config = inspect_data[0].get("Config", {})

        # Check entrypoint / cmd
        entrypoint = " ".join(config.get("Entrypoint") or [])
        cmd = " ".join(config.get("Cmd") or [])
        combined_cmd = f"{entrypoint} {cmd}"

        if any(re.search(pat, combined_cmd) for pat in A0_ENTRYPOINT_PATTERNS):
            return True

        # Check environment variables
        env_list = config.get("Env") or []
        for env_var in env_list:
            if any(marker in env_var for marker in A0_ENV_MARKERS):
                return True

        # Check working directory
        working_dir = config.get("WorkingDir", "")
        if working_dir in ("/a0", "/agent-zero", "/app/agent-zero"):
            return True

        # Check labels
        labels = config.get("Labels") or {}
        if any("agent-zero" in str(v).lower() or "agent_zero" in str(v).lower()
               for v in labels.values()):
            return True

    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, IndexError):
        pass

    return False


def _enrich_from_docker(inst: AgentZeroInstance):
    """Pull additional metadata from a running A0 container."""
    cid = inst.docker_container_id
    if not cid:
        return

    try:
        # Try to read settings from container
        result = subprocess.run(
            ["docker", "exec", cid, "cat", "/a0/usr/settings.json"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            settings = json.loads(result.stdout)
            _extract_settings_metadata(inst, settings)

        # Try to get version via git
        result = subprocess.run(
            ["docker", "exec", cid, "git", "-C", "/a0", "describe", "--tags", "--always"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            inst.version = result.stdout.strip()

        # Check for .env (detect which providers have keys, never extract keys)
        result = subprocess.run(
            ["docker", "exec", cid, "cat", "/a0/usr/.env"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            _detect_api_key_providers(inst, result.stdout)

        # Check for memory data
        result = subprocess.run(
            ["docker", "exec", cid, "ls", "/a0/memory"],
            capture_output=True, text=True, timeout=5,
        )
        inst.has_memory_data = result.returncode == 0 and bool(result.stdout.strip())

        # Check for knowledge data
        result = subprocess.run(
            ["docker", "exec", cid, "ls", "/a0/knowledge"],
            capture_output=True, text=True, timeout=5,
        )
        inst.has_knowledge_data = result.returncode == 0 and bool(result.stdout.strip())

        # Check for ZP governance state inside the container
        result = subprocess.run(
            ["docker", "exec", cid, "printenv", "ZP_GOVERNANCE_MODE"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            mode = result.stdout.strip().lower()
            try:
                inst.governance_state = GovernanceState(mode)
            except ValueError:
                pass

    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass


# ─── Filesystem detection ────────────────────────────────────────────

def _default_search_paths() -> list[str]:
    """Common locations where Agent Zero might be installed."""
    home = Path.home()
    paths = [
        str(home / "agent-zero"),
        str(home / "projects" / "agent-zero"),
        str(home / "Documents" / "agent-zero"),
        str(home / "Desktop" / "agent-zero"),
        str(home / "Code" / "agent-zero"),
        str(home / "dev" / "agent-zero"),
        str(home / "src" / "agent-zero"),
        "/opt/agent-zero",
    ]
    # Also scan immediate subdirectories of common project folders
    for parent in ["projects", "Code", "dev", "src", "Documents"]:
        parent_path = home / parent
        if parent_path.is_dir():
            try:
                for child in parent_path.iterdir():
                    if child.is_dir() and child.name not in (".", ".."):
                        paths.append(str(child))
            except PermissionError:
                pass

    return paths


def _discover_filesystem(search_path: str) -> list[AgentZeroInstance]:
    """Scan a directory for Agent Zero project markers."""
    instances = []
    path = Path(search_path)

    if not path.is_dir():
        return instances

    # Check if this directory IS an A0 installation
    markers_found = sum(1 for marker in A0_FS_MARKERS if (path / marker).exists())

    if markers_found >= 3:  # need at least 3 markers to be confident
        inst = AgentZeroInstance(
            source=DetectionSource.FILESYSTEM,
            instance_id=f"fs:{path}",
            location=str(path),
        )

        # Read settings if available
        settings_file = path / "usr" / "settings.json"
        if settings_file.exists():
            try:
                settings = json.loads(settings_file.read_text())
                _extract_settings_metadata(inst, settings)
            except (json.JSONDecodeError, IOError):
                pass

        # Check for .env
        env_file = path / "usr" / ".env"
        if env_file.exists():
            try:
                _detect_api_key_providers(inst, env_file.read_text())
            except IOError:
                pass

        # Check for memory/knowledge data
        inst.has_memory_data = (path / "memory").is_dir() and any((path / "memory").iterdir())
        inst.has_knowledge_data = (path / "knowledge").is_dir()

        # Try to get version
        try:
            result = subprocess.run(
                ["git", "-C", str(path), "describe", "--tags", "--always"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                inst.version = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        instances.append(inst)

    return instances


# ─── Port detection ──────────────────────────────────────────────────

def _discover_ports() -> list[AgentZeroInstance]:
    """Check if A0's default ports are in use."""
    instances = []

    for port in [A0_DEFAULT_WEB_PORT, 80, 8080]:
        if _port_in_use("127.0.0.1", port):
            inst = AgentZeroInstance(
                source=DetectionSource.NETWORK_PORT,
                instance_id=f"port:{port}",
                web_ui_port=port,
                metadata={"detection_note": f"Port {port} is in use — may be Agent Zero web UI"},
            )
            instances.append(inst)

    return instances


def _port_in_use(host: str, port: int) -> bool:
    """Check if a TCP port is in use."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex((host, port)) == 0
    except (socket.error, OSError):
        return False


# ─── ZP deployment detection ────────────────────────────────────────

def _discover_zp_deployments(search_paths: list[str]) -> list[AgentZeroInstance]:
    """Check for existing ZP deployment records for Agent Zero."""
    instances = []

    for search_path in search_paths:
        path = Path(search_path)
        # Look for .zp-bare-process/agent_zero/deployment.json
        deployment_file = path / ".zp-bare-process" / "agent_zero" / "deployment.json"
        if not deployment_file.exists():
            # Also check parent directories
            for parent in [path.parent, path.parent.parent]:
                alt = parent / ".zp-bare-process" / "agent_zero" / "deployment.json"
                if alt.exists():
                    deployment_file = alt
                    break

        if deployment_file.exists():
            try:
                deploy = json.loads(deployment_file.read_text())
                governance = deploy.get("governance_mode", "unmanaged")
                try:
                    gov_state = GovernanceState(governance)
                except ValueError:
                    gov_state = GovernanceState.UNMANAGED

                inst = AgentZeroInstance(
                    source=DetectionSource.ZP_DEPLOYMENT,
                    instance_id=f"zp-deploy:{deploy.get('deployment_id', 'unknown')}",
                    deployment_id=deploy.get("deployment_id"),
                    governance_state=gov_state,
                    location=str(deployment_file.parent.parent.parent),
                    metadata={
                        "deployment_type": deploy.get("deployment_type"),
                        "execution_mode": deploy.get("execution_mode"),
                        "runtimes": deploy.get("runtimes", []),
                        "created_at": deploy.get("created_at"),
                    },
                )
                instances.append(inst)
            except (json.JSONDecodeError, IOError):
                pass

    return instances


# ─── Settings and metadata extraction ────────────────────────────────

def _extract_settings_metadata(inst: AgentZeroInstance, settings: dict):
    """Extract model provider info from A0 settings (never extract keys)."""
    providers = set()
    for key in ["chat_model_provider", "util_model_provider",
                "browser_model_provider", "embed_model_provider"]:
        val = settings.get(key)
        if val:
            providers.add(val)
    inst.model_providers = sorted(providers)

    # Store model names for the survey phase
    inst.metadata["models"] = {
        "chat": f"{settings.get('chat_model_provider', '?')}/{settings.get('chat_model_name', '?')}",
        "utility": f"{settings.get('util_model_provider', '?')}/{settings.get('util_model_name', '?')}",
        "browser": f"{settings.get('browser_model_provider', '?')}/{settings.get('browser_model_name', '?')}",
        "embedding": f"{settings.get('embed_model_provider', '?')}/{settings.get('embed_model_name', '?')}",
    }


def _detect_api_key_providers(inst: AgentZeroInstance, env_content: str):
    """Detect which providers have API keys configured (never extract the keys)."""
    providers = []
    for line in env_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"API_KEY_(\w+)\s*=\s*(.+)", line)
        if match:
            provider = match.group(1).lower()
            value = match.group(2).strip().strip("'\"")
            if value and value not in ("None", "NA", ""):
                providers.append(provider)
    inst.api_keys_detected = sorted(providers)


# ─── Risk assessment ─────────────────────────────────────────────────

def _assess_risk(inst: AgentZeroInstance):
    """Evaluate risk factors for a discovered instance."""
    risks = []

    if inst.governance_state == GovernanceState.UNMANAGED:
        risks.append("no_zp_governance")

    if inst.api_keys_detected:
        risks.append(f"api_keys_configured:{','.join(inst.api_keys_detected)}")

    if inst.has_memory_data:
        risks.append("contains_memory_data")

    if inst.ssh_port:
        risks.append("ssh_exposed")

    if inst.web_ui_port and inst.web_ui_port in (80, 8080):
        risks.append("web_ui_on_common_port")

    # Check if running with default/no auth
    if inst.source == DetectionSource.DOCKER_CONTAINER:
        risks.append("docker_execution_surface")

    inst.risk_factors = risks


# ─── Port parsing helper ─────────────────────────────────────────────

def _extract_port(ports_str: str, internal_port: int) -> Optional[int]:
    """Extract host port mapped to a given internal port from Docker ports string."""
    # Docker format: "0.0.0.0:55022->22/tcp, 0.0.0.0:50080->80/tcp"
    pattern = rf"(\d+)->({internal_port})/tcp"
    match = re.search(pattern, ports_str)
    if match:
        return int(match.group(1))
    return None


# ─── CLI entry point ─────────────────────────────────────────────────

def main():
    """Standalone discovery — prints JSON results for the wizard to consume."""
    instances = discover_all()

    output = {
        "framework": "agent_zero",
        "instances_found": len(instances),
        "instances": [inst.to_dict() for inst in instances],
    }

    print(json.dumps(output, indent=2))
    return instances


if __name__ == "__main__":
    main()
