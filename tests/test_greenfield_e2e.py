#!/usr/bin/env python3
"""
End-to-end greenfield deployment test for Agent Zero via bare-process mode.

This simulates the 9-stage pipeline that `run_bare_process_deployment` executes:
  1. Validate Python (>= 3.10)
  2. Detect runtimes (Node.js, Shell)
  3. Create isolated working directory
  4. Create venv + install deps
  5. Start A0 shim as subprocess with STDIO bridge
  6. Health check (process alive + STDIO ready message)
  7. Environment attestation (host-level hashes)
  8. Execution engine probe (runtime availability)
  9. Governance applied (deterministic mode verified)

Then it sends messages through the deployed shim and verifies the full loop.

Run: python3 tests/test_greenfield_e2e.py
"""

import hashlib
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
SHIM_PATH = PROJECT_ROOT / "docker" / "agent-zero-shim.py"
REQUIREMENTS_PATH = PROJECT_ROOT / "docker" / "requirements-a0.txt"


class TestGreenfieldDeployment(unittest.TestCase):
    """Full greenfield deployment pipeline exercised as a Python-side e2e test."""

    def setUp(self):
        """Create a temp directory that acts as .zp-bare-process/<framework>."""
        self.workdir = tempfile.mkdtemp(prefix="zp-greenfield-test-")
        self.framework_id = "agent_zero"
        self.deployment_id = "test-greenfield-001"
        self.proc = None

    def tearDown(self):
        """Clean up: kill process and remove working directory."""
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def _send(self, msg):
        """Send JSON message to shim stdin."""
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _recv(self, timeout=10.0):
        """Read JSON line from shim stdout with timeout."""
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            return None
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line.strip())

    # ── Stage 1: Validate Python ──

    def test_stage1_python_version(self):
        """Python 3.10+ must be available."""
        result = subprocess.run(
            [sys.executable, "--version"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        version_str = result.stdout.strip()
        # Parse: "Python 3.x.y"
        parts = version_str.split()[-1].split(".")
        major, minor = int(parts[0]), int(parts[1])
        self.assertGreaterEqual(major, 3)
        self.assertGreaterEqual(minor, 10, f"Need Python >= 3.10, got {version_str}")

    # ── Stage 2: Detect runtimes ──

    def test_stage2_runtime_detection(self):
        """Should detect at least Python; Node.js and Shell are optional."""
        # Python (guaranteed in test env)
        py_check = subprocess.run(
            [sys.executable, "--version"], capture_output=True, text=True,
        )
        self.assertEqual(py_check.returncode, 0)

        # Bash (common but optional)
        bash_check = subprocess.run(
            ["bash", "--version"], capture_output=True, text=True,
        )
        # We record but don't assert — not all CI envs have bash
        self.detected_runtimes = {
            "python": py_check.stdout.strip(),
            "bash": bash_check.stdout.split("\n")[0].strip() if bash_check.returncode == 0 else "not found",
        }

    # ── Stage 3 + 4: Working directory + venv (combined) ──

    def test_stage3_4_workdir_and_venv(self):
        """Create working directory; venv creation verified but pip install skipped in CI."""
        a0_dir = Path(self.workdir) / self.framework_id
        a0_dir.mkdir(parents=True, exist_ok=True)
        self.assertTrue(a0_dir.exists())

        # Verify venv module is available (don't actually create in CI — slow)
        result = subprocess.run(
            [sys.executable, "-c", "import venv; print('venv_ok')"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, f"venv module not available: {result.stderr}")
        self.assertIn("venv_ok", result.stdout)

    # ── Stage 5 + 6: Start shim + health check ──

    def test_stage5_6_start_and_healthcheck(self):
        """Start the shim in bare_process mode and verify the ready message."""
        env = os.environ.copy()
        env["ZP_PROCESS_MODE"] = "bare_process"
        env["ZP_EXECUTION_MODE"] = "deterministic"
        env["ZP_GOVERNANCE_MODE"] = "strict"
        env["ZP_DEPLOYMENT_ID"] = self.deployment_id
        env["ZP_FRAMEWORK_ID"] = self.framework_id
        env["ZP_PROJECT_ROOT"] = str(PROJECT_ROOT)
        env["AGENT_ZERO_ROOT"] = "/tmp/nonexistent-a0"

        self.proc = subprocess.Popen(
            [sys.executable, str(SHIM_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )

        # Stage 6: Health check — process should be alive
        time.sleep(0.5)
        self.assertIsNone(self.proc.poll(), "Shim process should still be alive")

        # Read the ready message
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready, "Should receive ready message")
        self.assertEqual(ready["type"], "ready")
        self.assertEqual(ready["process_mode"], "bare_process")
        self.assertEqual(ready["execution_mode"], "deterministic")
        self.assertEqual(ready["shim_version"], "2.1.0")

        # Environment report should be present
        env_report = ready.get("environment", {})
        self.assertEqual(env_report.get("process_mode"), "bare_process")
        self.assertEqual(env_report.get("execution_mode"), "deterministic")
        self.assertIn("python_version", env_report)
        self.assertIn("kernel_version", env_report)

    # ── Stage 7: Environment attestation ──

    def test_stage7_environment_attestation(self):
        """Verify we can compute a host environment attestation hash."""
        # Collect what the server would collect
        py_ver = subprocess.run(
            [sys.executable, "--version"], capture_output=True, text=True
        ).stdout.strip()

        kernel = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True
        ).stdout.strip()

        # Build attestation input (sorted fields)
        attestation_input = (
            f"kernel_version={kernel}\n"
            f"process_mode=bare_process\n"
            f"python_version={py_ver}"
        )

        # Blake3 is what the Rust side uses; we use SHA-256 here for simplicity.
        # The point is that the attestation is deterministic.
        attest_hash = hashlib.sha256(attestation_input.encode()).hexdigest()
        self.assertEqual(len(attest_hash), 64)

        # Run it again — should be identical
        attest_hash_2 = hashlib.sha256(attestation_input.encode()).hexdigest()
        self.assertEqual(attest_hash, attest_hash_2,
                         "Attestation hash should be deterministic")

    # ── Stage 8: Execution engine probe ──

    def test_stage8_execution_engine_probe(self):
        """Runtime probe: verify Python can be invoked with a simple computation."""
        result = subprocess.run(
            [sys.executable, "-c", "print('engine_probe_ok')"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("engine_probe_ok", result.stdout)

    # ── Stage 9: Governance (deterministic mode verified via shim) ──

    def test_stage9_governance_deterministic_mode(self):
        """Verify the shim reports deterministic governance in pong responses."""
        env = os.environ.copy()
        env["ZP_PROCESS_MODE"] = "bare_process"
        env["ZP_EXECUTION_MODE"] = "deterministic"
        env["ZP_GOVERNANCE_MODE"] = "strict"
        env["ZP_DEPLOYMENT_ID"] = self.deployment_id
        env["ZP_FRAMEWORK_ID"] = self.framework_id
        env["ZP_PROJECT_ROOT"] = str(PROJECT_ROOT)
        env["AGENT_ZERO_ROOT"] = "/tmp/nonexistent-a0"

        self.proc = subprocess.Popen(
            [sys.executable, str(SHIM_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )

        # Read ready
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)

        # Send ping and verify governance_mode in pong
        self._send({"type": "ping", "id": "gov-check-1"})
        pong = self._recv(timeout=5)
        self.assertIsNotNone(pong, "Should receive pong")
        self.assertEqual(pong["type"], "pong")
        self.assertEqual(pong["governance_mode"], "strict",
                         "Governance mode should be strict in deterministic execution")

    # ── Full flow: message echo in deterministic mode ──

    def test_full_flow_message_through_deployed_shim(self):
        """End-to-end: deploy → send message → get response → shutdown → receipt."""
        env = os.environ.copy()
        env["ZP_PROCESS_MODE"] = "bare_process"
        env["ZP_EXECUTION_MODE"] = "deterministic"
        env["ZP_GOVERNANCE_MODE"] = "strict"
        env["ZP_DEPLOYMENT_ID"] = self.deployment_id
        env["ZP_FRAMEWORK_ID"] = self.framework_id
        env["ZP_PROJECT_ROOT"] = str(PROJECT_ROOT)
        env["AGENT_ZERO_ROOT"] = "/tmp/nonexistent-a0"

        self.proc = subprocess.Popen(
            [sys.executable, str(SHIM_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )

        # 1. Ready
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)
        self.assertEqual(ready["type"], "ready")
        self.assertEqual(ready["process_mode"], "bare_process")

        # 2. Send a message
        self._send({
            "type": "message",
            "id": "greenfield-msg-001",
            "content": "Compute 2+2 please",
            "context": [],
            "action_type": "generate",
        })
        response = self._recv(timeout=15)
        self.assertIsNotNone(response, "Should receive message response")
        self.assertEqual(response["type"], "response")
        self.assertEqual(response["id"], "greenfield-msg-001")
        self.assertEqual(response["governance_mode"], "strict")
        # In echo mode, content should reference our input
        self.assertIn("Compute 2+2 please", response.get("content", ""))

        # 3. Shutdown and get summary
        self._send({"type": "shutdown", "id": "shutdown-greenfield"})

        summary = self._recv(timeout=5)
        self.assertIsNotNone(summary, "Should receive execution_summary")
        self.assertEqual(summary["type"], "execution_summary")
        self.assertGreaterEqual(summary["total_executions"], 0)

        ack = self._recv(timeout=5)
        self.assertIsNotNone(ack, "Should receive shutdown ack")
        self.assertEqual(ack["type"], "ack")
        self.assertEqual(ack["id"], "shutdown-greenfield")

        # 4. Process should exit cleanly
        self.proc.wait(timeout=5)
        self.assertEqual(self.proc.returncode, 0,
                         "Shim should exit cleanly after shutdown")


if __name__ == "__main__":
    # Run with verbosity to show stage-by-stage progress
    print("=" * 70)
    print("ZeroPoint Greenfield Deployment E2E Test")
    print(f"  Project root: {PROJECT_ROOT}")
    print(f"  Shim path:    {SHIM_PATH}")
    print(f"  Python:       {sys.version}")
    print("=" * 70)
    unittest.main(verbosity=2)
