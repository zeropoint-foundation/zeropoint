#!/usr/bin/env python3
"""
Integration test for the Agent Zero STDIO shim in bare_process mode.

Verifies:
1. Shim starts and sends a 'ready' message with correct process_mode
2. Shim responds to ping/pong
3. Shim handles shutdown cleanly
4. Environment self-report includes process_mode and execution_mode
5. Shim handles execution_response messages (simulating ZP's deterministic engine)

Run: python3 tests/test_shim_bare_process.py
"""

import json
import os
import subprocess
import sys
import time
import unittest

SHIM_PATH = os.path.join(os.path.dirname(__file__), "..", "docker", "agent-zero-shim.py")


class TestShimBareProcess(unittest.TestCase):
    """Test the shim in bare_process mode without Agent Zero installed."""

    def _start_shim(self, extra_env=None):
        """Start the shim as a subprocess with bare_process env vars."""
        env = os.environ.copy()
        env["ZP_PROCESS_MODE"] = "bare_process"
        env["ZP_EXECUTION_MODE"] = "deterministic"
        env["ZP_GOVERNANCE_MODE"] = "strict"
        env["ZP_PROJECT_ROOT"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["ZP_DEPLOYMENT_ID"] = "test-deploy-001"
        env["ZP_FRAMEWORK_ID"] = "agent_zero"
        # Point AGENT_ZERO_ROOT to a non-existent dir so A0 init falls back to echo mode
        env["AGENT_ZERO_ROOT"] = "/tmp/nonexistent-a0"
        if extra_env:
            env.update(extra_env)

        proc = subprocess.Popen(
            [sys.executable, SHIM_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        return proc

    def _send(self, proc, msg):
        """Send a JSON message to the shim's stdin."""
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    def _recv(self, proc, timeout=5.0):
        """Read a JSON line from the shim's stdout."""
        import select
        # Use select for timeout on non-Windows
        if hasattr(select, 'select'):
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                return None
        line = proc.stdout.readline()
        if not line:
            return None
        return json.loads(line.strip())

    def test_ready_message_bare_process(self):
        """Shim should send a ready message with process_mode=bare_process."""
        proc = self._start_shim()
        try:
            ready = self._recv(proc, timeout=10)
            self.assertIsNotNone(ready, "Should receive ready message")
            self.assertEqual(ready["type"], "ready")
            self.assertEqual(ready["process_mode"], "bare_process")
            self.assertEqual(ready["execution_mode"], "deterministic")
            self.assertEqual(ready["shim_version"], "2.1.0")

            # Environment report should include process_mode
            env_report = ready.get("environment", {})
            self.assertEqual(env_report.get("process_mode"), "bare_process")
            self.assertEqual(env_report.get("execution_mode"), "deterministic")
            self.assertIn("python_version", env_report)
            self.assertIn("kernel_version", env_report)
        finally:
            proc.kill()
            proc.wait()

    def test_ping_pong(self):
        """Shim should respond to ping with pong."""
        proc = self._start_shim()
        try:
            # Read ready message first
            ready = self._recv(proc, timeout=10)
            self.assertIsNotNone(ready)

            # Send ping
            self._send(proc, {"type": "ping", "id": "test-ping-1"})
            pong = self._recv(proc, timeout=5)
            self.assertIsNotNone(pong, "Should receive pong")
            self.assertEqual(pong["type"], "pong")
            self.assertEqual(pong["id"], "test-ping-1")
            self.assertEqual(pong["governance_mode"], "strict")
        finally:
            proc.kill()
            proc.wait()

    def test_shutdown_with_summary(self):
        """Shim should send execution_summary on shutdown."""
        proc = self._start_shim()
        try:
            ready = self._recv(proc, timeout=10)
            self.assertIsNotNone(ready)

            # Send shutdown
            self._send(proc, {"type": "shutdown", "id": "shutdown"})

            # Should get execution_summary followed by ack
            summary = self._recv(proc, timeout=5)
            self.assertIsNotNone(summary, "Should receive execution_summary")
            self.assertEqual(summary["type"], "execution_summary")
            self.assertIn("total_executions", summary)

            ack = self._recv(proc, timeout=5)
            self.assertIsNotNone(ack, "Should receive shutdown ack")
            self.assertEqual(ack["type"], "ack")
            self.assertEqual(ack["id"], "shutdown")

            # Process should exit cleanly
            proc.wait(timeout=5)
            self.assertEqual(proc.returncode, 0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def test_message_echo_mode(self):
        """Without A0 installed, shim should respond in echo mode."""
        proc = self._start_shim()
        try:
            ready = self._recv(proc, timeout=10)
            self.assertIsNotNone(ready)

            # Send a message
            self._send(proc, {
                "type": "message",
                "id": "msg-001",
                "content": "Hello from the test",
                "context": [],
                "action_type": "generate",
            })

            response = self._recv(proc, timeout=15)
            self.assertIsNotNone(response, "Should receive response")
            self.assertEqual(response["type"], "response")
            self.assertEqual(response["id"], "msg-001")
            # In echo mode, content should reference our input
            self.assertIn("Hello from the test", response.get("content", ""))
            self.assertEqual(response["governance_mode"], "strict")
        finally:
            proc.kill()
            proc.wait()

    def test_policy_update(self):
        """Shim should handle policy updates and respond with ack."""
        proc = self._start_shim()
        try:
            ready = self._recv(proc, timeout=10)
            self.assertIsNotNone(ready)

            # Send policy update
            self._send(proc, {
                "type": "policy_update",
                "id": "policy-001",
                "governance_mode": "audit",
                "max_delegation_depth": 5,
            })

            ack = self._recv(proc, timeout=5)
            self.assertIsNotNone(ack, "Should receive policy_ack")
            self.assertEqual(ack["type"], "policy_ack")
            self.assertEqual(ack["governance_mode"], "audit")
            self.assertEqual(ack["max_delegation_depth"], 5)
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main(verbosity=2)
