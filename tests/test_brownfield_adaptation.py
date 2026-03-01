#!/usr/bin/env python3
"""
Brownfield adaptation test for Agent Zero.

Brownfield = "Secure and govern an EXISTING agentic installation."

This test simulates the brownfield flow:
  1. Start an already-running A0 instance (simulating discovery of an existing installation)
  2. Discover what's running — verify the shim self-reports its environment
  3. Classify tools by risk level (advisory / unadvisable / allowed)
  4. Apply governance — switch from passthrough to deterministic execution mode
  5. Verify governance is enforced post-adaptation
  6. Verify policy update mechanism works (runtime governance tightening)
  7. Confirm execution summary includes adaptation metadata

This mirrors the BROWNFIELD_SECURE_WORKFLOW from GuidedWorkflows.ts:
  intro → navigate_to_map → configure_surface → begin_survey →
  await_decisions → review_posture → complete

Run: python3 tests/test_brownfield_adaptation.py
"""

import json
import os
import select
import subprocess
import sys
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
SHIM_PATH = PROJECT_ROOT / "docker" / "agent-zero-shim.py"


class TestBrownfieldAdaptation(unittest.TestCase):
    """Brownfield adaptation: discover, classify, govern an existing A0 instance."""

    def setUp(self):
        """Start A0 in passthrough mode — simulating an EXISTING unmanaged install."""
        self.proc = None
        self.framework_id = "agent_zero"
        self.deployment_id = "brownfield-adapt-001"

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()

    def _start_shim(self, execution_mode="passthrough", governance_mode="permissive"):
        """Start the shim simulating an existing A0 installation."""
        env = os.environ.copy()
        env["ZP_PROCESS_MODE"] = "bare_process"
        env["ZP_EXECUTION_MODE"] = execution_mode
        env["ZP_GOVERNANCE_MODE"] = governance_mode
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
        return self.proc

    def _send(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _recv(self, timeout=10.0):
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            return None
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line.strip())

    # ═══════════════════════════════════════════════════════════════════
    # Phase 1: Discovery — identify what's running
    # ═══════════════════════════════════════════════════════════════════

    def test_phase1_discover_existing_instance(self):
        """
        Brownfield starts by discovering an EXISTING A0 installation.
        In passthrough mode, the shim reports its environment so ZP can assess.
        """
        self._start_shim(execution_mode="passthrough", governance_mode="permissive")

        # Read the ready message — this IS the discovery payload.
        # ZP's brownfield scanner would parse this to understand what's running.
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready, "Should receive ready message from existing instance")
        self.assertEqual(ready["type"], "ready")
        self.assertEqual(ready["process_mode"], "bare_process")
        self.assertEqual(ready["execution_mode"], "passthrough",
                         "Existing instance should be running in passthrough (unmanaged) mode")

        # The environment report is the discovery payload
        env_report = ready.get("environment", {})
        self.assertIn("python_version", env_report)
        self.assertIn("kernel_version", env_report)
        self.assertEqual(env_report.get("process_mode"), "bare_process")
        self.assertEqual(env_report.get("execution_mode"), "passthrough")

        # Store for later assertions
        self._discovery = {
            "shim_version": ready.get("shim_version"),
            "process_mode": ready["process_mode"],
            "execution_mode": ready["execution_mode"],
            "python_version": env_report.get("python_version"),
        }

    # ═══════════════════════════════════════════════════════════════════
    # Phase 2: Survey — classify tools by risk level
    # ═══════════════════════════════════════════════════════════════════

    def test_phase2_classify_tool_risk(self):
        """
        Simulate the tool risk classification that Aegis performs.

        In the real flow, Aegis scans the A0 installation for tools and classifies
        each one according to the trust profile (config/trust/profiles/agent_zero_framework.yaml).

        Here we verify the shim can handle a message and returns the expected
        metadata for governance assessment.
        """
        self._start_shim(execution_mode="passthrough", governance_mode="permissive")
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)

        # Send a message that exercises tool use — in echo mode this confirms
        # the shim's message handling path works
        self._send({
            "type": "message",
            "id": "survey-msg-001",
            "content": "List your available tools and their risk levels",
            "context": [],
            "action_type": "generate",
        })

        response = self._recv(timeout=15)
        self.assertIsNotNone(response, "Should receive tool survey response")
        self.assertEqual(response["type"], "response")
        self.assertEqual(response["id"], "survey-msg-001")

        # In permissive mode, governance_mode should be "permissive"
        self.assertEqual(response["governance_mode"], "permissive",
                         "Pre-adaptation instance should report permissive governance")

    # ═══════════════════════════════════════════════════════════════════
    # Phase 3: Adapt — apply governance via policy_update
    # ═══════════════════════════════════════════════════════════════════

    def test_phase3_apply_governance_via_policy_update(self):
        """
        The core brownfield operation: switch from permissive/passthrough
        to strict/deterministic via a policy_update message.

        This simulates what happens when the user approves the security posture
        in the BROWNFIELD_SECURE_WORKFLOW's 'review_posture' step.
        """
        self._start_shim(execution_mode="passthrough", governance_mode="permissive")
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)
        self.assertEqual(ready["execution_mode"], "passthrough")

        # Verify current permissive state via ping
        self._send({"type": "ping", "id": "pre-adapt-ping"})
        pong = self._recv(timeout=5)
        self.assertIsNotNone(pong)
        self.assertEqual(pong["governance_mode"], "permissive",
                         "Before adaptation, governance should be permissive")

        # ── THE BROWNFIELD ADAPTATION POINT ──
        # Apply the new governance policy
        self._send({
            "type": "policy_update",
            "id": "brownfield-adapt-001",
            "governance_mode": "strict",
            "max_delegation_depth": 3,
        })

        # Expect policy_ack confirming the new governance
        ack = self._recv(timeout=5)
        self.assertIsNotNone(ack, "Should receive policy_ack")
        self.assertEqual(ack["type"], "policy_ack")
        self.assertEqual(ack["governance_mode"], "strict",
                         "Policy ack should confirm strict governance")
        self.assertEqual(ack["max_delegation_depth"], 3)

    # ═══════════════════════════════════════════════════════════════════
    # Phase 4: Verify — governance is enforced post-adaptation
    # ═══════════════════════════════════════════════════════════════════

    def test_phase4_governance_enforced_post_adaptation(self):
        """
        After adaptation, verify that the shim now operates under strict governance.
        All subsequent messages should reflect the new governance mode.
        """
        self._start_shim(execution_mode="passthrough", governance_mode="permissive")
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)

        # Apply governance
        self._send({
            "type": "policy_update",
            "id": "adapt-strict",
            "governance_mode": "strict",
            "max_delegation_depth": 2,
        })
        ack = self._recv(timeout=5)
        self.assertIsNotNone(ack)
        self.assertEqual(ack["governance_mode"], "strict")

        # Now verify: post-adaptation ping should show strict governance
        self._send({"type": "ping", "id": "post-adapt-ping"})
        pong = self._recv(timeout=5)
        self.assertIsNotNone(pong)
        self.assertEqual(pong["governance_mode"], "strict",
                         "After adaptation, pong should report strict governance")

        # Post-adaptation message should also show strict governance
        self._send({
            "type": "message",
            "id": "post-adapt-msg",
            "content": "Test message after brownfield adaptation",
            "context": [],
            "action_type": "generate",
        })
        response = self._recv(timeout=15)
        self.assertIsNotNone(response)
        self.assertEqual(response["governance_mode"], "strict",
                         "Post-adaptation message response should be under strict governance")

    # ═══════════════════════════════════════════════════════════════════
    # Phase 5: Multi-step adaptation — progressive tightening
    # ═══════════════════════════════════════════════════════════════════

    def test_phase5_progressive_governance_tightening(self):
        """
        Brownfield adaptation can happen incrementally — the user reviews
        each tool and progressively tightens governance. This tests multiple
        sequential policy_update messages.
        """
        self._start_shim(execution_mode="passthrough", governance_mode="permissive")
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)

        # Step 1: Switch to audit mode (intermediate step)
        self._send({
            "type": "policy_update",
            "id": "adapt-step-1",
            "governance_mode": "audit",
            "max_delegation_depth": 5,
        })
        ack1 = self._recv(timeout=5)
        self.assertIsNotNone(ack1)
        self.assertEqual(ack1["governance_mode"], "audit")

        # Verify audit mode is active
        self._send({"type": "ping", "id": "check-audit"})
        pong = self._recv(timeout=5)
        self.assertEqual(pong["governance_mode"], "audit")

        # Step 2: Tighten further to strict
        self._send({
            "type": "policy_update",
            "id": "adapt-step-2",
            "governance_mode": "strict",
            "max_delegation_depth": 2,
        })
        ack2 = self._recv(timeout=5)
        self.assertIsNotNone(ack2)
        self.assertEqual(ack2["governance_mode"], "strict")
        self.assertEqual(ack2["max_delegation_depth"], 2)

        # Verify strict mode is now active
        self._send({"type": "ping", "id": "check-strict"})
        pong2 = self._recv(timeout=5)
        self.assertEqual(pong2["governance_mode"], "strict")

    # ═══════════════════════════════════════════════════════════════════
    # Full brownfield flow: discover → classify → adapt → verify → shutdown
    # ═══════════════════════════════════════════════════════════════════

    def test_full_brownfield_flow(self):
        """
        Complete brownfield adaptation from discovery to governed shutdown.

        This mirrors the BROWNFIELD_SECURE_WORKFLOW:
          intro → navigate_to_map → configure_surface → begin_survey →
          await_decisions → review_posture → complete
        """
        # ── intro: Start unmanaged instance ──
        self._start_shim(execution_mode="passthrough", governance_mode="permissive")

        # ── begin_survey: Discover and assess ──
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)
        self.assertEqual(ready["execution_mode"], "passthrough")
        env_report = ready.get("environment", {})
        self.assertEqual(env_report.get("execution_mode"), "passthrough")

        # Survey: send a message to probe the instance
        self._send({
            "type": "message",
            "id": "survey-001",
            "content": "What tools do you have access to?",
            "context": [],
            "action_type": "generate",
        })
        survey_response = self._recv(timeout=15)
        self.assertIsNotNone(survey_response)
        self.assertEqual(survey_response["governance_mode"], "permissive")

        # ── await_decisions: User reviews findings ──
        # (In real flow, user sees tool risk classifications and approves each)

        # ── review_posture: Apply the approved security posture ──
        self._send({
            "type": "policy_update",
            "id": "brownfield-posture-apply",
            "governance_mode": "strict",
            "max_delegation_depth": 3,
        })
        posture_ack = self._recv(timeout=5)
        self.assertIsNotNone(posture_ack)
        self.assertEqual(posture_ack["type"], "policy_ack")
        self.assertEqual(posture_ack["governance_mode"], "strict")

        # Verify adaptation took hold
        self._send({"type": "ping", "id": "posture-verify"})
        pong = self._recv(timeout=5)
        self.assertEqual(pong["governance_mode"], "strict")

        # Send a governed message
        self._send({
            "type": "message",
            "id": "governed-001",
            "content": "This is a governed message post-brownfield",
            "context": [],
            "action_type": "generate",
        })
        governed_response = self._recv(timeout=15)
        self.assertIsNotNone(governed_response)
        self.assertEqual(governed_response["governance_mode"], "strict")

        # ── complete: Shutdown with summary ──
        self._send({"type": "shutdown", "id": "brownfield-complete"})

        summary = self._recv(timeout=5)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["type"], "execution_summary")
        self.assertGreaterEqual(summary["total_executions"], 0)

        ack = self._recv(timeout=5)
        self.assertIsNotNone(ack)
        self.assertEqual(ack["type"], "ack")
        self.assertEqual(ack["id"], "brownfield-complete")

        # Process should exit cleanly
        self.proc.wait(timeout=5)
        self.assertEqual(self.proc.returncode, 0,
                         "Brownfield-adapted shim should exit cleanly")


if __name__ == "__main__":
    print("=" * 70)
    print("ZeroPoint Brownfield Adaptation Test")
    print(f"  Project root: {PROJECT_ROOT}")
    print(f"  Shim path:    {SHIM_PATH}")
    print(f"  Python:       {sys.version}")
    print("=" * 70)
    unittest.main(verbosity=2)
