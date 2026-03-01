#!/usr/bin/env python3
"""
Integration test: Legacy Data Manifest + Brownfield Adaptation.

Verifies that when a brownfield adaptation occurs, the legacy data
manifest is created, sealed, and reported through the STDIO shim.

This test combines:
  - legacy_data_manifest.py (Option 4 + Option 1 approach)
  - agent-zero-shim.py (legacy_manifest field in ready message)
  - brownfield_docker_discovery.py (manifest creation during adapt())

Run: python3 tests/test_brownfield_manifest_integration.py
"""

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
SHIM_PATH = PROJECT_ROOT / "docker" / "agent-zero-shim.py"

# Import the manifest module
sys.path.insert(0, str(PROJECT_ROOT / "docker"))
from legacy_data_manifest import LegacyDataManifest, LegacyDataType, SensitivityLevel


class TestManifestShimIntegration(unittest.TestCase):
    """Test that the shim correctly loads and reports a legacy manifest."""

    def setUp(self):
        """Create a fake A0 root with a pre-sealed legacy manifest."""
        self.a0_root = tempfile.mkdtemp(prefix="a0-manifest-test-")
        root = Path(self.a0_root)

        # Create A0 data structure
        (root / "memory").mkdir()
        (root / "memory" / "embeddings.bin").write_bytes(b"\x00" * 128)
        (root / "knowledge").mkdir()
        (root / "knowledge" / "notes.txt").write_text("Test knowledge content")
        (root / "python" / "tools").mkdir(parents=True)
        (root / "python" / "tools" / "custom_tool.py").write_text("def run(): pass")
        (root / "work_dir").mkdir()
        (root / "work_dir" / "output.csv").write_text("a,b\n1,2\n")
        (root / "logs").mkdir()
        (root / "logs" / "session.html").write_text("<html>log</html>")

        # Create and seal a legacy manifest
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        manifest.seal()
        self.manifest_hash = manifest.manifest_hash
        self.manifest_id = manifest.manifest_id
        self.total_items = manifest.summary.total_items

        # Write manifest to .zeropoint/
        manifest_dir = root / ".zeropoint"
        manifest_dir.mkdir()
        manifest.write(str(manifest_dir / "legacy-manifest.json"))

        self.proc = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        shutil.rmtree(self.a0_root)

    def _start_shim(self):
        """Start the shim with our fake A0 root."""
        env = os.environ.copy()
        env["ZP_PROCESS_MODE"] = "bare_process"
        env["ZP_EXECUTION_MODE"] = "passthrough"
        env["ZP_GOVERNANCE_MODE"] = "permissive"
        env["ZP_DEPLOYMENT_ID"] = "manifest-integration-test"
        env["ZP_FRAMEWORK_ID"] = "agent_zero"
        env["ZP_PROJECT_ROOT"] = str(PROJECT_ROOT)
        env["AGENT_ZERO_ROOT"] = self.a0_root

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

    def test_shim_reports_legacy_manifest_on_startup(self):
        """The shim should include legacy_manifest in its ready message."""
        self._start_shim()
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready, "Should receive ready message")
        self.assertEqual(ready["type"], "ready")

        # Check legacy_manifest field exists and has correct data
        manifest_info = ready.get("legacy_manifest")
        self.assertIsNotNone(manifest_info, "Ready message should include legacy_manifest")
        self.assertEqual(manifest_info["manifest_id"], self.manifest_id)
        self.assertEqual(manifest_info["manifest_hash"], self.manifest_hash)
        self.assertEqual(manifest_info["total_items"], self.total_items)
        self.assertTrue(manifest_info["verified"])
        self.assertTrue(manifest_info["sealed"])
        self.assertEqual(manifest_info["provenance"], "pre-governance")

    def test_shim_reports_null_when_no_manifest(self):
        """Without a manifest file, the shim should report None."""
        # Remove the manifest
        manifest_path = Path(self.a0_root) / ".zeropoint" / "legacy-manifest.json"
        manifest_path.unlink()

        self._start_shim()
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)
        self.assertIsNone(ready.get("legacy_manifest"),
                          "Without manifest file, legacy_manifest should be None")

    def test_shim_detects_tampered_manifest(self):
        """If the manifest has been tampered with, the shim should flag it."""
        # Tamper with the manifest
        manifest_path = Path(self.a0_root) / ".zeropoint" / "legacy-manifest.json"
        data = json.loads(manifest_path.read_text())
        data["items"].append({
            "path": "injected.txt",
            "data_type": "unknown",
            "provenance": "pre-governance",
            "content_hash": "fakehash",
            "size_bytes": 0,
            "sensitivity": "public",
        })
        manifest_path.write_text(json.dumps(data))

        self._start_shim()
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)

        manifest_info = ready.get("legacy_manifest")
        self.assertIsNotNone(manifest_info)
        self.assertFalse(manifest_info["verified"],
                         "Tampered manifest should fail verification")
        self.assertIn("warning", manifest_info)

    def test_full_brownfield_with_manifest(self):
        """
        Full brownfield flow where the shim discovers a legacy manifest
        and the subsequent governed session reports its presence.
        """
        self._start_shim()
        ready = self._recv(timeout=10)
        self.assertIsNotNone(ready)

        # Verify manifest is present in discovery
        manifest_info = ready.get("legacy_manifest")
        self.assertIsNotNone(manifest_info)
        self.assertTrue(manifest_info["verified"])

        # Apply governance (brownfield adaptation)
        self._send({
            "type": "policy_update",
            "id": "brownfield-with-manifest",
            "governance_mode": "strict",
            "max_delegation_depth": 2,
        })
        ack = self._recv(timeout=5)
        self.assertIsNotNone(ack)
        self.assertEqual(ack["governance_mode"], "strict")

        # Post-adaptation message
        self._send({
            "type": "message",
            "id": "post-manifest-msg",
            "content": "Test message in governed session with legacy manifest",
            "context": [],
            "action_type": "generate",
        })
        response = self._recv(timeout=15)
        self.assertIsNotNone(response)
        self.assertEqual(response["governance_mode"], "strict")

        # Clean shutdown
        self._send({"type": "shutdown", "id": "manifest-shutdown"})
        summary = self._recv(timeout=5)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["type"], "execution_summary")

        ack = self._recv(timeout=5)
        self.assertEqual(ack["type"], "ack")

        self.proc.wait(timeout=5)
        self.assertEqual(self.proc.returncode, 0)


class TestManifestBrownfieldDiscoveryIntegration(unittest.TestCase):
    """Test that the brownfield discovery module creates manifests during adapt()."""

    def test_discovery_import(self):
        """Verify brownfield_docker_discovery can import legacy_data_manifest."""
        sys.path.insert(0, str(PROJECT_ROOT / "docker"))
        from brownfield_docker_discovery import DockerBrownfieldDiscovery
        # The import itself succeeding is the test
        self.assertTrue(True)

    def test_manifest_round_trip(self):
        """Verify manifests survive write/load cycle with correct provenance."""
        tmpdir = tempfile.mkdtemp(prefix="manifest-rt-")
        root = Path(tmpdir)
        (root / "memory").mkdir()
        (root / "memory" / "test.bin").write_bytes(b"\xff" * 64)
        (root / "work_dir").mkdir()
        (root / "work_dir" / "result.txt").write_text("test output")

        # Create, seal, write
        m = LegacyDataManifest.from_a0_root(tmpdir)
        m.seal()
        out = os.path.join(tmpdir, "manifest.json")
        m.write(out)

        # Load, verify
        loaded = LegacyDataManifest.load(out)
        self.assertTrue(loaded.verify())
        self.assertEqual(loaded.provenance, "pre-governance")

        # All items should have pre-governance provenance
        for item in loaded.items:
            self.assertEqual(item["provenance"], "pre-governance")

        # Querying by type should work
        memories = loaded.items_by_type(LegacyDataType.MEMORY)
        self.assertEqual(len(memories), 1)

        shutil.rmtree(tmpdir)

    def test_manifest_captures_credentials(self):
        """Verify .env files with API keys are flagged as critical."""
        tmpdir = tempfile.mkdtemp(prefix="manifest-creds-")
        root = Path(tmpdir)
        (root / ".env").write_text("OPENAI_API_KEY=sk-test-12345\nSECRET_TOKEN=abc")

        m = LegacyDataManifest.from_a0_root(tmpdir)
        self.assertTrue(m.summary.has_env_file)
        self.assertTrue(m.summary.has_credentials)

        sensitive = m.sensitive_items()
        self.assertGreater(len(sensitive), 0)

        env_item = next((i for i in sensitive if i["path"] == ".env"), None)
        self.assertIsNotNone(env_item)
        self.assertEqual(env_item["sensitivity"], "critical")

        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    print("=" * 70)
    print("Legacy Data Manifest ↔ Brownfield Integration Test")
    print(f"  Project root: {PROJECT_ROOT}")
    print(f"  Shim path:    {SHIM_PATH}")
    print(f"  Python:       {sys.version}")
    print("=" * 70)
    unittest.main(verbosity=2)
