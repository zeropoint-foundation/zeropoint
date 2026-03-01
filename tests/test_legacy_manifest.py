#!/usr/bin/env python3
"""
Tests for the Legacy Data Manifest system.

Verifies that brownfield adaptation correctly catalogs, hashes, and seals
all pre-governance data in an Agent Zero installation.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add parent to path for import
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "docker"))

from legacy_data_manifest import (
    LegacyDataManifest, LegacyDataType, SensitivityLevel,
    _classify_path, _classify_sensitivity,
)


class TestPathClassification(unittest.TestCase):
    """Test that A0 paths are classified to the right data types."""

    def test_memory_paths(self):
        self.assertEqual(_classify_path("memory/embeddings.bin"), LegacyDataType.MEMORY)
        self.assertEqual(_classify_path("memory/index.faiss"), LegacyDataType.MEMORY)

    def test_knowledge_paths(self):
        self.assertEqual(_classify_path("knowledge/doc.pdf"), LegacyDataType.KNOWLEDGE)
        self.assertEqual(_classify_path("knowledge/notes.txt"), LegacyDataType.KNOWLEDGE)

    def test_skill_paths(self):
        self.assertEqual(_classify_path("python/tools/code_execution_tool.py"), LegacyDataType.SKILL)
        self.assertEqual(_classify_path("instruments/custom.py"), LegacyDataType.SKILL)

    def test_extension_paths(self):
        self.assertEqual(_classify_path("python/extensions/my_ext.py"), LegacyDataType.EXTENSION)

    def test_artifact_paths(self):
        self.assertEqual(_classify_path("work_dir/output.csv"), LegacyDataType.ARTIFACT)
        self.assertEqual(_classify_path("usr/files/report.docx"), LegacyDataType.ARTIFACT)

    def test_log_paths(self):
        self.assertEqual(_classify_path("logs/session_001.html"), LegacyDataType.LOG)

    def test_config_paths(self):
        self.assertEqual(_classify_path(".env"), LegacyDataType.CONFIG)
        self.assertEqual(_classify_path("prompts/default/agent.system.md"), LegacyDataType.CONFIG)
        self.assertEqual(_classify_path("agents/default.json"), LegacyDataType.CONFIG)

    def test_unknown_paths(self):
        self.assertEqual(_classify_path("random_file.dat"), LegacyDataType.UNKNOWN)


class TestSensitivityClassification(unittest.TestCase):
    """Test that sensitive content is detected."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_env_file_is_critical(self):
        env_file = Path(self.tmpdir) / ".env"
        env_file.write_text("OPENAI_API_KEY=sk-1234")
        level, reason = _classify_sensitivity(env_file, ".env")
        self.assertEqual(level, SensitivityLevel.CRITICAL)

    def test_api_key_in_content(self):
        f = Path(self.tmpdir) / "config.txt"
        f.write_text("my_api_key = sk-proj-abc123")
        level, reason = _classify_sensitivity(f, "config.txt")
        self.assertEqual(level, SensitivityLevel.SENSITIVE)

    def test_normal_file_is_public(self):
        f = Path(self.tmpdir) / "readme.txt"
        f.write_text("This is a normal readme file about the project.")
        level, reason = _classify_sensitivity(f, "readme.txt")
        self.assertEqual(level, SensitivityLevel.PUBLIC)

    def test_memory_is_internal(self):
        f = Path(self.tmpdir) / "embedding.bin"
        f.write_bytes(b"\x00" * 100)
        level, reason = _classify_sensitivity(f, "memory/embedding.bin")
        self.assertEqual(level, SensitivityLevel.INTERNAL)


class TestManifestCreation(unittest.TestCase):
    """Test full manifest creation from a simulated A0 installation."""

    def setUp(self):
        """Create a fake A0 directory structure."""
        self.a0_root = tempfile.mkdtemp(prefix="a0-test-")
        root = Path(self.a0_root)

        # Memories
        (root / "memory").mkdir()
        (root / "memory" / "embeddings.bin").write_bytes(b"\x00" * 256)
        (root / "memory" / "index.json").write_text('{"vectors": 42}')

        # Knowledge
        (root / "knowledge").mkdir()
        (root / "knowledge" / "manual.pdf").write_bytes(b"%PDF-fake")
        (root / "knowledge" / "notes.txt").write_text("Meeting notes from Q3")

        # Skills
        (root / "python" / "tools").mkdir(parents=True)
        (root / "python" / "tools" / "code_execution_tool.py").write_text("def execute(): pass")
        (root / "python" / "tools" / "browser_tool.py").write_text("def browse(): pass")

        # Extensions
        (root / "python" / "extensions").mkdir(parents=True)
        (root / "python" / "extensions" / "custom.py").write_text("# Custom extension")

        # Artifacts
        (root / "work_dir").mkdir()
        (root / "work_dir" / "output.csv").write_text("a,b,c\n1,2,3")
        (root / "work_dir" / "report.html").write_text("<h1>Report</h1>")

        # Logs
        (root / "logs").mkdir()
        (root / "logs" / "session_001.html").write_text("<html>session log</html>")

        # Config
        (root / "prompts" / "default").mkdir(parents=True)
        (root / "prompts" / "default" / "agent.system.md").write_text("# System Prompt")
        (root / ".env").write_text("OPENAI_API_KEY=sk-test-12345\nANTHROPIC_API_KEY=sk-ant-test")

    def tearDown(self):
        shutil.rmtree(self.a0_root)

    def test_manifest_creation(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        self.assertGreater(manifest.summary.total_items, 0)
        self.assertEqual(manifest.provenance, "pre-governance")
        self.assertTrue(manifest.manifest_id.startswith("legacy-"))

    def test_item_counts_by_type(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        s = manifest.summary
        self.assertEqual(s.memory_count, 2)
        self.assertEqual(s.skill_count, 2)
        self.assertEqual(s.artifact_count, 2)
        self.assertGreater(s.items_by_type.get("config", 0), 0)
        self.assertGreater(s.items_by_type.get("knowledge", 0), 0)

    def test_env_file_detected(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        self.assertTrue(manifest.summary.has_env_file)
        self.assertTrue(manifest.summary.has_credentials)

    def test_all_items_have_provenance(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        for item in manifest.items:
            self.assertEqual(item["provenance"], "pre-governance")

    def test_all_items_have_hashes(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        for item in manifest.items:
            self.assertNotEqual(item["content_hash"], "")
            self.assertEqual(len(item["content_hash"]), 64)  # SHA-256

    def test_seal_and_verify(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        self.assertFalse(manifest.sealed)

        manifest.seal()
        self.assertTrue(manifest.sealed)
        self.assertNotEqual(manifest.manifest_hash, "")
        self.assertTrue(manifest.verify())

    def test_seal_is_deterministic(self):
        m1 = LegacyDataManifest.from_a0_root(self.a0_root)
        m1.seal()
        m2 = LegacyDataManifest.from_a0_root(self.a0_root)
        # Use same manifest_id and created_at for determinism
        m2.manifest_id = m1.manifest_id
        m2.created_at = m1.created_at
        m2.seal()
        self.assertEqual(m1.manifest_hash, m2.manifest_hash)

    def test_tamper_detection(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        manifest.seal()
        self.assertTrue(manifest.verify())

        # Tamper with the items
        manifest.items.append({"path": "injected.txt", "content_hash": "fake", "data_type": "unknown"})
        self.assertFalse(manifest.verify())

    def test_write_and_load(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        manifest.seal()

        output_path = os.path.join(self.a0_root, ".zeropoint", "legacy-manifest.json")
        manifest.write(output_path)
        self.assertTrue(os.path.exists(output_path))

        loaded = LegacyDataManifest.load(output_path)
        self.assertEqual(loaded.manifest_id, manifest.manifest_id)
        self.assertEqual(loaded.manifest_hash, manifest.manifest_hash)
        self.assertTrue(loaded.verify())

    def test_query_by_type(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        memories = manifest.items_by_type(LegacyDataType.MEMORY)
        self.assertEqual(len(memories), 2)

    def test_query_sensitive_items(self):
        manifest = LegacyDataManifest.from_a0_root(self.a0_root)
        sensitive = manifest.sensitive_items()
        # .env should be critical
        self.assertGreater(len(sensitive), 0)
        env_item = next((i for i in sensitive if i["path"] == ".env"), None)
        self.assertIsNotNone(env_item)
        self.assertEqual(env_item["sensitivity"], "critical")


if __name__ == "__main__":
    print("=" * 60)
    print("Legacy Data Manifest Tests")
    print("=" * 60)
    unittest.main(verbosity=2)
