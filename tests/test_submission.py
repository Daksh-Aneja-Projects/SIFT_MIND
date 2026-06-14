from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from sift_mind.agent.loop import FixtureAgentRunner
from sift_mind.config import load_config
from sift_mind.submission import PROJECT_FILES, REPORT_FILES, collect_project_files, package_demo, scan_for_secrets


class SubmissionPackagingTests(unittest.TestCase):
    def test_package_demo_creates_manifest_and_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            package_dir = Path(tmp) / "package"
            config = load_config(
                case_root="fixture/case",
                output_dir=str(report_dir),
                evidence_chain_path=str(report_dir / "evidence_chain.log"),
                execution_log_path=str(report_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(report_dir / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            preflight_report = Path(tmp) / "sift_preflight_report.json"
            preflight_report.write_text('{"status":"READY"}', encoding="utf-8")
            smoke_report = Path(tmp) / "sift_smoke_report.json"
            smoke_report.write_text('{"status":"OK"}', encoding="utf-8")
            audit_report = Path(tmp) / "production_audit_report.json"
            audit_report.write_text('{"overall_status":"READY_FOR_FIXTURE_DEMO"}', encoding="utf-8")
            model_brief_report = Path(tmp) / "model_case_brief.json"
            model_brief_report.write_text(
                json.dumps(
                    {
                        "status": "OK",
                        "source_policy": "ledger_only_model_brief_not_report_source",
                        "validation": {"status": "PASS", "errors": []},
                        "executive_bullets": [],
                    }
                ),
                encoding="utf-8",
            )
            archive_path = Path(tmp) / "sift_mind_submission.zip"
            manifest = package_demo(
                output_dir=config.output_dir,
                ledger_db_path=config.ledger_db_path,
                evidence_chain_path=config.evidence_chain_path,
                execution_log_path=config.execution_log_path,
                package_dir=str(package_dir),
                preflight_report_path=str(preflight_report),
                smoke_report_path=str(smoke_report),
                audit_report_path=str(audit_report),
                model_brief_report_path=str(model_brief_report),
                archive_path=str(archive_path),
            )
            stale_file = package_dir / "project" / "stale_previous_run.txt"
            stale_file.write_text("old package content", encoding="utf-8")
            manifest = package_demo(
                output_dir=config.output_dir,
                ledger_db_path=config.ledger_db_path,
                evidence_chain_path=config.evidence_chain_path,
                execution_log_path=config.execution_log_path,
                package_dir=str(package_dir),
                preflight_report_path=str(preflight_report),
                smoke_report_path=str(smoke_report),
                audit_report_path=str(audit_report),
                model_brief_report_path=str(model_brief_report),
                archive_path=str(archive_path),
            )
            self.assertEqual(manifest["status"], "OK")
            self.assertEqual(manifest["evidence_verification"]["status"], "VERIFIED")
            self.assertEqual(manifest["redaction_scan"]["status"], "OK")
            self.assertEqual(manifest["missing_project_files"], [])
            self.assertFalse(stale_file.exists())
            self.assertNotIn("stale_previous_run.txt", manifest["project_files"])
            self.assertTrue(manifest["preflight_report"]["included"])
            self.assertTrue(manifest["smoke_report"]["included"])
            self.assertTrue(manifest["audit_report"]["included"])
            self.assertTrue(manifest["model_brief_report"]["included"])
            self.assertTrue(manifest["archive"]["included"])
            self.assertTrue(archive_path.exists())
            self.assertRegex(manifest["archive"]["sha256"], r"^[a-f0-9]{64}$")
            self.assertTrue((package_dir / "submission_manifest.json").exists())
            saved_manifest = json.loads((package_dir / "submission_manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(saved_manifest["archive"]["included"])
            self.assertEqual(saved_manifest["archive"]["verification_check"], "submission_archive_verified")
            self.assertNotIn("sha256", saved_manifest["archive"])
            self.assertTrue(saved_manifest["model_brief_report"]["included"])
            self.assertTrue((package_dir / "sift_preflight_report.json").exists())
            self.assertTrue((package_dir / "sift_smoke_report.json").exists())
            self.assertTrue((package_dir / "production_audit_report.json").exists())
            self.assertTrue((package_dir / "model_case_brief.json").exists())
            for name in REPORT_FILES:
                self.assertTrue((package_dir / name).exists(), name)
                self.assertRegex(manifest["reports"][name]["sha256"], r"^[a-f0-9]{64}$")
            for name in PROJECT_FILES:
                self.assertTrue((package_dir / "project" / name).exists(), name)
                self.assertRegex(manifest["project_files"][name]["sha256"], r"^[a-f0-9]{64}$")
            for name in ["src/sift_mind/run.py", "tests/test_submission.py", ".github/workflows/ci.yml"]:
                self.assertIn(name, manifest["project_files"])
                self.assertTrue((package_dir / "project" / name).exists(), name)
            self.assertIn(".env.example", manifest["project_files"])
            self.assertTrue((package_dir / "project" / ".env.example").exists())
            self.assertIn(".gitignore", manifest["project_files"])
            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
            self.assertIn("submission_manifest.json", names)
            self.assertIn("model_case_brief.json", names)
            self.assertIn("project/.env.example", names)
            self.assertIn("project/case_data/public_sample_manifest.schema.json", names)
            self.assertIn("project/src/sift_mind/run.py", names)
            self.assertFalse(any(Path(name).is_absolute() for name in names))

    def test_collect_project_files_includes_runnable_repo_without_generated_artifacts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        files = collect_project_files(root)

        self.assertIn("pyproject.toml", files)
        self.assertIn("requirements.txt", files)
        self.assertIn(".env.example", files)
        self.assertIn(".gitignore", files)
        self.assertIn(".github/workflows/ci.yml", files)
        self.assertIn("case_data/public_sample_manifest.schema.json", files)
        self.assertIn("src/sift_mind/run.py", files)
        self.assertIn("tests/test_submission.py", files)
        self.assertNotIn(".tmp/submission_package/submission_manifest.json", files)
        self.assertFalse(any("__pycache__" in name for name in files))

    def test_collect_project_files_includes_new_markdown_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "EXTRA.md").write_text("# Extra", encoding="utf-8")
            (root / ".tmp").mkdir()
            (root / ".tmp" / "ignored.md").write_text("# Ignored", encoding="utf-8")

            files = collect_project_files(root)

            self.assertIn("EXTRA.md", files)
            self.assertNotIn(".tmp/ignored.md", files)

    def test_secret_scan_flags_api_keys_without_exposing_full_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.txt"
            fake_key = "sk-test" + "abcdefghijklmnopqrstuvwxyz123456"
            path.write_text(f"SIFT_MIND_CLOUD_API_KEY={fake_key}", encoding="utf-8")
            result = scan_for_secrets([path])
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["findings"][0]["pattern"], "openai_key")
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz", result["findings"][0]["preview"])

    def test_secret_scan_does_not_flag_environment_lookup_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safe.py"
            path.write_text('api_key = os.environ.get("SIFT_MIND_CLOUD_API_KEY", "")', encoding="utf-8")
            result = scan_for_secrets([path])
            self.assertEqual(result["status"], "OK")

    def test_env_example_is_safe_for_redaction_scan(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = scan_for_secrets([root / ".env.example"])
        self.assertEqual(result["status"], "OK")


if __name__ == "__main__":
    unittest.main()
