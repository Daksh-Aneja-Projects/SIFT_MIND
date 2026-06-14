from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from sift_mind.agent.loop import FixtureAgentRunner
from sift_mind.config import load_config
from sift_mind.production_audit import production_audit
from sift_mind.run import main as run_main
from sift_mind.submission import package_demo


class ProductionAuditTests(unittest.TestCase):
    def test_fixture_audit_passes_with_verified_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            package_dir = root / "package"
            config = load_config(
                case_root="fixture/case",
                output_dir=str(report_dir),
                evidence_chain_path=str(report_dir / "evidence_chain.log"),
                execution_log_path=str(report_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(report_dir / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            preflight_report = root / "sift_preflight_report.json"
            preflight_report.write_text('{"status":"READY"}', encoding="utf-8")
            smoke_report = root / "sift_smoke_report.json"
            smoke_report.write_text('{"status":"OK"}', encoding="utf-8")
            audit_report = root / "production_audit_report.json"
            audit_report.write_text('{"overall_status":"READY_FOR_FIXTURE_DEMO"}', encoding="utf-8")
            model_brief_report = root / "model_case_brief.json"
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
            archive_path = root / "sift_mind_submission.zip"
            package_demo(
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

            audit = production_audit(config, package_dir=package_dir, archive_path=archive_path, target="fixture")

            self.assertEqual(audit["overall_status"], "READY_FOR_FIXTURE_DEMO")
            self.assertEqual(audit["blocking_failure_count"], 0)
            checks = {check["id"]: check for check in audit["checks"]}
            self.assertEqual(checks["submission_package_verified"]["status"], "PASS")
            self.assertEqual(checks["submission_package_project_artifacts_complete"]["status"], "PASS")
            self.assertEqual(checks["submission_package_project_artifacts_complete"]["evidence"]["missing_markdown"], [])
            self.assertTrue(checks["submission_package_project_artifacts_complete"]["evidence"]["preflight_report_included"])
            self.assertTrue(checks["submission_package_project_artifacts_complete"]["evidence"]["smoke_report_included"])
            self.assertTrue(checks["submission_package_project_artifacts_complete"]["evidence"]["audit_report_included"])
            self.assertTrue(checks["submission_package_project_artifacts_complete"]["evidence"]["model_brief_report_included"])
            self.assertTrue(checks["submission_package_project_artifacts_complete"]["evidence"]["model_brief_report_status"]["ready"])
            self.assertEqual(checks["markdown_implementation_references_current"]["status"], "PASS")
            self.assertEqual(checks["markdown_requirement_traceability_complete"]["status"], "PASS")
            self.assertEqual(
                checks["markdown_requirement_traceability_complete"]["evidence"]["untraced_markdown_files"],
                [],
            )
            self.assertEqual(checks["mcp_tool_registration_complete"]["status"], "PASS")
            self.assertEqual(checks["evidence_chain_hashes_generated_outputs"]["status"], "PASS")
            self.assertEqual(checks["hardware_aware_model_planning"]["status"], "PASS")
            self.assertEqual(checks["local_hardware_model_plan_present"]["status"], "PASS")
            self.assertEqual(checks["ledger_only_model_briefing"]["status"], "PASS")
            self.assertEqual(checks["submission_archive_verified"]["status"], "PASS")
            self.assertEqual(checks["submission_archive_verified"]["evidence"]["unsafe_entries"], [])

            audit_path = root / "production_audit_report.json"
            with redirect_stdout(StringIO()):
                exit_code = run_main(
                    [
                        "production-audit",
                        "--target",
                        "fixture",
                        "--mode",
                        "fixture",
                        "--output-dir",
                        str(report_dir),
                        "--ledger-db",
                        str(report_dir / "ledger.db"),
                        "--evidence-chain",
                        str(report_dir / "evidence_chain.log"),
                        "--execution-log",
                        str(report_dir / "agent_execution_log.jsonl"),
                        "--package-dir",
                        str(package_dir),
                        "--archive-path",
                        str(archive_path),
                        "--report",
                        str(audit_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            saved_audit = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_audit["overall_status"], "READY_FOR_FIXTURE_DEMO")
            self.assertEqual(saved_audit["report_path"], str(audit_path))

    def test_markdown_requirement_traceability_covers_core_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(
                case_root="fixture/case",
                output_dir=str(root / "out"),
                evidence_chain_path=str(root / "out" / "evidence_chain.log"),
                execution_log_path=str(root / "out" / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "out" / "ledger.db"),
                mode="fixture",
            )

            audit = production_audit(config, target="fixture")

            checks = {check["id"]: check for check in audit["checks"]}
            trace = checks["markdown_requirement_traceability_complete"]["evidence"]
            requirement_ids = {item["id"] for item in trace["requirements"]}
            self.assertEqual(checks["markdown_requirement_traceability_complete"]["status"], "PASS")
            self.assertEqual(trace["untraced_markdown_files"], [])
            self.assertFalse(trace["failing_requirement_ids"])
            self.assertTrue(
                {
                    "typed_mcp_security_boundary",
                    "cryptographic_evidence_chain",
                    "sqlite_epistemic_ledger",
                    "contradiction_hard_blocking",
                    "ledger_only_report_generation",
                    "documented_tool_coverage",
                    "local_ollama_and_cloud_model_path",
                    "submission_package_and_demo_assets",
                }.issubset(requirement_ids)
            )

    def test_fixture_audit_fails_package_artifact_check_without_audit_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            package_dir = root / "package"
            config = load_config(
                case_root="fixture/case",
                output_dir=str(report_dir),
                evidence_chain_path=str(report_dir / "evidence_chain.log"),
                execution_log_path=str(report_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(report_dir / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            preflight_report = root / "sift_preflight_report.json"
            preflight_report.write_text('{"status":"READY"}', encoding="utf-8")
            smoke_report = root / "sift_smoke_report.json"
            smoke_report.write_text('{"status":"OK"}', encoding="utf-8")
            package_demo(
                output_dir=config.output_dir,
                ledger_db_path=config.ledger_db_path,
                evidence_chain_path=config.evidence_chain_path,
                execution_log_path=config.execution_log_path,
                package_dir=str(package_dir),
                preflight_report_path=str(preflight_report),
                smoke_report_path=str(smoke_report),
            )

            audit = production_audit(config, package_dir=package_dir, target="fixture")

            self.assertEqual(audit["overall_status"], "ACTION_REQUIRED")
            checks = {check["id"]: check for check in audit["checks"]}
            artifact_check = checks["submission_package_project_artifacts_complete"]
            self.assertEqual(artifact_check["status"], "FAIL")
            self.assertFalse(artifact_check["evidence"]["audit_report_included"])
            self.assertFalse(artifact_check["evidence"]["audit_report_exists"])

    def test_fixture_audit_fails_package_with_unmanifested_project_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            package_dir = root / "package"
            config = load_config(
                case_root="fixture/case",
                output_dir=str(report_dir),
                evidence_chain_path=str(report_dir / "evidence_chain.log"),
                execution_log_path=str(report_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(report_dir / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            preflight_report = root / "sift_preflight_report.json"
            preflight_report.write_text('{"status":"READY"}', encoding="utf-8")
            smoke_report = root / "sift_smoke_report.json"
            smoke_report.write_text('{"status":"OK"}', encoding="utf-8")
            audit_report = root / "production_audit_report.json"
            audit_report.write_text('{"overall_status":"READY_FOR_FIXTURE_DEMO"}', encoding="utf-8")
            package_demo(
                output_dir=config.output_dir,
                ledger_db_path=config.ledger_db_path,
                evidence_chain_path=config.evidence_chain_path,
                execution_log_path=config.execution_log_path,
                package_dir=str(package_dir),
                preflight_report_path=str(preflight_report),
                smoke_report_path=str(smoke_report),
                audit_report_path=str(audit_report),
            )
            stale_file = package_dir / "project" / "stale_previous_run.txt"
            stale_file.write_text("old package content", encoding="utf-8")

            audit = production_audit(config, package_dir=package_dir, target="fixture")

            self.assertEqual(audit["overall_status"], "ACTION_REQUIRED")
            checks = {check["id"]: check for check in audit["checks"]}
            artifact_check = checks["submission_package_project_artifacts_complete"]
            self.assertEqual(artifact_check["status"], "FAIL")
            self.assertIn("stale_previous_run.txt", artifact_check["evidence"]["unexpected_packaged_project_files"])

    def test_sift_audit_reports_missing_external_environment_as_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            output_dir = root / "out"
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(output_dir / "ledger.db"),
                mode="sift",
            )

            audit = production_audit(config, target="sift")

            self.assertEqual(audit["overall_status"], "ACTION_REQUIRED")
            self.assertGreater(audit["blocking_failure_count"], 0)
            checks = {check["id"]: check for check in audit["checks"]}
            self.assertEqual(checks["sift_runtime_ready"]["status"], "FAIL")
            self.assertIn("host_environment", checks["sift_runtime_ready"]["evidence"])
            self.assertIn("Run inside SIFT VM/WSL", checks["sift_runtime_ready"]["remediation"])


if __name__ == "__main__":
    unittest.main()
