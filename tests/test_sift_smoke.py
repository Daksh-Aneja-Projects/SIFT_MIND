from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from sift_mind.config import load_config
from sift_mind.run import main as run_main
from sift_mind.sift_smoke import SUPPORTED_SMOKE_TOOLS, load_smoke_manifest, run_sift_preflight, run_sift_smoke, smoke_manifest_schema


class SiftSmokeTests(unittest.TestCase):
    def test_fixture_preflight_is_ready_without_real_artifact_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "out"
            manifest_path = root / "manifest.json"
            report_path = output_dir / "sift_preflight_report.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "case_id": "fixture-preflight",
                        "artifacts": {"prefetch": "fixture/Prefetch"},
                        "tools": ["analyze_prefetch"],
                        "required_tools": ["analyze_prefetch"],
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(
                case_root="fixture/case",
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(output_dir / "ledger.db"),
                mode="fixture",
            )

            report = run_sift_preflight(config, manifest_path, report_path)

            self.assertEqual(report["status"], "READY")
            self.assertEqual(report["preflight"]["status"], "READY")
            self.assertTrue(report["preflight"]["artifact_checks"][0]["fixture_virtual"])
            self.assertTrue(report_path.exists())
            self.assertFalse((output_dir / "evidence_chain.log").exists())

    def test_sift_preflight_reports_missing_artifact_and_tool_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            case_root.mkdir()
            output_dir = root / "out"
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "case_id": "sift-preflight",
                        "artifacts": {"prefetch": "Windows/Prefetch"},
                        "tools": ["analyze_prefetch"],
                        "required_tools": ["analyze_prefetch"],
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(output_dir / "ledger.db"),
                mode="sift",
            )

            with patch("sift_mind.runtime.shutil.which", return_value=None):
                report = run_sift_preflight(config, manifest_path)

            self.assertEqual(report["status"], "ACTION_REQUIRED")
            self.assertGreaterEqual(report["preflight"]["error_count"], 2)
            self.assertIn("selected tool unavailable", " ".join(report["preflight"]["errors"]))
            self.assertIn("artifact path does not exist", " ".join(report["preflight"]["errors"]))
            self.assertFalse((output_dir / "evidence_chain.log").exists())

    def test_sift_preflight_refuses_managed_paths_inside_case_root_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            artifact_dir = case_root / "Windows" / "Prefetch"
            artifact_dir.mkdir(parents=True)
            output_dir = case_root / "out"
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "case_id": "unsafe-output-preflight",
                        "artifacts": {"prefetch": "Windows/Prefetch"},
                        "tools": ["analyze_prefetch"],
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(output_dir / "ledger.db"),
                mode="sift",
            )

            with patch("sift_mind.runtime.shutil.which", return_value=str(root / "PECmd.exe")):
                report = run_sift_preflight(config, manifest_path, output_dir / "sift_preflight_report.json")

            self.assertEqual(report["status"], "ACTION_REQUIRED")
            joined_errors = " ".join(report["preflight"]["errors"])
            self.assertIn("OUTPUT_DIR must be outside CASE_ROOT", joined_errors)
            self.assertIn("Preflight report path must be outside CASE_ROOT", report["output_path_error"])
            self.assertFalse(output_dir.exists())

    def test_cli_sift_preflight_does_not_create_unsafe_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            artifact_dir = case_root / "Windows" / "Prefetch"
            artifact_dir.mkdir(parents=True)
            output_dir = case_root / "out"
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "case_id": "unsafe-cli-output",
                        "artifacts": {"prefetch": "Windows/Prefetch"},
                        "tools": ["analyze_prefetch"],
                    }
                ),
                encoding="utf-8",
            )

            with patch("sift_mind.runtime.shutil.which", return_value=str(root / "PECmd.exe")):
                with redirect_stdout(StringIO()):
                    exit_code = run_main(
                        [
                            "sift-preflight",
                            "--mode",
                            "sift",
                            "--case-root",
                            str(case_root),
                            "--manifest",
                            str(manifest_path),
                            "--output-dir",
                            str(output_dir),
                            "--report",
                            str(output_dir / "sift_preflight_report.json"),
                        ]
                    )

            self.assertEqual(exit_code, 1)
            self.assertFalse(output_dir.exists())

    def test_fixture_smoke_manifest_runs_and_verifies_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "out"
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "case_id": "fixture-smoke",
                        "artifacts": {
                            "prefetch": "fixture/Prefetch",
                            "memory": "fixture/memory.raw",
                            "security_evtx": "fixture/Security.evtx",
                            "pcap": "fixture/network.pcap",
                        },
                        "tools": ["analyze_prefetch", "list_processes", "parse_evtx", "parse_pcap_summary"],
                        "required_tools": ["analyze_prefetch", "list_processes"],
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(
                case_root="fixture/case",
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(output_dir / "ledger.db"),
                mode="fixture",
            )

            report = run_sift_smoke(config, manifest_path)

            self.assertEqual(report["status"], "OK")
            self.assertEqual(report["tool_counts"]["OK"], 4)
            self.assertEqual(report["evidence_verification"]["status"], "VERIFIED")
            self.assertEqual(report["evidence_verification"]["execution_records_checked"], 4)
            self.assertTrue((output_dir / "sift_smoke_report.json").exists())

    def test_fixture_smoke_fresh_resets_managed_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "out"
            output_dir.mkdir()
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "case_id": "fresh-smoke",
                        "artifacts": {"prefetch": "fixture/Prefetch"},
                        "tools": ["analyze_prefetch"],
                    }
                ),
                encoding="utf-8",
            )
            (output_dir / "evidence_chain.log").write_text("stale\n", encoding="utf-8")
            (output_dir / "agent_execution_log.jsonl").write_text("stale\n", encoding="utf-8")
            (output_dir / "ledger.db").write_text("stale\n", encoding="utf-8")
            config = load_config(
                case_root="fixture/case",
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(output_dir / "ledger.db"),
                mode="fixture",
            )

            report = run_sift_smoke(config, manifest_path, fresh=True)

            self.assertEqual(report["status"], "OK")
            self.assertEqual(report["evidence_verification"]["records_checked"], 1)
            self.assertNotIn("stale", (output_dir / "evidence_chain.log").read_text(encoding="utf-8"))

    def test_sift_smoke_records_structured_missing_tool_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            case_root.mkdir()
            output_dir = root / "out"
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "case_id": "missing-tool-smoke",
                        "artifacts": {"prefetch": "Windows/Prefetch"},
                        "tools": ["analyze_prefetch"],
                        "required_tools": ["analyze_prefetch"],
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(output_dir / "ledger.db"),
                mode="sift",
            )

            with patch("sift_mind.mcp_server.tools.base.shutil.which", return_value=None):
                report = run_sift_smoke(config, manifest_path)

            self.assertEqual(report["status"], "ERROR")
            self.assertEqual(report["tool_counts"]["ERROR"], 1)
            self.assertIn("unavailable on PATH", report["results"][0]["error"])
            self.assertRegex(report["results"][0]["raw_hash"], r"^[a-f0-9]{64}$")
            self.assertEqual(report["evidence_verification"]["status"], "VERIFIED")

    def test_smoke_manifest_rejects_unknown_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text(
                json.dumps({"tools": ["execute_shell_cmd"], "artifacts": {}}),
                encoding="utf-8",
            )
            with self.assertRaises(ValidationError):
                load_smoke_manifest(manifest_path)

    def test_smoke_manifest_rejects_unknown_top_level_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text(
                json.dumps({"toolz": ["analyze_prefetch"], "artifacts": {}}),
                encoding="utf-8",
            )
            with self.assertRaises(ValidationError):
                load_smoke_manifest(manifest_path)

    def test_manifest_schema_matches_runtime_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        checked_in = json.loads((root / "case_data" / "public_sample_manifest.schema.json").read_text(encoding="utf-8"))
        generated = smoke_manifest_schema()

        self.assertFalse(generated["additionalProperties"])
        self.assertEqual(sorted(SUPPORTED_SMOKE_TOOLS), generated["properties"]["tools"]["items"]["enum"])
        self.assertEqual(generated["properties"]["tools"]["items"]["enum"], checked_in["properties"]["tools"]["items"]["enum"])
        self.assertEqual(generated["x-supported_artifact_keys"], checked_in["x-supported_artifact_keys"])

    def test_cli_manifest_schema_writes_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "schema.json"
            with redirect_stdout(StringIO()):
                exit_code = run_main(["manifest-schema", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            schema = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(schema["title"], "SIFT-MIND Public Sample Smoke Manifest")
            self.assertIn("analyze_prefetch", schema["properties"]["tools"]["items"]["enum"])


if __name__ == "__main__":
    unittest.main()
