from __future__ import annotations

import tempfile
import unittest
import json
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch

from sift_mind.config import load_config
from sift_mind.contracts import ResponseStatus, ToolResult
from sift_mind.mcp_server.tools.disk import DiskToolWrapper
from sift_mind.mcp_server.tools.logs import LogToolWrapper
from sift_mind.mcp_server.tools.memory import MemoryToolWrapper
from sift_mind.mcp_server.tools.network import NetworkToolWrapper
from sift_mind.mcp_server.tools.timeline import TimelineToolWrapper
from sift_mind.mcp_server.tools.base import ToolWrapper
from sift_mind.mcp_server.tools.parsers import parse_prefetch


class MissingToolWrapper(ToolWrapper):
    def run_missing_tool(self, artifact_path: str):
        return self._external_tool_response(
            tool_name="missing_tool_smoke",
            artifact_path=artifact_path,
            command=["definitely_missing_sift_mind_tool_12345", artifact_path],
            parser=lambda raw: {"raw": raw},
            confidence=0.1,
        )


class GeneratedOutputWrapper(ToolWrapper):
    def run_generated_output(self, artifact_path: str, script_path: Path):
        output_path = self._tool_output_file("generated_output_smoke", ".json")
        return self._external_tool_response(
            tool_name="generated_output_smoke",
            artifact_path=artifact_path,
            command=[sys.executable, str(script_path), str(output_path)],
            parser=parse_prefetch,
            confidence=0.9,
            output_paths=[output_path],
        )

    def run_invalid_generated_output_path(self, artifact_path: str, script_path: Path, output_path: Path):
        return self._external_tool_response(
            tool_name="generated_output_smoke",
            artifact_path=artifact_path,
            command=[sys.executable, str(script_path), str(output_path)],
            parser=parse_prefetch,
            confidence=0.9,
            output_paths=[output_path],
        )


class CandidateToolWrapper(ToolWrapper):
    def run_candidate_tool(self, artifact_path: str):
        return self._external_tool_response(
            tool_name="candidate_smoke",
            artifact_path=artifact_path,
            command=["missing-primary-tool", artifact_path],
            parser=lambda raw: {"raw": raw},
            confidence=0.5,
            executable_candidates=["available-secondary-tool"],
        )


class ToolWrapperTests(unittest.TestCase):
    def test_all_documented_fixture_tools_return_structured_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            disk = DiskToolWrapper(config)
            memory = MemoryToolWrapper(config)
            logs = LogToolWrapper(config)
            timeline = TimelineToolWrapper(config)
            network = NetworkToolWrapper(config)
            responses = [
                disk.get_amcache("fixture/Amcache.hve"),
                disk.parse_mft("fixture/$MFT"),
                disk.analyze_prefetch("fixture/Prefetch"),
                disk.list_registry_hives("fixture/config"),
                disk.get_registry_key("fixture/SYSTEM", "SYSTEM", "Services\\SystemUpdate"),
                disk.extract_shellbags("fixture/USRCLASS.DAT"),
                disk.parse_lnk_files("fixture/Recent"),
                disk.get_usnjrnl_entries("fixture/$UsnJrnl"),
                memory.list_processes("fixture/memory.raw"),
                memory.get_network_connections("fixture/memory.raw"),
                memory.extract_injected_code("fixture/memory.raw"),
                memory.find_hidden_modules("fixture/memory.raw"),
                memory.get_handles("fixture/memory.raw"),
                memory.scan_memory_yara("fixture/memory.raw"),
                logs.parse_evtx("fixture/Security.evtx"),
                logs.get_security_events("fixture/Security.evtx"),
                logs.get_logon_events("fixture/Security.evtx"),
                logs.get_process_creation_events("fixture/Security.evtx"),
                timeline.build_super_timeline("fixture/case"),
                timeline.correlate_timestamps(["finding-1"]),
                timeline.get_artifact_at_time("fixture/case", "2026-06-10T03:17:00Z"),
                network.parse_pcap_summary("fixture/network.pcap"),
                network.extract_dns_queries("fixture/network.pcap"),
                network.get_http_requests("fixture/network.pcap"),
            ]
            for response in responses:
                self.assertEqual(response.status, ResponseStatus.OK)
                self.assertIsInstance(response.result, ToolResult)
                self.assertTrue(response.result.raw_hash)
            chain_lines = Path(config.evidence_chain_path).read_text(encoding="utf-8").splitlines()
            execution_lines = Path(config.execution_log_path).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(chain_lines), len(responses))
            self.assertEqual(len(execution_lines), len(responses))
            first_chain_record = json.loads(chain_lines[0])
            second_chain_record = json.loads(chain_lines[1])
            self.assertIn("record_hash", first_chain_record)
            self.assertEqual(first_chain_record["previous_record_hash"], "")
            self.assertEqual(second_chain_record["previous_record_hash"], first_chain_record["record_hash"])
            self.assertIn('"token_estimate"', execution_lines[0])
            self.assertIn('"status": "OK"', execution_lines[0])

    def test_sift_mode_refuses_managed_paths_inside_case_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_root = Path(tmp) / "case"
            case_root.mkdir()
            output_dir = case_root / "sift_mind_output"
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="sift",
            )
            with self.assertRaises(ValueError):
                DiskToolWrapper(config)
            self.assertFalse(output_dir.exists())

    def test_sift_mode_missing_external_tool_returns_structured_error_without_case_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_root = Path(tmp) / "case"
            case_root.mkdir()
            artifact = case_root / "memory.raw"
            artifact.write_bytes(b"fixture")
            output_dir = Path(tmp) / "out"
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="sift",
            )
            before = sorted(path.relative_to(case_root) for path in case_root.rglob("*"))
            response = MissingToolWrapper(config).run_missing_tool(str(artifact))
            after = sorted(path.relative_to(case_root) for path in case_root.rglob("*"))
            self.assertEqual(response.status, ResponseStatus.ERROR)
            self.assertIsInstance(response.result, ToolResult)
            self.assertIn("unavailable on PATH", response.error)
            self.assertEqual(before, after)
            self.assertTrue(Path(config.evidence_chain_path).exists())
            self.assertTrue(Path(config.execution_log_path).exists())

    def test_sift_mode_blocks_artifact_paths_outside_case_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_root = Path(tmp) / "case"
            case_root.mkdir()
            outside = Path(tmp) / "outside.pf"
            outside.write_text("outside", encoding="utf-8")
            output_dir = Path(tmp) / "out"
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="sift",
            )
            response = DiskToolWrapper(config).analyze_prefetch(str(outside), "MIMIKATZ.EXE")
            self.assertEqual(response.status, ResponseStatus.ERROR)
            self.assertIn("outside CASE_ROOT", response.error)

    def test_external_tool_generated_output_is_hashed_and_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            case_root.mkdir()
            artifact = case_root / "prefetch"
            artifact.mkdir()
            script = root / "emit_prefetch.py"
            script.write_text(
                "\n".join(
                    [
                        "import json",
                        "import sys",
                        "payload = {'entries': [{'executable': 'MIMIKATZ.EXE', 'run_count': 3, 'loaded_files': 'SAMLIB.DLL'}]}",
                        "with open(sys.argv[1], 'w', encoding='utf-8') as handle:",
                        "    json.dump(payload, handle)",
                        "print('generated prefetch json')",
                    ]
                ),
                encoding="utf-8",
            )
            output_dir = root / "out"
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "ledger.db"),
                mode="sift",
            )

            response = GeneratedOutputWrapper(config).run_generated_output(str(artifact), script)

            self.assertEqual(response.status, ResponseStatus.OK)
            self.assertIsInstance(response.result, ToolResult)
            self.assertEqual(response.result.parsed["entries"][0]["executable"], "MIMIKATZ.EXE")
            self.assertEqual(response.result.parsed["entries"][0]["run_count"], 3)
            generated = response.result.parsed["_generated_outputs"][0]
            self.assertTrue(generated["exists"])
            self.assertEqual(generated["size_bytes"], Path(generated["path"]).stat().st_size)
            self.assertNotIn("content", generated)
            chain_record = json.loads(Path(config.evidence_chain_path).read_text(encoding="utf-8").splitlines()[0])
            execution_record = json.loads(Path(config.execution_log_path).read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(chain_record["raw_hash"], response.result.raw_hash)
            self.assertEqual(execution_record["raw_hash"], response.result.raw_hash)
            self.assertIn("generated_outputs", chain_record)
            self.assertNotEqual(
                chain_record["raw_hash"],
                __import__("hashlib").sha256("generated prefetch json\n".encode("utf-8")).hexdigest(),
            )

    def test_external_tool_generated_output_path_must_stay_in_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            case_root.mkdir()
            artifact = case_root / "prefetch"
            artifact.mkdir()
            script = root / "emit_prefetch.py"
            script.write_text("print('should not run')\n", encoding="utf-8")
            output_dir = root / "out"
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "ledger.db"),
                mode="sift",
            )

            response = GeneratedOutputWrapper(config).run_invalid_generated_output_path(
                str(artifact),
                script,
                root / "outside.json",
            )

            self.assertEqual(response.status, ResponseStatus.ERROR)
            self.assertIn("inside OUTPUT_DIR", response.error)

    def test_external_tool_uses_fixed_executable_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_root = root / "case"
            case_root.mkdir()
            artifact = case_root / "artifact.bin"
            artifact.write_text("artifact", encoding="utf-8")
            output_dir = root / "out"
            resolved = str(root / "available-secondary-tool")
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "ledger.db"),
                mode="sift",
            )

            def fake_which(candidate: str) -> str | None:
                return resolved if candidate == "available-secondary-tool" else None

            def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                if command == [resolved, "--version"]:
                    return subprocess.CompletedProcess(command, 0, stdout="candidate 1.0", stderr="")
                return subprocess.CompletedProcess(command, 0, stdout="candidate output", stderr="")

            with patch("sift_mind.mcp_server.tools.base.shutil.which", side_effect=fake_which):
                with patch("sift_mind.mcp_server.tools.base.subprocess.run", side_effect=fake_run):
                    response = CandidateToolWrapper(config).run_candidate_tool(str(artifact))

            self.assertEqual(response.status, ResponseStatus.OK)
            self.assertIsInstance(response.result, ToolResult)
            self.assertTrue(response.result.command_run.startswith(resolved))
            self.assertEqual(response.result.tool_version, "candidate 1.0")


if __name__ == "__main__":
    unittest.main()
