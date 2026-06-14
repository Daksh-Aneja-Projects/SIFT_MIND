from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sift_mind.config import load_config
from sift_mind.mcp_server.server import create_server


class FakeFastMCP:
    def __init__(self, name: str):
        self.name = name
        self.tools = {}

    def tool(self):
        def decorator(func):
            self.tools[func.__name__] = func
            return func

        return decorator

    def run(self) -> None:
        return None


class MCPServerTests(unittest.TestCase):
    def test_report_status_and_finalize_ingest_execution_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                execution_log_path=str(Path(tmp) / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            with patch("sift_mind.mcp_server.server._load_fastmcp", return_value=FakeFastMCP):
                server = create_server(config)
            prefetch = server.tools["analyze_prefetch"]("fixture/Prefetch", "MIMIKATZ.EXE")
            raw_hash = prefetch["result"]["raw_hash"]
            add_result = server.tools["ledger_add_finding"](
                "fixture/Prefetch",
                "Prefetch reports MIMIKATZ.EXE executed.",
                "INFERRED",
                0.8,
                raw_hash,
                "T1003.001",
            )
            self.assertEqual(add_result["status"], "OK")
            status = server.tools["report_get_status"]()
            self.assertEqual(status["status"], "READY")
            self.assertEqual(status["summary"]["tool_executions"], 1)
            finalized = server.tools["report_finalize"](tmp)
            self.assertEqual(finalized["status"], "OK")
            self.assertEqual(finalized["execution_ingestion"]["inserted"], 1)
            self.assertEqual(finalized["evidence_verification"]["status"], "VERIFIED")

    def test_report_finalize_blocks_malformed_execution_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            execution_log = Path(tmp) / "agent_execution_log.jsonl"
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                execution_log_path=str(execution_log),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            with patch("sift_mind.mcp_server.server._load_fastmcp", return_value=FakeFastMCP):
                server = create_server(config)
            prefetch = server.tools["analyze_prefetch"]("fixture/Prefetch", "MIMIKATZ.EXE")
            server.tools["ledger_add_finding"](
                "fixture/Prefetch",
                "Prefetch reports MIMIKATZ.EXE executed.",
                "INFERRED",
                0.8,
                prefetch["result"]["raw_hash"],
                "T1003.001",
            )
            execution_log.write_text(execution_log.read_text(encoding="utf-8") + "not-json\n", encoding="utf-8")
            finalized = server.tools["report_finalize"](tmp)
            self.assertEqual(finalized["status"], "BLOCKED")
            self.assertEqual(finalized["execution_ingestion"]["malformed_count"], 1)

    def test_ledger_add_finding_accepts_metadata_and_blocks_contradiction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                execution_log_path=str(Path(tmp) / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            with patch("sift_mind.mcp_server.server._load_fastmcp", return_value=FakeFastMCP):
                server = create_server(config)

            prefetch = server.tools["analyze_prefetch"]("fixture/Prefetch", "MIMIKATZ.EXE")
            mft = server.tools["parse_mft"]("fixture/$MFT", "mimikatz.exe")
            first = server.tools["ledger_add_finding"](
                "fixture/Prefetch",
                "Prefetch identifies MIMIKATZ.EXE execution artifact.",
                "INFERRED",
                0.86,
                json.dumps([prefetch["result"]["raw_hash"]]),
                "T1003.001",
                json.dumps({"run_count": 3}),
            )
            self.assertEqual(first["status"], "OK")
            second = server.tools["ledger_add_finding"](
                "fixture/$MFT",
                "MFT identifies MIMIKATZ.EXE execution artifact.",
                "INFERRED",
                0.75,
                mft["result"]["raw_hash"],
                "T1003.001",
                json.dumps({"run_count": 1}),
            )
            self.assertEqual(second["status"], "BLOCKED")
            self.assertIn("Run count mismatch", second["blocked_reason"])
            contested = server.tools["ledger_get_contested"]()
            self.assertEqual(contested["contested_count"], 1)
            resolved = server.tools["ledger_resolve_contradiction"](
                second["contradictions"][0]["id"],
                "USN and timeline evidence show tool-specific counting semantics.",
                json.dumps([mft["result"]["raw_hash"]]),
            )
            self.assertTrue(resolved["resolved"])
            contested = server.tools["ledger_get_contested"]()
            self.assertEqual(contested["contested_count"], 0)

    def test_ledger_add_finding_returns_structured_error_for_invalid_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                execution_log_path=str(Path(tmp) / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            with patch("sift_mind.mcp_server.server._load_fastmcp", return_value=FakeFastMCP):
                server = create_server(config)

            bad = server.tools["ledger_add_finding"](
                "fixture/Prefetch",
                "Prefetch identifies MIMIKATZ.EXE execution artifact.",
                "NOT_A_TIER",
                0.86,
                "abc123",
                "T1003.001",
                "not-json",
            )
            self.assertEqual(bad["status"], "ERROR")
            self.assertIn("Invalid finding payload", bad["error"])


if __name__ == "__main__":
    unittest.main()
