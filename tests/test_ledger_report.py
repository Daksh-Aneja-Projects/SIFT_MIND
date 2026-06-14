from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from sift_mind.config import load_config
from sift_mind.contracts import EpistemicStatus, Finding, ReportSection
from sift_mind.ledger.ledger import EpistemicLedger
from sift_mind.mcp_server.tools.disk import DiskToolWrapper
from sift_mind.report.writer import ReportWriter


class LedgerReportTests(unittest.TestCase):
    def test_contradiction_blocks_and_resolution_unblocks_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence_chain.log"
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(evidence),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            ledger = EpistemicLedger(config.ledger_db_path)
            disk = DiskToolWrapper(config)
            prefetch = disk.analyze_prefetch("fixture/Prefetch").result
            mft = disk.parse_mft("fixture/$MFT").result
            ledger.add_finding(
                Finding(
                    artifact_path=prefetch.artifact_path,
                    claim="Prefetch reports MIMIKATZ.EXE executed 3 times.",
                    status=EpistemicStatus.INFERRED,
                    confidence=0.9,
                    sources=[prefetch],
                    metadata={"run_count": 3},
                )
            )
            status, contradictions = ledger.add_finding(
                Finding(
                    artifact_path=mft.artifact_path,
                    claim="MFT analysis reports MIMIKATZ.EXE run_count=1.",
                    status=EpistemicStatus.INFERRED,
                    confidence=0.8,
                    sources=[mft],
                    metadata={"run_count": 1},
                )
            )
            ingestion = ledger.ingest_execution_log(config.execution_log_path, replace=True)
            self.assertEqual(ingestion["status"], "OK")
            self.assertEqual(ingestion["inserted"], 2)
            self.assertEqual(len(ledger.get_tool_executions()), 2)
            original_execution_log = Path(config.execution_log_path).read_text(encoding="utf-8")
            Path(config.execution_log_path).write_text(
                original_execution_log + "not-json\n",
                encoding="utf-8",
            )
            bad_ingestion = ledger.ingest_execution_log(config.execution_log_path, replace=True)
            self.assertEqual(bad_ingestion["status"], "FAILED")
            self.assertEqual(bad_ingestion["malformed_count"], 1)
            Path(config.execution_log_path).write_text(original_execution_log, encoding="utf-8")
            ledger.ingest_execution_log(config.execution_log_path, replace=True)
            self.assertEqual(status, "BLOCKED")
            self.assertEqual(len(ledger.get_contested()), 1)
            writer = ReportWriter(ledger, str(evidence))
            with self.assertRaises(RuntimeError):
                writer.write_all(tmp)
            self.assertTrue(ledger.resolve_contradiction(contradictions[0].id, "VSS explains the count mismatch.", []))
            self.assertEqual(len(ledger.get_contested()), 0)
            linked = ledger.get_all_findings(include_blocked=False)[0]
            ledger.add_report_section(
                ReportSection(
                    name="UNSOURCED TITLE SHOULD NOT APPEAR",
                    content_markdown="UNSOURCED AGENT PROSE SHOULD NOT APPEAR",
                    finding_ids=[linked.id],
                )
            )
            paths = writer.write_all(tmp)
            self.assertTrue(Path(paths["case_narrative"]).exists())
            narrative = Path(paths["case_narrative"]).read_text(encoding="utf-8")
            self.assertIn("Ledger Section 1", narrative)
            self.assertIn(linked.id, narrative)
            self.assertNotIn("UNSOURCED TITLE SHOULD NOT APPEAR", narrative)
            self.assertNotIn("UNSOURCED AGENT PROSE SHOULD NOT APPEAR", narrative)
            self.assertEqual(writer.verify_evidence_chain()["status"], "VERIFIED")
            original_chain = evidence.read_text(encoding="utf-8")
            chain_records = [json.loads(line) for line in original_chain.splitlines() if line.strip()]
            chain_records[0]["command_run"] = "tampered"
            evidence.write_text("\n".join(json.dumps(record, sort_keys=True) for record in chain_records) + "\n", encoding="utf-8")
            tampered = writer.verify_evidence_chain()
            self.assertEqual(tampered["status"], "FAILED")
            self.assertEqual(tampered["invalid_record_hash_count"], 1)
            with self.assertRaises(RuntimeError):
                writer.write_all(tmp)
            chain_records = [json.loads(line) for line in original_chain.splitlines() if line.strip()]
            chain_records[0].pop("record_hash")
            evidence.write_text("\n".join(json.dumps(record, sort_keys=True) for record in chain_records) + "\n", encoding="utf-8")
            missing_record_hash = writer.verify_evidence_chain()
            self.assertEqual(missing_record_hash["status"], "FAILED")
            self.assertEqual(missing_record_hash["missing_record_hash_count"], 1)
            chain_records = [json.loads(line) for line in original_chain.splitlines() if line.strip()]
            chain_records[1]["previous_record_hash"] = "0" * 64
            evidence.write_text("\n".join(json.dumps(record, sort_keys=True) for record in chain_records) + "\n", encoding="utf-8")
            broken_link = writer.verify_evidence_chain()
            self.assertEqual(broken_link["status"], "FAILED")
            self.assertEqual(broken_link["chain_link_mismatch_count"], 1)
            evidence.write_text(original_chain + "not-json\n", encoding="utf-8")
            malformed = writer.verify_evidence_chain()
            self.assertEqual(malformed["status"], "FAILED")
            self.assertEqual(malformed["malformed_count"], 1)
            evidence.write_text(original_chain + json.dumps({"tool_name": "fixture"}) + "\n", encoding="utf-8")
            missing_raw_hash = writer.verify_evidence_chain()
            self.assertEqual(missing_raw_hash["status"], "FAILED")
            self.assertEqual(missing_raw_hash["missing_raw_hash_count"], 1)
            evidence.write_text("", encoding="utf-8")
            self.assertEqual(writer.verify_evidence_chain()["status"], "FAILED")

    def test_evidence_chain_cross_checks_execution_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence_chain.log"
            execution_log = Path(tmp) / "agent_execution_log.jsonl"
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(evidence),
                execution_log_path=str(execution_log),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            ledger = EpistemicLedger(config.ledger_db_path)
            disk = DiskToolWrapper(config)
            prefetch = disk.analyze_prefetch("fixture/Prefetch").result
            mft = disk.parse_mft("fixture/$MFT").result
            ledger.add_finding(
                Finding(
                    artifact_path=prefetch.artifact_path,
                    claim="Prefetch reports MIMIKATZ.EXE executed 3 times.",
                    status=EpistemicStatus.INFERRED,
                    confidence=0.9,
                    evidence_hashes=[prefetch.raw_hash],
                    metadata={"run_count": 3},
                )
            )
            writer = ReportWriter(ledger, str(evidence), str(execution_log))
            self.assertEqual(writer.verify_evidence_chain()["status"], "VERIFIED")

            original_execution = execution_log.read_text(encoding="utf-8")
            execution_log.write_text(original_execution.splitlines()[0] + "\n", encoding="utf-8")
            missing_execution = writer.verify_evidence_chain()
            self.assertEqual(missing_execution["status"], "FAILED")
            self.assertEqual(missing_execution["missing_execution_record_count"], 1)
            self.assertIn(mft.raw_hash, missing_execution["missing_execution_record_hashes"])

            execution_log.write_text(
                original_execution + json.dumps({"raw_hash": "0" * 64, "status": "OK"}) + "\n",
                encoding="utf-8",
            )
            extra_execution = writer.verify_evidence_chain()
            self.assertEqual(extra_execution["status"], "FAILED")
            self.assertEqual(extra_execution["execution_record_missing_chain_count"], 1)

            execution_log.write_text(original_execution + "not-json\n", encoding="utf-8")
            malformed_execution = writer.verify_evidence_chain()
            self.assertEqual(malformed_execution["status"], "FAILED")
            self.assertEqual(malformed_execution["execution_records_missing_raw_hash_count"], 1)


if __name__ == "__main__":
    unittest.main()
