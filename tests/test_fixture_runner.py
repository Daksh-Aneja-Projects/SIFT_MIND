from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sift_mind.agent.loop import FixtureAgentRunner
from sift_mind.config import load_config
from sift_mind.ledger.ledger import EpistemicLedger


class FixtureRunnerTests(unittest.TestCase):
    def test_fixture_runner_produces_reports_and_resolves_contradiction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            result = FixtureAgentRunner(config).run()
            self.assertEqual(result["status"], "OK")
            self.assertEqual(result["summary"]["contradictions"], 1)
            self.assertEqual(result["summary"]["unresolved_contradictions"], 0)
            self.assertEqual(result["summary"]["tool_executions"], 13)
            self.assertEqual(result["evidence_verification"]["status"], "VERIFIED")
            ledger = EpistemicLedger(config.ledger_db_path)
            self.assertEqual(len(ledger.get_tool_executions()), 13)
            for path in result["reports"].values():
                self.assertTrue(Path(path).exists(), path)
            execution_log = Path(result["reports"]["agent_execution_log"]).read_text(encoding="utf-8")
            self.assertIn('"token_estimate"', execution_log)
            self.assertIn('"tool_name"', execution_log)

    def test_fixture_accuracy_report_compares_configured_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            baseline.write_text(
                json.dumps(
                    {
                        "expected_findings": [
                            {
                                "id": "mimikatz_execution",
                                "must_include": ["MIMIKATZ.EXE", "executed"],
                                "status": "CONFIRMED",
                                "mitre": "T1003.001",
                            }
                        ],
                        "expected_iocs": [{"type": "ip", "value": "185.199.108.153"}],
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                baseline_path=str(baseline),
                mode="fixture",
            )
            result = FixtureAgentRunner(config).run()

            accuracy = Path(result["reports"]["accuracy_report"]).read_text(encoding="utf-8")
            self.assertIn("## Baseline Comparison", accuracy)
            self.assertIn("- Status: MATCHED", accuracy)
            self.assertIn("- Expected findings: 1", accuracy)
            self.assertIn("- Matched findings: 1", accuracy)
            self.assertIn("- Expected IOCs: 1", accuracy)
            self.assertIn("- Matched IOCs: 1", accuracy)


if __name__ == "__main__":
    unittest.main()
