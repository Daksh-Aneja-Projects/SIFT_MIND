from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sift_mind.agent.loop import FixtureAgentRunner
from sift_mind.agent.model_brief import generate_model_case_brief, write_model_case_brief
from sift_mind.config import load_config
from sift_mind.ledger.ledger import EpistemicLedger


class FakeBriefClient:
    def __init__(self, response: dict):
        self.response = response
        self.prompt = ""
        self.schema = {}

    def generate_json(self, prompt: str, schema: dict | None = None) -> dict:
        self.prompt = prompt
        self.schema = schema or {}
        return dict(self.response)


class ModelBriefTests(unittest.TestCase):
    def test_model_brief_accepts_ledger_cited_bullets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(
                case_root="fixture/case",
                output_dir=str(root / "report"),
                evidence_chain_path=str(root / "report" / "evidence_chain.log"),
                execution_log_path=str(root / "report" / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "report" / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            ledger = EpistemicLedger(config.ledger_db_path)
            finding = ledger.get_all_findings(include_blocked=False)[0]
            client = FakeBriefClient(
                {
                    "status": "ok",
                    "executive_bullets": [
                        {
                            "text": "MIMIKATZ execution is supported by ledger evidence.",
                            "finding_ids": [finding.id],
                            "evidence_hashes": [finding.evidence_hashes[0]],
                        }
                    ],
                    "open_questions": [],
                    "handoff": "Continue with SIFT-mode public sample validation.",
                    "_metadata": {"provider": "fake", "model": "fake-local", "fallback_used": False},
                }
            )

            result = generate_model_case_brief(ledger, config, client=client)

            self.assertEqual(result["status"], "OK")
            self.assertEqual(result["validation"]["status"], "PASS")
            self.assertEqual(result["source_policy"], "ledger_only_model_brief_not_report_source")
            self.assertEqual(result["model"]["provider"], "fake")
            self.assertEqual(
                result["handoff"],
                "No unresolved contradictions remain; review ledger-cited findings and proceed to report/package verification.",
            )
            self.assertIn("model handoff text discarded", " ".join(result["validation"]["warnings"]))
            self.assertIn("LEDGER_SNAPSHOT_JSON=", client.prompt)
            self.assertIn("executive_bullets", client.schema["required"])

    def test_model_brief_rejects_unknown_citations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(
                case_root="fixture/case",
                output_dir=str(root / "report"),
                evidence_chain_path=str(root / "report" / "evidence_chain.log"),
                execution_log_path=str(root / "report" / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "report" / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            ledger = EpistemicLedger(config.ledger_db_path)
            client = FakeBriefClient(
                {
                    "status": "ok",
                    "executive_bullets": [
                        {
                            "text": "Unsupported finding.",
                            "finding_ids": ["missing-finding"],
                            "evidence_hashes": ["0" * 64],
                        }
                    ],
                    "open_questions": [],
                    "handoff": "",
                }
            )

            result = generate_model_case_brief(ledger, config, client=client)

            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["validation"]["status"], "FAIL")
            self.assertIn("unknown finding IDs", " ".join(result["validation"]["errors"]))
            self.assertIn("unknown evidence hashes", " ".join(result["validation"]["errors"]))

    def test_model_brief_drops_invalid_optional_open_questions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(
                case_root="fixture/case",
                output_dir=str(root / "report"),
                evidence_chain_path=str(root / "report" / "evidence_chain.log"),
                execution_log_path=str(root / "report" / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "report" / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            ledger = EpistemicLedger(config.ledger_db_path)
            finding = ledger.get_all_findings(include_blocked=False)[0]
            client = FakeBriefClient(
                {
                    "status": "ok",
                    "executive_bullets": [
                        {
                            "text": "Ledger-cited bullet.",
                            "finding_ids": [finding.id],
                            "evidence_hashes": [finding.evidence_hashes[0]],
                        }
                    ],
                    "open_questions": [
                        {
                            "question": "Invented citation?",
                            "reason": "The model supplied a stale finding ID.",
                            "finding_ids": ["missing-finding"],
                            "evidence_hashes": ["0" * 64],
                        }
                    ],
                    "handoff": "",
                }
            )

            result = generate_model_case_brief(ledger, config, client=client)

            self.assertEqual(result["status"], "OK")
            self.assertEqual(result["validation"]["status"], "PASS")
            self.assertEqual(result["open_questions"], [])
            self.assertIn("item dropped", " ".join(result["validation"]["warnings"]))

    def test_model_brief_writer_saves_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(
                case_root="fixture/case",
                output_dir=str(root / "report"),
                evidence_chain_path=str(root / "report" / "evidence_chain.log"),
                execution_log_path=str(root / "report" / "agent_execution_log.jsonl"),
                ledger_db_path=str(root / "report" / "ledger.db"),
                mode="fixture",
            )
            FixtureAgentRunner(config).run()
            ledger = EpistemicLedger(config.ledger_db_path)
            finding = ledger.get_all_findings(include_blocked=False)[0]
            output = root / "brief.json"
            client = FakeBriefClient(
                {
                    "status": "ok",
                    "executive_bullets": [
                        {
                            "text": "Ledger-cited brief.",
                            "finding_ids": [finding.id],
                            "evidence_hashes": [finding.evidence_hashes[0]],
                        }
                    ],
                    "open_questions": [],
                    "handoff": "",
                }
            )

            result = write_model_case_brief(ledger, config, output, client=client)

            self.assertEqual(result["status"], "OK")
            self.assertEqual(result["path"], str(output))
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
