from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sift_mind.config import load_config
from sift_mind.contracts import EpistemicStatus, Finding
from sift_mind.ledger.ledger import EpistemicLedger


class RicherContradictionRuleTests(unittest.TestCase):
    def test_hash_replacement_blocks_same_algorithm_disagreement(self) -> None:
        sha_a = "a" * 64
        sha_b = "b" * 64
        status, contradictions = self._add_pair(
            Finding(
                artifact_path="fixture/Amcache.hve",
                claim=f"Amcache reports EVIL.EXE sha256={sha_a}.",
                status=EpistemicStatus.INFERRED,
                confidence=0.82,
                metadata={"sha256": sha_a},
            ),
            Finding(
                artifact_path="fixture/$MFT",
                claim=f"MFT reports EVIL.EXE sha256={sha_b}.",
                status=EpistemicStatus.INFERRED,
                confidence=0.78,
                metadata={"sha256": sha_b},
            ),
        )

        self.assertEqual(status, "BLOCKED")
        self.assertIn("Hash mismatch", contradictions[0].conflict_description)
        self.assertIn("get_amcache", contradictions[0].resolution_suggestion)

    def test_process_visibility_blocks_hiding_disagreement(self) -> None:
        status, contradictions = self._add_pair(
            Finding(
                artifact_path="fixture/memory.raw",
                claim="pslist reports visible process EVIL.EXE PID 4821.",
                status=EpistemicStatus.INFERRED,
                confidence=0.83,
                metadata={"pid": 4821, "process_name": "EVIL.EXE", "process_visible": True},
            ),
            Finding(
                artifact_path="fixture/memory.raw",
                claim="psscan reports hidden process EVIL.EXE PID 4821 absent from pslist.",
                status=EpistemicStatus.INFERRED,
                confidence=0.84,
                metadata={"pid": 4821, "process_name": "EVIL.EXE", "process_visible": False},
            ),
        )

        self.assertEqual(status, "BLOCKED")
        self.assertIn("Process visibility mismatch", contradictions[0].conflict_description)
        self.assertIn("find_hidden_modules", contradictions[0].resolution_suggestion)

    def test_network_observation_blocks_pcap_memory_disagreement(self) -> None:
        status, contradictions = self._add_pair(
            Finding(
                artifact_path="fixture/network.pcap",
                claim="PCAP observed HTTP request to 203.0.113.50.",
                status=EpistemicStatus.INFERRED,
                confidence=0.86,
                metadata={"remote_ip": "203.0.113.50", "network_observed": True, "source_type": "pcap"},
            ),
            Finding(
                artifact_path="fixture/memory.raw",
                claim="Memory netscan reports no connection to 203.0.113.50.",
                status=EpistemicStatus.INFERRED,
                confidence=0.73,
                metadata={"remote_ip": "203.0.113.50", "network_observed": False, "source_type": "memory"},
            ),
        )

        self.assertEqual(status, "BLOCKED")
        self.assertIn("Network observation mismatch", contradictions[0].conflict_description)
        self.assertIn("parse_pcap_summary", contradictions[0].resolution_suggestion)

    def _add_pair(self, first: Finding, second: Finding) -> tuple[str, list]:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            ledger = EpistemicLedger(config.ledger_db_path)
            first_status, first_contradictions = ledger.add_finding(first)
            self.assertEqual(first_status, "OK")
            self.assertEqual(first_contradictions, [])
            return ledger.add_finding(second)


if __name__ == "__main__":
    unittest.main()
