from __future__ import annotations

import unittest

from pydantic import ValidationError

from sift_mind.contracts import EpistemicStatus, Finding, ToolResult


class ContractTests(unittest.TestCase):
    def test_tool_result_rejects_invalid_confidence(self) -> None:
        with self.assertRaises(ValidationError):
            ToolResult(tool_name="x", artifact_path="a", raw_hash="h", confidence=1.5)

    def test_finding_strips_empty_hashes(self) -> None:
        finding = Finding(
            artifact_path="fixture",
            claim="MIMIKATZ.EXE was observed.",
            status=EpistemicStatus.INFERRED,
            confidence=0.8,
            evidence_hashes=["abc", "", "def"],
        )
        self.assertEqual(finding.evidence_hashes, ["abc", "def"])


if __name__ == "__main__":
    unittest.main()
