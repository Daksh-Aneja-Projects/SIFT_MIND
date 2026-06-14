"""Timeline and correlation wrappers."""

from __future__ import annotations

from .base import ToolWrapper
from sift_mind.contracts import MCPResponse
from sift_mind.mcp_server.tools.parsers import parse_timeline


class TimelineToolWrapper(ToolWrapper):
    def build_super_timeline(self, case_path: str, sources: str = "all") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="build_super_timeline",
                artifact_path=case_path or "fixture/case",
                confidence=0.82,
                parsed={
                    "case_path": case_path or "fixture/case",
                    "sources": sources,
                    "time_range": {"start": "2026-06-10T03:10:00Z", "end": "2026-06-10T03:25:00Z"},
                    "suspicious_windows": [
                        {
                            "start": "2026-06-10T03:14:00Z",
                            "end": "2026-06-10T03:22:00Z",
                            "reason": "Off-hours execution, credential-tool artifacts, persistence creation.",
                            "score": 0.94,
                        }
                    ],
                    "top_events": [
                        "03:14 shadow copy observed",
                        "03:17 mimikatz execution",
                        "03:20 scheduled task persistence",
                    ],
                },
            )
        timeline_path = self._tool_output_file("build_super_timeline", ".plaso")
        return self._external_tool_response(
            tool_name="build_super_timeline",
            artifact_path=case_path,
            command=["log2timeline.py", str(timeline_path), case_path],
            parser=parse_timeline,
            confidence=0.75,
            timeout=1800,
            output_paths=[timeline_path],
        )

    def correlate_timestamps(self, finding_ids: list[str]) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="correlate_timestamps",
                artifact_path="ledger",
                confidence=0.8,
                parsed={
                    "finding_ids": finding_ids,
                    "clusters": [
                        {
                            "start": "2026-06-10T03:17:00Z",
                            "end": "2026-06-10T03:18:04Z",
                            "description": "Disk, log, and memory evidence align around MIMIKATZ.EXE execution.",
                            "confidence": 0.93,
                        }
                    ],
                },
            )
        return self._fixture_response(
            tool_name="correlate_timestamps",
            artifact_path="ledger",
            confidence=0.2,
            parsed={"finding_ids": finding_ids, "clusters": [], "note": "Real correlation is performed by the agent/ledger layer."},
        )

    def get_artifact_at_time(self, case_path: str, timestamp: str, window_minutes: int = 5) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_artifact_at_time",
                artifact_path=case_path or "fixture/case",
                confidence=0.88,
                parsed={
                    "timestamp": timestamp,
                    "window_minutes": window_minutes,
                    "artifacts": [
                        {
                            "type": "vss_shadow_copy",
                            "timestamp": "2026-06-10T03:14:00Z",
                            "description": "Shadow copy captured filesystem state before later prefetch increments.",
                        },
                        {
                            "type": "usnjrnl",
                            "timestamp": "2026-06-10T03:17:03Z",
                            "description": "Mimikatz file activity in the execution window.",
                        },
                    ],
                    "resolution_note": (
                        "The MFT observation can reflect the shadow-copy state while Prefetch reflects "
                        "post-shadow executions, explaining the run-count mismatch."
                    ),
                },
            )
        timeline_path = self._tool_output_file("get_artifact_at_time", ".plaso")
        return self._external_tool_response(
            tool_name="get_artifact_at_time",
            artifact_path=case_path,
            command=["log2timeline.py", "--status_view", "none", str(timeline_path), case_path],
            parser=parse_timeline,
            confidence=0.7,
            timeout=1800,
            output_paths=[timeline_path],
        )
