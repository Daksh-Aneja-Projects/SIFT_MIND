"""Windows log wrappers."""

from __future__ import annotations

from .base import ToolWrapper
from sift_mind.contracts import MCPResponse
from sift_mind.mcp_server.tools.parsers import parse_evtx


class LogToolWrapper(ToolWrapper):
    def parse_evtx(self, log_path: str, event_ids: list[int] | None = None, time_start: str = "", time_end: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="parse_evtx",
                artifact_path=log_path or "fixture/Windows/System32/winevt/Logs/Security.evtx",
                confidence=0.9,
                parsed={
                    "events": [
                        {
                            "event_id": 4688,
                            "timestamp": "2026-06-10T03:17:01Z",
                            "process": "C:\\Users\\admin\\Desktop\\mimikatz.exe",
                            "parent_process": "C:\\Windows\\System32\\cmd.exe",
                            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                        },
                        {
                            "event_id": 4698,
                            "timestamp": "2026-06-10T03:20:00Z",
                            "task_name": "\\SystemUpdate",
                            "author": "WORKSTATION01\\admin",
                        },
                    ],
                    "filters": {"event_ids": event_ids, "time_start": time_start, "time_end": time_end},
                },
            )
        command = ["evtx_dump.py", log_path]
        return self._external_tool_response(
            tool_name="parse_evtx",
            artifact_path=log_path,
            command=command,
            parser=lambda raw: parse_evtx(raw, event_ids),
            confidence=0.85,
            executable_candidates=["evtx_dump.py", "evtx_dump"],
        )

    def get_security_events(self, log_path: str, username: str = "", time_start: str = "", time_end: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_security_events",
                artifact_path=log_path or "fixture/Security.evtx",
                confidence=0.86,
                parsed={
                    "events": [
                        {
                            "event_id": 4624,
                            "timestamp": "2026-06-10T03:13:12Z",
                            "username": username or "admin",
                            "logon_type": 10,
                            "source_ip": "10.0.0.44",
                            "lateral_movement_indicators": ["remote interactive logon"],
                        }
                    ]
                },
            )
        return self.parse_evtx(log_path, [4624, 4625, 4648, 4672], time_start, time_end)

    def get_logon_events(self, log_path: str, username: str = "", time_start: str = "", time_end: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_logon_events",
                artifact_path=log_path or "fixture/Security.evtx",
                confidence=0.83,
                parsed={
                    "events": [
                        {
                            "event_id": 4648,
                            "timestamp": "2026-06-10T03:22:30Z",
                            "username": username or "admin",
                            "target_server": "WORKSTATION02",
                            "status": "explicit credential logon observed",
                        }
                    ]
                },
            )
        return self.parse_evtx(log_path, [4624, 4625, 4648], time_start, time_end)

    def get_process_creation_events(self, log_path: str, time_start: str = "", time_end: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_process_creation_events",
                artifact_path=log_path or "fixture/Security.evtx",
                confidence=0.92,
                parsed={
                    "events": [
                        {
                            "event_id": 4688,
                            "timestamp": "2026-06-10T03:17:01Z",
                            "new_process_name": "C:\\Users\\admin\\Desktop\\mimikatz.exe",
                            "creator_process_name": "C:\\Windows\\System32\\cmd.exe",
                            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                        }
                    ],
                    "filters": {"time_start": time_start, "time_end": time_end},
                },
            )
        return self.parse_evtx(log_path, [4688], time_start, time_end)
