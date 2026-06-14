"""Memory artifact wrappers."""

from __future__ import annotations

from pathlib import Path

from .base import ToolWrapper
from sift_mind.contracts import MCPResponse
from sift_mind.mcp_server.tools.parsers import (
    parse_volatility_handles,
    parse_volatility_netscan,
    parse_volatility_processes,
    parse_yara,
)


class MemoryToolWrapper(ToolWrapper):
    def list_processes(self, memory_path: str, profile: str = "auto") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="list_processes",
                artifact_path=memory_path or "fixture/memory.raw",
                confidence=0.93,
                parsed={
                    "profile": profile,
                    "processes": [
                        {
                            "pid": 4821,
                            "ppid": 1248,
                            "name": "mimikatz.exe",
                            "create_time": "2026-06-10T03:17:00Z",
                            "exit_time": None,
                            "is_running": True,
                            "path": "C:\\Users\\admin\\Desktop\\mimikatz.exe",
                            "parent_name": "cmd.exe",
                            "anomalies": ["unusual_parent", "known_tool_name"],
                            "hidden": False,
                        }
                    ],
                    "orphaned_processes": [],
                    "hollowed_suspected": [],
                },
            )
        return self._volatility("list_processes", memory_path, ["windows.pslist.PsList"])

    def get_network_connections(self, memory_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_network_connections",
                artifact_path=memory_path or "fixture/memory.raw",
                confidence=0.82,
                parsed={
                    "connections": [
                        {
                            "pid": 4821,
                            "process": "mimikatz.exe",
                            "local": "10.0.0.5:49722",
                            "remote": "185.199.108.153:443",
                            "state": "ESTABLISHED",
                            "timestamp": "2026-06-10T03:18:04Z",
                        }
                    ]
                },
            )
        return self._volatility("get_network_connections", memory_path, ["windows.netscan.NetScan"])

    def extract_injected_code(self, memory_path: str, pid: int = 0) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="extract_injected_code",
                artifact_path=memory_path or "fixture/memory.raw",
                confidence=0.7,
                parsed={
                    "pid": pid or 4821,
                    "regions": [],
                    "analysis_note": "No injected executable private memory regions detected in fixture.",
                },
            )
        command = ["vol", "-f", memory_path, "windows.malfind.Malfind"]
        if pid:
            command.extend(["--pid", str(pid)])
        return self._external_tool_response(
            tool_name="extract_injected_code",
            artifact_path=memory_path,
            command=command,
            parser=self._json_or_lines,
            confidence=0.75,
            executable_candidates=["vol.py", "volatility3"],
        )

    def find_hidden_modules(self, memory_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="find_hidden_modules",
                artifact_path=memory_path or "fixture/memory.raw",
                confidence=0.84,
                parsed={"hidden_modules": [], "dkom_indicators": [], "cross_view_checked": True},
            )
        return self._volatility("find_hidden_modules", memory_path, ["windows.modules.Modules"])

    def get_handles(self, memory_path: str, pid: int = 0) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_handles",
                artifact_path=memory_path or "fixture/memory.raw",
                confidence=0.88,
                parsed={
                    "pid": pid or 4821,
                    "handles": [
                        {"type": "Process", "name": "lsass.exe", "access": "PROCESS_VM_READ"},
                        {"type": "File", "name": "C:\\Windows\\System32\\config\\SAM", "access": "READ"},
                    ],
                    "suspicious_access": ["lsass.exe handle", "SAM hive read"],
                },
            )
        command = ["vol", "-f", memory_path, "windows.handles.Handles"]
        if pid:
            command.extend(["--pid", str(pid)])
        return self._external_tool_response(
            tool_name="get_handles",
            artifact_path=memory_path,
            command=command,
            parser=parse_volatility_handles,
            confidence=0.85,
            executable_candidates=["vol.py", "volatility3"],
        )

    def scan_memory_yara(self, memory_path: str, ruleset: str = "default") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="scan_memory_yara",
                artifact_path=memory_path or "fixture/memory.raw",
                confidence=0.91,
                parsed={
                    "ruleset": ruleset,
                    "matches": [
                        {
                            "rule": "MimikatzStrings",
                            "pid": 4821,
                            "offset": "0x7ffdf001",
                            "mitre": "T1003.001",
                            "confidence": "HIGH",
                        }
                    ],
                },
            )
        if ruleset == "default":
            ruleset = str(Path(__file__).with_name("yara_rules") / "credential_tools.yar")
        command = ["yara", "-r", ruleset, memory_path]
        return self._external_tool_response(
            tool_name="scan_memory_yara",
            artifact_path=memory_path,
            command=command,
            parser=parse_yara,
            confidence=0.85,
        )

    def _volatility(self, tool_name: str, memory_path: str, plugin_args: list[str]) -> MCPResponse:
        parser = self._json_or_lines
        if tool_name == "list_processes":
            parser = parse_volatility_processes
        elif tool_name == "get_network_connections":
            parser = parse_volatility_netscan
        elif tool_name == "find_hidden_modules":
            parser = self._json_or_lines
        return self._external_tool_response(
            tool_name=tool_name,
            artifact_path=memory_path,
            command=["vol", "-f", memory_path, *plugin_args],
            parser=parser,
            confidence=0.8,
            executable_candidates=["vol.py", "volatility3"],
        )
