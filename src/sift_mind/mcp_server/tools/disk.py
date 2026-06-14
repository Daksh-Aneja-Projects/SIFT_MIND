"""Disk artifact wrappers."""

from __future__ import annotations

from typing import Any

from .base import ToolWrapper
from sift_mind.contracts import MCPResponse
from sift_mind.mcp_server.tools.parsers import (
    parse_amcache,
    parse_json_csv_or_lines,
    parse_mft,
    parse_prefetch,
    parse_registry,
)


class DiskToolWrapper(ToolWrapper):
    def analyze_prefetch(self, artifact_path: str, exe_name: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            executable = exe_name.upper() if exe_name else "MIMIKATZ.EXE"
            return self._fixture_response(
                tool_name="analyze_prefetch",
                artifact_path=artifact_path or "fixture/Windows/Prefetch/MIMIKATZ.EXE-ABCD1234.pf",
                confidence=0.92,
                parsed={
                    "entries": [
                        {
                            "executable": executable,
                            "prefetch_hash": "ABCD1234",
                            "run_count": 3,
                            "last_run_times": [
                                "2026-06-10T03:17:00Z",
                                "2026-06-10T03:19:10Z",
                                "2026-06-10T03:21:42Z",
                            ],
                            "volume_path": "\\\\DEVICE\\\\HARDDISKVOLUME3",
                            "loaded_files": ["ntdll.dll", "SAMLIB.DLL", "CRYPTDLL.DLL", "VAULTCLI.DLL"],
                            "loaded_files_ioc_matches": [
                                {"dll": "SAMLIB.DLL", "significance": "SAM database access"},
                                {"dll": "VAULTCLI.DLL", "significance": "Windows Vault credential access"},
                            ],
                        }
                    ],
                    "total_found": 1,
                },
            )
        prefetch_output_dir = self._tool_output_dir("analyze_prefetch")
        command = ["PECmd.exe", "-d", artifact_path, "--json", str(prefetch_output_dir)]
        if exe_name:
            command.extend(["--filter", exe_name])
        return self._external_tool_response(
            tool_name="analyze_prefetch",
            artifact_path=artifact_path,
            command=command,
            parser=parse_prefetch,
            confidence=0.9,
            output_paths=[prefetch_output_dir],
            executable_candidates=["PECmd", "pecmd"],
        )

    def get_amcache(self, artifact_path: str, key_filter: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_amcache",
                artifact_path=artifact_path or "fixture/Windows/AppCompat/Programs/Amcache.hve",
                confidence=0.9,
                parsed={
                    "entries": [
                        {
                            "program_name": "mimikatz.exe",
                            "full_path": "C:\\Users\\admin\\Desktop\\mimikatz.exe",
                            "sha1": "d34db33fd34db33fd34db33fd34db33fd34db33f",
                            "last_modified": "2026-06-10T03:16:40Z",
                            "publisher": None,
                            "is_known_malicious": True,
                            "confidence_note": "Fixture Amcache entry corroborates execution-path evidence.",
                        }
                    ],
                    "total_entries": 847,
                    "filtered_entries": 1,
                },
            )
        command = ["amcacheparser", "-f", artifact_path]
        if key_filter:
            command.extend(["--filter", key_filter])
        return self._external_tool_response(
            tool_name="get_amcache",
            artifact_path=artifact_path,
            command=command,
            parser=parse_amcache,
            confidence=0.85,
            executable_candidates=["AmcacheParser.exe", "AmcacheParser"],
        )

    def parse_mft(self, artifact_path: str, path_filter: str = "", time_start: str = "", time_end: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="parse_mft",
                artifact_path=artifact_path or "fixture/$MFT",
                confidence=0.84,
                parsed={
                    "entries": [
                        {
                            "filename": "mimikatz.exe",
                            "full_path": "C:\\Users\\admin\\Desktop\\mimikatz.exe",
                            "created": "2026-06-10T03:10:00Z",
                            "modified": "2026-06-10T03:16:00Z",
                            "accessed": "2026-06-10T03:17:00Z",
                            "mft_modified": "2026-06-10T03:17:05Z",
                            "size_bytes": 1355264,
                            "is_deleted": False,
                            "run_count_observed": 1,
                            "timestomp_suspected": False,
                        }
                    ],
                    "timestomp_analysis": {
                        "checked": True,
                        "method": "$STANDARD_INFORMATION vs $FILE_NAME comparison",
                    },
                },
            )
        command = ["mft2csv", artifact_path]
        return self._external_tool_response(
            tool_name="parse_mft",
            artifact_path=artifact_path,
            command=command,
            parser=parse_mft,
            confidence=0.8,
        )

    def list_registry_hives(self, artifact_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="list_registry_hives",
                artifact_path=artifact_path or "fixture/Windows/System32/config",
                confidence=0.88,
                parsed={
                    "hives": [
                        {"name": "SYSTEM", "path": "C:\\Windows\\System32\\config\\SYSTEM"},
                        {"name": "SOFTWARE", "path": "C:\\Windows\\System32\\config\\SOFTWARE"},
                        {"name": "SECURITY", "path": "C:\\Windows\\System32\\config\\SECURITY"},
                        {"name": "SAM", "path": "C:\\Windows\\System32\\config\\SAM"},
                        {"name": "NTUSER.DAT", "path": "C:\\Users\\admin\\NTUSER.DAT"},
                    ]
                },
            )
        command = ["find", artifact_path, "-iname", "*.dat"]
        return self._external_tool_response(
            tool_name="list_registry_hives",
            artifact_path=artifact_path,
            command=command,
            parser=lambda raw: {"hives": [{"path": line} for line in raw.splitlines() if line.strip()]},
            confidence=0.7,
        )

    def get_registry_key(self, artifact_path: str, hive: str, key_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_registry_key",
                artifact_path=artifact_path or f"fixture/registry/{hive or 'SYSTEM'}",
                confidence=0.89,
                parsed={
                    "hive": hive or "SYSTEM",
                    "key_path": key_path or "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SystemUpdate",
                    "last_modified": "2026-06-10T03:20:00Z",
                    "values": [
                        {"name": "ImagePath", "type": "REG_SZ", "data": "C:\\Windows\\Temp\\evil.exe"},
                        {"name": "Start", "type": "REG_DWORD", "data": 2},
                    ],
                    "persistence_indicators": ["Service auto-start", "Non-standard ImagePath location"],
                },
            )
        command = ["rip.pl", "-r", artifact_path, "-p", "services"]
        return self._external_tool_response(
            tool_name="get_registry_key",
            artifact_path=artifact_path,
            command=command,
            parser=parse_registry,
            confidence=0.8,
        )

    def extract_shellbags(self, artifact_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="extract_shellbags",
                artifact_path=artifact_path or "fixture/Users/admin/USRCLASS.DAT",
                confidence=0.73,
                parsed={
                    "entries": [
                        {
                            "path": "C:\\Users\\admin\\Desktop",
                            "last_interaction": "2026-06-10T03:15:00Z",
                            "source": "USRCLASS.DAT",
                        }
                    ]
                },
            )
        command = ["SBECmd.exe", "-f", artifact_path]
        return self._external_tool_response(
            tool_name="extract_shellbags",
            artifact_path=artifact_path,
            command=command,
            parser=parse_json_csv_or_lines,
            confidence=0.7,
            executable_candidates=["SBECmd", "sbecmd"],
        )

    def parse_lnk_files(self, artifact_path: str, path_filter: str = "") -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="parse_lnk_files",
                artifact_path=artifact_path or "fixture/Users/admin/AppData/Roaming/Microsoft/Windows/Recent",
                confidence=0.76,
                parsed={
                    "entries": [
                        {
                            "lnk_path": "C:\\Users\\admin\\Recent\\mimikatz.lnk",
                            "target_path": "C:\\Users\\admin\\Desktop\\mimikatz.exe",
                            "created": "2026-06-10T03:14:50Z",
                            "machine_id": "WORKSTATION01",
                        }
                    ]
                },
            )
        command = ["LECmd.exe", "-d", artifact_path]
        return self._external_tool_response(
            tool_name="parse_lnk_files",
            artifact_path=artifact_path,
            command=command,
            parser=parse_json_csv_or_lines,
            confidence=0.75,
            executable_candidates=["LECmd", "lecmd"],
        )

    def get_usnjrnl_entries(
        self,
        artifact_path: str,
        time_start: str = "",
        time_end: str = "",
        filename_filter: str = "",
    ) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_usnjrnl_entries",
                artifact_path=artifact_path or "fixture/$Extend/$UsnJrnl",
                confidence=0.86,
                parsed={
                    "entries": [
                        {
                            "timestamp": "2026-06-10T03:14:00Z",
                            "filename": "mimikatz.exe",
                            "reason": "FILE_CREATE",
                            "note": "Creation precedes the first prefetch timestamp.",
                        },
                        {
                            "timestamp": "2026-06-10T03:17:03Z",
                            "filename": "mimikatz.exe",
                            "reason": "DATA_EXTEND",
                            "note": "Activity aligns with execution window.",
                        },
                    ],
                    "filters": {"time_start": time_start, "time_end": time_end, "filename_filter": filename_filter},
                },
            )
        command = ["usn.py", artifact_path]
        return self._external_tool_response(
            tool_name="get_usnjrnl_entries",
            artifact_path=artifact_path,
            command=command,
            parser=parse_json_csv_or_lines,
            confidence=0.8,
        )

    def _parse_prefetch_output(self, raw_output: str) -> dict[str, Any]:
        return parse_prefetch(raw_output)
