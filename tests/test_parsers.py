from __future__ import annotations

import json
import unittest

from sift_mind.mcp_server.tools.parsers import (
    parse_amcache,
    parse_evtx,
    parse_mft,
    parse_prefetch,
    parse_timeline,
    parse_tshark_conversations,
    parse_tshark_json,
    parse_volatility_handles,
    parse_volatility_netscan,
    parse_volatility_processes,
    parse_yara,
)


class ParserTests(unittest.TestCase):
    def test_prefetch_json_normalizes_entries(self) -> None:
        raw = json.dumps(
            [
                {
                    "ExecutableName": "MIMIKATZ.EXE",
                    "Hash": "ABCD1234",
                    "RunCount": 3,
                    "LastRunTimes": ["2026-06-10T03:17:00Z"],
                    "FilesLoaded": "C:\\Windows\\SAMLIB.DLL;C:\\Windows\\CRYPTDLL.DLL",
                }
            ]
        )
        parsed = parse_prefetch(raw)
        self.assertEqual(parsed["entries"][0]["executable"], "MIMIKATZ.EXE")
        self.assertEqual(parsed["entries"][0]["run_count"], 3)
        self.assertEqual(parsed["entries"][0]["loaded_files_ioc_matches"][0]["dll"], "SAMLIB.DLL")

    def test_amcache_csv_normalizes_hash_and_path(self) -> None:
        raw = (
            "ProgramName,FullPath,SHA1,LastModifiedTime,Publisher\n"
            "mimikatz.exe,C:\\Users\\admin\\Desktop\\mimikatz.exe,d34d,2026-06-10T03:16:40Z,\n"
        )
        parsed = parse_amcache(raw)
        self.assertEqual(parsed["entries"][0]["program_name"], "mimikatz.exe")
        self.assertTrue(parsed["entries"][0]["is_known_malicious"])

    def test_mft_csv_checks_timestamps(self) -> None:
        raw = (
            "Filename,FullPath,Created,Modified,Accessed,Size\n"
            "mimikatz.exe,C:\\Users\\admin\\Desktop\\mimikatz.exe,2026-06-10T03:10:00+00:00,2026-06-10T03:16:00+00:00,2026-06-10T03:17:00+00:00,1355264\n"
        )
        parsed = parse_mft(raw)
        self.assertEqual(parsed["entries"][0]["size_bytes"], 1355264)
        self.assertFalse(parsed["entries"][0]["timestomp_suspected"])

    def test_volatility_process_table(self) -> None:
        raw = (
            "PID  PPID  ImageFileName  CreateTime  ExitTime\n"
            "4821  1248  mimikatz.exe  2026-06-10T03:17:00Z  \n"
        )
        parsed = parse_volatility_processes(raw)
        self.assertEqual(parsed["processes"][0]["pid"], 4821)
        self.assertIn("known_tool_name", parsed["processes"][0]["anomalies"])

    def test_volatility_netscan_table(self) -> None:
        raw = (
            "PID  Owner  LocalAddr  LocalPort  ForeignAddr  ForeignPort  State\n"
            "4821  mimikatz.exe  10.0.0.5  49722  185.199.108.153  443  ESTABLISHED\n"
        )
        parsed = parse_volatility_netscan(raw)
        self.assertEqual(parsed["connections"][0]["remote"], "185.199.108.153:443")

    def test_handles_table_flags_lsass(self) -> None:
        raw = (
            "PID  Type  Name  GrantedAccess\n"
            "4821  Process  lsass.exe  PROCESS_VM_READ\n"
        )
        parsed = parse_volatility_handles(raw)
        self.assertIn("lsass.exe", parsed["suspicious_access"])

    def test_yara_line_output(self) -> None:
        parsed = parse_yara("MimikatzStrings fixture/memory.raw 0x7ffdf001\n")
        self.assertEqual(parsed["matches"][0]["rule"], "MimikatzStrings")

    def test_evtx_xml_extracts_event_data(self) -> None:
        raw = """
        <Event>
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4688</EventID>
            <TimeCreated SystemTime="2026-06-10T03:17:01Z"/>
            <Computer>WORKSTATION01</Computer>
          </System>
          <EventData>
            <Data Name="NewProcessName">C:\\Users\\admin\\Desktop\\mimikatz.exe</Data>
            <Data Name="CommandLine">mimikatz.exe privilege::debug</Data>
          </EventData>
        </Event>
        """
        parsed = parse_evtx(raw, [4688])
        self.assertEqual(parsed["events"][0]["event_id"], 4688)
        self.assertIn("mimikatz.exe", parsed["events"][0]["command_line"])

    def test_tshark_dns_and_http_json(self) -> None:
        raw = json.dumps(
            [
                {
                    "_source": {
                        "layers": {
                            "frame": {"frame.time": "2026-06-10T03:18:00Z"},
                            "dns": {"dns.qry.name": "cdn-update.example", "dns.a": "185.199.108.153"},
                            "http": {
                                "http.request.method": "GET",
                                "http.host": "cdn-update.example",
                                "http.request.uri": "/checkin",
                            },
                        }
                    }
                }
            ]
        )
        self.assertEqual(parse_tshark_json(raw, "dns")["queries"][0]["query"], "cdn-update.example")
        self.assertEqual(parse_tshark_json(raw, "http")["requests"][0]["method"], "GET")

    def test_tshark_conversation_summary(self) -> None:
        raw = "10.0.0.5:49722 <-> 185.199.108.153:443  10  184224\n"
        parsed = parse_tshark_conversations(raw)
        self.assertEqual(parsed["conversations"][0]["dst_port"], 443)

    def test_timeline_csv_builds_window(self) -> None:
        raw = (
            "datetime,source,desc,filename,user,host\n"
            "2026-06-10T03:17:00Z,EVTX,MIMIKATZ.EXE process creation,C:\\x,admin,WORKSTATION01\n"
        )
        parsed = parse_timeline(raw)
        self.assertEqual(parsed["total_entries"], 1)
        self.assertTrue(parsed["suspicious_windows"])


if __name__ == "__main__":
    unittest.main()
