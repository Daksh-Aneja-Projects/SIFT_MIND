"""Network artifact wrappers."""

from __future__ import annotations

from .base import ToolWrapper
from sift_mind.contracts import MCPResponse
from sift_mind.mcp_server.tools.parsers import parse_tshark_conversations, parse_tshark_json


class NetworkToolWrapper(ToolWrapper):
    def parse_pcap_summary(self, pcap_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="parse_pcap_summary",
                artifact_path=pcap_path or "fixture/network.pcap",
                confidence=0.79,
                parsed={
                    "packets": 2304,
                    "conversations": [
                        {"src": "10.0.0.5", "dst": "185.199.108.153", "dst_port": 443, "bytes": 184224}
                    ],
                    "suspicious": ["external HTTPS session from compromised host during execution window"],
                },
            )
        return self._external_tool_response(
            tool_name="parse_pcap_summary",
            artifact_path=pcap_path,
            command=["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"],
            parser=parse_tshark_conversations,
            confidence=0.75,
        )

    def extract_dns_queries(self, pcap_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="extract_dns_queries",
                artifact_path=pcap_path or "fixture/network.pcap",
                confidence=0.81,
                parsed={
                    "queries": [
                        {
                            "timestamp": "2026-06-10T03:18:00Z",
                            "query": "cdn-update.example",
                            "answer": "185.199.108.153",
                        }
                    ]
                },
            )
        return self._external_tool_response(
            tool_name="extract_dns_queries",
            artifact_path=pcap_path,
            command=["tshark", "-r", pcap_path, "-Y", "dns", "-T", "json"],
            parser=lambda raw: parse_tshark_json(raw, "dns"),
            confidence=0.75,
        )

    def get_http_requests(self, pcap_path: str) -> MCPResponse:
        if self.config.mode == "fixture":
            return self._fixture_response(
                tool_name="get_http_requests",
                artifact_path=pcap_path or "fixture/network.pcap",
                confidence=0.72,
                parsed={
                    "requests": [
                        {
                            "timestamp": "2026-06-10T03:18:03Z",
                            "method": "GET",
                            "host": "cdn-update.example",
                            "uri": "/checkin",
                            "user_agent": "Mozilla/5.0",
                        }
                    ]
                },
            )
        return self._external_tool_response(
            tool_name="get_http_requests",
            artifact_path=pcap_path,
            command=["tshark", "-r", pcap_path, "-Y", "http.request", "-T", "json"],
            parser=lambda raw: parse_tshark_json(raw, "http"),
            confidence=0.7,
        )
