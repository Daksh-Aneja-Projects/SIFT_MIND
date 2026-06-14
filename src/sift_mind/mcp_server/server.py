"""SIFT-MIND FastMCP server.

The server exposes typed functions only. It does not expose arbitrary shell
execution or evidence mutation endpoints.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sift_mind.config import load_config
from sift_mind.contracts import EpistemicStatus, Finding, ReportSection, RunConfig
from sift_mind.ledger.ledger import EpistemicLedger
from sift_mind.mcp_server.tools.disk import DiskToolWrapper
from sift_mind.mcp_server.tools.logs import LogToolWrapper
from sift_mind.mcp_server.tools.memory import MemoryToolWrapper
from sift_mind.mcp_server.tools.network import NetworkToolWrapper
from sift_mind.mcp_server.tools.timeline import TimelineToolWrapper
from sift_mind.report.writer import ReportWriter


def _load_fastmcp():
    try:
        from mcp.server.fastmcp import FastMCP

        return FastMCP
    except Exception:
        try:
            from fastmcp import FastMCP

            return FastMCP
        except Exception as exc:
            raise RuntimeError(
                "FastMCP is not installed. Install with `pip install -e .[mcp]` or use fixture CLI mode."
            ) from exc


def create_server(config: RunConfig | None = None):
    config = config or load_config()
    FastMCP = _load_fastmcp()
    mcp = FastMCP("SIFT-MIND")

    disk = DiskToolWrapper(config)
    memory = MemoryToolWrapper(config)
    logs = LogToolWrapper(config)
    timeline = TimelineToolWrapper(config)
    network = NetworkToolWrapper(config)
    ledger = EpistemicLedger(config.ledger_db_path)
    writer = ReportWriter(ledger, config.evidence_chain_path, config.execution_log_path, config.baseline_path)

    def dump(response_or_data: Any) -> dict[str, Any]:
        if hasattr(response_or_data, "model_dump"):
            return response_or_data.model_dump(mode="json")
        return response_or_data

    def ingest_execution_records() -> dict[str, Any]:
        return ledger.ingest_execution_log(config.execution_log_path, replace=True)

    def parse_hashes(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        raw = str(value).strip()
        if not raw:
            return []
        if raw.startswith("["):
            parsed = json.loads(raw)
            if not isinstance(parsed, list):
                raise ValueError("source_hashes JSON must be a list.")
            return [str(item).strip() for item in parsed if str(item).strip()]
        return [item.strip() for item in raw.split(",") if item.strip()]

    def parse_metadata(value: Any) -> dict[str, Any]:
        if value is None or value == "":
            return {}
        if isinstance(value, dict):
            return value
        parsed = json.loads(str(value))
        if not isinstance(parsed, dict):
            raise ValueError("metadata_json must decode to an object.")
        return parsed

    @mcp.tool()
    def analyze_prefetch(artifact_path: str, exe_name: str = "") -> dict:
        return dump(disk.analyze_prefetch(artifact_path, exe_name))

    @mcp.tool()
    def get_amcache(artifact_path: str, key_filter: str = "") -> dict:
        return dump(disk.get_amcache(artifact_path, key_filter))

    @mcp.tool()
    def parse_mft(artifact_path: str, path_filter: str = "", time_start: str = "", time_end: str = "") -> dict:
        return dump(disk.parse_mft(artifact_path, path_filter, time_start, time_end))

    @mcp.tool()
    def list_registry_hives(artifact_path: str) -> dict:
        return dump(disk.list_registry_hives(artifact_path))

    @mcp.tool()
    def get_registry_key(artifact_path: str, hive: str, key_path: str) -> dict:
        return dump(disk.get_registry_key(artifact_path, hive, key_path))

    @mcp.tool()
    def extract_shellbags(artifact_path: str) -> dict:
        return dump(disk.extract_shellbags(artifact_path))

    @mcp.tool()
    def parse_lnk_files(artifact_path: str, path_filter: str = "") -> dict:
        return dump(disk.parse_lnk_files(artifact_path, path_filter))

    @mcp.tool()
    def get_usnjrnl_entries(
        artifact_path: str,
        time_start: str = "",
        time_end: str = "",
        filename_filter: str = "",
    ) -> dict:
        return dump(disk.get_usnjrnl_entries(artifact_path, time_start, time_end, filename_filter))

    @mcp.tool()
    def list_processes(memory_path: str, profile: str = "auto") -> dict:
        return dump(memory.list_processes(memory_path, profile))

    @mcp.tool()
    def get_network_connections(memory_path: str) -> dict:
        return dump(memory.get_network_connections(memory_path))

    @mcp.tool()
    def extract_injected_code(memory_path: str, pid: int = 0) -> dict:
        return dump(memory.extract_injected_code(memory_path, pid))

    @mcp.tool()
    def find_hidden_modules(memory_path: str) -> dict:
        return dump(memory.find_hidden_modules(memory_path))

    @mcp.tool()
    def get_handles(memory_path: str, pid: int = 0) -> dict:
        return dump(memory.get_handles(memory_path, pid))

    @mcp.tool()
    def scan_memory_yara(memory_path: str, ruleset: str = "default") -> dict:
        return dump(memory.scan_memory_yara(memory_path, ruleset))

    @mcp.tool()
    def parse_evtx(log_path: str, event_ids: str = "", time_start: str = "", time_end: str = "") -> dict:
        ids = [int(item.strip()) for item in event_ids.split(",") if item.strip()] if event_ids else None
        return dump(logs.parse_evtx(log_path, ids, time_start, time_end))

    @mcp.tool()
    def get_security_events(log_path: str, username: str = "", time_start: str = "", time_end: str = "") -> dict:
        return dump(logs.get_security_events(log_path, username, time_start, time_end))

    @mcp.tool()
    def get_logon_events(log_path: str, username: str = "", time_start: str = "", time_end: str = "") -> dict:
        return dump(logs.get_logon_events(log_path, username, time_start, time_end))

    @mcp.tool()
    def get_process_creation_events(log_path: str, time_start: str = "", time_end: str = "") -> dict:
        return dump(logs.get_process_creation_events(log_path, time_start, time_end))

    @mcp.tool()
    def build_super_timeline(case_path: str, sources: str = "all") -> dict:
        return dump(timeline.build_super_timeline(case_path, sources))

    @mcp.tool()
    def correlate_timestamps(finding_ids: str) -> dict:
        ids = [item.strip() for item in finding_ids.split(",") if item.strip()]
        return dump(timeline.correlate_timestamps(ids))

    @mcp.tool()
    def get_artifact_at_time(case_path: str, timestamp: str, window_minutes: int = 5) -> dict:
        return dump(timeline.get_artifact_at_time(case_path, timestamp, window_minutes))

    @mcp.tool()
    def parse_pcap_summary(pcap_path: str) -> dict:
        return dump(network.parse_pcap_summary(pcap_path))

    @mcp.tool()
    def extract_dns_queries(pcap_path: str) -> dict:
        return dump(network.extract_dns_queries(pcap_path))

    @mcp.tool()
    def get_http_requests(pcap_path: str) -> dict:
        return dump(network.get_http_requests(pcap_path))

    @mcp.tool()
    def ledger_add_finding(
        artifact_path: str,
        claim: str,
        status: str,
        confidence: float,
        source_hashes: str,
        mitre_technique: str = "",
        metadata_json: str = "",
    ) -> dict:
        try:
            hashes = parse_hashes(source_hashes)
            metadata = parse_metadata(metadata_json)
            finding = Finding(
                artifact_path=artifact_path,
                claim=claim,
                status=EpistemicStatus(status),
                confidence=confidence,
                evidence_hashes=hashes,
                timestamp=datetime.now(timezone.utc),
                mitre_technique=mitre_technique,
                metadata=metadata,
            )
        except Exception as exc:
            return {"status": "ERROR", "error": f"Invalid finding payload: {exc}"}
        result_status, contradictions = ledger.add_finding(finding)
        return {
            "status": result_status,
            "finding_id": finding.id,
            "contradictions": [item.model_dump(mode="json") for item in contradictions],
            "blocked_reason": contradictions[0].conflict_description if contradictions else "",
            "next_suggested_tool": contradictions[0].resolution_suggestion if contradictions else "",
        }

    @mcp.tool()
    def ledger_mark_contradiction(finding_a_id: str, finding_b_id: str, description: str) -> dict:
        return ledger.mark_contradiction(finding_a_id, finding_b_id, description).model_dump(mode="json")

    @mcp.tool()
    def ledger_resolve_contradiction(contradiction_id: str, explanation: str, supporting_hashes: str) -> dict:
        try:
            hashes = parse_hashes(supporting_hashes)
        except Exception as exc:
            return {"resolved": False, "status": "ERROR", "error": f"Invalid supporting_hashes payload: {exc}"}
        success = ledger.resolve_contradiction(contradiction_id, explanation, hashes)
        return {"resolved": success}

    @mcp.tool()
    def ledger_get_contested() -> dict:
        contested = ledger.get_contested()
        return {"contested_count": len(contested), "findings": [item.model_dump(mode="json") for item in contested]}

    @mcp.tool()
    def ledger_get_summary() -> dict:
        ingestion = ingest_execution_records()
        summary = ledger.get_summary()
        summary["execution_ingestion"] = ingestion
        return summary

    @mcp.tool()
    def report_write_section(section_name: str, content_markdown: str, finding_ids: str = "") -> dict:
        ids = [item.strip() for item in finding_ids.split(",") if item.strip()]
        missing = [finding_id for finding_id in ids if ledger.get_finding(finding_id) is None]
        if missing:
            return {"status": "ERROR", "error": f"Unknown finding IDs: {', '.join(missing)}"}
        ledger.add_report_section(ReportSection(name=section_name, content_markdown=content_markdown, finding_ids=ids))
        return {"status": "OK"}

    @mcp.tool()
    def report_get_status() -> dict:
        ingestion = ingest_execution_records()
        summary = ledger.get_summary()
        missing_hashes = ledger.findings_missing_hashes()
        ingestion_failed = ingestion["status"] == "FAILED"
        return {
            "status": "BLOCKED"
            if summary["unresolved_contradictions"] or missing_hashes or ingestion_failed
            else "READY",
            "summary": summary,
            "execution_ingestion": ingestion,
            "findings_missing_hashes": [item.id for item in missing_hashes],
        }

    @mcp.tool()
    def report_finalize(output_dir: str = "") -> dict:
        ingestion = ingest_execution_records()
        if ingestion["status"] == "FAILED":
            return {
                "status": "BLOCKED",
                "reason": "Execution log contains malformed records.",
                "execution_ingestion": ingestion,
            }
        contested = ledger.get_contested()
        if contested:
            return {
                "status": "BLOCKED",
                "reason": f"{len(contested)} findings have unresolved contradictions.",
                "contested_finding_ids": [item.id for item in contested],
            }
        missing_hashes = ledger.findings_missing_hashes()
        if missing_hashes:
            return {
                "status": "BLOCKED",
                "reason": "Every report finding must have at least one evidence hash.",
                "finding_ids": [item.id for item in missing_hashes],
            }
        verification = writer.verify_evidence_chain()
        if verification["status"] != "VERIFIED":
            return {"status": "BLOCKED", "reason": "Evidence chain verification failed.", "verification": verification}
        try:
            paths = writer.write_all(output_dir or config.output_dir)
        except RuntimeError as exc:
            return {"status": "BLOCKED", "reason": str(exc)}
        return {"status": "OK", "output_files": paths, "execution_ingestion": ingestion, "evidence_verification": verification}

    return mcp


def run_server(config: RunConfig | None = None) -> None:
    server = create_server(config)
    server.run()


if __name__ == "__main__":
    run_server(load_config())
