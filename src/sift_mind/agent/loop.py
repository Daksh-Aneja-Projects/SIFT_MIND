"""Deterministic fixture runner for the documented SIFT-MIND workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sift_mind.contracts import EpistemicStatus, Finding, ReportSection, RunConfig, ToolResult
from sift_mind.ledger.ledger import EpistemicLedger
from sift_mind.mcp_server.tools.disk import DiskToolWrapper
from sift_mind.mcp_server.tools.logs import LogToolWrapper
from sift_mind.mcp_server.tools.memory import MemoryToolWrapper
from sift_mind.mcp_server.tools.network import NetworkToolWrapper
from sift_mind.mcp_server.tools.timeline import TimelineToolWrapper
from sift_mind.report.writer import ReportWriter


class FixtureAgentRunner:
    """Runs a reproducible end-to-end case without external forensic binaries."""

    def __init__(self, config: RunConfig):
        self.config = config
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        self._reset_fixture_state()
        self.ledger = EpistemicLedger(config.ledger_db_path)
        self.disk = DiskToolWrapper(config)
        self.memory = MemoryToolWrapper(config)
        self.logs = LogToolWrapper(config)
        self.timeline = TimelineToolWrapper(config)
        self.network = NetworkToolWrapper(config)
        self.writer = ReportWriter(
            self.ledger,
            config.evidence_chain_path,
            config.execution_log_path,
            config.baseline_path,
        )

    def _reset_fixture_state(self) -> None:
        if self.config.mode != "fixture":
            return
        for raw_path in [
            self.config.ledger_db_path,
            f"{self.config.ledger_db_path}-wal",
            f"{self.config.ledger_db_path}-shm",
            self.config.evidence_chain_path,
            self.config.execution_log_path,
        ]:
            path = Path(raw_path)
            if path.exists():
                path.unlink()

    def run(self) -> dict[str, Any]:
        self._reconnaissance()
        self._triage()
        self._deep_analysis_with_contradiction()
        self._reporting_section()
        self.ledger.ingest_execution_log(self.config.execution_log_path, replace=True)
        paths = self.writer.write_all(self.config.output_dir)
        verification = self.writer.verify_evidence_chain()
        return {
            "status": "OK",
            "summary": self.ledger.get_summary(),
            "reports": paths,
            "evidence_verification": verification,
        }

    def _reconnaissance(self) -> None:
        self.ledger.add_report_section(
            ReportSection(
                name="Reconnaissance",
                content_markdown=(
                    "Fixture case contains a Windows disk image, paired memory capture, "
                    "Security.evtx logs, and a small PCAP summary. Prior ledger state: "
                    f"{self.ledger.get_summary()}."
                ),
            )
        )

    def _triage(self) -> None:
        timeline = self._tool(self.timeline.build_super_timeline(self.config.case_root, "all"))
        window = timeline.parsed["suspicious_windows"][0]
        self.ledger.add_report_section(
            ReportSection(
                name="Triage Summary",
                content_markdown=(
                    f"Suspicious window identified from {window['start']} to {window['end']}: "
                    f"{window['reason']}"
                ),
            )
        )

    def _deep_analysis_with_contradiction(self) -> None:
        prefetch = self._tool(self.disk.analyze_prefetch("fixture/Windows/Prefetch", "MIMIKATZ.EXE"))
        prefetch_finding = Finding(
            artifact_path=prefetch.artifact_path,
            claim="Prefetch reports MIMIKATZ.EXE executed 3 times, first observed at 2026-06-10T03:17:00Z.",
            status=EpistemicStatus.INFERRED,
            confidence=0.9,
            sources=[prefetch],
            metadata={"run_count": 3},
            mitre_technique="T1003.001",
        )
        self.ledger.add_finding(prefetch_finding)

        mft = self._tool(self.disk.parse_mft("fixture/$MFT", "mimikatz.exe"))
        mft_finding = Finding(
            artifact_path=mft.artifact_path,
            claim="MFT analysis reports MIMIKATZ.EXE run_count=1 for the same execution artifact.",
            status=EpistemicStatus.INFERRED,
            confidence=0.78,
            sources=[mft],
            metadata={"run_count": 1},
            mitre_technique="T1003.001",
        )
        status, contradictions = self.ledger.add_finding(mft_finding)
        if status == "BLOCKED":
            artifact_window = self._tool(
                self.timeline.get_artifact_at_time(self.config.case_root, "2026-06-10T03:17:00Z", 10)
            )
            usn = self._tool(
                self.disk.get_usnjrnl_entries(
                    "fixture/$Extend/$UsnJrnl",
                    "2026-06-10T03:10:00Z",
                    "2026-06-10T03:25:00Z",
                    "mimikatz.exe",
                )
            )
            for contradiction in contradictions:
                self.ledger.resolve_contradiction(
                    contradiction.id,
                    (
                        "A VSS shadow copy at 2026-06-10T03:14:00Z captured earlier filesystem "
                        "state, while Prefetch reflects later executions. The tools are measuring "
                        "different points in the artifact lifecycle."
                    ),
                    [artifact_window.raw_hash, usn.raw_hash],
                )

        process_events = self._tool(self.logs.get_process_creation_events("fixture/Security.evtx"))
        amcache = self._tool(self.disk.get_amcache("fixture/Amcache.hve", "mimikatz"))
        confirmed = Finding(
            artifact_path="fixture/case",
            claim="MIMIKATZ.EXE was executed at 2026-06-10T03:17:00Z from C:\\Users\\admin\\Desktop\\mimikatz.exe.",
            status=EpistemicStatus.CONFIRMED,
            confidence=0.94,
            sources=[prefetch, process_events, amcache],
            mitre_technique="T1003.001",
        )
        self.ledger.add_finding(confirmed)

        handles = self._tool(self.memory.get_handles("fixture/memory.raw", 4821))
        yara = self._tool(self.memory.scan_memory_yara("fixture/memory.raw", "credential"))
        self.ledger.add_finding(
            Finding(
                artifact_path="fixture/memory.raw",
                claim="MIMIKATZ.EXE likely accessed LSASS/SAM credential material based on handles and YARA indicators.",
                status=EpistemicStatus.INFERRED,
                confidence=0.87,
                sources=[handles, yara],
                mitre_technique="T1003.001",
            )
        )

        registry = self._tool(
            self.disk.get_registry_key(
                "fixture/SYSTEM",
                "SYSTEM",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SystemUpdate",
            )
        )
        evtx = self._tool(self.logs.parse_evtx("fixture/Security.evtx", [4698]))
        self.ledger.add_finding(
            Finding(
                artifact_path="fixture/SYSTEM",
                claim="Persistence was established via scheduled task or service-like SystemUpdate configuration at 2026-06-10T03:20:00Z.",
                status=EpistemicStatus.CONFIRMED,
                confidence=0.91,
                sources=[registry, evtx],
                mitre_technique="T1053",
            )
        )

        net = self._tool(self.network.parse_pcap_summary("fixture/network.pcap"))
        dns = self._tool(self.network.extract_dns_queries("fixture/network.pcap"))
        self.ledger.add_finding(
            Finding(
                artifact_path="fixture/network.pcap",
                claim="Host 10.0.0.5 contacted 185.199.108.153 during the credential-access window.",
                status=EpistemicStatus.INFERRED,
                confidence=0.78,
                sources=[net, dns],
                mitre_technique="T1071.001",
            )
        )

    def _reporting_section(self) -> None:
        contested = self.ledger.get_contested()
        finding_ids = [finding.id for finding in self.ledger.get_all_findings(include_blocked=False)]
        self.ledger.add_report_section(
            ReportSection(
                name="Reporting Gate",
                content_markdown=(
                    f"ledger_get_contested returned {len(contested)} contested findings before finalization. "
                    "Report generation proceeds only when this count is zero."
                ),
                finding_ids=finding_ids,
            )
        )

    def _tool(self, response) -> ToolResult:
        if response.status.value != "OK" or not isinstance(response.result, ToolResult):
            raise RuntimeError(f"Tool failed: {response.error or response.status.value}")
        return response.result
