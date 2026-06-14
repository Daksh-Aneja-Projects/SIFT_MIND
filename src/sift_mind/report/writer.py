"""Mechanical report writer that renders only ledger-backed findings."""

from __future__ import annotations

import json
import re
import shutil
import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any

from sift_mind.contracts import EpistemicStatus, Finding, utc_now
from sift_mind.ledger.ledger import EpistemicLedger


class ReportWriter:
    def __init__(
        self,
        ledger: EpistemicLedger,
        evidence_chain_path: str,
        execution_log_path: str | None = None,
        baseline_path: str | None = None,
    ):
        self.ledger = ledger
        self.evidence_chain_path = Path(evidence_chain_path)
        self.execution_log_path = Path(execution_log_path) if execution_log_path else None
        self.baseline_path = Path(baseline_path) if baseline_path else None

    def write_all(self, output_dir: str) -> dict[str, str]:
        contested = self.ledger.get_contested()
        if contested:
            raise RuntimeError(f"Cannot finalize report: {len(contested)} findings are contested.")
        missing = self.ledger.findings_missing_hashes()
        if missing:
            ids = ", ".join(finding.id for finding in missing)
            raise RuntimeError(f"Cannot finalize report: findings missing evidence hashes: {ids}")
        verification = self.verify_evidence_chain()
        if verification["status"] != "VERIFIED":
            raise RuntimeError(f"Cannot finalize report: evidence chain verification failed: {verification}")

        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        paths = {
            "case_narrative": output / "case_narrative.md",
            "executive_summary": output / "executive_summary.md",
            "ioc_summary": output / "ioc_summary.json",
            "accuracy_report": output / "accuracy_report.md",
            "agent_execution_log": output / "agent_execution_log.jsonl",
            "evidence_chain": output / "evidence_chain.log",
        }
        paths["case_narrative"].write_text(self._case_narrative(), encoding="utf-8")
        paths["executive_summary"].write_text(self._executive_summary(), encoding="utf-8")
        paths["ioc_summary"].write_text(json.dumps(self._ioc_summary(), indent=2, sort_keys=True), encoding="utf-8")
        paths["accuracy_report"].write_text(self._accuracy_report(), encoding="utf-8")
        self._write_agent_execution_log(paths["agent_execution_log"])
        if self.evidence_chain_path.exists() and self.evidence_chain_path.resolve() != paths["evidence_chain"].resolve():
            shutil.copyfile(self.evidence_chain_path, paths["evidence_chain"])
        elif not paths["evidence_chain"].exists():
            paths["evidence_chain"].write_text("", encoding="utf-8")
        return {key: str(value) for key, value in paths.items()}

    def verify_evidence_chain(self, evidence_chain_path: str | None = None) -> dict[str, Any]:
        path = Path(evidence_chain_path) if evidence_chain_path else self.evidence_chain_path
        chain = self._read_chain_index(path)
        chain_hashes = chain["hashes"]
        findings = self.ledger.get_all_findings(include_blocked=False)
        required = sorted({raw_hash for finding in findings for raw_hash in finding.evidence_hashes})
        missing = [raw_hash for raw_hash in required if raw_hash not in chain_hashes]
        malformed_count = chain["malformed_count"]
        missing_raw_hash_count = chain["missing_raw_hash_count"]
        missing_record_hash_count = chain["missing_record_hash_count"]
        invalid_record_hash_count = chain["invalid_record_hash_count"]
        chain_link_mismatch_count = chain["chain_link_mismatch_count"]
        execution = self._read_execution_records()
        execution_records_with_raw_hash = [
            record
            for record in execution
            if isinstance(record.get("raw_hash"), str) and record.get("raw_hash")
        ]
        execution_hashes = sorted({record["raw_hash"] for record in execution_records_with_raw_hash})
        execution_records_missing_raw_hash_count = len(execution) - len(execution_records_with_raw_hash)
        missing_execution_records = [raw_hash for raw_hash in sorted(chain_hashes) if raw_hash not in execution_hashes]
        execution_records_missing_chain = [raw_hash for raw_hash in execution_hashes if raw_hash not in chain_hashes]
        return {
            "status": "VERIFIED"
            if (
                not missing
                and malformed_count == 0
                and missing_raw_hash_count == 0
                and missing_record_hash_count == 0
                and invalid_record_hash_count == 0
                and chain_link_mismatch_count == 0
                and execution_records_missing_raw_hash_count == 0
                and not missing_execution_records
                and not execution_records_missing_chain
            )
            else "FAILED",
            "evidence_chain": str(path),
            "findings_checked": len(findings),
            "required_hashes": len(required),
            "chain_hashes": len(chain_hashes),
            "missing_count": len(missing),
            "missing_hashes": missing,
            "records_checked": chain["records_checked"],
            "malformed_count": malformed_count,
            "malformed_lines": chain["malformed_lines"],
            "missing_raw_hash_count": missing_raw_hash_count,
            "missing_raw_hash_lines": chain["missing_raw_hash_lines"],
            "duplicate_hash_count": chain["duplicate_hash_count"],
            "missing_record_hash_count": missing_record_hash_count,
            "missing_record_hash_lines": chain["missing_record_hash_lines"],
            "invalid_record_hash_count": invalid_record_hash_count,
            "invalid_record_hash_lines": chain["invalid_record_hash_lines"],
            "chain_link_mismatch_count": chain_link_mismatch_count,
            "chain_link_mismatch_lines": chain["chain_link_mismatch_lines"],
            "execution_records_checked": len(execution),
            "execution_hashes": len(execution_hashes),
            "execution_records_missing_raw_hash_count": execution_records_missing_raw_hash_count,
            "missing_execution_record_count": len(missing_execution_records),
            "missing_execution_record_hashes": missing_execution_records,
            "execution_record_missing_chain_count": len(execution_records_missing_chain),
            "execution_record_missing_chain_hashes": execution_records_missing_chain,
        }

    def _case_narrative(self) -> str:
        findings = self.ledger.get_all_findings(include_blocked=False)
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            grouped[finding.status.value].append(finding)
        sections = self.ledger.get_report_sections()
        contradictions = self.ledger.get_contradictions()
        lines = [
            "# SIFT-MIND Case Narrative",
            f"Generated: {utc_now().isoformat()}",
            "",
            "## Summary",
            self._summary_sentence(),
            "",
        ]
        if sections:
            lines.append("## Analysis Sections")
            for index, section in enumerate(sections, start=1):
                lines.extend(self._report_section_block(index, section.finding_ids, section.timestamp.isoformat()))
        for status in [EpistemicStatus.CONFIRMED, EpistemicStatus.INFERRED, EpistemicStatus.SPECULATIVE]:
            lines.append(f"## {status.value} Findings")
            if not grouped[status.value]:
                lines.extend(["No findings in this tier.", ""])
                continue
            for finding in grouped[status.value]:
                lines.extend(self._finding_block(finding))
        lines.append("## Contradiction History")
        if not contradictions:
            lines.append("No contradictions were detected.")
        for contradiction in contradictions:
            lines.extend(
                [
                    f"- `{contradiction.id}`",
                    f"  - Conflict: {contradiction.conflict_description}",
                    f"  - Resolved: {contradiction.resolved}",
                    f"  - Resolution: {contradiction.resolution_explanation or 'pending'}",
                ]
            )
        lines.extend(["", "## Evidence Chain", f"Source: `{self.evidence_chain_path}`", ""])
        return "\n".join(lines)

    def _executive_summary(self) -> str:
        summary = self.ledger.get_summary()
        top = self.ledger.get_all_findings(status=EpistemicStatus.CONFIRMED, include_blocked=False)[:5]
        lines = [
            "# Executive Summary",
            f"Generated: {utc_now().isoformat()}",
            "",
            self._summary_sentence(),
            "",
            "## Key Confirmed Findings",
        ]
        if not top:
            lines.append("No confirmed findings were recorded.")
        for finding in top:
            lines.append(f"- {finding.claim} (confidence {finding.confidence:.2f})")
        lines.extend(
            [
                "",
                "## Ledger Counts",
                f"- Confirmed: {summary['confirmed']}",
                f"- Inferred: {summary['inferred']}",
                f"- Speculative: {summary['speculative']}",
                f"- Unresolved contradictions: {summary['unresolved_contradictions']}",
            ]
        )
        return "\n".join(lines)

    def _accuracy_report(self) -> str:
        summary = self.ledger.get_summary()
        contradictions = self.ledger.get_contradictions()
        verification = self.verify_evidence_chain()
        execution = self._read_execution_records()
        baseline = self._baseline_comparison()
        lines = [
            "# SIFT-MIND Accuracy Report",
            f"Generated: {utc_now().isoformat()}",
            "",
            "## Finding Statistics",
            "| Status | Count |",
            "|---|---:|",
            f"| CONFIRMED | {summary['confirmed']} |",
            f"| INFERRED | {summary['inferred']} |",
            f"| SPECULATIVE | {summary['speculative']} |",
            f"| BLOCKED at finalization | {summary['blocked']} |",
            "",
            "## Contradiction Analysis",
            f"- Contradictions detected: {summary['contradictions']}",
            f"- Unresolved contradictions: {summary['unresolved_contradictions']}",
        ]
        for contradiction in contradictions:
            lines.append(
                f"- {contradiction.conflict_description} Resolution: "
                f"{contradiction.resolution_explanation or 'unresolved'}"
            )
        lines.extend(
            [
                "",
                "## Hallucination Prevention",
                f"- BLOCKED events: {len(contradictions)}",
                "- Report finalization refuses unresolved contradictions and unsourced findings.",
                "",
                "## Evidence Integrity",
                f"- Hash chain status: {verification['status']}",
                f"- Required hashes: {verification['required_hashes']}",
                f"- Missing hashes: {verification['missing_count']}",
                f"- Malformed evidence records: {verification['malformed_count']}",
                f"- Evidence records missing raw_hash: {verification['missing_raw_hash_count']}",
                f"- Evidence records missing record_hash: {verification['missing_record_hash_count']}",
                f"- Evidence record hash mismatches: {verification['invalid_record_hash_count']}",
                f"- Evidence chain link mismatches: {verification['chain_link_mismatch_count']}",
                f"- Missing execution records for evidence hashes: {verification['missing_execution_record_count']}",
                f"- Execution records missing chain entries: {verification['execution_record_missing_chain_count']}",
                f"- Tool execution records: {len(execution)}",
                f"- Truncated tool responses: {len([item for item in execution if item.get('truncated')])}",
                f"- Tool errors: {len([item for item in execution if item.get('status') == 'ERROR'])}",
                "",
                "## Baseline Comparison",
                f"- Status: {baseline['status']}",
                f"- Baseline path: {baseline['baseline_path'] or 'not configured'}",
                f"- Expected findings: {baseline['expected_findings_count']}",
                f"- Matched findings: {baseline['matched_findings_count']}",
                f"- Missing expected findings: {', '.join(baseline['missing_finding_ids']) or 'none'}",
                f"- Expected IOCs: {baseline['expected_iocs_count']}",
                f"- Matched IOCs: {baseline['matched_iocs_count']}",
                f"- Missing expected IOCs: {', '.join(baseline['missing_iocs']) or 'none'}",
                "",
                "## Known Limitations",
                "- Fixture mode demonstrates workflow behavior with deterministic public-safe data.",
                "- Real SIFT mode depends on SIFT/Volatility/Plaso/YARA/PCAP tools being installed in the runtime.",
            ]
        )
        return "\n".join(lines)

    def _baseline_comparison(self) -> dict[str, Any]:
        empty = {
            "status": "NOT_CONFIGURED",
            "baseline_path": "",
            "expected_findings_count": 0,
            "matched_findings_count": 0,
            "missing_finding_ids": [],
            "expected_iocs_count": 0,
            "matched_iocs_count": 0,
            "missing_iocs": [],
        }
        if not self.baseline_path:
            return empty
        result = dict(empty)
        result["baseline_path"] = str(self.baseline_path)
        if not self.baseline_path.exists():
            result["status"] = "ERROR"
            result["missing_finding_ids"] = [f"baseline file missing: {self.baseline_path}"]
            return result
        try:
            baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            result["status"] = "ERROR"
            result["missing_finding_ids"] = [f"baseline JSON invalid: {exc}"]
            return result

        findings = self.ledger.get_all_findings(include_blocked=False)
        claims = [(finding.id, finding.claim.lower(), finding.status.value, finding.mitre_technique) for finding in findings]
        expected_findings = baseline.get("expected_findings", [])
        missing_finding_ids: list[str] = []
        matched_findings = 0
        for item in expected_findings:
            if not isinstance(item, dict):
                continue
            expected_id = str(item.get("id", item.get("name", "unnamed")))
            tokens = [str(value).lower() for value in item.get("must_include", []) if str(value)]
            expected_status = str(item.get("status", ""))
            expected_mitre = str(item.get("mitre", ""))
            matched = False
            for _, claim, status, mitre in claims:
                if tokens and not all(token in claim for token in tokens):
                    continue
                if expected_status and expected_status != status:
                    continue
                if expected_mitre and expected_mitre != mitre:
                    continue
                matched = True
                break
            if matched:
                matched_findings += 1
            else:
                missing_finding_ids.append(expected_id)

        expected_iocs = baseline.get("expected_iocs", [])
        observed_iocs = {(item["type"], item["value"]) for item in self._ioc_summary()["iocs"]}
        missing_iocs: list[str] = []
        matched_iocs = 0
        for item in expected_iocs:
            if not isinstance(item, dict):
                continue
            ioc_type = str(item.get("type", ""))
            value = str(item.get("value", ""))
            if (ioc_type, value) in observed_iocs:
                matched_iocs += 1
            else:
                missing_iocs.append(f"{ioc_type}:{value}")

        result.update(
            {
                "status": "MATCHED" if not missing_finding_ids and not missing_iocs else "MISSING_EXPECTED",
                "expected_findings_count": len([item for item in expected_findings if isinstance(item, dict)]),
                "matched_findings_count": matched_findings,
                "missing_finding_ids": missing_finding_ids,
                "expected_iocs_count": len([item for item in expected_iocs if isinstance(item, dict)]),
                "matched_iocs_count": matched_iocs,
                "missing_iocs": missing_iocs,
            }
        )
        return result

    def _ioc_summary(self) -> dict[str, Any]:
        findings = self.ledger.get_all_findings(include_blocked=False)
        iocs: list[dict[str, Any]] = []
        for finding in findings:
            for value in sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", finding.claim))):
                iocs.append(self._ioc("ip", value, finding))
            for value in sorted(set(re.findall(r"\b[A-Fa-f0-9]{32,64}\b", finding.claim))):
                iocs.append(self._ioc("hash", value, finding))
            for value in sorted(set(re.findall(r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd)\b", finding.claim, re.I))):
                iocs.append(self._ioc("file_name", value, finding))
            for source in finding.sources:
                for value in sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", json.dumps(source.parsed)))):
                    iocs.append(self._ioc("ip", value, finding))
        return {"generated": utc_now().isoformat(), "iocs": iocs}

    def _ioc(self, ioc_type: str, value: str, finding: Finding) -> dict[str, Any]:
        return {
            "type": ioc_type,
            "value": value,
            "status": finding.status.value,
            "confidence": finding.confidence,
            "associated_finding": finding.id,
            "mitre": finding.mitre_technique,
        }

    def _write_agent_execution_log(self, destination: Path) -> None:
        if self.execution_log_path and self.execution_log_path.exists():
            if self.execution_log_path.resolve() != destination.resolve():
                shutil.copyfile(self.execution_log_path, destination)
            return
        destination.write_text(self._fallback_agent_execution_log(), encoding="utf-8")

    def _fallback_agent_execution_log(self) -> str:
        if not self.evidence_chain_path.exists():
            return ""
        records = []
        for line in self.evidence_chain_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                record.setdefault("status", "OK")
                record.setdefault("token_estimate", 0)
                record.setdefault("truncated", False)
                records.append(record)
            except json.JSONDecodeError:
                records.append({"raw": line})
        return "\n".join(json.dumps(record, sort_keys=True) for record in records) + ("\n" if records else "")

    def _read_execution_records(self) -> list[dict[str, Any]]:
        ledger_records = self.ledger.get_tool_executions()
        if ledger_records:
            return [record.model_dump(mode="json") for record in ledger_records]
        path = self.execution_log_path
        if not path or not path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"raw": line, "status": "ERROR"})
        return records

    def _summary_sentence(self) -> str:
        summary = self.ledger.get_summary()
        return (
            f"The ledger contains {summary['total']} findings: {summary['confirmed']} confirmed, "
            f"{summary['inferred']} inferred, and {summary['speculative']} speculative. "
            f"Unresolved contradictions at report time: {summary['unresolved_contradictions']}."
        )

    def _finding_block(self, finding: Finding) -> list[str]:
        lines = [
            f"### {finding.claim}",
            f"- Finding ID: `{finding.id}`",
            f"- Status: {finding.status.value}",
            f"- Confidence: {finding.confidence:.2f}",
            f"- MITRE: {finding.mitre_technique or 'not mapped'}",
            f"- Evidence hashes: {', '.join(finding.evidence_hashes)}",
        ]
        if finding.resolution_note:
            lines.append(f"- Resolution note: {finding.resolution_note}")
        if finding.sources:
            lines.append("- Sources:")
            for source in finding.sources:
                lines.append(f"  - {source.tool_name}: `{source.raw_hash}`")
        lines.append("")
        return lines

    def _report_section_block(self, section_number: int, finding_ids: list[str], timestamp: str) -> list[str]:
        lines = [f"### Ledger Section {section_number}", f"- Recorded: {timestamp}"]
        linked_findings = [self.ledger.get_finding(finding_id) for finding_id in finding_ids]
        linked_findings = [finding for finding in linked_findings if finding and not finding.blocked]
        if not linked_findings:
            lines.extend(["- Linked findings: none", ""])
            return lines
        lines.append("- Linked findings:")
        for finding in linked_findings:
            lines.append(
                f"  - `{finding.id}` {finding.status.value} confidence {finding.confidence:.2f}: {finding.claim}"
            )
            lines.append(f"    Evidence hashes: {', '.join(finding.evidence_hashes)}")
        lines.append("")
        return lines

    def _read_chain_index(self, path: Path) -> dict[str, Any]:
        hashes: set[str] = set()
        malformed_lines: list[int] = []
        missing_raw_hash_lines: list[int] = []
        missing_record_hash_lines: list[int] = []
        invalid_record_hash_lines: list[int] = []
        chain_link_mismatch_lines: list[int] = []
        duplicate_hash_count = 0
        records_checked = 0
        previous_record_hash = ""
        if not path.exists():
            return {
                "hashes": hashes,
                "records_checked": records_checked,
                "malformed_count": 0,
                "malformed_lines": malformed_lines,
                "missing_raw_hash_count": 0,
                "missing_raw_hash_lines": missing_raw_hash_lines,
                "duplicate_hash_count": duplicate_hash_count,
                "missing_record_hash_count": 0,
                "missing_record_hash_lines": missing_record_hash_lines,
                "invalid_record_hash_count": 0,
                "invalid_record_hash_lines": invalid_record_hash_lines,
                "chain_link_mismatch_count": 0,
                "chain_link_mismatch_lines": chain_link_mismatch_lines,
            }
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            records_checked += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines.append(line_number)
                continue
            raw_hash = record.get("raw_hash")
            if not isinstance(raw_hash, str) or not raw_hash:
                missing_raw_hash_lines.append(line_number)
            else:
                if raw_hash in hashes:
                    duplicate_hash_count += 1
                hashes.add(raw_hash)
            record_hash = record.get("record_hash")
            if not isinstance(record_hash, str) or not record_hash:
                missing_record_hash_lines.append(line_number)
            else:
                expected_hash = self._evidence_record_hash(record)
                if record_hash != expected_hash:
                    invalid_record_hash_lines.append(line_number)
                previous = record.get("previous_record_hash")
                if previous != previous_record_hash:
                    chain_link_mismatch_lines.append(line_number)
                previous_record_hash = record_hash
        return {
            "hashes": hashes,
            "records_checked": records_checked,
            "malformed_count": len(malformed_lines),
            "malformed_lines": malformed_lines[:20],
            "missing_raw_hash_count": len(missing_raw_hash_lines),
            "missing_raw_hash_lines": missing_raw_hash_lines[:20],
            "duplicate_hash_count": duplicate_hash_count,
            "missing_record_hash_count": len(missing_record_hash_lines),
            "missing_record_hash_lines": missing_record_hash_lines[:20],
            "invalid_record_hash_count": len(invalid_record_hash_lines),
            "invalid_record_hash_lines": invalid_record_hash_lines[:20],
            "chain_link_mismatch_count": len(chain_link_mismatch_lines),
            "chain_link_mismatch_lines": chain_link_mismatch_lines[:20],
        }

    def _evidence_record_hash(self, record: dict[str, Any]) -> str:
        content = {key: value for key, value in record.items() if key != "record_hash"}
        serialized = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialized.encode("utf-8", errors="replace")).hexdigest()
