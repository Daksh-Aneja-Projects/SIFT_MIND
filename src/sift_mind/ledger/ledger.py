"""SQLite-backed epistemic ledger."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sift_mind.contracts import (
    Contradiction,
    EpistemicStatus,
    Finding,
    ReportSection,
    ToolExecutionRecord,
    ToolResult,
    utc_now,
)
from sift_mind.contradiction.graph import ContradictionGraph


class EpistemicLedger:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.graph = ContradictionGraph()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with self._connection() as conn:
            conn.executescript(schema)

    def add_finding(self, finding: Finding) -> tuple[str, list[Contradiction]]:
        if finding.sources:
            source_hashes = [source.raw_hash for source in finding.sources]
            finding.evidence_hashes = sorted(set(finding.evidence_hashes + source_hashes))

        existing = self.get_all_findings(include_blocked=False)
        contradictions = self.graph.find_contradictions(finding, existing)
        if contradictions:
            finding.blocked = True
            finding.resolved = False
            finding.contradictions = [item.id for item in contradictions]
            self._insert_or_replace_finding(finding)
            for contradiction in contradictions:
                self._insert_contradiction(contradiction)
            return "BLOCKED", contradictions

        finding.blocked = False
        finding.resolved = True
        self._insert_or_replace_finding(finding)
        return "OK", []

    def mark_contradiction(
        self,
        finding_a_id: str,
        finding_b_id: str,
        description: str,
        suggestion: str = "Run targeted corroborating tools and resolve the contradiction.",
    ) -> Contradiction:
        contradiction = Contradiction(
            finding_a_id=finding_a_id,
            finding_b_id=finding_b_id,
            conflict_description=description,
            resolution_suggestion=suggestion,
        )
        self._insert_contradiction(contradiction)
        with self._connection() as conn:
            conn.execute("UPDATE findings SET blocked = 1, resolved = 0 WHERE id = ?", (finding_a_id,))
        return contradiction

    def resolve_contradiction(
        self,
        contradiction_id: str,
        explanation: str,
        supporting_hashes: list[str],
    ) -> bool:
        resolved_at = utc_now()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT finding_a_id FROM contradictions WHERE id = ?",
                (contradiction_id,),
            ).fetchone()
            if not row:
                return False
            conn.execute(
                """
                UPDATE contradictions
                SET resolved = 1, resolution_explanation = ?, supporting_hashes_json = ?, resolved_at = ?
                WHERE id = ?
                """,
                (explanation, json.dumps(supporting_hashes), resolved_at.isoformat(), contradiction_id),
            )
            finding_id = row["finding_a_id"]
            remaining = conn.execute(
                """
                SELECT COUNT(*) AS count FROM contradictions
                WHERE finding_a_id = ? AND resolved = 0
                """,
                (finding_id,),
            ).fetchone()["count"]
            if remaining == 0:
                finding = self.get_finding(finding_id)
                merged_hashes = sorted(set((finding.evidence_hashes if finding else []) + supporting_hashes))
                conn.execute(
                    """
                    UPDATE findings
                    SET blocked = 0, resolved = 1, resolution_note = ?, evidence_hashes_json = ?
                    WHERE id = ?
                    """,
                    (explanation, json.dumps(merged_hashes), finding_id),
                )
        return True

    def upgrade_status(
        self,
        finding_id: str,
        new_status: EpistemicStatus,
        new_confidence: float,
        additional_source_hash: str = "",
    ) -> bool:
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        hashes = sorted(set(finding.evidence_hashes + ([additional_source_hash] if additional_source_hash else [])))
        with self._connection() as conn:
            conn.execute(
                "UPDATE findings SET status = ?, confidence = ?, evidence_hashes_json = ? WHERE id = ?",
                (new_status.value, new_confidence, json.dumps(hashes), finding_id),
            )
        return True

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._row_to_finding(row) if row else None

    def get_all_findings(
        self,
        status: EpistemicStatus | None = None,
        include_blocked: bool = True,
    ) -> list[Finding]:
        query = "SELECT * FROM findings"
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status.value)
        if not include_blocked:
            clauses.append("blocked = 0")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY confidence DESC, timestamp ASC"
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def get_contested(self) -> list[Finding]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE blocked = 1 OR resolved = 0 ORDER BY timestamp ASC"
            ).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def get_contradictions(self, include_resolved: bool = True) -> list[Contradiction]:
        query = "SELECT * FROM contradictions"
        if not include_resolved:
            query += " WHERE resolved = 0"
        query += " ORDER BY resolved ASC, resolved_at ASC"
        with self._connection() as conn:
            rows = conn.execute(query).fetchall()
        return [self._row_to_contradiction(row) for row in rows]

    def get_summary(self) -> dict[str, Any]:
        findings = self.get_all_findings()
        counts = {status.value: 0 for status in EpistemicStatus}
        blocked = 0
        for finding in findings:
            counts[finding.status.value] += 1
            blocked += 1 if finding.blocked else 0
        avg = sum(item.confidence for item in findings) / max(len(findings), 1)
        contradictions = self.get_contradictions()
        tool_executions = self.get_tool_executions()
        return {
            "total": len(findings),
            "confirmed": counts["CONFIRMED"],
            "inferred": counts["INFERRED"],
            "speculative": counts["SPECULATIVE"],
            "blocked": blocked,
            "contradictions": len(contradictions),
            "unresolved_contradictions": len([item for item in contradictions if not item.resolved]),
            "avg_confidence": round(avg, 4),
            "tool_executions": len(tool_executions),
            "tool_errors": len([item for item in tool_executions if item.status == "ERROR"]),
            "tool_truncated": len([item for item in tool_executions if item.truncated]),
        }

    def add_report_section(self, section: ReportSection) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO report_sections (name, content_markdown, finding_ids_json, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (
                    section.name,
                    section.content_markdown,
                    json.dumps(section.finding_ids),
                    section.timestamp.isoformat(),
                ),
            )

    def get_report_sections(self) -> list[ReportSection]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM report_sections ORDER BY id ASC").fetchall()
        return [
            ReportSection(
                name=row["name"],
                content_markdown=row["content_markdown"],
                finding_ids=json.loads(row["finding_ids_json"]),
                timestamp=row["timestamp"],
            )
            for row in rows
        ]

    def findings_missing_hashes(self) -> list[Finding]:
        return [
            finding
            for finding in self.get_all_findings(include_blocked=False)
            if not finding.evidence_hashes
        ]

    def record_tool_execution(self, record: ToolExecutionRecord) -> None:
        with self._connection() as conn:
            self._insert_tool_execution(conn, record)

    def ingest_execution_log(self, execution_log_path: str, replace: bool = False) -> dict[str, Any]:
        path = Path(execution_log_path)
        stats: dict[str, Any] = {
            "status": "OK" if path.exists() else "MISSING",
            "path": str(path),
            "records_seen": 0,
            "inserted": 0,
            "malformed_count": 0,
            "malformed_lines": [],
        }
        with self._connection() as conn:
            if replace:
                conn.execute("DELETE FROM tool_executions")
            if not path.exists():
                return stats
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                stats["records_seen"] += 1
                try:
                    record = ToolExecutionRecord.model_validate(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    stats["malformed_count"] += 1
                    if len(stats["malformed_lines"]) < 20:
                        stats["malformed_lines"].append(line_number)
                    continue
                self._insert_tool_execution(conn, record)
                stats["inserted"] += 1
        if stats["malformed_count"]:
            stats["status"] = "FAILED"
        return stats

    def get_tool_executions(self, status: str | None = None) -> list[ToolExecutionRecord]:
        query = "SELECT * FROM tool_executions"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY id ASC"
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_tool_execution(row) for row in rows]

    def _insert_or_replace_finding(self, finding: Finding) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, artifact_path, claim, status, confidence, evidence_hashes_json,
                    sources_json, contradictions_json, resolved, blocked, resolution_note,
                    timestamp, iteration, mitre_technique, metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.artifact_path,
                    finding.claim,
                    finding.status.value,
                    finding.confidence,
                    json.dumps(finding.evidence_hashes),
                    json.dumps([source.model_dump(mode="json") for source in finding.sources]),
                    json.dumps(finding.contradictions),
                    1 if finding.resolved else 0,
                    1 if finding.blocked else 0,
                    finding.resolution_note,
                    finding.timestamp.isoformat(),
                    finding.iteration,
                    finding.mitre_technique,
                    json.dumps(finding.metadata),
                ),
            )

    def _insert_tool_execution(self, conn: sqlite3.Connection, record: ToolExecutionRecord) -> None:
        conn.execute(
            """
            INSERT INTO tool_executions (
                timestamp, tool_name, artifact_path, raw_hash, command_run, status,
                token_estimate, truncated, confidence, tool_version, error, provider, model
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.timestamp.isoformat(),
                record.tool_name,
                record.artifact_path,
                record.raw_hash,
                record.command_run,
                record.status,
                record.token_estimate,
                1 if record.truncated else 0,
                record.confidence,
                record.tool_version,
                record.error,
                record.provider,
                record.model,
            ),
        )

    def _insert_contradiction(self, contradiction: Contradiction) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO contradictions (
                    id, finding_a_id, finding_b_id, conflict_description, resolution_suggestion,
                    resolved, resolution_explanation, supporting_hashes_json, resolved_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    contradiction.id,
                    contradiction.finding_a_id,
                    contradiction.finding_b_id,
                    contradiction.conflict_description,
                    contradiction.resolution_suggestion,
                    1 if contradiction.resolved else 0,
                    contradiction.resolution_explanation,
                    json.dumps(contradiction.supporting_hashes),
                    contradiction.resolved_at.isoformat() if contradiction.resolved_at else None,
                ),
            )

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        sources = [ToolResult.model_validate(item) for item in json.loads(row["sources_json"])]
        return Finding(
            id=row["id"],
            artifact_path=row["artifact_path"],
            claim=row["claim"],
            status=EpistemicStatus(row["status"]),
            confidence=row["confidence"],
            evidence_hashes=json.loads(row["evidence_hashes_json"]),
            sources=sources,
            contradictions=json.loads(row["contradictions_json"]),
            resolved=bool(row["resolved"]),
            blocked=bool(row["blocked"]),
            resolution_note=row["resolution_note"],
            timestamp=row["timestamp"],
            iteration=row["iteration"],
            mitre_technique=row["mitre_technique"],
            metadata=json.loads(row["metadata_json"]),
        )

    def _row_to_contradiction(self, row: sqlite3.Row) -> Contradiction:
        return Contradiction(
            id=row["id"],
            finding_a_id=row["finding_a_id"],
            finding_b_id=row["finding_b_id"],
            conflict_description=row["conflict_description"],
            resolution_suggestion=row["resolution_suggestion"],
            resolved=bool(row["resolved"]),
            resolution_explanation=row["resolution_explanation"],
            supporting_hashes=json.loads(row["supporting_hashes_json"]),
            resolved_at=row["resolved_at"],
        )

    def _row_to_tool_execution(self, row: sqlite3.Row) -> ToolExecutionRecord:
        return ToolExecutionRecord(
            timestamp=row["timestamp"],
            tool_name=row["tool_name"],
            artifact_path=row["artifact_path"],
            raw_hash=row["raw_hash"],
            command_run=row["command_run"],
            status=row["status"],
            token_estimate=row["token_estimate"],
            truncated=bool(row["truncated"]),
            confidence=row["confidence"],
            tool_version=row["tool_version"],
            error=row["error"],
            provider=row["provider"],
            model=row["model"],
        )
