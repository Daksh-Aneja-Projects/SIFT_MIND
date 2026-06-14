PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    artifact_path TEXT NOT NULL,
    claim TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('CONFIRMED', 'INFERRED', 'SPECULATIVE')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence_hashes_json TEXT NOT NULL DEFAULT '[]',
    sources_json TEXT NOT NULL DEFAULT '[]',
    contradictions_json TEXT NOT NULL DEFAULT '[]',
    resolved INTEGER NOT NULL DEFAULT 1,
    blocked INTEGER NOT NULL DEFAULT 0,
    resolution_note TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    iteration INTEGER NOT NULL DEFAULT 1,
    mitre_technique TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS contradictions (
    id TEXT PRIMARY KEY,
    finding_a_id TEXT NOT NULL,
    finding_b_id TEXT NOT NULL,
    conflict_description TEXT NOT NULL,
    resolution_suggestion TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    resolution_explanation TEXT NOT NULL DEFAULT '',
    supporting_hashes_json TEXT NOT NULL DEFAULT '[]',
    resolved_at TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS report_sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    content_markdown TEXT NOT NULL,
    finding_ids_json TEXT NOT NULL DEFAULT '[]',
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    raw_hash TEXT NOT NULL,
    command_run TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OK', 'ERROR')),
    token_estimate INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    tool_version TEXT NOT NULL DEFAULT 'unknown',
    error TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT 'deterministic',
    model TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_artifact ON findings(artifact_path);
CREATE INDEX IF NOT EXISTS idx_findings_blocked ON findings(blocked);
CREATE INDEX IF NOT EXISTS idx_contradictions_resolved ON contradictions(resolved);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_executions_status ON tool_executions(status);
CREATE INDEX IF NOT EXISTS idx_tool_executions_raw_hash ON tool_executions(raw_hash);
