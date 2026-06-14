"""Shared data contracts for every SIFT-MIND boundary."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import tempfile
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EpistemicStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    SPECULATIVE = "SPECULATIVE"


class ResponseStatus(str, Enum):
    OK = "OK"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class ModelConfig(BaseModel):
    provider: str = "ollama"
    model: str = "qwen2.5-coder:7b"
    fallback_model: str = "qwen2.5-coder:3b"
    host: str = "http://localhost:11434"
    api_key_env: str = "SIFT_MIND_CLOUD_API_KEY"
    max_context_tokens: int = 8192
    temperature: float = 0.1
    timeout_seconds: int = 120


class RunConfig(BaseModel):
    case_root: str = "/mnt/case"
    output_dir: str = str(Path(tempfile.gettempdir()) / "sift_mind_report")
    evidence_chain_path: str = str(Path(tempfile.gettempdir()) / "sift_mind_report" / "evidence_chain.log")
    execution_log_path: str = str(Path(tempfile.gettempdir()) / "sift_mind_report" / "agent_execution_log.jsonl")
    ledger_db_path: str = str(Path(tempfile.gettempdir()) / "sift_mind_report" / "sift_mind_ledger.db")
    baseline_path: str = ""
    mode: Literal["fixture", "sift"] = "fixture"
    max_tool_tokens: int = 4000
    model: ModelConfig = Field(default_factory=ModelConfig)


class ToolResult(BaseModel):
    tool_name: str
    artifact_path: str
    raw_hash: str
    parsed: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    truncated: bool = False
    token_estimate: int = 0
    timestamp: datetime = Field(default_factory=utc_now)
    tool_version: str = "unknown"
    command_run: str = ""


class ToolExecutionRecord(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    tool_name: str
    artifact_path: str
    raw_hash: str
    command_run: str
    status: Literal["OK", "ERROR"]
    token_estimate: int
    truncated: bool
    confidence: float = Field(ge=0.0, le=1.0)
    tool_version: str = "unknown"
    error: str = ""
    provider: str = "deterministic"
    model: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    artifact_path: str
    claim: str = Field(min_length=1, max_length=1000)
    status: EpistemicStatus
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[ToolResult] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    resolved: bool = True
    blocked: bool = False
    resolution_note: str = ""
    evidence_hashes: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)
    iteration: int = 1
    mitre_technique: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_hashes")
    @classmethod
    def strip_empty_hashes(cls, values: list[str]) -> list[str]:
        return [value for value in values if value]


class Contradiction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    finding_a_id: str
    finding_b_id: str
    conflict_description: str
    resolution_suggestion: str
    resolved: bool = False
    resolution_explanation: str = ""
    supporting_hashes: list[str] = Field(default_factory=list)
    resolved_at: datetime | None = None


class ReportSection(BaseModel):
    name: str
    content_markdown: str
    finding_ids: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)


class MCPResponse(BaseModel):
    status: ResponseStatus
    result: ToolResult | Finding | dict[str, Any] | None = None
    contradictions: list[Contradiction] = Field(default_factory=list)
    blocked_reason: str = ""
    next_suggested_tool: str = ""
    error: str = ""

    @classmethod
    def ok(cls, result: ToolResult | Finding | dict[str, Any] | None = None) -> "MCPResponse":
        return cls(status=ResponseStatus.OK, result=result)

    @classmethod
    def blocked(cls, contradictions: list[Contradiction]) -> "MCPResponse":
        first = contradictions[0] if contradictions else None
        return cls(
            status=ResponseStatus.BLOCKED,
            contradictions=contradictions,
            blocked_reason=first.conflict_description if first else "",
            next_suggested_tool=first.resolution_suggestion if first else "",
        )

    @classmethod
    def error_response(cls, message: str, result: ToolResult | None = None) -> "MCPResponse":
        return cls(status=ResponseStatus.ERROR, result=result, error=message)
