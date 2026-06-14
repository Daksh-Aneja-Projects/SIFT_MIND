"""Configuration loading for local fixture, SIFT, and model-provider runs."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .contracts import ModelConfig, RunConfig


def load_config(
    *,
    case_root: str | None = None,
    output_dir: str | None = None,
    evidence_chain_path: str | None = None,
    execution_log_path: str | None = None,
    ledger_db_path: str | None = None,
    baseline_path: str | None = None,
    mode: str | None = None,
) -> RunConfig:
    default_output = str(Path(tempfile.gettempdir()) / "sift_mind_report")
    output = output_dir or os.environ.get("OUTPUT_DIR", default_output)
    evidence = evidence_chain_path or os.environ.get(
        "EVIDENCE_CHAIN", str(Path(output) / "evidence_chain.log")
    )
    execution = execution_log_path or os.environ.get("AGENT_EXECUTION_LOG", str(Path(output) / "agent_execution_log.jsonl"))
    ledger = ledger_db_path or os.environ.get(
        "LEDGER_DB", str(Path(output) / "sift_mind_ledger.db")
    )
    provider = os.environ.get("SIFT_MIND_MODEL_PROVIDER", "ollama").lower()
    default_model = "qwen2.5-coder:7b" if provider == "ollama" else "gpt-4.1-mini"
    default_fallback = "qwen2.5-coder:3b" if provider == "ollama" else ""
    default_host = (
        os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        if provider == "ollama"
        else os.environ.get("SIFT_MIND_CLOUD_BASE_URL", "https://api.openai.com/v1")
    )
    model = ModelConfig(
        provider=provider,
        model=os.environ.get("SIFT_MIND_MODEL", default_model),
        fallback_model=os.environ.get("SIFT_MIND_FALLBACK_MODEL", default_fallback),
        host=os.environ.get("SIFT_MIND_MODEL_HOST", default_host),
        api_key_env=os.environ.get("SIFT_MIND_CLOUD_API_KEY_ENV", "SIFT_MIND_CLOUD_API_KEY"),
        max_context_tokens=int(os.environ.get("SIFT_MIND_MAX_CONTEXT", "8192")),
        temperature=float(os.environ.get("SIFT_MIND_TEMPERATURE", "0.1")),
        timeout_seconds=int(os.environ.get("SIFT_MIND_MODEL_TIMEOUT", "120")),
    )
    return RunConfig(
        case_root=case_root or os.environ.get("CASE_ROOT", "/mnt/case"),
        output_dir=output,
        evidence_chain_path=evidence,
        execution_log_path=execution,
        ledger_db_path=ledger,
        baseline_path=baseline_path or os.environ.get("SIFT_MIND_BASELINE", ""),
        mode=(mode or os.environ.get("SIFT_MIND_MODE", "fixture")).lower(),
        max_tool_tokens=int(os.environ.get("SIFT_MIND_MAX_TOOL_TOKENS", "4000")),
        model=model,
    )
