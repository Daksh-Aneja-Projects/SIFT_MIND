"""Ledger-only model briefing for local Ollama or cloud-compatible models."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sift_mind.contracts import RunConfig, utc_now
from sift_mind.ledger.ledger import EpistemicLedger
from sift_mind.model_provider import ModelClient, ModelProviderError, build_model_client


MODEL_BRIEF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {"type": "string"},
        "executive_bullets": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "evidence_hashes": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["text", "finding_ids", "evidence_hashes"],
            },
        },
        "open_questions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "question": {"type": "string"},
                    "reason": {"type": "string"},
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "evidence_hashes": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["question", "reason", "finding_ids", "evidence_hashes"],
            },
        },
        "handoff": {"type": "string"},
    },
    "required": ["status", "executive_bullets", "open_questions", "handoff"],
}


def generate_model_case_brief(
    ledger: EpistemicLedger,
    config: RunConfig,
    *,
    client: ModelClient | None = None,
    max_findings: int = 20,
) -> dict[str, Any]:
    """Generate a bounded model brief and reject uncited model claims.

    The brief is intentionally not an input to report finalization. It is a
    reviewer aid produced from a compact ledger snapshot, with citation checks
    that force every accepted bullet to point back to ledger finding IDs and
    evidence hashes.
    """

    snapshot = _ledger_snapshot(ledger, max_findings=max_findings)
    prompt = _model_brief_prompt(snapshot)
    model_client = client or build_model_client(config.model)
    try:
        response = model_client.generate_json(prompt, MODEL_BRIEF_SCHEMA)
    except ModelProviderError as exc:
        return {
            "status": "ERROR",
            "error": str(exc),
            "source_policy": "ledger_only_model_brief_not_report_source",
            "snapshot_hash": _snapshot_hash(snapshot),
            "generated": utc_now().isoformat(),
        }

    return validate_model_brief(response, snapshot, config)


def validate_model_brief(response: dict[str, Any], snapshot: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    metadata = response.get("_metadata", {}) if isinstance(response, dict) else {}
    body = {key: value for key, value in response.items() if key != "_metadata"} if isinstance(response, dict) else {}
    known_findings = {item["id"]: item for item in snapshot["findings"]}
    known_hashes = {
        raw_hash
        for item in snapshot["findings"]
        for raw_hash in item["evidence_hashes"]
    }
    validation_errors: list[str] = []
    bullets = body.get("executive_bullets", [])
    questions = body.get("open_questions", [])
    if not isinstance(bullets, list):
        validation_errors.append("executive_bullets must be a list")
        bullets = []
    if not isinstance(questions, list):
        validation_errors.append("open_questions must be a list")
        questions = []
    if snapshot["findings"] and not bullets:
        validation_errors.append("at least one executive bullet is required when ledger findings exist")

    validation_warnings: list[str] = []
    sanitized_bullets = _sanitize_items(
        bullets,
        text_key="text",
        known_findings=known_findings,
        known_hashes=known_hashes,
        validation_errors=validation_errors,
        validation_warnings=validation_warnings,
        require_citation=True,
        drop_invalid=False,
    )
    sanitized_questions = _sanitize_items(
        questions,
        text_key="question",
        known_findings=known_findings,
        known_hashes=known_hashes,
        validation_errors=validation_errors,
        validation_warnings=validation_warnings,
        require_citation=False,
        drop_invalid=True,
    )
    if str(body.get("handoff", "")).strip():
        validation_warnings.append("model handoff text discarded; deterministic ledger handoff used")
    status = "OK" if not validation_errors else "ERROR"
    return {
        "status": status,
        "generated": utc_now().isoformat(),
        "source_policy": "ledger_only_model_brief_not_report_source",
        "model": {
            "provider": metadata.get("provider", config.model.provider),
            "model": metadata.get("model", config.model.model),
            "fallback_used": bool(metadata.get("fallback_used", False)),
        },
        "snapshot_hash": _snapshot_hash(snapshot),
        "ledger_summary": snapshot["summary"],
        "executive_bullets": sanitized_bullets,
        "open_questions": sanitized_questions,
        "handoff": _deterministic_handoff(snapshot),
        "validation": {
            "status": "PASS" if not validation_errors else "FAIL",
            "errors": validation_errors,
            "warnings": validation_warnings,
            "known_finding_count": len(known_findings),
            "known_evidence_hash_count": len(known_hashes),
        },
    }


def write_model_case_brief(
    ledger: EpistemicLedger,
    config: RunConfig,
    output_path: str | Path,
    *,
    client: ModelClient | None = None,
) -> dict[str, Any]:
    brief = generate_model_case_brief(ledger, config, client=client)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(brief, indent=2, sort_keys=True, default=str), encoding="utf-8")
    brief["path"] = str(path)
    return brief


def _ledger_snapshot(ledger: EpistemicLedger, *, max_findings: int) -> dict[str, Any]:
    findings = ledger.get_all_findings(include_blocked=False)[:max_findings]
    contradictions = ledger.get_contradictions()
    return {
        "summary": ledger.get_summary(),
        "findings": [
            {
                "id": finding.id,
                "claim": finding.claim,
                "status": finding.status.value,
                "confidence": finding.confidence,
                "artifact_path": finding.artifact_path,
                "evidence_hashes": finding.evidence_hashes,
                "mitre_technique": finding.mitre_technique,
            }
            for finding in findings
        ],
        "contradictions": [
            {
                "id": contradiction.id,
                "conflict_description": contradiction.conflict_description,
                "resolved": contradiction.resolved,
                "resolution_explanation": contradiction.resolution_explanation,
                "supporting_hashes": contradiction.supporting_hashes,
            }
            for contradiction in contradictions
        ],
    }


def _model_brief_prompt(snapshot: dict[str, Any]) -> str:
    compact = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return (
        "Create a compact SIFT-MIND case brief from this ledger snapshot only. "
        "Do not invent facts. Every executive_bullets item must cite one or more finding_ids "
        "and evidence_hashes from the snapshot. Open questions may be empty, but any open "
        "question that mentions evidence must cite the relevant finding_ids and evidence_hashes. "
        "Return JSON matching the provided schema.\n\n"
        f"LEDGER_SNAPSHOT_JSON={compact}"
    )


def _deterministic_handoff(snapshot: dict[str, Any]) -> str:
    summary = snapshot["summary"]
    unresolved = int(summary.get("unresolved_contradictions", 0))
    if unresolved:
        return f"Resolve {unresolved} unresolved contradiction(s) before report finalization."
    if int(summary.get("total", 0)) == 0:
        return "No ledger findings are available yet; continue evidence collection before reporting."
    return "No unresolved contradictions remain; review ledger-cited findings and proceed to report/package verification."


def _sanitize_items(
    items: list[Any],
    *,
    text_key: str,
    known_findings: dict[str, dict[str, Any]],
    known_hashes: set[str],
    validation_errors: list[str],
    validation_warnings: list[str],
    require_citation: bool,
    drop_invalid: bool,
) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        item_errors: list[str] = []
        if not isinstance(item, dict):
            item_errors.append(f"{text_key} item {index} must be an object")
            if drop_invalid:
                validation_warnings.extend(f"{error}; item dropped" for error in item_errors)
            else:
                validation_errors.extend(item_errors)
            continue
        text = str(item.get(text_key, "")).strip()[:500]
        finding_ids = _string_list(item.get("finding_ids", []))
        evidence_hashes = _string_list(item.get("evidence_hashes", []))
        unknown_findings = sorted(finding_id for finding_id in finding_ids if finding_id not in known_findings)
        unknown_hashes = sorted(raw_hash for raw_hash in evidence_hashes if raw_hash not in known_hashes)
        cited_hashes = {
            raw_hash
            for finding_id in finding_ids
            if finding_id in known_findings
            for raw_hash in known_findings[finding_id]["evidence_hashes"]
        }
        mismatched_hashes = sorted(raw_hash for raw_hash in evidence_hashes if raw_hash in known_hashes and raw_hash not in cited_hashes)
        if require_citation and (not finding_ids or not evidence_hashes):
            item_errors.append(f"{text_key} item {index} must cite finding_ids and evidence_hashes")
        if unknown_findings:
            item_errors.append(f"{text_key} item {index} cites unknown finding IDs: {', '.join(unknown_findings)}")
        if unknown_hashes:
            item_errors.append(f"{text_key} item {index} cites unknown evidence hashes: {', '.join(unknown_hashes)}")
        if mismatched_hashes:
            item_errors.append(
                f"{text_key} item {index} cites hashes not attached to its finding_ids: {', '.join(mismatched_hashes)}"
            )
        if item_errors and drop_invalid:
            validation_warnings.extend(f"{error}; item dropped" for error in item_errors)
            continue
        validation_errors.extend(item_errors)
        sanitized_item = {
            text_key: text,
            "finding_ids": finding_ids,
            "evidence_hashes": evidence_hashes,
        }
        if text_key == "question":
            sanitized_item["reason"] = str(item.get("reason", "")).strip()[:500]
        sanitized.append(sanitized_item)
    return sanitized


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _snapshot_hash(snapshot: dict[str, Any]) -> str:
    serialized = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
