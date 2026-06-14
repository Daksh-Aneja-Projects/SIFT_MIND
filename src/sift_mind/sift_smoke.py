"""Manifest-driven SIFT/public-sample smoke runner."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import MCPResponse, ResponseStatus, RunConfig, ToolResult, utc_now
from .ledger.ledger import EpistemicLedger
from .mcp_server.tools.disk import DiskToolWrapper
from .mcp_server.tools.logs import LogToolWrapper
from .mcp_server.tools.memory import MemoryToolWrapper
from .mcp_server.tools.network import NetworkToolWrapper
from .mcp_server.tools.timeline import TimelineToolWrapper
from .report.writer import ReportWriter
from .runtime import readiness_report


class SmokeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = "unnamed-case"
    description: str = ""
    artifacts: dict[str, str] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)
    tools: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)

    @field_validator("tools", "required_tools")
    @classmethod
    def validate_tool_names(cls, values: list[str]) -> list[str]:
        unknown = sorted({value for value in values if value not in SUPPORTED_SMOKE_TOOLS})
        if unknown:
            raise ValueError(f"Unsupported smoke tools: {', '.join(unknown)}")
        return values


@dataclass(frozen=True)
class SmokeToolSpec:
    name: str
    artifact_keys: tuple[str, ...]
    run: Callable[[str], MCPResponse]
    artifact_label: str = ""


def load_smoke_manifest(path: str | Path) -> SmokeManifest:
    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return SmokeManifest.model_validate(data)


def smoke_manifest_schema() -> dict[str, Any]:
    """Return a JSON Schema for public-sample smoke manifests."""

    schema = SmokeManifest.model_json_schema()
    tool_names = sorted(SUPPORTED_SMOKE_TOOLS)
    artifact_keys = sorted({key for spec in _tool_specs_for_selection() for key in spec.artifact_keys})
    schema["$id"] = "https://sift-mind.local/schema/public-sample-manifest.schema.json"
    schema["title"] = "SIFT-MIND Public Sample Smoke Manifest"
    schema["description"] = (
        "Manifest for selecting typed SIFT-MIND forensic wrappers and case artifacts. "
        "Artifact paths may be absolute paths under CASE_ROOT or paths relative to CASE_ROOT."
    )
    schema["x-supported_artifact_keys"] = artifact_keys
    for field in ("tools", "required_tools"):
        schema["properties"][field]["items"] = {
            "type": "string",
            "enum": tool_names,
        }
    schema["properties"]["artifacts"]["description"] = (
        "Artifact path map. Common keys include: " + ", ".join(artifact_keys) + "."
    )
    schema["properties"]["options"]["description"] = (
        "Optional wrapper arguments such as exe_name, hive, registry_key, username, event_ids, "
        "timestamp, window_minutes, ruleset, and timeline_sources."
    )
    return schema


def run_sift_smoke(
    config: RunConfig,
    manifest_path: str | Path,
    output_path: str | Path | None = None,
    *,
    fresh: bool = False,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = load_smoke_manifest(manifest_file)
    output = Path(output_path) if output_path else Path(config.output_dir) / "sift_smoke_report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    if fresh:
        _reset_smoke_outputs(config, output)

    disk = DiskToolWrapper(config)
    memory = MemoryToolWrapper(config)
    logs = LogToolWrapper(config)
    network = NetworkToolWrapper(config)
    timeline = TimelineToolWrapper(config)
    specs = _tool_specs(disk, memory, logs, network, timeline, manifest.options)
    selected = _selected_tools(manifest)
    required = set(manifest.required_tools)
    preflight = build_sift_preflight(config, manifest, selected)
    results: list[dict[str, Any]] = []
    started = utc_now()

    for spec in specs:
        requested = spec.name in selected
        if not requested:
            continue
        artifact = _artifact_for(manifest, spec.artifact_keys)
        if not artifact:
            results.append(
                {
                    "tool_name": spec.name,
                    "status": "SKIPPED",
                    "artifact_keys": list(spec.artifact_keys),
                    "reason": f"Manifest does not define any of: {', '.join(spec.artifact_keys)}",
                    "required": spec.name in required,
                }
            )
            continue
        response = spec.run(artifact)
        results.append(_result_summary(spec.name, spec.artifact_keys, artifact, response, spec.name in required))

    ledger = EpistemicLedger(config.ledger_db_path)
    execution_ingestion = ledger.ingest_execution_log(config.execution_log_path, replace=True)
    writer = ReportWriter(ledger, config.evidence_chain_path, config.execution_log_path)
    verification = writer.verify_evidence_chain()
    counts = Counter(item["status"] for item in results)
    required_skipped = [
        item["tool_name"] for item in results if item["status"] == "SKIPPED" and item.get("required")
    ]
    status = _smoke_status(results, verification, execution_ingestion, required_skipped)
    report = {
        "status": status,
        "case_id": manifest.case_id,
        "description": manifest.description,
        "mode": config.mode,
        "started": started.isoformat(),
        "finished": utc_now().isoformat(),
        "manifest_path": str(manifest_file),
        "output_path": str(output),
        "tool_counts": dict(sorted(counts.items())),
        "tools_requested": sorted(selected),
        "required_tools": sorted(required),
        "preflight": preflight,
        "required_skipped": required_skipped,
        "results": results,
        "evidence_verification": verification,
        "execution_ingestion": execution_ingestion,
        "readiness": _compact_readiness(config),
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return report


def run_sift_preflight(
    config: RunConfig,
    manifest_path: str | Path,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate a public-sample manifest without executing forensic tools."""

    manifest_file = Path(manifest_path)
    manifest = load_smoke_manifest(manifest_file)
    selected = _selected_tools(manifest)
    preflight = build_sift_preflight(config, manifest, selected)
    report = {
        "status": "READY" if preflight["error_count"] == 0 else "ACTION_REQUIRED",
        "case_id": manifest.case_id,
        "description": manifest.description,
        "mode": config.mode,
        "generated": utc_now().isoformat(),
        "manifest_path": str(manifest_file),
        "tools_requested": sorted(selected),
        "required_tools": sorted(manifest.required_tools),
        "preflight": preflight,
        "readiness": _compact_readiness(config),
    }
    if output_path:
        output = Path(output_path)
        output_error = _preflight_output_path_error(config, output)
        if output_error:
            _append_preflight_error(report, output_error)
            return report
        output.parent.mkdir(parents=True, exist_ok=True)
        report["output_path"] = str(output)
        output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return report


SUPPORTED_SMOKE_TOOLS = {
    "analyze_prefetch",
    "get_amcache",
    "parse_mft",
    "list_registry_hives",
    "get_registry_key",
    "extract_shellbags",
    "parse_lnk_files",
    "get_usnjrnl_entries",
    "list_processes",
    "get_network_connections",
    "extract_injected_code",
    "find_hidden_modules",
    "get_handles",
    "scan_memory_yara",
    "parse_evtx",
    "get_security_events",
    "get_logon_events",
    "get_process_creation_events",
    "build_super_timeline",
    "get_artifact_at_time",
    "parse_pcap_summary",
    "extract_dns_queries",
    "get_http_requests",
}


def _tool_specs(
    disk: DiskToolWrapper,
    memory: MemoryToolWrapper,
    logs: LogToolWrapper,
    network: NetworkToolWrapper,
    timeline: TimelineToolWrapper,
    options: dict[str, Any],
) -> list[SmokeToolSpec]:
    exe_name = str(options.get("exe_name", ""))
    key_filter = str(options.get("key_filter", ""))
    path_filter = str(options.get("path_filter", ""))
    time_start = str(options.get("time_start", ""))
    time_end = str(options.get("time_end", ""))
    filename_filter = str(options.get("filename_filter", ""))
    hive = str(options.get("hive", "SYSTEM"))
    registry_key = str(options.get("registry_key", ""))
    username = str(options.get("username", ""))
    pid = int(options.get("pid", 0) or 0)
    ruleset = str(options.get("ruleset", "default"))
    event_ids = _event_ids(options.get("event_ids"))
    sources = str(options.get("timeline_sources", "all"))
    timestamp = str(options.get("timestamp", ""))
    window_minutes = int(options.get("window_minutes", 5) or 5)
    return [
        SmokeToolSpec("analyze_prefetch", ("prefetch", "prefetch_dir"), lambda artifact: disk.analyze_prefetch(artifact, exe_name)),
        SmokeToolSpec("get_amcache", ("amcache",), lambda artifact: disk.get_amcache(artifact, key_filter)),
        SmokeToolSpec("parse_mft", ("mft",), lambda artifact: disk.parse_mft(artifact, path_filter, time_start, time_end)),
        SmokeToolSpec("list_registry_hives", ("registry_root", "registry_dir"), disk.list_registry_hives),
        SmokeToolSpec("get_registry_key", ("registry_hive", "system_hive"), lambda artifact: disk.get_registry_key(artifact, hive, registry_key)),
        SmokeToolSpec("extract_shellbags", ("shellbags", "usrclass"), disk.extract_shellbags),
        SmokeToolSpec("parse_lnk_files", ("lnk_dir", "lnk_files"), lambda artifact: disk.parse_lnk_files(artifact, path_filter)),
        SmokeToolSpec("get_usnjrnl_entries", ("usnjrnl",), lambda artifact: disk.get_usnjrnl_entries(artifact, time_start, time_end, filename_filter)),
        SmokeToolSpec("list_processes", ("memory", "memory_image"), memory.list_processes),
        SmokeToolSpec("get_network_connections", ("memory", "memory_image"), memory.get_network_connections),
        SmokeToolSpec("extract_injected_code", ("memory", "memory_image"), lambda artifact: memory.extract_injected_code(artifact, pid)),
        SmokeToolSpec("find_hidden_modules", ("memory", "memory_image"), memory.find_hidden_modules),
        SmokeToolSpec("get_handles", ("memory", "memory_image"), lambda artifact: memory.get_handles(artifact, pid)),
        SmokeToolSpec("scan_memory_yara", ("memory", "memory_image"), lambda artifact: memory.scan_memory_yara(artifact, ruleset)),
        SmokeToolSpec("parse_evtx", ("evtx", "security_evtx"), lambda artifact: logs.parse_evtx(artifact, event_ids, time_start, time_end)),
        SmokeToolSpec("get_security_events", ("security_evtx", "evtx"), lambda artifact: logs.get_security_events(artifact, username, time_start, time_end)),
        SmokeToolSpec("get_logon_events", ("security_evtx", "evtx"), lambda artifact: logs.get_logon_events(artifact, username, time_start, time_end)),
        SmokeToolSpec("get_process_creation_events", ("security_evtx", "evtx"), lambda artifact: logs.get_process_creation_events(artifact, time_start, time_end)),
        SmokeToolSpec("build_super_timeline", ("case_path",), lambda artifact: timeline.build_super_timeline(artifact, sources)),
        SmokeToolSpec("get_artifact_at_time", ("case_path",), lambda artifact: timeline.get_artifact_at_time(artifact, timestamp, window_minutes)),
        SmokeToolSpec("parse_pcap_summary", ("pcap",), network.parse_pcap_summary),
        SmokeToolSpec("extract_dns_queries", ("pcap",), network.extract_dns_queries),
        SmokeToolSpec("get_http_requests", ("pcap",), network.get_http_requests),
    ]


def _event_ids(raw: Any) -> list[int] | None:
    if raw in (None, ""):
        return None
    if isinstance(raw, list):
        return [int(value) for value in raw]
    return [int(item.strip()) for item in str(raw).split(",") if item.strip()]


def _selected_tools(manifest: SmokeManifest) -> set[str]:
    if manifest.tools:
        return set(manifest.tools) | set(manifest.required_tools)
    inferred: set[str] = set()
    artifact_keys = {key for key, value in manifest.artifacts.items() if value}
    for spec in _tool_specs_for_selection():
        if artifact_keys.intersection(spec.artifact_keys):
            inferred.add(spec.name)
    return inferred | set(manifest.required_tools)


def _tool_specs_for_selection() -> list[SmokeToolSpec]:
    return [
        SmokeToolSpec(name, keys, lambda artifact: MCPResponse.error_response("selection-only"))
        for name, keys in [
            ("analyze_prefetch", ("prefetch", "prefetch_dir")),
            ("get_amcache", ("amcache",)),
            ("parse_mft", ("mft",)),
            ("list_registry_hives", ("registry_root", "registry_dir")),
            ("get_registry_key", ("registry_hive", "system_hive")),
            ("extract_shellbags", ("shellbags", "usrclass")),
            ("parse_lnk_files", ("lnk_dir", "lnk_files")),
            ("get_usnjrnl_entries", ("usnjrnl",)),
            ("list_processes", ("memory", "memory_image")),
            ("get_network_connections", ("memory", "memory_image")),
            ("extract_injected_code", ("memory", "memory_image")),
            ("find_hidden_modules", ("memory", "memory_image")),
            ("get_handles", ("memory", "memory_image")),
            ("scan_memory_yara", ("memory", "memory_image")),
            ("parse_evtx", ("evtx", "security_evtx")),
            ("get_security_events", ("security_evtx", "evtx")),
            ("get_logon_events", ("security_evtx", "evtx")),
            ("get_process_creation_events", ("security_evtx", "evtx")),
            ("build_super_timeline", ("case_path",)),
            ("get_artifact_at_time", ("case_path",)),
            ("parse_pcap_summary", ("pcap",)),
            ("extract_dns_queries", ("pcap",)),
            ("get_http_requests", ("pcap",)),
        ]
    ]


def _artifact_for(manifest: SmokeManifest, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = manifest.artifacts.get(key)
        if value:
            return str(value)
    return ""


def build_sift_preflight(
    config: RunConfig,
    manifest: SmokeManifest,
    selected_tools: set[str] | None = None,
) -> dict[str, Any]:
    selected = selected_tools or _selected_tools(manifest)
    readiness = readiness_report(config)
    selection_specs = {spec.name: spec.artifact_keys for spec in _tool_specs_for_selection()}
    tool_checks = []
    artifact_checks = []
    errors: list[str] = []
    warnings: list[str] = []
    paths = readiness["paths"]

    if config.mode == "sift":
        _collect_sift_path_errors(paths, errors)

    for tool_name in sorted(selected):
        tool_status = readiness["external_tools"].get(tool_name, {})
        available = bool(tool_status.get("available", False))
        required = tool_name in manifest.required_tools
        missing_in_sift = config.mode == "sift" and not available
        check = {
            "tool_name": tool_name,
            "required": required,
            "available": available,
            "candidates": tool_status.get("candidates", []),
            "matches": tool_status.get("matches", {}),
            "internal": bool(tool_status.get("internal", False)),
            "status": "ERROR" if missing_in_sift else "OK",
        }
        if missing_in_sift:
            check["error"] = "Selected SIFT tool is unavailable on PATH."
            errors.append(f"{tool_name}: selected tool unavailable on PATH")
        tool_checks.append(check)

    for tool_name in sorted(selected):
        keys = selection_specs.get(tool_name, ())
        artifact = _artifact_for(manifest, keys)
        if not artifact:
            errors.append(f"{tool_name}: missing manifest artifact for keys {', '.join(keys)}")
            artifact_checks.append(
                {
                    "tool_name": tool_name,
                    "artifact_keys": list(keys),
                    "required": tool_name in manifest.required_tools,
                    "artifact_path": "",
                    "status": "ERROR",
                    "error": f"Manifest does not define any of: {', '.join(keys)}",
                }
            )
            continue
        artifact_checks.append(_artifact_preflight(config, tool_name, keys, artifact, tool_name in manifest.required_tools, errors, warnings))

    unused_artifacts = sorted(
        key for key, value in manifest.artifacts.items() if value and key not in _used_artifact_keys(selected, selection_specs)
    )
    if unused_artifacts:
        warnings.append(f"Manifest defines unused artifact keys: {', '.join(unused_artifacts)}")

    return {
        "status": "READY" if not errors else "ACTION_REQUIRED",
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": errors,
        "warnings": warnings,
        "tool_checks": tool_checks,
        "artifact_checks": artifact_checks,
        "unused_artifacts": unused_artifacts,
        "case_root": readiness["paths"]["case_root"],
        "managed_paths": {
            "output_dir": readiness["paths"]["output_dir"],
            "evidence_chain_parent": readiness["paths"]["evidence_chain_parent"],
            "execution_log_parent": readiness["paths"]["execution_log_parent"],
        },
    }


def _artifact_preflight(
    config: RunConfig,
    tool_name: str,
    keys: tuple[str, ...],
    artifact: str,
    required: bool,
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    check: dict[str, Any] = {
        "tool_name": tool_name,
        "artifact_keys": list(keys),
        "required": required,
        "artifact_path": artifact,
    }
    if config.mode == "fixture":
        check.update({"status": "OK", "fixture_virtual": True})
        return check

    case_root = Path(config.case_root)
    candidate = Path(artifact)
    if not candidate.is_absolute():
        candidate = case_root / candidate
    try:
        resolved = candidate.resolve()
        root = case_root.resolve()
    except OSError as exc:
        message = f"Could not resolve artifact path for {tool_name}: {exc}"
        errors.append(message)
        check.update({"status": "ERROR", "error": message})
        return check

    inside_case_root = resolved == root or root in resolved.parents
    exists = resolved.exists()
    check.update(
        {
            "resolved_path": str(resolved),
            "exists": exists,
            "inside_case_root": inside_case_root,
            "is_file": resolved.is_file(),
            "is_dir": resolved.is_dir(),
        }
    )
    if not inside_case_root:
        message = f"{tool_name}: artifact path is outside CASE_ROOT: {resolved}"
        errors.append(message)
        check.update({"status": "ERROR", "error": message})
        return check
    if not exists:
        message = f"{tool_name}: artifact path does not exist: {resolved}"
        errors.append(message)
        check.update({"status": "ERROR", "error": message})
        return check
    check["status"] = "OK"
    return check


def _collect_sift_path_errors(paths: dict[str, Any], errors: list[str]) -> None:
    case_root = paths["case_root"]
    if not case_root.get("exists"):
        errors.append(f"CASE_ROOT does not exist: {case_root.get('path')}")
    elif not case_root.get("is_dir"):
        errors.append(f"CASE_ROOT is not a directory: {case_root.get('path')}")

    managed_labels = {
        "output_dir": "OUTPUT_DIR",
        "evidence_chain_parent": "EVIDENCE_CHAIN parent",
        "execution_log_parent": "AGENT_EXECUTION_LOG parent",
    }
    for key, label in managed_labels.items():
        item = paths[key]
        if not item.get("outside_case_root"):
            errors.append(f"{label} must be outside CASE_ROOT: {item.get('path')}")
        elif not item.get("writable"):
            errors.append(f"{label} is not writable: {item.get('path')}")


def _preflight_output_path_error(config: RunConfig, output: Path) -> str:
    if config.mode == "fixture":
        return ""
    try:
        resolved = output.resolve()
        root = Path(config.case_root).resolve()
    except OSError as exc:
        return f"Could not resolve preflight report path: {exc}"
    if resolved == root or root in resolved.parents:
        return f"Preflight report path must be outside CASE_ROOT: {resolved}"
    return ""


def _append_preflight_error(report: dict[str, Any], message: str) -> None:
    preflight = report["preflight"]
    preflight["errors"].append(message)
    preflight["error_count"] = len(preflight["errors"])
    preflight["status"] = "ACTION_REQUIRED"
    report["status"] = "ACTION_REQUIRED"
    report["output_path_error"] = message


def _used_artifact_keys(selected: set[str], selection_specs: dict[str, tuple[str, ...]]) -> set[str]:
    used: set[str] = set()
    for tool_name in selected:
        used.update(selection_specs.get(tool_name, ()))
    return used


def _result_summary(
    tool_name: str,
    artifact_keys: tuple[str, ...],
    artifact_path: str,
    response: MCPResponse,
    required: bool,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "tool_name": tool_name,
        "status": response.status.value if isinstance(response.status, ResponseStatus) else str(response.status),
        "artifact_keys": list(artifact_keys),
        "artifact_path": artifact_path,
        "required": required,
        "error": response.error,
    }
    if isinstance(response.result, ToolResult):
        parsed = response.result.parsed
        item.update(
            {
                "raw_hash": response.result.raw_hash,
                "confidence": response.result.confidence,
                "truncated": response.result.truncated,
                "token_estimate": response.result.token_estimate,
                "tool_version": response.result.tool_version,
                "command_run": response.result.command_run,
                "parsed_summary": _parsed_summary(parsed),
            }
        )
    return item


def _parsed_summary(parsed: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {"keys": sorted(parsed.keys())[:30]}
    for key, value in parsed.items():
        if isinstance(value, list):
            summary[f"{key}_count"] = len(value)
        elif isinstance(value, dict):
            summary[f"{key}_keys"] = sorted(value.keys())[:20]
    if "error" in parsed:
        summary["error"] = str(parsed["error"])[:300]
    return summary


def _smoke_status(
    results: list[dict[str, Any]],
    verification: dict[str, Any],
    execution_ingestion: dict[str, Any],
    required_skipped: list[str],
) -> str:
    if not results:
        return "ERROR"
    if verification.get("status") != "VERIFIED" or execution_ingestion.get("status") == "FAILED":
        return "ERROR"
    if any(item["status"] == "ERROR" for item in results):
        return "ERROR"
    if required_skipped:
        return "ERROR"
    if any(item["status"] == "SKIPPED" for item in results):
        return "PARTIAL"
    return "OK"


def _compact_readiness(config: RunConfig) -> dict[str, Any]:
    report = readiness_report(config)
    return {
        "status": report["status"],
        "missing_required_for_sift_mode": report["missing_required_for_sift_mode"],
        "case_root": report["paths"]["case_root"],
        "model_provider": report["model_provider"],
    }


def _reset_smoke_outputs(config: RunConfig, output_path: Path) -> None:
    output_root = Path(config.output_dir).resolve()
    targets = [
        Path(config.evidence_chain_path),
        Path(config.execution_log_path),
        Path(config.ledger_db_path),
        Path(str(config.ledger_db_path) + "-wal"),
        Path(str(config.ledger_db_path) + "-shm"),
        output_path,
    ]
    for target in targets:
        try:
            resolved = target.resolve()
        except OSError as exc:
            raise ValueError(f"Could not resolve smoke output target: {target}: {exc}") from exc
        if output_root not in [resolved, *resolved.parents]:
            raise ValueError(f"Refusing fresh smoke reset outside OUTPUT_DIR: {resolved}")
    for target in targets:
        if target.exists() and target.is_file():
            target.unlink()
