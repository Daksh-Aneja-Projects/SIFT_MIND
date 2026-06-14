"""Production readiness audit for the SIFT-MIND deliverable."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .contracts import RunConfig
from .runtime import TOOL_GROUPS, readiness_report
from .submission import REPORT_FILES, collect_project_files, sha256_file


DOCUMENTED_MARKDOWN_FILES = {
    "README.md",
    "README (1).md",
    "BUILD.md",
    "SPEC.md",
    "ARCHITECTURE.md",
    "DESIGN.md",
    "PROMPTS.md",
    "SKILLS.md",
    "DEMO_SCRIPT.md",
    "SUBMISSION.md",
    "case_data/README.md",
}

FORENSIC_TOOL_NAMES = set(TOOL_GROUPS)
LEDGER_REPORT_TOOL_NAMES = {
    "ledger_add_finding",
    "ledger_mark_contradiction",
    "ledger_resolve_contradiction",
    "ledger_get_contested",
    "ledger_get_summary",
    "report_write_section",
    "report_get_status",
    "report_finalize",
}
MCP_TOOL_NAMES = FORENSIC_TOOL_NAMES | LEDGER_REPORT_TOOL_NAMES
PROMPT_PHASES = {"reconnaissance", "triage", "deep analysis", "reporting"}
STALE_MARKDOWN_REFERENCES = {
    "src/sift_mind/mcp_server/tools/_base.py",
    "sift_mind.mcp_server.tools._base",
    "from ._base import",
    "from .models import",
    "from ..ledger.models import",
    "sift_mind.ledger.models",
    "models.py           # Finding",
    "hasher.py       # Evidence hasher",
    "report/templates",
    "prefetch-hash>=1.0",
    "pytsk3>=20230125",
}

MARKDOWN_REQUIREMENT_TRACE = [
    {
        "id": "markdown_vision_preservation",
        "sources": sorted(DOCUMENTED_MARKDOWN_FILES),
        "implementation": [
            "src/sift_mind/production_audit.py",
            "src/sift_mind/submission.py",
        ],
        "tests": [
            "tests/test_production_audit.py",
            "tests/test_submission.py",
        ],
        "tokens": [
            "DOCUMENTED_MARKDOWN_FILES",
            "markdown_vision_files_present",
            "collect_project_files",
        ],
    },
    {
        "id": "four_phase_agent_workflow",
        "sources": ["PROMPTS.md", "DESIGN.md", "README.md", "SPEC.md"],
        "implementation": [
            "src/sift_mind/agent/prompts.py",
            "src/sift_mind/agent/loop.py",
        ],
        "tests": ["tests/test_fixture_runner.py"],
        "tokens": [
            "reconnaissance",
            "triage",
            "deep analysis",
            "reporting",
            "ledger_get_contested",
        ],
    },
    {
        "id": "typed_mcp_security_boundary",
        "sources": ["ARCHITECTURE.md", "SKILLS.md", "SPEC.md", "README.md"],
        "implementation": [
            "src/sift_mind/contracts.py",
            "src/sift_mind/mcp_server/server.py",
            "src/sift_mind/mcp_server/tools/base.py",
        ],
        "tests": [
            "tests/test_mcp_server.py",
            "tests/test_tools.py",
        ],
        "tokens": [
            "@mcp.tool()",
            "ToolResult",
            "MCPResponse",
            "_bound_tokens",
        ],
    },
    {
        "id": "no_generic_shell_and_case_write_safety",
        "sources": ["ARCHITECTURE.md", "SKILLS.md", "BUILD.md"],
        "implementation": [
            "src/sift_mind/mcp_server/server.py",
            "src/sift_mind/mcp_server/tools/base.py",
            "src/sift_mind/sift_smoke.py",
        ],
        "tests": [
            "tests/test_tools.py",
            "tests/test_sift_smoke.py",
        ],
        "tokens": [
            "_validate_artifact_path",
            "_validate_generated_output_path",
            "_validate_managed_paths_outside_case_root",
            "outside CASE_ROOT",
        ],
    },
    {
        "id": "cryptographic_evidence_chain",
        "sources": ["ARCHITECTURE.md", "DESIGN.md", "SPEC.md", "README.md"],
        "implementation": [
            "src/sift_mind/contracts.py",
            "src/sift_mind/mcp_server/tools/base.py",
            "src/sift_mind/report/writer.py",
        ],
        "tests": [
            "tests/test_tools.py",
            "tests/test_ledger_report.py",
        ],
        "tokens": [
            "raw_hash",
            "previous_record_hash",
            "record_hash",
            "verify_evidence_chain",
            "generated_outputs",
        ],
    },
    {
        "id": "sqlite_epistemic_ledger",
        "sources": ["DESIGN.md", "SPEC.md", "ARCHITECTURE.md", "README.md"],
        "implementation": [
            "src/sift_mind/contracts.py",
            "src/sift_mind/ledger/ledger.py",
            "src/sift_mind/ledger/schema.sql",
        ],
        "tests": [
            "tests/test_ledger_report.py",
            "tests/test_mcp_server.py",
        ],
        "tokens": [
            "CONFIRMED",
            "INFERRED",
            "SPECULATIVE",
            "PRAGMA journal_mode=WAL",
            "get_summary",
        ],
    },
    {
        "id": "contradiction_hard_blocking",
        "sources": ["DESIGN.md", "ARCHITECTURE.md", "SPEC.md", "DEMO_SCRIPT.md"],
        "implementation": [
            "src/sift_mind/contradiction/graph.py",
            "src/sift_mind/ledger/ledger.py",
            "src/sift_mind/mcp_server/server.py",
        ],
        "tests": [
            "tests/test_contradiction_graph.py",
            "tests/test_ledger_report.py",
            "tests/test_mcp_server.py",
        ],
        "tokens": [
            "ContradictionGraph",
            "BLOCKED",
            "get_contested",
            "resolve_contradiction",
            "unresolved contradictions",
        ],
    },
    {
        "id": "ledger_only_report_generation",
        "sources": ["ARCHITECTURE.md", "DESIGN.md", "SPEC.md", "SUBMISSION.md"],
        "implementation": [
            "src/sift_mind/report/writer.py",
            "src/sift_mind/mcp_server/server.py",
        ],
        "tests": [
            "tests/test_fixture_runner.py",
            "tests/test_ledger_report.py",
            "tests/test_mcp_server.py",
        ],
        "tokens": [
            "get_all_findings",
            "findings_missing_hashes",
            "case_narrative",
            "executive_summary",
            "ioc_summary",
            "accuracy_report",
        ],
    },
    {
        "id": "documented_tool_coverage",
        "sources": ["SKILLS.md", "SPEC.md", "README.md"],
        "implementation": [
            "src/sift_mind/runtime.py",
            "src/sift_mind/mcp_server/server.py",
            "src/sift_mind/mcp_server/tools/disk.py",
            "src/sift_mind/mcp_server/tools/memory.py",
            "src/sift_mind/mcp_server/tools/logs.py",
            "src/sift_mind/mcp_server/tools/network.py",
            "src/sift_mind/mcp_server/tools/timeline.py",
        ],
        "tests": [
            "tests/test_runtime.py",
            "tests/test_tools.py",
        ],
        "tokens": sorted(FORENSIC_TOOL_NAMES),
    },
    {
        "id": "structured_parsers_and_sift_smoke",
        "sources": ["SKILLS.md", "BUILD.md", "case_data/README.md", "README (1).md"],
        "implementation": [
            "src/sift_mind/mcp_server/tools/parsers.py",
            "src/sift_mind/sift_smoke.py",
            "case_data/public_sample_manifest.schema.json",
            "case_data/public_sample_manifest.example.json",
            "scripts/sift_mode_smoke.sh",
            "scripts/sift_mode_smoke_wsl.ps1",
        ],
        "tests": [
            "tests/test_parsers.py",
            "tests/test_sift_smoke.py",
        ],
        "tokens": [
            "parse_prefetch",
            "parse_evtx",
            "parse_tshark_json",
            "run_sift_preflight",
            "run_sift_smoke",
            "required_tools",
        ],
    },
    {
        "id": "local_ollama_and_cloud_model_path",
        "sources": ["README.md", "BUILD.md", "SPEC.md", "SUBMISSION.md"],
        "implementation": [
            ".env.example",
            "src/sift_mind/agent/model_brief.py",
            "src/sift_mind/config.py",
            "src/sift_mind/model_provider.py",
            "src/sift_mind/runtime.py",
            "src/sift_mind/run.py",
        ],
        "tests": [
            "tests/test_model_brief.py",
            "tests/test_model_provider.py",
            "tests/test_runtime.py",
        ],
        "tokens": [
            "generate_model_case_brief",
            "ledger_only_model_brief_not_report_source",
            "model-brief",
            "OllamaClient",
            "OpenAICompatibleClient",
            "qwen2.5-coder:7b",
            "qwen2.5-coder:3b",
            "SIFT_MIND_MODEL_PROVIDER",
            "LOCAL_HARDWARE_PROFILE",
        ],
    },
    {
        "id": "fixture_money_shot_demo",
        "sources": ["DEMO_SCRIPT.md", "README.md", "BUILD.md", "case_data/README.md"],
        "implementation": [
            "src/sift_mind/agent/loop.py",
            "src/sift_mind/mcp_server/tools/disk.py",
            "src/sift_mind/mcp_server/tools/timeline.py",
            "case_data/fixture_baseline.json",
        ],
        "tests": [
            "tests/test_fixture_runner.py",
            "tests/test_ledger_report.py",
        ],
        "tokens": [
            "MIMIKATZ.EXE",
            "run_count",
            "VSS shadow copy",
            "get_usnjrnl_entries",
        ],
    },
    {
        "id": "submission_package_and_demo_assets",
        "sources": ["SUBMISSION.md", "DEMO_SCRIPT.md", "BUILD.md", "README.md"],
        "implementation": [
            "src/sift_mind/submission.py",
            "src/sift_mind/production_audit.py",
            "scripts/verify.ps1",
            "ARCHITECTURE_DIAGRAM.mmd",
        ],
        "tests": [
            "tests/test_submission.py",
            "tests/test_production_audit.py",
        ],
        "tokens": [
            "create_package_archive",
            "scan_for_secrets",
            "submission_archive_verified",
            "sift_mind_submission.zip",
        ],
    },
]


def production_audit(
    config: RunConfig,
    *,
    repo_root: str | Path | None = None,
    package_dir: str | Path | None = None,
    archive_path: str | Path | None = None,
    target: str = "fixture",
) -> dict[str, Any]:
    """Return a requirement-oriented readiness audit.

    The audit is intentionally conservative: fixture/demo readiness can pass on
    a laptop, while real SIFT readiness remains failed until case data and
    external forensic binaries are present.
    """

    root = Path(repo_root or Path.cwd())
    checks: list[dict[str, Any]] = []
    runtime = readiness_report(config)

    def add_check(
        check_id: str,
        status: str,
        evidence: Any,
        *,
        scope: str,
        blocking_for: list[str] | None = None,
        remediation: str = "",
    ) -> None:
        checks.append(
            {
                "id": check_id,
                "status": status,
                "scope": scope,
                "blocking_for": blocking_for or [],
                "evidence": evidence,
                "remediation": remediation,
            }
        )

    markdown = _markdown_status(root)
    add_check(
        "markdown_vision_files_present",
        "PASS" if not markdown["missing"] else "FAIL",
        markdown,
        scope="documentation",
        blocking_for=["fixture", "sift"] if markdown["missing"] else [],
        remediation="Restore every Markdown planning/spec/submission file referenced by the project vision.",
    )

    doc_drift = _markdown_drift_status(root)
    add_check(
        "markdown_implementation_references_current",
        "PASS" if not doc_drift["stale_references"] else "FAIL",
        doc_drift,
        scope="documentation",
        blocking_for=["fixture", "sift"] if doc_drift["stale_references"] else [],
        remediation="Update Markdown examples so they point at current implementation files and imports.",
    )

    requirement_trace = _markdown_requirement_trace_status(root)
    add_check(
        "markdown_requirement_traceability_complete",
        "PASS" if requirement_trace["ready"] else "FAIL",
        requirement_trace,
        scope="documentation",
        blocking_for=["fixture", "sift"] if not requirement_trace["ready"] else [],
        remediation="Map every Markdown requirement family to current implementation files and tests.",
    )

    phases = _prompt_phase_status(root)
    add_check(
        "four_phase_prompt_workflow_present",
        "PASS" if not phases["missing"] else "FAIL",
        phases,
        scope="agent_workflow",
        blocking_for=["fixture", "sift"] if phases["missing"] else [],
        remediation="PROMPTS.md must preserve reconnaissance, triage, deep analysis, and reporting.",
    )

    server_tools = _registered_mcp_tools(root)
    missing_mcp = sorted(MCP_TOOL_NAMES - server_tools)
    add_check(
        "mcp_tool_registration_complete",
        "PASS" if not missing_mcp else "FAIL",
        {"registered_count": len(server_tools), "missing": missing_mcp},
        scope="mcp_boundary",
        blocking_for=["fixture", "sift"] if missing_mcp else [],
        remediation="Register every documented forensic, ledger, and report tool in the FastMCP server.",
    )

    shell_scan = _generic_shell_endpoint_scan(root)
    add_check(
        "no_generic_shell_endpoint",
        "PASS" if not shell_scan["matches"] else "FAIL",
        shell_scan,
        scope="mcp_boundary",
        blocking_for=["fixture", "sift"] if shell_scan["matches"] else [],
        remediation="Remove generic shell/command execution endpoints from the MCP server.",
    )

    source_scan = _source_capability_scan(root)
    for check_id, result in source_scan.items():
        add_check(
            check_id,
            "PASS" if result["present"] else "FAIL",
            result,
            scope=result["scope"],
            blocking_for=["fixture", "sift"] if not result["present"] else [],
            remediation=result["remediation"],
        )

    add_check(
        "fixture_runtime_ready",
        "PASS" if runtime["status"]["fixture_ready"] else "FAIL",
        runtime["status"],
        scope="runtime",
        blocking_for=["fixture", "sift"] if not runtime["status"]["fixture_ready"] else [],
        remediation="Install required Python dependencies and ensure OUTPUT_DIR is writable.",
    )
    add_check(
        "local_or_fallback_model_ready",
        "PASS" if runtime["status"]["model_ready"] else "WARN",
        runtime["model_provider"],
        scope="model",
        blocking_for=[],
        remediation="Start Ollama and make qwen2.5-coder:7b or qwen2.5-coder:3b available.",
    )
    model_plan = runtime.get("model_hardware_plan", {})
    add_check(
        "local_hardware_model_plan_present",
        "PASS" if _model_plan_is_complete(model_plan) else "WARN",
        model_plan,
        scope="model",
        blocking_for=[],
        remediation="Keep the Ollama model plan aligned to the 16 GB RAM / RTX 3050 6 GB local hardware target.",
    )
    add_check(
        "sift_runtime_ready",
        "PASS" if runtime["status"]["sift_ready"] else "FAIL",
        {
            "status": runtime["status"],
            "missing_required_for_sift_mode": runtime["missing_required_for_sift_mode"],
            "case_root": runtime["paths"]["case_root"],
            "host_environment": runtime.get("host_environment", {}),
        },
        scope="sift",
        blocking_for=["sift"] if not runtime["status"]["sift_ready"] else [],
        remediation="Run inside SIFT VM/WSL with CASE_ROOT mounted and required forensic binaries on PATH.",
    )

    if package_dir:
        package = _package_status(Path(package_dir))
        add_check(
            "submission_package_verified",
            "PASS" if package["ready"] else "FAIL",
            package,
            scope="submission",
            blocking_for=["fixture", "sift"] if not package["ready"] else [],
            remediation="Run the fixture workflow and package-demo, then verify submission_manifest.json.",
        )
        project_package = _package_project_artifact_status(Path(package_dir), root)
        add_check(
            "submission_package_project_artifacts_complete",
            "PASS" if project_package["ready"] else "FAIL",
            project_package,
            scope="submission",
            blocking_for=["fixture", "sift"] if not project_package["ready"] else [],
            remediation=(
                "Package the runnable code repo, Markdown docs, architecture/dataset artifacts, and the fixture SIFT preflight, smoke, and production audit reports."
            ),
        )
        if archive_path:
            archive = _archive_status(Path(package_dir), Path(archive_path))
            add_check(
                "submission_archive_verified",
                "PASS" if archive["ready"] else "FAIL",
                archive,
                scope="submission",
                blocking_for=["fixture", "sift"] if not archive["ready"] else [],
                remediation="Regenerate the deterministic submission ZIP with package-demo --archive-path.",
            )
    else:
        add_check(
            "submission_package_verified",
            "WARN",
            {"package_dir": None, "ready": False},
            scope="submission",
            blocking_for=[],
            remediation="Pass --package-dir to include package manifest checks.",
        )
        add_check(
            "submission_package_project_artifacts_complete",
            "WARN",
            {"package_dir": None, "ready": False},
            scope="submission",
            blocking_for=[],
            remediation="Pass --package-dir to verify project code, docs, and preflight/smoke/audit artifacts.",
        )

    blocking_failures = [
        check
        for check in checks
        if check["status"] == "FAIL" and target in check["blocking_for"]
    ]
    warnings = [check for check in checks if check["status"] == "WARN"]
    overall_status = "READY_FOR_FIXTURE_DEMO"
    if target == "sift" and not blocking_failures:
        overall_status = "SIFT_READY"
    if blocking_failures:
        overall_status = "ACTION_REQUIRED"

    return {
        "target": target,
        "overall_status": overall_status,
        "blocking_failure_count": len(blocking_failures),
        "warning_count": len(warnings),
        "checks": checks,
        "runtime_status": runtime["status"],
        "missing_required_for_sift_mode": runtime["missing_required_for_sift_mode"],
        "next_actions": _next_actions(checks, target),
    }


def _markdown_status(root: Path) -> dict[str, Any]:
    present = []
    missing = []
    for name in sorted(DOCUMENTED_MARKDOWN_FILES):
        path = root / name
        if path.exists():
            present.append(name)
        else:
            missing.append(name)
    discovered = _repo_markdown_files(root)
    undocumented = sorted(name for name in discovered if name not in DOCUMENTED_MARKDOWN_FILES)
    return {
        "present": present,
        "missing": missing,
        "discovered_markdown_files": discovered,
        "undocumented_markdown_files": undocumented,
    }


def _markdown_drift_status(root: Path) -> dict[str, Any]:
    stale: list[dict[str, Any]] = []
    for relative in _repo_markdown_files(root):
        path = root / relative
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in sorted(STALE_MARKDOWN_REFERENCES):
            index = text.find(token)
            if index == -1:
                continue
            stale.append(
                {
                    "file": relative,
                    "line": text.count("\n", 0, index) + 1,
                    "reference": token,
                }
            )
    return {
        "checked_markdown_files": _repo_markdown_files(root),
        "stale_references": stale,
    }


def _markdown_requirement_trace_status(root: Path) -> dict[str, Any]:
    traced_sources = sorted(
        {
            source
            for requirement in MARKDOWN_REQUIREMENT_TRACE
            for source in requirement["sources"]
        }
    )
    repo_markdown = _repo_markdown_files(root)
    untraced_markdown = sorted(name for name in repo_markdown if name not in traced_sources)
    requirements: list[dict[str, Any]] = []
    for requirement in MARKDOWN_REQUIREMENT_TRACE:
        implementation = [str(item) for item in requirement["implementation"]]
        tests = [str(item) for item in requirement["tests"]]
        sources = [str(item) for item in requirement["sources"]]
        tokens = [str(item) for item in requirement["tokens"]]
        missing_sources = _missing_paths(root, sources)
        missing_implementation = _missing_paths(root, implementation)
        missing_tests = _missing_paths(root, tests)
        implementation_text = "\n".join(
            (root / relative).read_text(encoding="utf-8", errors="replace")
            for relative in implementation
            if (root / relative).exists() and (root / relative).is_file()
        )
        lowered = implementation_text.lower()
        missing_tokens = [token for token in tokens if token.lower() not in lowered]
        ready = not any([missing_sources, missing_implementation, missing_tests, missing_tokens])
        requirements.append(
            {
                "id": requirement["id"],
                "sources": sources,
                "implementation": implementation,
                "tests": tests,
                "required_tokens": tokens,
                "missing_sources": missing_sources,
                "missing_implementation": missing_implementation,
                "missing_tests": missing_tests,
                "missing_tokens": missing_tokens,
                "status": "PASS" if ready else "FAIL",
            }
        )

    failing = [item["id"] for item in requirements if item["status"] != "PASS"]
    return {
        "ready": not failing and not untraced_markdown,
        "requirement_count": len(requirements),
        "traced_markdown_files": traced_sources,
        "untraced_markdown_files": untraced_markdown,
        "failing_requirement_ids": failing,
        "requirements": requirements,
    }


def _missing_paths(root: Path, relatives: list[str]) -> list[str]:
    return sorted(
        relative
        for relative in relatives
        if not (root / relative).exists()
    )


def _repo_markdown_files(root: Path) -> list[str]:
    ignored_parts = {".git", ".tmp", ".venv", ".pytest_cache", "__pycache__"}
    files = []
    for path in root.rglob("*.md"):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in ignored_parts for part in relative.parts):
            continue
        files.append(relative.as_posix())
    return sorted(files)


def _prompt_phase_status(root: Path) -> dict[str, Any]:
    path = root / "PROMPTS.md"
    text = path.read_text(encoding="utf-8", errors="replace").lower() if path.exists() else ""
    missing = sorted(phase for phase in PROMPT_PHASES if phase not in text)
    return {"path": str(path), "expected": sorted(PROMPT_PHASES), "missing": missing}


def _registered_mcp_tools(root: Path) -> set[str]:
    server_path = root / "src" / "sift_mind" / "mcp_server" / "server.py"
    if not server_path.exists():
        return set()
    text = server_path.read_text(encoding="utf-8", errors="replace")
    return set(re.findall(r"@mcp\.tool\(\)\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", text))


def _generic_shell_endpoint_scan(root: Path) -> dict[str, Any]:
    server_path = root / "src" / "sift_mind" / "mcp_server" / "server.py"
    if not server_path.exists():
        return {"path": str(server_path), "matches": ["server.py missing"]}
    text = server_path.read_text(encoding="utf-8", errors="replace")
    suspicious = []
    for pattern in (r"def\s+execute_shell", r"def\s+run_shell", r"def\s+shell", r"subprocess\.run"):
        if re.search(pattern, text):
            suspicious.append(pattern)
    return {"path": str(server_path), "matches": suspicious}


def _source_capability_scan(root: Path) -> dict[str, dict[str, Any]]:
    files = {
        "base": root / "src" / "sift_mind" / "mcp_server" / "tools" / "base.py",
        "ledger": root / "src" / "sift_mind" / "ledger" / "ledger.py",
        "ledger_schema": root / "src" / "sift_mind" / "ledger" / "schema.sql",
        "report": root / "src" / "sift_mind" / "report" / "writer.py",
        "server": root / "src" / "sift_mind" / "mcp_server" / "server.py",
        "model": root / "src" / "sift_mind" / "model_provider.py",
        "model_brief": root / "src" / "sift_mind" / "agent" / "model_brief.py",
        "model_brief_tests": root / "tests" / "test_model_brief.py",
        "runtime": root / "src" / "sift_mind" / "runtime.py",
        "graph": root / "src" / "sift_mind" / "contradiction" / "graph.py",
        "graph_tests": root / "tests" / "test_contradiction_graph.py",
    }
    text = {key: path.read_text(encoding="utf-8", errors="replace") if path.exists() else "" for key, path in files.items()}
    return {
        "evidence_chain_hashes_generated_outputs": {
            "present": all(token in text["base"] for token in ["previous_record_hash", "record_hash", "generated_outputs"]),
            "scope": "evidence_integrity",
            "evidence": str(files["base"]),
            "remediation": "Ensure base wrapper hashes stdout/stderr and generated output files into a linked evidence chain.",
        },
        "sqlite_wal_epistemic_ledger": {
            "present": "PRAGMA journal_mode=WAL" in text["ledger_schema"] and "EpistemicStatus" in text["ledger"],
            "scope": "ledger",
            "evidence": [str(files["ledger"]), str(files["ledger_schema"])],
            "remediation": "Ledger must initialize SQLite WAL mode and preserve mandatory epistemic tiers.",
        },
        "contradictions_block_report_finalization": {
            "present": "get_contested" in text["server"] and "unresolved contradictions" in text["server"],
            "scope": "contradiction_blocking",
            "evidence": str(files["server"]),
            "remediation": "report_finalize must refuse unresolved contradictions.",
        },
        "report_writer_ledger_only": {
            "present": "get_all_findings" in text["report"] and "content_markdown" not in text["report"],
            "scope": "reporting",
            "evidence": str(files["report"]),
            "remediation": "Final report generation must read ledger findings, not raw tool output or agent prose.",
        },
        "ollama_and_cloud_provider_abstraction": {
            "present": all(token in text["model"] for token in ["OllamaClient", "OpenAICompatibleClient", "generate_json"]),
            "scope": "model",
            "evidence": str(files["model"]),
            "remediation": "Keep local Ollama and OpenAI-compatible cloud providers behind the same bounded JSON interface.",
        },
        "hardware_aware_model_planning": {
            "present": all(
                token in text["runtime"]
                for token in ["LOCAL_HARDWARE_PROFILE", "model_hardware_plan", "RTX 3050", "qwen2.5-coder:7b"]
            ),
            "scope": "model",
            "evidence": str(root / "src" / "sift_mind" / "runtime.py"),
            "remediation": "Expose a hardware-aware local Ollama plan for the 16 GB RAM / RTX 3050 6 GB target.",
        },
        "ledger_only_model_briefing": {
            "present": all(
                token in text["model_brief"]
                for token in [
                    "generate_model_case_brief",
                    "validate_model_brief",
                    "ledger_only_model_brief_not_report_source",
                    "evidence_hashes",
                ]
            )
            and "ModelBriefTests" in text["model_brief_tests"],
            "scope": "model",
            "evidence": [str(files["model_brief"]), str(files["model_brief_tests"])],
            "remediation": "Keep local/cloud model summaries ledger-only and citation-validated.",
        },
        "richer_contradiction_rules_present": {
            "present": all(
                token in text["graph"]
                for token in [
                    "_hash_conflict",
                    "_process_visibility_conflict",
                    "_network_observation_conflict",
                ]
            )
            and "RicherContradictionRuleTests" in text["graph_tests"],
            "scope": "contradiction_blocking",
            "evidence": [str(files["graph"]), str(files["graph_tests"])],
            "remediation": "Keep process visibility, PCAP/memory observation, and file hash mismatch rules covered by tests.",
        },
    }


def _model_plan_is_complete(model_plan: Any) -> bool:
    if not isinstance(model_plan, dict):
        return False
    hardware = model_plan.get("hardware_profile", {})
    if not isinstance(hardware, dict):
        return False
    return bool(
        hardware.get("ram_gb") == 16
        and hardware.get("vram_gb") == 6
        and "RTX 3050" in str(hardware.get("gpu", ""))
        and model_plan.get("recommended_primary")
        and model_plan.get("recommended_fallback")
    )


def _package_status(package_dir: Path) -> dict[str, Any]:
    manifest_path = package_dir / "submission_manifest.json"
    result: dict[str, Any] = {
        "package_dir": str(package_dir),
        "manifest": str(manifest_path),
        "ready": False,
        "missing_reports": [],
    }
    if not manifest_path.exists():
        result["error"] = "submission_manifest.json is missing"
        result["missing_reports"] = [name for name in REPORT_FILES if not (package_dir / name).exists()]
        return result
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result["error"] = f"manifest is not valid JSON: {exc}"
        return result
    missing_reports = [name for name in REPORT_FILES if not (package_dir / name).exists()]
    evidence_ok = manifest.get("evidence_verification", {}).get("status") == "VERIFIED"
    redaction_ok = manifest.get("redaction_scan", {}).get("status") == "OK"
    status_ok = manifest.get("status") == "OK"
    result.update(
        {
            "manifest_status": manifest.get("status"),
            "evidence_verification": manifest.get("evidence_verification", {}).get("status"),
            "redaction_scan": manifest.get("redaction_scan", {}).get("status"),
            "missing_reports": missing_reports,
            "ready": bool(status_ok and evidence_ok and redaction_ok and not missing_reports),
        }
    )
    return result


def _package_project_artifact_status(package_dir: Path, root: Path) -> dict[str, Any]:
    manifest_path = package_dir / "submission_manifest.json"
    result: dict[str, Any] = {
        "package_dir": str(package_dir),
        "manifest": str(manifest_path),
        "ready": False,
    }
    if not manifest_path.exists():
        result["error"] = "submission_manifest.json is missing"
        return result
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result["error"] = f"manifest is not valid JSON: {exc}"
        return result

    project_files = manifest.get("project_files", {})
    project_file_names = set(project_files) if isinstance(project_files, dict) else set()
    actual_packaged_project_files = _packaged_project_files(package_dir)
    unexpected_packaged_project_files = sorted(name for name in actual_packaged_project_files if name not in project_file_names)
    repo_markdown = _repo_markdown_files(root)
    missing_markdown = sorted(name for name in repo_markdown if name not in project_file_names)
    expected_project_files = collect_project_files(root)
    missing_expected_project_files = sorted(name for name in expected_project_files if name not in project_file_names)
    missing_project_files = manifest.get("missing_project_files", [])
    if not isinstance(missing_project_files, list):
        missing_project_files = ["missing_project_files is not a list"]

    missing_packaged_paths = []
    for name in sorted(project_file_names):
        item = project_files.get(name, {}) if isinstance(project_files, dict) else {}
        path_value = item.get("path") if isinstance(item, dict) else None
        if not path_value or not Path(path_value).exists():
            missing_packaged_paths.append(name)

    preflight_report = manifest.get("preflight_report", {})
    preflight_included = isinstance(preflight_report, dict) and preflight_report.get("included") is True
    preflight_path = preflight_report.get("path") if isinstance(preflight_report, dict) else None
    preflight_exists = bool(preflight_path and Path(preflight_path).exists())

    smoke_report = manifest.get("smoke_report", {})
    smoke_included = isinstance(smoke_report, dict) and smoke_report.get("included") is True
    smoke_path = smoke_report.get("path") if isinstance(smoke_report, dict) else None
    smoke_exists = bool(smoke_path and Path(smoke_path).exists())

    audit_report = manifest.get("audit_report", {})
    audit_included = isinstance(audit_report, dict) and audit_report.get("included") is True
    audit_path = audit_report.get("path") if isinstance(audit_report, dict) else None
    audit_exists = bool(audit_path and Path(audit_path).exists())

    model_brief_report = manifest.get("model_brief_report", {})
    model_brief_included = isinstance(model_brief_report, dict) and model_brief_report.get("included") is True
    model_brief_path = model_brief_report.get("path") if isinstance(model_brief_report, dict) else None
    model_brief_exists = bool(model_brief_path and Path(model_brief_path).exists())
    model_brief_status = _model_brief_artifact_status(Path(str(model_brief_path))) if model_brief_exists else {
        "ready": not model_brief_included,
        "included": model_brief_included,
        "exists": model_brief_exists,
    }

    required_extra_files = {
        ".env.example",
        ".gitignore",
        "ARCHITECTURE_DIAGRAM.mmd",
        "case_data/public_sample_manifest.schema.json",
        "case_data/public_sample_manifest.example.json",
        "case_data/fixture_baseline.json",
        "scripts/verify.ps1",
        "scripts/sift_mode_smoke.sh",
        "scripts/sift_mode_smoke_wsl.ps1",
        "pyproject.toml",
        "requirements.txt",
        ".github/workflows/ci.yml",
    }
    missing_required_extra = sorted(name for name in required_extra_files if name not in project_file_names)

    ready = bool(
        not missing_markdown
        and not missing_expected_project_files
        and not missing_project_files
        and not missing_packaged_paths
        and not unexpected_packaged_project_files
        and not missing_required_extra
        and preflight_included
        and preflight_exists
        and smoke_included
        and smoke_exists
        and audit_included
        and audit_exists
        and model_brief_status["ready"]
    )
    result.update(
        {
            "ready": ready,
            "repo_markdown_count": len(repo_markdown),
            "expected_project_file_count": len(expected_project_files),
            "actual_packaged_project_file_count": len(actual_packaged_project_files),
            "project_file_count": len(project_file_names),
            "missing_markdown": missing_markdown,
            "missing_expected_project_files": missing_expected_project_files,
            "missing_project_files": missing_project_files,
            "missing_packaged_paths": missing_packaged_paths,
            "unexpected_packaged_project_files": unexpected_packaged_project_files,
            "missing_required_extra": missing_required_extra,
            "preflight_report_included": preflight_included,
            "preflight_report_exists": preflight_exists,
            "smoke_report_included": smoke_included,
            "smoke_report_exists": smoke_exists,
            "audit_report_included": audit_included,
            "audit_report_exists": audit_exists,
            "model_brief_report_included": model_brief_included,
            "model_brief_report_exists": model_brief_exists,
            "model_brief_report_status": model_brief_status,
        }
    )
    return result


def _model_brief_artifact_status(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "included": True,
        "exists": path.exists(),
        "path": str(path),
        "ready": False,
    }
    if not path.exists():
        result["error"] = "model_case_brief.json is missing"
        return result
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result["error"] = f"model_case_brief.json is not valid JSON: {exc}"
        return result
    validation = data.get("validation", {})
    errors = validation.get("errors", []) if isinstance(validation, dict) else []
    bullets = data.get("executive_bullets", [])
    ready = bool(
        data.get("status") == "OK"
        and data.get("source_policy") == "ledger_only_model_brief_not_report_source"
        and isinstance(validation, dict)
        and validation.get("status") == "PASS"
        and isinstance(errors, list)
        and not errors
        and isinstance(bullets, list)
    )
    result.update(
        {
            "ready": ready,
            "status": data.get("status"),
            "source_policy": data.get("source_policy"),
            "validation_status": validation.get("status") if isinstance(validation, dict) else None,
            "validation_error_count": len(errors) if isinstance(errors, list) else None,
            "executive_bullet_count": len(bullets) if isinstance(bullets, list) else None,
            "model": data.get("model", {}),
        }
    )
    return result


def _archive_status(package_dir: Path, archive_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "package_dir": str(package_dir),
        "archive_path": str(archive_path),
        "ready": False,
    }
    if not package_dir.exists() or not package_dir.is_dir():
        result["error"] = f"Package directory does not exist: {package_dir}"
        return result
    if not archive_path.exists() or not archive_path.is_file():
        result["error"] = f"Archive does not exist: {archive_path}"
        return result
    package_root = package_dir.resolve()
    archive_resolved = archive_path.resolve()
    if archive_resolved == package_root or archive_resolved.is_relative_to(package_root):
        result["error"] = "Archive path must be outside the package directory."
        return result

    expected_files = sorted(
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*")
        if path.is_file()
    )
    try:
        with zipfile.ZipFile(archive_resolved) as archive:
            zip_files = sorted(info.filename for info in archive.infolist() if not info.is_dir())
    except zipfile.BadZipFile as exc:
        result["error"] = f"Archive is not a valid ZIP file: {exc}"
        return result

    unsafe_entries = [
        name
        for name in zip_files
        if _unsafe_zip_entry(name)
    ]
    missing_files = sorted(set(expected_files) - set(zip_files))
    unexpected_files = sorted(set(zip_files) - set(expected_files))
    result.update(
        {
            "sha256": sha256_file(archive_resolved),
            "bytes": archive_resolved.stat().st_size,
            "entry_count": len(zip_files),
            "expected_file_count": len(expected_files),
            "has_submission_manifest": "submission_manifest.json" in zip_files,
            "has_project_source": "project/src/sift_mind/run.py" in zip_files,
            "has_production_audit_report": "production_audit_report.json" in zip_files,
            "unsafe_entries": unsafe_entries,
            "missing_files": missing_files,
            "unexpected_files": unexpected_files,
            "ready": bool(
                zip_files
                and not unsafe_entries
                and not missing_files
                and not unexpected_files
                and "submission_manifest.json" in zip_files
                and "project/src/sift_mind/run.py" in zip_files
                and "production_audit_report.json" in zip_files
            ),
        }
    )
    return result


def _unsafe_zip_entry(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return (
        not name
        or "\\" in name
        or name.startswith("/")
        or bool(re.match(r"^[A-Za-z]:", name))
        or ".." in parts
    )


def _packaged_project_files(package_dir: Path) -> list[str]:
    project_dir = package_dir / "project"
    if not project_dir.exists():
        return []
    files = []
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(project_dir)
        except ValueError:
            continue
        files.append(relative.as_posix())
    return sorted(files)


def _next_actions(checks: list[dict[str, Any]], target: str) -> list[str]:
    actions = []
    for check in checks:
        if check["status"] == "FAIL" and target in check["blocking_for"] and check["remediation"]:
            actions.append(check["remediation"])
    if not actions:
        actions = [
            "Run the real SIFT-mode smoke inside SIFT VM/WSL with mounted public sample data before claiming full production completion."
        ]
    return actions[:5]
