"""Runtime readiness checks for fixture and SIFT mode."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .contracts import RunConfig


TOOL_GROUPS: dict[str, dict[str, Any]] = {
    "analyze_prefetch": {
        "category": "disk",
        "candidates": ["PECmd.exe", "PECmd", "pecmd"],
        "required_for_sift_mode": True,
    },
    "get_amcache": {
        "category": "disk",
        "candidates": ["AmcacheParser.exe", "AmcacheParser", "amcacheparser"],
        "required_for_sift_mode": True,
    },
    "parse_mft": {
        "category": "disk",
        "candidates": ["MFTECmd.exe", "MFTECmd", "mftecmd", "mft2csv", "analyzeMFT.py"],
        "required_for_sift_mode": True,
    },
    "list_registry_hives": {
        "category": "disk",
        "candidates": ["find"],
        "required_for_sift_mode": False,
    },
    "get_registry_key": {
        "category": "disk",
        "candidates": ["rip.pl", "regripper", "reglookup"],
        "required_for_sift_mode": True,
    },
    "extract_shellbags": {
        "category": "disk",
        "candidates": ["SBECmd.exe", "SBECmd", "sbecmd"],
        "required_for_sift_mode": False,
    },
    "parse_lnk_files": {
        "category": "disk",
        "candidates": ["LECmd.exe", "LECmd", "lecmd"],
        "required_for_sift_mode": False,
    },
    "get_usnjrnl_entries": {
        "category": "disk",
        "candidates": ["UsnJrnl2Csv.exe", "usn.py", "usnparser"],
        "required_for_sift_mode": True,
    },
    "list_processes": {
        "category": "memory",
        "candidates": ["vol", "vol.py", "volatility3"],
        "required_for_sift_mode": True,
    },
    "get_network_connections": {
        "category": "memory",
        "candidates": ["vol", "vol.py", "volatility3"],
        "required_for_sift_mode": True,
    },
    "extract_injected_code": {
        "category": "memory",
        "candidates": ["vol", "vol.py", "volatility3"],
        "required_for_sift_mode": True,
    },
    "find_hidden_modules": {
        "category": "memory",
        "candidates": ["vol", "vol.py", "volatility3"],
        "required_for_sift_mode": True,
    },
    "get_handles": {
        "category": "memory",
        "candidates": ["vol", "vol.py", "volatility3"],
        "required_for_sift_mode": True,
    },
    "scan_memory_yara": {
        "category": "memory",
        "candidates": ["yara"],
        "required_for_sift_mode": True,
    },
    "parse_evtx": {
        "category": "logs",
        "candidates": ["evtx_dump.py", "evtx_dump", "EvtxECmd.exe"],
        "required_for_sift_mode": True,
    },
    "get_security_events": {
        "category": "logs",
        "candidates": ["evtx_dump.py", "evtx_dump", "EvtxECmd.exe"],
        "required_for_sift_mode": True,
    },
    "get_logon_events": {
        "category": "logs",
        "candidates": ["evtx_dump.py", "evtx_dump", "EvtxECmd.exe"],
        "required_for_sift_mode": True,
    },
    "get_process_creation_events": {
        "category": "logs",
        "candidates": ["evtx_dump.py", "evtx_dump", "EvtxECmd.exe"],
        "required_for_sift_mode": True,
    },
    "build_super_timeline": {
        "category": "timeline",
        "candidates": ["log2timeline.py"],
        "required_for_sift_mode": True,
    },
    "correlate_timestamps": {
        "category": "timeline",
        "candidates": [],
        "required_for_sift_mode": False,
        "internal": True,
    },
    "get_artifact_at_time": {
        "category": "timeline",
        "candidates": ["log2timeline.py", "psort.py"],
        "required_for_sift_mode": True,
    },
    "parse_pcap_summary": {
        "category": "network",
        "candidates": ["tshark", "tcpdump"],
        "required_for_sift_mode": True,
    },
    "extract_dns_queries": {
        "category": "network",
        "candidates": ["tshark"],
        "required_for_sift_mode": True,
    },
    "get_http_requests": {
        "category": "network",
        "candidates": ["tshark"],
        "required_for_sift_mode": True,
    },
}


PYTHON_PACKAGES = {
    "pydantic": "required",
    "jinja2": "templating",
    "networkx": "graph",
    "rich": "ui",
    "click": "cli",
    "mcp": "mcp",
    "fastmcp": "mcp",
    "Evtx": "forensics",
    "yara": "forensics",
    "pyewf": "forensics",
}

LOCAL_HARDWARE_PROFILE = {
    "ram_gb": 16,
    "gpu": "RTX 3050",
    "vram_gb": 6,
    "policy": "Keep one 7B/8B-class quantized model loaded at a time; use a 3B-class fallback under memory pressure.",
}

OLLAMA_RECOMMENDED_ORDER = [
    "qwen2.5-coder:7b",
    "mistral:7b-instruct-v0.3-q4_K_M",
    "qwen2.5-coder:3b",
    "phi4-mini:latest",
    "llama3.2:1b",
    "qwen2.5-coder:1.5b",
]


def ollama_status(host: str, model: str, fallback_model: str = "") -> dict[str, object]:
    url = f"{host.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {
            "reachable": False,
            "host": host,
            "configured_model": model,
            "fallback_model": fallback_model,
            "model_available": False,
            "fallback_available": False,
            "error": str(exc),
        }
    models = [item.get("name", "") for item in body.get("models", [])]
    return {
        "reachable": True,
        "host": host,
        "configured_model": model,
        "fallback_model": fallback_model,
        "model_available": model in models,
        "fallback_available": bool(fallback_model and fallback_model in models),
        "available_models": models,
    }


def model_status(config: RunConfig) -> dict[str, object]:
    provider = config.model.provider.lower()
    if provider == "ollama":
        status = ollama_status(config.model.host, config.model.model, config.model.fallback_model)
        status["provider"] = "ollama"
        return status
    if provider in {"openai-compatible", "openai", "cloud"}:
        api_key_present = bool(os.environ.get(config.model.api_key_env, ""))
        return {
            "provider": provider,
            "host": config.model.host,
            "configured_model": config.model.model,
            "fallback_model": config.model.fallback_model,
            "api_key_env": config.model.api_key_env,
            "api_key_present": api_key_present,
            "reachable": None,
            "model_available": api_key_present and bool(config.model.model and config.model.host),
            "fallback_available": False,
            "note": "Cloud model availability is validated by model-smoke; readiness only checks non-secret configuration.",
        }
    return {
        "provider": provider,
        "host": config.model.host,
        "configured_model": config.model.model,
        "fallback_model": config.model.fallback_model,
        "api_key_env": config.model.api_key_env,
        "api_key_present": False,
        "reachable": False,
        "model_available": False,
        "fallback_available": False,
        "error": f"Unknown provider: {config.model.provider}",
    }


def model_hardware_plan(config: RunConfig, model: dict[str, object]) -> dict[str, object]:
    """Return a local-hardware-aware model selection plan without invoking generation."""

    provider = config.model.provider.lower()
    if provider != "ollama":
        return {
            "provider": provider,
            "mode": "cloud",
            "hardware_profile": LOCAL_HARDWARE_PROFILE,
            "selected_model": config.model.model,
            "selection_source": "cloud_config",
            "ready_for_local_demo": bool(model.get("model_available")),
            "notes": [
                "Cloud providers use the same bounded JSON contract as Ollama.",
                "Do not store API-key values in reports, evidence logs, or readiness output.",
            ],
        }

    available_models = [str(item) for item in model.get("available_models", []) or []]
    available = set(available_models)
    configured = config.model.model
    fallback = config.model.fallback_model
    selected = ""
    selection_source = "none"
    notes = [
        "Primary target is a 7B-class local instruct/coder model for 16 GB RAM and RTX 3050 6 GB VRAM.",
        "Fallback target is a 3B/4B-class model when the primary fails, runs slowly, or memory is constrained.",
    ]

    if model.get("model_available"):
        selected = configured
        selection_source = "configured_primary"
    elif model.get("fallback_available"):
        selected = fallback
        selection_source = "configured_fallback"
    else:
        detected = [name for name in OLLAMA_RECOMMENDED_ORDER if name in available]
        if detected:
            selected = detected[0]
            selection_source = "detected_recommended"

    warnings: list[str] = []
    if not model.get("reachable"):
        warnings.append("Ollama is not reachable at the configured host.")
    if configured not in available and available:
        warnings.append(f"Configured primary model is not downloaded: {configured}.")
    if fallback and fallback not in available and available:
        warnings.append(f"Configured fallback model is not downloaded: {fallback}.")
    selected_profile = _model_fit_profile(selected)
    if selected and not selected_profile["fits_rtx_3050_6gb"]:
        warnings.append(f"Selected model may exceed the RTX 3050 6 GB comfort target: {selected}.")
    if not selected:
        warnings.append("No recommended local Ollama model is currently available.")

    return {
        "provider": "ollama",
        "mode": "local",
        "hardware_profile": LOCAL_HARDWARE_PROFILE,
        "recommended_primary": "qwen2.5-coder:7b",
        "recommended_fallback": "qwen2.5-coder:3b",
        "configured_primary": configured,
        "configured_fallback": fallback,
        "selected_model": selected,
        "selection_source": selection_source,
        "selected_profile": selected_profile,
        "ready_for_local_demo": bool(model.get("model_available") or model.get("fallback_available")),
        "available_recommended_models": [name for name in OLLAMA_RECOMMENDED_ORDER if name in available],
        "available_model_count": len(available_models),
        "warnings": warnings,
        "notes": notes,
    }


def _model_fit_profile(model_name: str) -> dict[str, object]:
    normalized = model_name.lower()
    if not model_name:
        return {
            "class": "unknown",
            "fits_rtx_3050_6gb": False,
            "role": "none",
        }
    if "14b" in normalized:
        return {
            "class": "14B",
            "fits_rtx_3050_6gb": False,
            "role": "avoid_for_default_local_run",
        }
    if "7b" in normalized or "8b" in normalized:
        return {
            "class": "7B/8B",
            "fits_rtx_3050_6gb": True,
            "role": "recommended_primary",
        }
    if any(marker in normalized for marker in ("4b", "3b", "mini", "1.5b", "1b")):
        return {
            "class": "small",
            "fits_rtx_3050_6gb": True,
            "role": "fallback_or_fast_smoke",
        }
    return {
        "class": "unknown",
        "fits_rtx_3050_6gb": True,
        "role": "operator_review",
    }


def package_status() -> dict[str, dict[str, object]]:
    return {
        name: {
            "available": importlib.util.find_spec(name) is not None,
            "group": group,
        }
        for name, group in PYTHON_PACKAGES.items()
    }


def tool_status() -> dict[str, dict[str, object]]:
    status: dict[str, dict[str, object]] = {}
    for capability, meta in TOOL_GROUPS.items():
        candidates = meta.get("candidates", [])
        matches = {candidate: shutil.which(candidate) for candidate in candidates}
        available = bool(meta.get("internal") or any(matches.values()))
        status[capability] = {
            "category": meta["category"],
            "available": available,
            "required_for_sift_mode": bool(meta.get("required_for_sift_mode")),
            "candidates": candidates,
            "matches": {key: value for key, value in matches.items() if value},
            "internal": bool(meta.get("internal", False)),
        }
    return status


def host_environment_status(config: RunConfig) -> dict[str, object]:
    """Return host diagnostics that explain how to reach real SIFT mode."""

    system = platform.system() or "unknown"
    is_windows = system.lower() == "windows"
    report: dict[str, object] = {
        "os": system,
        "python_executable": sys.executable,
        "windows_host": is_windows,
        "sift_mode_requested": config.mode == "sift",
        "wsl": {
            "applicable": is_windows,
            "ready": True,
            "status": "NOT_REQUIRED",
            "recommendation": "Run SIFT-MIND directly inside a SIFT VM, Linux host, or WSL distribution.",
        },
    }
    if not is_windows:
        return report

    wsl_path = shutil.which("wsl.exe") or shutil.which("wsl")
    wsl_report: dict[str, object] = {
        "applicable": True,
        "command": wsl_path or "wsl.exe",
        "available": bool(wsl_path),
        "ready": False,
        "status": "MISSING_WSL_COMMAND" if not wsl_path else "UNKNOWN",
        "installed_distributions": [],
        "recommendation": "Install a WSL distribution or use a SIFT VM before running real SIFT mode.",
    }
    if not wsl_path:
        report["wsl"] = wsl_report
        return report

    try:
        completed = subprocess.run(
            [wsl_path, "-l", "-v"],
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        wsl_report.update(
            {
                "status": "WSL_CHECK_FAILED",
                "error": str(exc),
                "recommendation": "Run `wsl.exe -l -v` manually, then run scripts/sift_mode_smoke.sh inside the SIFT VM/WSL shell.",
            }
        )
        report["wsl"] = wsl_report
        return report

    output = _decode_command_output(completed.stdout + completed.stderr)
    distributions = _parse_wsl_distributions(output)
    ready = completed.returncode == 0 and bool(distributions)
    wsl_report.update(
        {
            "returncode": completed.returncode,
            "output_excerpt": output[:500],
            "installed_distributions": distributions,
            "ready": ready,
            "status": "READY" if ready else "NO_DISTRIBUTION",
            "recommendation": (
                "Open the SIFT/WSL distribution, mount evidence read-only at CASE_ROOT, then run scripts/sift_mode_smoke.sh."
                if ready
                else "Install a WSL distribution or use a SIFT VM, then rerun doctor/readiness from that Linux environment."
            ),
        }
    )
    report["wsl"] = wsl_report
    return report


def _decode_command_output(raw: bytes) -> str:
    if not raw:
        return ""
    for encoding in ("utf-8", "utf-16-le", "cp1252"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    return text.replace("\x00", "").strip()


def _parse_wsl_distributions(output: str) -> list[dict[str, str]]:
    distributions: list[dict[str, str]] = []
    for line in output.splitlines():
        normalized = line.strip().lstrip("*").strip()
        if not normalized or normalized.upper().startswith("NAME"):
            continue
        if normalized.lower().startswith("windows subsystem"):
            continue
        if "install" in normalized.lower() and "distribution" in normalized.lower():
            continue
        parts = normalized.split()
        if len(parts) >= 3 and parts[-1].isdigit():
            distributions.append(
                {
                    "name": " ".join(parts[:-2]),
                    "state": parts[-2],
                    "version": parts[-1],
                }
            )
    return distributions


def path_status(config: RunConfig) -> dict[str, object]:
    output_dir = Path(config.output_dir)
    case_root = Path(config.case_root)
    output_outside_case = not _is_within(output_dir, case_root)
    evidence_parent = Path(config.evidence_chain_path).parent
    execution_parent = Path(config.execution_log_path).parent
    evidence_outside_case = not _is_within(evidence_parent, case_root)
    execution_outside_case = not _is_within(execution_parent, case_root)
    writable = _can_write(output_dir) if output_outside_case else False
    return {
        "case_root": {
            "path": config.case_root,
            "exists": case_root.exists(),
            "is_dir": case_root.is_dir(),
            "required_for_sift_mode": True,
        },
        "output_dir": {
            "path": str(output_dir),
            "exists": output_dir.exists(),
            "writable": writable,
            "outside_case_root": output_outside_case,
        },
        "evidence_chain_parent": {
            "path": str(evidence_parent),
            "writable": _can_write(evidence_parent) if evidence_outside_case else False,
            "outside_case_root": evidence_outside_case,
        },
        "execution_log_parent": {
            "path": str(execution_parent),
            "writable": _can_write(execution_parent) if execution_outside_case else False,
            "outside_case_root": execution_outside_case,
        },
    }


def readiness_report(config: RunConfig) -> dict[str, object]:
    packages = package_status()
    tools = tool_status()
    paths = path_status(config)
    model = model_status(config)
    model_plan = model_hardware_plan(config, model)
    host = host_environment_status(config)

    required_packages_ok = all(
        item["available"] for item in packages.values() if item["group"] == "required"
    )
    mcp_packages_ok = packages["mcp"]["available"] or packages["fastmcp"]["available"]
    required_tools = {
        name: item
        for name, item in tools.items()
        if item["required_for_sift_mode"]
    }
    sift_tools_ok = all(item["available"] for item in required_tools.values())
    fixture_ready = required_packages_ok and paths["output_dir"]["writable"]
    managed_paths_outside_case = (
        paths["output_dir"]["outside_case_root"]
        and paths["evidence_chain_parent"]["outside_case_root"]
        and paths["execution_log_parent"]["outside_case_root"]
    )
    sift_ready = (
        fixture_ready
        and mcp_packages_ok
        and sift_tools_ok
        and managed_paths_outside_case
        and paths["case_root"]["exists"]
        and paths["case_root"]["is_dir"]
    )
    model_ready = bool(model["model_available"] or model["fallback_available"])
    return {
        "python": sys.version,
        "mode": config.mode,
        "status": {
            "fixture_ready": fixture_ready,
            "sift_ready": sift_ready,
            "model_ready": model_ready,
        },
        "model_provider": model,
        "model_hardware_plan": model_plan,
        "host_environment": host,
        "ollama": model if model.get("provider") == "ollama" else None,
        "python_packages": packages,
        "external_tools": tools,
        "paths": paths,
        "missing_required_for_sift_mode": [
            name for name, item in required_tools.items() if not item["available"]
        ],
        "notes": [
            "Fixture mode does not require external forensic binaries.",
            "SIFT mode requires read-only case data mounted at CASE_ROOT and the required external tools available on PATH.",
            "On Windows hosts, doctor/readiness reports WSL distribution status for the SIFT VM/WSL handoff.",
            "Local Ollama is checked via /api/tags; cloud providers are checked for non-secret configuration and validated with model-smoke.",
        ],
    }


def _is_within(path: Path, root: Path) -> bool:
    try:
        resolved_path = path.resolve()
        resolved_root = root.resolve()
    except OSError:
        return False
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _can_write(directory: Path) -> bool:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=directory, delete=True) as handle:
            handle.write(b"ok")
        return True
    except OSError:
        return False
