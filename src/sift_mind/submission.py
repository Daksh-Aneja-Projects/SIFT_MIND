"""Submission packaging and redaction checks."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any

from sift_mind.contracts import utc_now
from sift_mind.ledger.ledger import EpistemicLedger
from sift_mind.report.writer import ReportWriter


REPORT_FILES = [
    "case_narrative.md",
    "executive_summary.md",
    "ioc_summary.json",
    "accuracy_report.md",
    "evidence_chain.log",
    "agent_execution_log.jsonl",
]

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]

PROJECT_FILES = [
    ".env.example",
    ".gitignore",
    "README.md",
    "README (1).md",
    "BUILD.md",
    "ARCHITECTURE.md",
    "ARCHITECTURE_DIAGRAM.mmd",
    "SPEC.md",
    "DESIGN.md",
    "PROMPTS.md",
    "SKILLS.md",
    "DEMO_SCRIPT.md",
    "SUBMISSION.md",
    "case_data/README.md",
    "case_data/public_sample_manifest.schema.json",
    "case_data/public_sample_manifest.example.json",
    "case_data/fixture_baseline.json",
    "scripts/verify.ps1",
    "scripts/sift_mode_smoke.sh",
    "scripts/sift_mode_smoke_wsl.ps1",
    "pyproject.toml",
    "requirements.txt",
    ".github/workflows/ci.yml",
]

PROJECT_FILE_DIRS = [
    "src",
    "tests",
]

PROJECT_FILE_IGNORED_PARTS = {
    ".git",
    ".tmp",
    ".venv",
    ".pytest_cache",
    "__pycache__",
}

PROJECT_FILE_IGNORED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".db",
    ".db-shm",
    ".db-wal",
}

SECRET_PATTERNS = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9_\-\.=]{12,}", re.I),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_api_key_assignment": re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{12,}[\"']?"
    ),
}

GENERATED_PACKAGE_ENTRIES = [
    "project",
    "sift_preflight_report.json",
    "sift_smoke_report.json",
    "production_audit_report.json",
    "model_case_brief.json",
    "submission_manifest.json",
    *REPORT_FILES,
]


def package_demo(
    *,
    output_dir: str,
    ledger_db_path: str,
    evidence_chain_path: str,
    execution_log_path: str,
    package_dir: str,
    repo_root: str | None = None,
    preflight_report_path: str | None = None,
    smoke_report_path: str | None = None,
    audit_report_path: str | None = None,
    model_brief_report_path: str | None = None,
    archive_path: str | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    package = Path(package_dir)
    root = Path(repo_root).resolve() if repo_root else DEFAULT_REPO_ROOT
    _prepare_package_dir(package)

    missing = [name for name in REPORT_FILES if not (output / name).exists()]
    if missing:
        return {"status": "ERROR", "error": f"Missing report files: {', '.join(missing)}"}

    ledger = EpistemicLedger(ledger_db_path)
    writer = ReportWriter(ledger, evidence_chain_path, execution_log_path)
    verification = writer.verify_evidence_chain(evidence_chain_path)
    if verification["status"] != "VERIFIED":
        return {"status": "ERROR", "error": "Evidence chain verification failed", "verification": verification}

    copied: dict[str, dict[str, Any]] = {}
    for name in REPORT_FILES:
        source = output / name
        destination = package / name
        if source.resolve() != destination.resolve():
            shutil.copyfile(source, destination)
        copied[name] = file_manifest(destination)

    project_files: dict[str, dict[str, Any]] = {}
    missing_project_files: list[str] = []
    for relative in collect_project_files(root):
        source = root / relative
        if not source.exists():
            missing_project_files.append(relative)
            continue
        destination = package / "project" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination.resolve():
            shutil.copyfile(source, destination)
        project_files[relative] = file_manifest(destination)

    smoke_report: dict[str, Any] = {"included": False}
    preflight_report: dict[str, Any] = {"included": False}
    if preflight_report_path:
        source = Path(preflight_report_path)
        if source.exists():
            destination = package / "sift_preflight_report.json"
            if source.resolve() != destination.resolve():
                shutil.copyfile(source, destination)
            preflight_report = {"included": True, **file_manifest(destination)}
        else:
            preflight_report = {"included": False, "missing": str(source)}

    if smoke_report_path:
        source = Path(smoke_report_path)
        if source.exists():
            destination = package / "sift_smoke_report.json"
            if source.resolve() != destination.resolve():
                shutil.copyfile(source, destination)
            smoke_report = {"included": True, **file_manifest(destination)}
        else:
            smoke_report = {"included": False, "missing": str(source)}

    audit_report: dict[str, Any] = {"included": False}
    if audit_report_path:
        source = Path(audit_report_path)
        if source.exists():
            destination = package / "production_audit_report.json"
            if source.resolve() != destination.resolve():
                shutil.copyfile(source, destination)
            audit_report = {"included": True, **file_manifest(destination)}
        else:
            audit_report = {"included": False, "missing": str(source)}

    model_brief_report: dict[str, Any] = {"included": False}
    if model_brief_report_path:
        source = Path(model_brief_report_path)
        if source.exists():
            destination = package / "model_case_brief.json"
            if source.resolve() != destination.resolve():
                shutil.copyfile(source, destination)
            model_brief_report = {"included": True, **file_manifest(destination)}
        else:
            model_brief_report = {"included": False, "missing": str(source)}

    archive_record: dict[str, Any] = {
        "included": bool(archive_path),
        "note": (
            "Archive SHA-256 is returned by package-demo and verified by production-audit; "
            "it is not embedded in the package manifest to avoid a self-referential ZIP hash."
        ),
    }
    if archive_path:
        archive_record["path"] = str(Path(archive_path))
        archive_record["verification_check"] = "submission_archive_verified"

    scan_paths = [Path(item["path"]) for item in copied.values()]
    scan_paths.extend(Path(item["path"]) for item in project_files.values())
    if preflight_report.get("included") and preflight_report.get("path"):
        scan_paths.append(Path(str(preflight_report["path"])))
    if smoke_report.get("included") and smoke_report.get("path"):
        scan_paths.append(Path(str(smoke_report["path"])))
    if audit_report.get("included") and audit_report.get("path"):
        scan_paths.append(Path(str(audit_report["path"])))
    if model_brief_report.get("included") and model_brief_report.get("path"):
        scan_paths.append(Path(str(model_brief_report["path"])))
    redaction = scan_for_secrets(scan_paths)
    manifest = {
        "status": "OK" if redaction["status"] == "OK" and not missing_project_files else "FAILED",
        "generated": utc_now().isoformat(),
        "package_dir": str(package),
        "reports": copied,
        "project_files": project_files,
        "missing_project_files": missing_project_files,
        "preflight_report": preflight_report,
        "smoke_report": smoke_report,
        "audit_report": audit_report,
        "model_brief_report": model_brief_report,
        "archive": archive_record,
        "evidence_verification": verification,
        "redaction_scan": redaction,
        "submission_notes": [
            "Fixture package is deterministic and public-safe.",
            "Evidence chain hashes are verified against ledger findings.",
            "Runnable code repo, project story, architecture, dataset docs, preflight/smoke/audit artifacts, and baseline are checksummed.",
            "No API key values are expected in package artifacts.",
        ],
    }
    manifest_path = package / "submission_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    manifest["manifest"] = {
        "path": str(manifest_path),
        "sha256": sha256_file(manifest_path),
        "bytes": manifest_path.stat().st_size,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    if archive_path:
        manifest["archive"] = {**archive_record, **create_package_archive(package, Path(archive_path))}
    return manifest


def _prepare_package_dir(package: Path) -> None:
    package.mkdir(parents=True, exist_ok=True)
    package_root = package.resolve()
    for relative in GENERATED_PACKAGE_ENTRIES:
        target = package / relative
        if not target.exists() and not target.is_symlink():
            continue
        _remove_generated_package_path(package_root, target)


def _remove_generated_package_path(package_root: Path, target: Path) -> None:
    parent = target.parent.resolve()
    if parent != package_root and not parent.is_relative_to(package_root):
        raise ValueError(f"Refusing to remove package path outside package directory: {target}")
    if target.is_symlink() or target.is_file():
        target.unlink()
        return
    if target.is_dir():
        resolved = target.resolve()
        if resolved != package_root and not resolved.is_relative_to(package_root):
            raise ValueError(f"Refusing to remove directory outside package directory: {target}")
        shutil.rmtree(target)


def collect_project_files(root: Path) -> list[str]:
    """Return repo files that make the fixture package a runnable code handoff."""

    files = set(PROJECT_FILES)
    for path in root.rglob("*.md"):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if _is_ignored_project_path(relative):
            continue
        files.add(relative.as_posix())
    for directory in PROJECT_FILE_DIRS:
        base = root / directory
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            if _is_ignored_project_path(relative):
                continue
            files.add(relative.as_posix())
    return sorted(files)


def create_package_archive(package_dir: Path, archive_path: Path) -> dict[str, Any]:
    """Create a deterministic ZIP archive of a finished package directory."""

    package_root = package_dir.resolve()
    if not package_root.exists() or not package_root.is_dir():
        return {"included": False, "error": f"Package directory does not exist: {package_dir}"}
    archive = archive_path.resolve()
    if archive == package_root or archive.is_relative_to(package_root):
        return {"included": False, "error": "Archive path must be outside the package directory."}
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        archive.unlink()

    files = sorted(path for path in package_root.rglob("*") if path.is_file())
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as handle:
        for path in files:
            relative = path.relative_to(package_root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            handle.writestr(info, path.read_bytes())
    return {
        "included": True,
        "path": str(archive),
        "sha256": sha256_file(archive),
        "bytes": archive.stat().st_size,
        "file_count": len(files),
    }


def _is_ignored_project_path(relative: Path) -> bool:
    if any(part in PROJECT_FILE_IGNORED_PARTS for part in relative.parts):
        return True
    return relative.suffix.lower() in PROJECT_FILE_IGNORED_SUFFIXES


def scan_for_secrets(paths: list[Path]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for path in paths:
        if not path.exists() or path.is_dir():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                findings.append(
                    {
                        "file": str(path),
                        "pattern": name,
                        "line": text.count("\n", 0, match.start()) + 1,
                        "preview": _redacted_preview(match.group(0)),
                    }
                )
    return {"status": "OK" if not findings else "FAILED", "findings": findings, "files_scanned": len(paths)}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_manifest(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _redacted_preview(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return value[:4] + "[REDACTED]" + value[-4:]
