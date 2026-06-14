"""Base class for evidence-safe SIFT tool wrappers."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any
from uuid import uuid4

from sift_mind.contracts import MCPResponse, RunConfig, ToolExecutionRecord, ToolResult, utc_now
from sift_mind.mcp_server.tools.parsers import parse_json_csv_or_lines


MAX_GENERATED_OUTPUT_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_GENERATED_OUTPUT_FILES = 25
TEXT_OUTPUT_SUFFIXES = {
    ".csv",
    ".json",
    ".jsonl",
    ".log",
    ".txt",
    ".tsv",
    ".xml",
    ".yaml",
    ".yml",
}


class ToolWrapper:
    def __init__(self, config: RunConfig):
        self.config = config
        self.case_root = Path(config.case_root)
        self.evidence_chain_path = Path(config.evidence_chain_path)
        self.execution_log_path = Path(config.execution_log_path)
        self.output_dir = Path(config.output_dir)
        self._validate_managed_paths_outside_case_root()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_chain_path.parent.mkdir(parents=True, exist_ok=True)
        self.execution_log_path.parent.mkdir(parents=True, exist_ok=True)

    def _fixture_response(
        self,
        *,
        tool_name: str,
        artifact_path: str,
        parsed: dict[str, Any],
        confidence: float,
        command_run: str | None = None,
    ) -> MCPResponse:
        raw_output = json.dumps(parsed, sort_keys=True)
        raw_hash = self._log_evidence_chain(tool_name, artifact_path, command_run or f"fixture://{tool_name}", raw_output)
        result = self._build_result(
            tool_name=tool_name,
            artifact_path=artifact_path,
            raw_hash=raw_hash,
            parsed=parsed,
            confidence=confidence,
            command_run=command_run or f"fixture://{tool_name}",
            tool_version="fixture",
        )
        self._log_tool_execution(result, "OK", "")
        return MCPResponse.ok(result)

    def _external_tool_response(
        self,
        *,
        tool_name: str,
        artifact_path: str,
        command: list[str],
        parser,
        confidence: float,
        timeout: int = 300,
        output_paths: list[str | Path] | None = None,
        executable_candidates: list[str] | None = None,
    ) -> MCPResponse:
        safety_error = self._validate_artifact_path(artifact_path)
        if safety_error:
            return self._error_result(tool_name, artifact_path, " ".join(command), safety_error)
        for output_path in output_paths or []:
            output_error = self._validate_generated_output_path(Path(output_path))
            if output_error:
                return self._error_result(tool_name, artifact_path, " ".join(command), output_error)
        resolved_executable = self._resolve_executable(command[0], executable_candidates or [])
        if not resolved_executable:
            return self._error_result(
                tool_name,
                artifact_path,
                " ".join(command),
                "Required external tool is unavailable on PATH: "
                + ", ".join(self._candidate_executables(command[0], executable_candidates or [])),
            )
        command = [resolved_executable, *command[1:]]
        executable = command[0]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.case_root),
                check=False,
            )
            stdout_stderr = result.stdout + result.stderr
        except (OSError, subprocess.SubprocessError) as exc:
            return self._error_result(tool_name, artifact_path, " ".join(command), f"Tool execution failed: {exc}")

        generated_outputs = self._capture_generated_outputs(output_paths or [])
        raw_output = self._compose_raw_output(stdout_stderr, generated_outputs)
        parser_input = self._parser_input(stdout_stderr, generated_outputs)
        raw_hash = self._hash_external_raw_output(stdout_stderr, generated_outputs)
        raw_hash = self._log_evidence_chain(
            tool_name,
            artifact_path,
            " ".join(command),
            raw_output,
            raw_hash=raw_hash,
            extra_record={
                "generated_outputs": self._generated_output_metadata(generated_outputs),
            },
        )
        try:
            parsed = parser(parser_input)
        except Exception as exc:  # Parsers must degrade into structured errors.
            parsed = {"error": f"Parser failed: {exc}", "raw_preview": parser_input[:1000]}
            confidence = 0.0
        if generated_outputs:
            parsed["_generated_outputs"] = self._generated_output_metadata(generated_outputs)
        result = self._build_result(
            tool_name=tool_name,
            artifact_path=artifact_path,
            raw_hash=raw_hash,
            parsed=parsed,
            confidence=confidence,
            command_run=" ".join(command),
            tool_version=self._tool_version(executable),
        )
        self._log_tool_execution(result, "OK", "")
        return MCPResponse.ok(result)

    def _build_result(
        self,
        *,
        tool_name: str,
        artifact_path: str,
        raw_hash: str,
        parsed: dict[str, Any],
        confidence: float,
        command_run: str,
        tool_version: str,
    ) -> ToolResult:
        bounded, truncated = self._bound_tokens(parsed, self.config.max_tool_tokens)
        return ToolResult(
            tool_name=tool_name,
            artifact_path=artifact_path,
            raw_hash=raw_hash,
            parsed=bounded,
            confidence=confidence,
            truncated=truncated,
            token_estimate=max(len(json.dumps(bounded, default=str)) // 4, 1),
            timestamp=utc_now(),
            tool_version=tool_version,
            command_run=command_run,
        )

    def _error_result(self, tool_name: str, artifact_path: str, command_run: str, message: str) -> MCPResponse:
        parsed = {"error": message, "tool_available": False}
        raw_hash = self._log_evidence_chain(tool_name, artifact_path, command_run, json.dumps(parsed, sort_keys=True))
        result = self._build_result(
            tool_name=tool_name,
            artifact_path=artifact_path,
            raw_hash=raw_hash,
            parsed=parsed,
            confidence=0.0,
            command_run=command_run,
            tool_version="unavailable",
        )
        self._log_tool_execution(result, "ERROR", message)
        return MCPResponse.error_response(message, result)

    def _log_evidence_chain(
        self,
        tool_name: str,
        artifact_path: str,
        command_run: str,
        raw_output: str,
        raw_hash: str | None = None,
        extra_record: dict[str, Any] | None = None,
    ) -> str:
        raw_hash = raw_hash or hashlib.sha256(raw_output.encode("utf-8", errors="replace")).hexdigest()
        record = {
            "timestamp": utc_now().isoformat(),
            "tool_name": tool_name,
            "artifact_path": artifact_path,
            "raw_hash": raw_hash,
            "command_run": command_run,
            "previous_record_hash": self._last_evidence_record_hash(),
        }
        if extra_record:
            record.update(extra_record)
        record["record_hash"] = self._evidence_record_hash(record)
        with self.evidence_chain_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return raw_hash

    def _last_evidence_record_hash(self) -> str:
        if not self.evidence_chain_path.exists():
            return ""
        for line in reversed(self.evidence_chain_path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return ""
            record_hash = record.get("record_hash")
            return record_hash if isinstance(record_hash, str) else ""
        return ""

    def _evidence_record_hash(self, record: dict[str, Any]) -> str:
        content = {key: value for key, value in record.items() if key != "record_hash"}
        serialized = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialized.encode("utf-8", errors="replace")).hexdigest()

    def _log_tool_execution(self, result: ToolResult, status: str, error: str) -> None:
        record = ToolExecutionRecord(
            timestamp=result.timestamp,
            tool_name=result.tool_name,
            artifact_path=result.artifact_path,
            raw_hash=result.raw_hash,
            command_run=result.command_run,
            status=status,
            token_estimate=result.token_estimate,
            truncated=result.truncated,
            confidence=result.confidence,
            tool_version=result.tool_version,
            error=error,
            provider=self.config.model.provider,
            model=self.config.model.model,
        )
        with self.execution_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.model_dump(mode="json"), sort_keys=True) + "\n")

    def _bound_tokens(self, data: dict[str, Any], max_tokens: int) -> tuple[dict[str, Any], bool]:
        serialized = json.dumps(data, default=str)
        if len(serialized) <= max_tokens * 4:
            return data, False
        bounded: dict[str, Any] = {"_truncated": True}
        for key, value in data.items():
            candidate = dict(bounded)
            candidate[key] = value
            if len(json.dumps(candidate, default=str)) > max_tokens * 4:
                if isinstance(value, list):
                    bounded[key] = value[: max(1, max_tokens // 80)]
                else:
                    bounded[key] = str(value)[: max_tokens * 2]
                break
            bounded = candidate
        return bounded, True

    def _validate_artifact_path(self, artifact_path: str) -> str:
        if self.config.mode == "fixture":
            return ""
        if not artifact_path:
            return "artifact_path is required."
        root = self.case_root.resolve()
        candidate = Path(artifact_path)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve()
        except OSError as exc:
            return f"Could not resolve artifact_path: {exc}"
        if root not in [resolved, *resolved.parents]:
            return f"Artifact path is outside CASE_ROOT: {resolved}"
        return ""

    def _validate_generated_output_path(self, output_path: Path) -> str:
        output_root = self.output_dir.resolve()
        try:
            resolved = output_path.resolve()
        except OSError as exc:
            return f"Could not resolve generated output path: {exc}"
        if output_root not in [resolved, *resolved.parents]:
            return f"Generated output path must stay inside OUTPUT_DIR: {resolved}"
        return ""

    def _validate_managed_paths_outside_case_root(self) -> None:
        if self.config.mode == "fixture":
            return
        root = self.case_root.resolve()
        managed_paths = {
            "OUTPUT_DIR": self.output_dir,
            "EVIDENCE_CHAIN parent": self.evidence_chain_path.parent,
            "AGENT_EXECUTION_LOG parent": self.execution_log_path.parent,
        }
        for label, path in managed_paths.items():
            resolved = path.resolve()
            if resolved == root or root in resolved.parents:
                raise ValueError(f"{label} must be outside CASE_ROOT to preserve evidence integrity: {resolved}")

    def _tool_version(self, executable: str) -> str:
        try:
            result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            return "unknown"
        return (result.stdout or result.stderr or "unknown").strip()[:200]

    def _candidate_executables(self, primary: str, candidates: list[str]) -> list[str]:
        ordered = [primary, *candidates]
        deduped: list[str] = []
        for value in ordered:
            if value and value not in deduped:
                deduped.append(value)
        return deduped

    def _resolve_executable(self, primary: str, candidates: list[str]) -> str:
        for candidate in self._candidate_executables(primary, candidates):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        return ""

    def _json_or_lines(self, raw_output: str) -> dict[str, Any]:
        return parse_json_csv_or_lines(raw_output)

    def _tool_output_file(self, tool_name: str, suffix: str) -> Path:
        safe_tool = self._safe_path_part(tool_name)
        name = f"{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}-{uuid4().hex[:8]}{suffix}"
        path = self.output_dir / "tool_outputs" / safe_tool / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _tool_output_dir(self, tool_name: str) -> Path:
        safe_tool = self._safe_path_part(tool_name)
        path = self.output_dir / "tool_outputs" / safe_tool / f"{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}-{uuid4().hex[:8]}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _safe_path_part(self, value: str) -> str:
        return "".join(character if character.isalnum() or character in {"-", "_"} else "_" for character in value)[:80]

    def _capture_generated_outputs(self, output_paths: list[str | Path]) -> list[dict[str, Any]]:
        captures: list[dict[str, Any]] = []
        for output_path in output_paths:
            path = Path(output_path)
            try:
                resolved = path.resolve()
            except OSError as exc:
                captures.append({"path": str(path), "exists": False, "error": f"resolve failed: {exc}"})
                continue
            if not resolved.exists():
                captures.append({"path": str(resolved), "exists": False, "error": "generated output was not created"})
                continue
            if resolved.is_dir():
                files = sorted(child for child in resolved.rglob("*") if child.is_file())[:MAX_GENERATED_OUTPUT_FILES]
                captures.append(
                    {
                        "path": str(resolved),
                        "exists": True,
                        "is_dir": True,
                        "file_count_captured": len(files),
                        "files": [self._capture_generated_file(child) for child in files],
                    }
                )
                continue
            captures.append(self._capture_generated_file(resolved))
        return captures

    def _capture_generated_file(self, path: Path) -> dict[str, Any]:
        size = path.stat().st_size
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        with path.open("rb") as handle:
            sample = handle.read(MAX_GENERATED_OUTPUT_CAPTURE_BYTES + 1)
        truncated = len(sample) > MAX_GENERATED_OUTPUT_CAPTURE_BYTES
        captured = sample[:MAX_GENERATED_OUTPUT_CAPTURE_BYTES]
        content = ""
        text = self._looks_like_text_output(path, captured)
        if text:
            content = captured.decode("utf-8", errors="replace")
        return {
            "path": str(path),
            "exists": True,
            "is_dir": False,
            "size_bytes": size,
            "sha256": digest.hexdigest(),
            "captured_bytes": len(captured),
            "truncated": truncated,
            "text": text,
            "content": content,
        }

    def _looks_like_text_output(self, path: Path, data: bytes) -> bool:
        if path.suffix.lower() in TEXT_OUTPUT_SUFFIXES:
            return True
        if b"\x00" in data[:4096]:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    def _compose_raw_output(self, stdout_stderr: str, generated_outputs: list[dict[str, Any]]) -> str:
        return json.dumps(
            {
                "stdout_stderr": stdout_stderr,
                "generated_outputs": self._generated_output_metadata(generated_outputs),
            },
            sort_keys=True,
            default=str,
        )

    def _parser_input(self, stdout_stderr: str, generated_outputs: list[dict[str, Any]]) -> str:
        texts: list[str] = []
        for output in generated_outputs:
            texts.extend(self._generated_output_texts(output))
        return "\n".join(texts) if texts else stdout_stderr

    def _generated_output_texts(self, output: dict[str, Any]) -> list[str]:
        if output.get("is_dir"):
            texts: list[str] = []
            for child in output.get("files", []):
                texts.extend(self._generated_output_texts(child))
            return texts
        content = output.get("content")
        if isinstance(content, str) and content:
            return [content]
        return []

    def _generated_output_metadata(self, generated_outputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self._strip_generated_content(output) for output in generated_outputs]

    def _strip_generated_content(self, output: dict[str, Any]) -> dict[str, Any]:
        stripped = {key: value for key, value in output.items() if key != "content"}
        if "files" in stripped and isinstance(stripped["files"], list):
            stripped["files"] = [self._strip_generated_content(child) for child in stripped["files"]]
        return stripped

    def _hash_external_raw_output(self, stdout_stderr: str, generated_outputs: list[dict[str, Any]]) -> str:
        digest = hashlib.sha256()
        digest.update(stdout_stderr.encode("utf-8", errors="replace"))
        for output in generated_outputs:
            self._update_digest_with_generated_output(digest, output)
        return digest.hexdigest()

    def _update_digest_with_generated_output(self, digest: Any, output: dict[str, Any]) -> None:
        digest.update(json.dumps(self._strip_generated_content(output), sort_keys=True, default=str).encode("utf-8"))
        if output.get("is_dir"):
            for child in output.get("files", []):
                self._update_digest_with_generated_output(digest, child)
            return
        if not output.get("exists"):
            return
        path = Path(str(output["path"]))
        if not path.is_file():
            return
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
