"""Deterministic contradiction detection rules.

The graph is intentionally conservative: it flags clear conflicts that matter
for forensic correctness and returns concrete next tools for adjudication.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

from sift_mind.contracts import Contradiction, Finding


class ContradictionGraph:
    def find_contradictions(self, finding: Finding, existing: Iterable[Finding]) -> list[Contradiction]:
        contradictions: list[Contradiction] = []
        for other in existing:
            conflict = self._check_pair(finding, other)
            if conflict:
                contradictions.append(
                    Contradiction(
                        id=str(uuid4()),
                        finding_a_id=finding.id,
                        finding_b_id=other.id,
                        conflict_description=conflict["description"],
                        resolution_suggestion=conflict["suggestion"],
                    )
                )
        return contradictions

    def _check_pair(self, a: Finding, b: Finding) -> dict[str, str] | None:
        same_subject = self._same_subject(a.claim, b.claim)
        same_artifact = a.artifact_path == b.artifact_path
        same_process = self._same_process_identity(a, b)
        same_network = self._same_network_indicator(a, b)
        if not any([same_subject, same_artifact, same_process, same_network]):
            return None

        a_count = self._extract_run_count(a)
        b_count = self._extract_run_count(b)
        if a_count is not None and b_count is not None and a_count != b_count:
            subject = self._subject(a.claim) or self._subject(b.claim) or "artifact"
            return {
                "description": (
                    f"Run count mismatch for {subject}: new finding reports {a_count}, "
                    f"existing finding reports {b_count}."
                ),
                "suggestion": (
                    "Run get_artifact_at_time() and get_usnjrnl_entries() around the "
                    "execution window to check shadow copies, deletion/recreation, or "
                    "tool-specific counting semantics."
                ),
            }

        hash_conflict = self._hash_conflict(a, b) if same_subject or same_artifact else None
        if hash_conflict:
            return hash_conflict

        if same_process:
            visibility_conflict = self._process_visibility_conflict(a, b)
            if visibility_conflict:
                return visibility_conflict

        if same_network:
            network_conflict = self._network_observation_conflict(a, b)
            if network_conflict:
                return network_conflict

        a_ts = self._extract_timestamp(a.claim)
        b_ts = self._extract_timestamp(b.claim)
        if a_ts and b_ts:
            delta = abs((a_ts - b_ts).total_seconds())
            if delta > 60 and (same_subject or same_process or same_network):
                return {
                    "description": (
                        f"Timestamp mismatch for {self._subject(a.claim) or 'artifact'}: "
                        f"new finding reports {a_ts.isoformat()}, existing finding reports "
                        f"{b_ts.isoformat()}."
                    ),
                    "suggestion": (
                        "Run get_artifact_at_time() and get_usnjrnl_entries() around both "
                        "timestamps to establish the actual sequence."
                    ),
                }

        if self._claims_existence(a.claim, b.claim):
            return {
                "description": "Existence conflict: one finding says the artifact exists while another says it was deleted.",
                "suggestion": "Run get_usnjrnl_entries() and parse_mft() for the artifact path to reconstruct lifecycle.",
            }

        if self._process_state_conflict(a.claim, b.claim):
            return {
                "description": "Process state conflict: one source reports a running process while another reports it exited.",
                "suggestion": "Run find_hidden_modules(), list_processes(), and extract_injected_code() for the suspicious PID.",
            }

        return None

    def _same_subject(self, claim_a: str, claim_b: str) -> bool:
        subject_a = self._subject(claim_a)
        subject_b = self._subject(claim_b)
        return bool(subject_a and subject_b and subject_a == subject_b)

    def _same_process_identity(self, finding_a: Finding, finding_b: Finding) -> bool:
        return bool(self._process_tokens(finding_a).intersection(self._process_tokens(finding_b)))

    def _same_network_indicator(self, finding_a: Finding, finding_b: Finding) -> bool:
        return bool(self._network_tokens(finding_a).intersection(self._network_tokens(finding_b)))

    def _subject(self, claim: str) -> str | None:
        match = re.search(r"\b([A-Z0-9_.-]+\.(?:EXE|DLL|SYS|PS1|BAT|CMD))\b", claim.upper())
        if match:
            return match.group(1)
        ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", claim)
        return ip.group(0) if ip else None

    def _process_tokens(self, finding: Finding) -> set[str]:
        tokens: set[str] = set()
        pid = self._metadata_value(finding, "pid", "process_id")
        if pid not in (None, ""):
            tokens.add(f"pid:{pid}")
        name = self._metadata_value(finding, "process_name", "image_name", "exe_name")
        if name:
            tokens.add(f"name:{str(name).upper()}")
        subject = self._subject(finding.claim)
        if subject and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", subject):
            tokens.add(f"name:{subject.upper()}")
        pid_match = re.search(r"\bpid\s*[=: ]\s*(\d+)\b", finding.claim, re.IGNORECASE)
        if pid_match:
            tokens.add(f"pid:{pid_match.group(1)}")
        return tokens

    def _network_tokens(self, finding: Finding) -> set[str]:
        tokens: set[str] = set()
        for key in (
            "remote_ip",
            "destination_ip",
            "dst_ip",
            "source_ip",
            "src_ip",
            "ip",
            "domain",
            "host",
            "dns_query",
            "http_host",
        ):
            value = finding.metadata.get(key)
            if value:
                tokens.add(f"net:{str(value).strip().lower()}")
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", finding.claim):
            tokens.add(f"net:{ip}")
        domain_match = re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", finding.claim, re.IGNORECASE)
        if domain_match:
            tokens.add(f"net:{domain_match.group(1).lower()}")
        return tokens

    def _extract_run_count(self, finding: Finding) -> int | None:
        metadata_count = finding.metadata.get("run_count")
        if isinstance(metadata_count, int):
            return metadata_count
        patterns = [
            r"run[_ -]?count\s*[=:]\s*(\d+)",
            r"executed\s+(\d+)\s+times?",
            r"ran\s+(\d+)\s+times?",
            r"reports\s+(\d+)\s+runs?",
        ]
        for pattern in patterns:
            match = re.search(pattern, finding.claim, re.IGNORECASE)
            if match:
                return int(match.group(1))
        return None

    def _hash_conflict(self, a: Finding, b: Finding) -> dict[str, str] | None:
        hashes_a = self._extract_hashes(a)
        hashes_b = self._extract_hashes(b)
        for algorithm in sorted(set(hashes_a).intersection(hashes_b)):
            if hashes_a[algorithm] == hashes_b[algorithm]:
                continue
            subject = self._subject(a.claim) or self._subject(b.claim) or a.artifact_path or "artifact"
            return {
                "description": (
                    f"Hash mismatch for {subject}: new finding reports {algorithm}={hashes_a[algorithm]}, "
                    f"existing finding reports {algorithm}={hashes_b[algorithm]}."
                ),
                "suggestion": (
                    "Run get_amcache(), parse_mft(), get_usnjrnl_entries(), and parse_lnk_files() "
                    "to determine whether the binary was replaced, renamed, or parsed from different versions."
                ),
            }
        return None

    def _extract_hashes(self, finding: Finding) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for key in ("md5", "sha1", "sha256", "hash", "file_hash", "imphash"):
            value = finding.metadata.get(key)
            if isinstance(value, str):
                normalized = self._normalize_hash_value(value)
                if normalized:
                    hashes[self._hash_algorithm(key, normalized)] = normalized
        algorithm = finding.metadata.get("hash_algorithm")
        value = finding.metadata.get("hash_value")
        if isinstance(algorithm, str) and isinstance(value, str):
            normalized = self._normalize_hash_value(value)
            if normalized:
                hashes[algorithm.lower()] = normalized
        for match in re.finditer(
            r"\b(md5|sha1|sha256|imphash)\s*[=:]\s*([a-fA-F0-9]{32,64})\b",
            finding.claim,
            re.IGNORECASE,
        ):
            algorithm, value = match.groups()
            normalized = self._normalize_hash_value(value)
            if normalized:
                hashes[algorithm.lower()] = normalized
        return hashes

    def _normalize_hash_value(self, value: str) -> str:
        candidate = value.strip().lower()
        return candidate if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", candidate) else ""

    def _hash_algorithm(self, key: str, value: str) -> str:
        normalized_key = key.lower()
        if normalized_key in {"md5", "sha1", "sha256", "imphash"}:
            return normalized_key
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]

    def _process_visibility_conflict(self, a: Finding, b: Finding) -> dict[str, str] | None:
        visible_a = self._process_visible(a)
        visible_b = self._process_visible(b)
        if visible_a is None or visible_b is None or visible_a == visible_b:
            return None
        subject = self._process_label(a, b)
        return {
            "description": (
                f"Process visibility mismatch for {subject}: one source reports the process visible "
                "while another reports it hidden or absent from pslist."
            ),
            "suggestion": (
                "Run list_processes(), find_hidden_modules(), extract_injected_code(), and get_handles() "
                "for the PID before promoting either process-hiding claim."
            ),
        }

    def _process_visible(self, finding: Finding) -> bool | None:
        hidden = self._metadata_bool(finding, "hidden", "hidden_process", "unlinked")
        if hidden is True:
            return False
        visible = self._metadata_bool(finding, "visible", "process_visible", "in_pslist", "listed")
        if visible is not None:
            return visible
        claim = finding.claim.lower()
        if any(marker in claim for marker in ("hidden process", "unlinked process", "not in pslist", "absent from pslist")):
            return False
        if any(marker in claim for marker in ("pslist reports", "process list shows", "visible process", "listed process")):
            return True
        return None

    def _network_observation_conflict(self, a: Finding, b: Finding) -> dict[str, str] | None:
        observed_a = self._network_observed(a)
        observed_b = self._network_observed(b)
        if observed_a is None or observed_b is None or observed_a == observed_b:
            return None
        subject = self._network_label(a, b)
        return {
            "description": (
                f"Network observation mismatch for {subject}: one source reports activity present "
                "while another reports it absent."
            ),
            "suggestion": (
                "Run parse_pcap_summary(), extract_dns_queries(), get_http_requests(), "
                "get_network_connections(), and correlate_timestamps() for the same time window."
            ),
        }

    def _network_observed(self, finding: Finding) -> bool | None:
        observed = self._metadata_bool(
            finding,
            "network_observed",
            "observed",
            "connection_present",
            "pcap_seen",
            "memory_seen",
            "seen",
        )
        if observed is not None:
            return observed
        claim = finding.claim.lower()
        if any(marker in claim for marker in ("no connection", "not seen", "absent", "no dns", "no http")):
            return False
        if any(marker in claim for marker in ("pcap observed", "dns query", "http request", "netscan reports")):
            return True
        return None

    def _extract_timestamp(self, claim: str) -> datetime | None:
        patterns = [
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?",
            r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}",
        ]
        for pattern in patterns:
            match = re.search(pattern, claim)
            if not match:
                continue
            raw = match.group(0).replace("Z", "+00:00").replace(" ", "T")
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        return None

    def _claims_existence(self, claim_a: str, claim_b: str) -> bool:
        joined = f"{claim_a.lower()} || {claim_b.lower()}"
        return (" exists" in joined or " present" in joined) and (" deleted" in joined or " wiped" in joined)

    def _process_state_conflict(self, claim_a: str, claim_b: str) -> bool:
        joined = f"{claim_a.lower()} || {claim_b.lower()}"
        return "process" in joined and "running" in joined and "exited" in joined

    def _metadata_value(self, finding: Finding, *keys: str) -> object:
        for key in keys:
            value = finding.metadata.get(key)
            if value not in (None, ""):
                return value
        return None

    def _metadata_bool(self, finding: Finding, *keys: str) -> bool | None:
        for key in keys:
            value = finding.metadata.get(key)
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"true", "yes", "1", "present", "visible", "seen"}:
                    return True
                if lowered in {"false", "no", "0", "absent", "hidden", "not_seen"}:
                    return False
        return None

    def _process_label(self, a: Finding, b: Finding) -> str:
        for finding in (a, b):
            pid = self._metadata_value(finding, "pid", "process_id")
            name = self._metadata_value(finding, "process_name", "image_name", "exe_name")
            if pid and name:
                return f"{name} PID {pid}"
            if pid:
                return f"PID {pid}"
            if name:
                return str(name)
        return self._subject(a.claim) or self._subject(b.claim) or "process"

    def _network_label(self, a: Finding, b: Finding) -> str:
        tokens = sorted(self._network_tokens(a).intersection(self._network_tokens(b)))
        if tokens:
            return tokens[0].removeprefix("net:")
        return self._subject(a.claim) or self._subject(b.claim) or "network indicator"
