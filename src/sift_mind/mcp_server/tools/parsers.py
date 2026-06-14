"""Structured parsers for common SIFT/DFIR tool output.

These parsers are intentionally dependency-light. They prefer JSON/CSV when a
tool can emit it, and fall back to conservative table/XML-ish extraction.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from datetime import datetime
from typing import Any, Iterable


def parse_json_csv_or_lines(raw_output: str) -> dict[str, Any]:
    parsed = _json(raw_output)
    if parsed is not None:
        return parsed if isinstance(parsed, dict) else {"entries": parsed, "total_entries": len(parsed)}
    csv_rows = _csv_rows(raw_output)
    if csv_rows:
        return {"entries": csv_rows, "total_entries": len(csv_rows), "format": "csv"}
    table_rows = _table_rows(raw_output)
    if table_rows:
        return {"entries": table_rows, "total_entries": len(table_rows), "format": "table"}
    return {"lines": _lines(raw_output), "format": "lines"}


def parse_prefetch(raw_output: str) -> dict[str, Any]:
    rows = _entry_rows(raw_output)
    entries = []
    for row in rows:
        normalized = _normalize_dict(row)
        executable = _first(normalized, "executable", "executablename", "filename", "file_name", "name")
        if not executable:
            continue
        loaded_files = _split_list(_first(normalized, "filesloaded", "loadedfiles", "loaded_files"))
        entries.append(
            {
                "executable": executable,
                "prefetch_hash": _first(normalized, "hash", "prefetchhash", "prefetch_hash"),
                "run_count": _to_int(_first(normalized, "runcount", "run_count", "numberofexecutions")),
                "last_run_times": _extract_timestamps(" ".join(str(value) for value in row.values())),
                "volume_path": _first(normalized, "volumepath", "volumeserialnumber", "volume"),
                "loaded_files": loaded_files[:50],
                "loaded_files_ioc_matches": _ioc_loaded_files(loaded_files),
            }
        )
    return {"entries": entries, "total_found": len(entries), "format": _format_name(raw_output)}


def parse_amcache(raw_output: str) -> dict[str, Any]:
    rows = _entry_rows(raw_output)
    entries = []
    for row in rows:
        normalized = _normalize_dict(row)
        program = _first(normalized, "programname", "program_name", "name", "filename", "file_name")
        path = _first(normalized, "fullpath", "full_path", "path", "filepath", "file_path")
        if not program and path:
            program = path.replace("/", "\\").split("\\")[-1]
        if not program and not path:
            continue
        entries.append(
            {
                "program_name": program,
                "full_path": path,
                "sha1": _first(normalized, "sha1", "hash", "filesha1"),
                "last_modified": _first_timestamp(row),
                "publisher": _first(normalized, "publisher", "companyname"),
                "is_known_malicious": _looks_suspicious(program, path),
            }
        )
    return {"entries": entries, "total_entries": len(rows), "filtered_entries": len(entries), "format": _format_name(raw_output)}


def parse_mft(raw_output: str) -> dict[str, Any]:
    rows = _entry_rows(raw_output)
    entries = []
    for row in rows:
        normalized = _normalize_dict(row)
        filename = _first(normalized, "filename", "file_name", "name")
        full_path = _first(normalized, "fullpath", "full_path", "path")
        if not filename and full_path:
            filename = full_path.replace("/", "\\").split("\\")[-1]
        if not filename and not full_path:
            continue
        created = _first(normalized, "created", "sicreated", "created0x10", "fncreated")
        modified = _first(normalized, "modified", "simodified", "modified0x10", "fnmodified")
        accessed = _first(normalized, "accessed", "siaccessed", "accessed0x10", "fnaccessed")
        mft_modified = _first(normalized, "mftmodified", "entrymodified", "si_entry_modified")
        timestomp = _timestamp_suspicious(created, modified, accessed)
        entries.append(
            {
                "filename": filename,
                "full_path": full_path,
                "created": created,
                "modified": modified,
                "accessed": accessed,
                "mft_modified": mft_modified,
                "size_bytes": _to_int(_first(normalized, "size", "sizebytes", "logicalsize")),
                "is_deleted": _truthy(_first(normalized, "deleted", "isdeleted", "inuse")),
                "timestomp_suspected": timestomp,
            }
        )
    return {
        "entries": entries,
        "total_entries": len(entries),
        "timestomp_analysis": {
            "checked": True,
            "method": "timestamp ordering and available $SI/$FN-style fields",
        },
        "format": _format_name(raw_output),
    }


def parse_registry(raw_output: str) -> dict[str, Any]:
    structured = parse_json_csv_or_lines(raw_output)
    if "entries" in structured and structured["entries"]:
        return {"values": structured["entries"], "format": structured.get("format", "structured")}
    key_path = ""
    last_modified = ""
    values = []
    for line in _lines(raw_output):
        if re.search(r"key\s*path|path", line, re.I) and ":" in line:
            key_path = line.split(":", 1)[1].strip()
        elif re.search(r"last\s*(write|modified)", line, re.I) and ":" in line:
            last_modified = line.split(":", 1)[1].strip()
        elif "=" in line:
            name, data = line.split("=", 1)
            values.append({"name": name.strip(), "data": data.strip(), "type": ""})
    indicators = []
    joined = raw_output.lower()
    if "imagepath" in joined and ("temp" in joined or "appdata" in joined):
        indicators.append("Non-standard ImagePath location")
    if re.search(r"\bstart\s*=\s*2\b", joined):
        indicators.append("Service auto-start")
    return {"key_path": key_path, "last_modified": last_modified, "values": values, "persistence_indicators": indicators}


def parse_volatility_processes(raw_output: str) -> dict[str, Any]:
    rows = _entry_rows(raw_output)
    processes = []
    for row in rows:
        normalized = _normalize_dict(row)
        pid = _to_int(_first(normalized, "pid"))
        name = _first(normalized, "imagefilename", "image_file_name", "name", "process", "proc")
        if pid is None and not name:
            continue
        processes.append(
            {
                "pid": pid,
                "ppid": _to_int(_first(normalized, "ppid", "parentpid")),
                "name": name,
                "create_time": _first(normalized, "createtime", "create_time"),
                "exit_time": _first(normalized, "exittime", "exit_time"),
                "is_running": not bool(_first(normalized, "exittime", "exit_time")),
                "path": _first(normalized, "path"),
                "parent_name": _first(normalized, "parent", "parentname", "parent_name"),
                "anomalies": _process_anomalies(name, _first(normalized, "parent", "parentname")),
                "hidden": False,
            }
        )
    return {"processes": processes, "orphaned_processes": [], "hollowed_suspected": [], "format": _format_name(raw_output)}


def parse_volatility_netscan(raw_output: str) -> dict[str, Any]:
    rows = _entry_rows(raw_output)
    connections = []
    for row in rows:
        normalized = _normalize_dict(row)
        local = _endpoint(_first(normalized, "localaddr", "localaddress", "local"), _first(normalized, "localport"))
        remote = _endpoint(_first(normalized, "foreignaddr", "foreignaddress", "remoteaddr", "remote"), _first(normalized, "foreignport", "remoteport"))
        if not local and not remote:
            continue
        connections.append(
            {
                "pid": _to_int(_first(normalized, "pid", "ownerpid")),
                "process": _first(normalized, "owner", "process", "name"),
                "local": local,
                "remote": remote,
                "state": _first(normalized, "state"),
                "timestamp": _first(normalized, "created", "timestamp", "time"),
            }
        )
    return {"connections": connections, "format": _format_name(raw_output)}


def parse_volatility_handles(raw_output: str) -> dict[str, Any]:
    rows = _entry_rows(raw_output)
    handles = []
    suspicious = []
    for row in rows:
        normalized = _normalize_dict(row)
        name = _first(normalized, "name", "details")
        handle = {
            "pid": _to_int(_first(normalized, "pid")),
            "type": _first(normalized, "type"),
            "name": name,
            "access": _first(normalized, "grantedaccess", "access"),
        }
        if not any(handle.values()):
            continue
        handles.append(handle)
        if name and re.search(r"lsass|\\sam\b|\\security\b", name, re.I):
            suspicious.append(name)
    return {"handles": handles, "suspicious_access": suspicious, "format": _format_name(raw_output)}


def parse_yara(raw_output: str) -> dict[str, Any]:
    parsed = _json(raw_output)
    if parsed is not None:
        rows = parsed if isinstance(parsed, list) else parsed.get("matches", parsed.get("entries", []))
    else:
        rows = []
        for line in _lines(raw_output):
            parts = line.split()
            if parts:
                rows.append({"rule": parts[0], "target": parts[1] if len(parts) > 1 else "", "offset": parts[2] if len(parts) > 2 else ""})
    matches = []
    for row in rows:
        normalized = _normalize_dict(row)
        rule = _first(normalized, "rule", "rulename", "name")
        if not rule:
            continue
        matches.append(
            {
                "rule": rule,
                "pid": _to_int(_first(normalized, "pid", "processid")),
                "offset": _first(normalized, "offset"),
                "target": _first(normalized, "target", "file", "path"),
                "mitre": _first(normalized, "mitre"),
                "confidence": _first(normalized, "confidence"),
            }
        )
    return {"matches": matches, "total_matches": len(matches), "format": _format_name(raw_output)}


def parse_evtx(raw_output: str, event_ids: Iterable[int] | None = None) -> dict[str, Any]:
    wanted = {int(value) for value in event_ids or []}
    parsed = _json(raw_output)
    rows: list[dict[str, Any]] = []
    if parsed is not None:
        if isinstance(parsed, list):
            rows = parsed
        elif isinstance(parsed, dict):
            rows = parsed.get("events", parsed.get("entries", [parsed]))
    elif "<Event" in raw_output:
        rows = _xml_events(raw_output)
    else:
        rows = _entry_rows(raw_output)
    events = []
    for row in rows:
        normalized = _normalize_dict(row)
        event_id = _to_int(_first(normalized, "eventid", "event_id", "id"))
        if wanted and event_id not in wanted:
            continue
        event = {
            "event_id": event_id,
            "timestamp": _first(normalized, "timestamp", "timecreated", "systemtime", "time"),
            "provider": _first(normalized, "provider", "providername"),
            "computer": _first(normalized, "computer", "host"),
            "username": _first(normalized, "targetusername", "subjectusername", "username", "user"),
            "process": _first(normalized, "newprocessname", "process", "image"),
            "parent_process": _first(normalized, "parentprocessname", "parentprocess"),
            "command_line": _first(normalized, "commandline", "processcommandline"),
            "source_ip": _first(normalized, "ipaddress", "sourceip", "source_ip"),
            "task_name": _first(normalized, "taskname", "task_name"),
            "raw": row,
        }
        events.append(event)
    return {"events": events, "total_events": len(events), "filters": {"event_ids": sorted(wanted)}, "format": _format_name(raw_output)}


def parse_tshark_json(raw_output: str, kind: str) -> dict[str, Any]:
    parsed = _json(raw_output)
    if parsed is None:
        if kind == "conversations":
            return parse_tshark_conversations(raw_output)
        return {"entries": _lines(raw_output), "format": "lines"}
    packets = parsed if isinstance(parsed, list) else parsed.get("packets", parsed.get("entries", []))
    if kind == "dns":
        queries = []
        for packet in packets:
            fields = _packet_fields(packet)
            query = _first(fields, "dnsqryname", "dns_qry_name")
            if query:
                queries.append({"timestamp": _first(fields, "frametime", "frame_time"), "query": query, "answer": _first(fields, "dnsa", "dns_a")})
        return {"queries": queries, "format": "tshark_json"}
    if kind == "http":
        requests = []
        for packet in packets:
            fields = _packet_fields(packet)
            method = _first(fields, "httprequestmethod", "http_request_method")
            if method:
                requests.append(
                    {
                        "timestamp": _first(fields, "frametime", "frame_time"),
                        "method": method,
                        "host": _first(fields, "httphost", "http_host"),
                        "uri": _first(fields, "httprequesturi", "http_request_uri"),
                        "user_agent": _first(fields, "httpuseragent", "http_user_agent"),
                    }
                )
        return {"requests": requests, "format": "tshark_json"}
    return {"packets": len(packets), "entries": packets[:500], "format": "tshark_json"}


def parse_tshark_conversations(raw_output: str) -> dict[str, Any]:
    conversations = []
    pattern = re.compile(
        r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?\s+<->\s+"
        r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?.*?(?P<bytes>\d+)\s*$"
    )
    for line in _lines(raw_output):
        match = pattern.search(line)
        if not match:
            continue
        conversations.append(
            {
                "src": match.group("src"),
                "src_port": _to_int(match.group("src_port")),
                "dst": match.group("dst"),
                "dst_port": _to_int(match.group("dst_port")),
                "bytes": _to_int(match.group("bytes")),
            }
        )
    return {"packets": None, "conversations": conversations, "format": "tshark_conversations"}


def parse_timeline(raw_output: str) -> dict[str, Any]:
    rows = _entry_rows(raw_output)
    entries = []
    timestamps = []
    for row in rows:
        normalized = _normalize_dict(row)
        timestamp = _first(normalized, "datetime", "date", "timestamp", "time")
        description = _first(normalized, "desc", "description", "message", "short")
        if timestamp:
            timestamps.append(str(timestamp))
        entries.append(
            {
                "timestamp": timestamp,
                "source": _first(normalized, "source", "sourcetype"),
                "artifact": _first(normalized, "filename", "path", "artifact"),
                "description": description,
                "user": _first(normalized, "user"),
                "host": _first(normalized, "host"),
            }
        )
    suspicious = _suspicious_windows(entries)
    return {
        "time_range": {"start": min(timestamps) if timestamps else "", "end": max(timestamps) if timestamps else ""},
        "suspicious_windows": suspicious,
        "entries": entries[:500],
        "total_entries": len(entries),
        "format": _format_name(raw_output),
    }


def _json(raw_output: str) -> Any | None:
    text = raw_output.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    values = []
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        try:
            value, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            return None
        values.append(value)
        idx = end
    return values if values else None


def _csv_rows(raw_output: str) -> list[dict[str, str]]:
    sample = raw_output.strip()
    if not sample or "," not in sample.splitlines()[0]:
        return []
    try:
        reader = csv.DictReader(io.StringIO(sample))
        return [dict(row) for row in reader if any(row.values())]
    except csv.Error:
        return []


def _table_rows(raw_output: str) -> list[dict[str, str]]:
    lines = _lines(raw_output)
    if len(lines) < 2:
        return []
    header_index = None
    for idx, line in enumerate(lines[:-1]):
        if len(re.split(r"\s{2,}|\t", line.strip())) >= 2:
            header_index = idx
            break
    if header_index is None:
        return []
    headers = [item.strip() for item in re.split(r"\s{2,}|\t", lines[header_index].strip()) if item.strip()]
    rows = []
    for line in lines[header_index + 1 :]:
        if set(line.strip()) <= {"-", "="}:
            continue
        values = [item.strip() for item in re.split(r"\s{2,}|\t", line.strip(), maxsplit=len(headers) - 1)]
        if len(values) < 2:
            continue
        while len(values) < len(headers):
            values.append("")
        rows.append(dict(zip(headers, values[: len(headers)])))
    return rows


def _entry_rows(raw_output: str) -> list[dict[str, Any]]:
    parsed = _json(raw_output)
    if parsed is not None:
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            for key in ("entries", "events", "processes", "connections", "rows", "data"):
                if isinstance(parsed.get(key), list):
                    return [item for item in parsed[key] if isinstance(item, dict)]
            return [parsed]
    return _csv_rows(raw_output) or _table_rows(raw_output)


def _xml_events(raw_output: str) -> list[dict[str, str]]:
    events = []
    for event_text in re.findall(r"<Event\b.*?</Event>", raw_output, flags=re.S):
        row: dict[str, str] = {}
        event_id = re.search(r"<EventID[^>]*>(.*?)</EventID>", event_text, flags=re.S)
        if event_id:
            row["EventID"] = _strip_xml(event_id.group(1))
        time = re.search(r"<TimeCreated[^>]*SystemTime=[\"']([^\"']+)[\"']", event_text)
        if time:
            row["SystemTime"] = time.group(1)
        provider = re.search(r"<Provider[^>]*Name=[\"']([^\"']+)[\"']", event_text)
        if provider:
            row["Provider"] = provider.group(1)
        computer = re.search(r"<Computer>(.*?)</Computer>", event_text, flags=re.S)
        if computer:
            row["Computer"] = _strip_xml(computer.group(1))
        for name, value in re.findall(r"<Data[^>]*Name=[\"']([^\"']+)[\"'][^>]*>(.*?)</Data>", event_text, flags=re.S):
            row[name] = _strip_xml(value)
        events.append(row)
    return events


def _packet_fields(packet: dict[str, Any]) -> dict[str, Any]:
    source = packet.get("_source", {}).get("layers", packet.get("layers", packet))
    flat: dict[str, Any] = {}

    def visit(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                visit(key, child)
        elif isinstance(value, list):
            flat[_normalize_key(prefix)] = value[0] if value else ""
        else:
            flat[_normalize_key(prefix)] = value

    visit("", source)
    return flat


def _normalize_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {_normalize_key(str(key)): value for key, value in row.items()}


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(_normalize_key(key))
        if value is not None and value != "":
            return str(value)
    return ""


def _first_timestamp(row: dict[str, Any]) -> str:
    for value in row.values():
        match = _extract_timestamps(str(value))
        if match:
            return match[0]
    return ""


def _extract_timestamps(text: str) -> list[str]:
    patterns = [
        r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?",
        r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?",
    ]
    found = []
    for pattern in patterns:
        found.extend(match.group(0).replace(" ", "T", 1) for match in re.finditer(pattern, text, flags=re.I))
    return found


def _split_list(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in re.split(r"[|;,]", value) if item.strip()]


def _ioc_loaded_files(files: list[str]) -> list[dict[str, str]]:
    indicators = {
        "SAMLIB.DLL": "SAM database access",
        "CRYPTDLL.DLL": "Cryptographic operations",
        "VAULTCLI.DLL": "Windows Vault credential access",
        "WDIGEST.DLL": "WDigest credential access",
        "LSASRV.DLL": "LSA server access",
    }
    matches = []
    for file_name in files:
        leaf = file_name.upper().split("\\")[-1].split("/")[-1]
        if leaf in indicators:
            matches.append({"dll": leaf, "significance": indicators[leaf]})
    return matches


def _looks_suspicious(*values: str) -> bool:
    joined = " ".join(value or "" for value in values).lower()
    return any(term in joined for term in ["mimikatz", "psexec", "cobalt", "temp\\evil", "sekurlsa"])


def _timestamp_suspicious(created: str, modified: str, accessed: str) -> bool:
    parsed = [_parse_dt(value) for value in (created, modified, accessed) if value]
    parsed = [value for value in parsed if value is not None]
    if len(parsed) < 2:
        return False
    return any(parsed[idx] < parsed[0] for idx in range(1, len(parsed)))


def _parse_dt(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _truthy(value: str) -> bool:
    if value.lower() == "false":
        return False
    if value.lower() in {"true", "yes", "y", "1", "deleted"}:
        return True
    if value.lower() in {"inuse", "allocated"}:
        return False
    return False


def _to_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        match = re.search(r"\d+", str(value))
        return int(match.group(0)) if match else None


def _endpoint(address: str, port: str) -> str:
    if not address:
        return ""
    if ":" in address and not port:
        return address
    return f"{address}:{port}" if port else address


def _process_anomalies(name: str, parent: str) -> list[str]:
    anomalies = []
    if name and re.search(r"mimikatz|procdump|psexec", name, re.I):
        anomalies.append("known_tool_name")
    if parent and re.search(r"cmd|powershell|wscript|cscript", parent, re.I):
        anomalies.append("unusual_parent")
    return anomalies


def _suspicious_windows(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: Counter[str] = Counter()
    reasons: dict[str, list[str]] = {}
    for entry in entries:
        timestamp = str(entry.get("timestamp") or "")
        if len(timestamp) < 13:
            continue
        bucket = timestamp[:13] + ":00:00Z"
        description = str(entry.get("description") or "")
        suspicious = bool(re.search(r"mimikatz|credential|lsass|scheduled task|service|psexec|powershell", description, re.I))
        buckets[bucket] += 2 if suspicious else 1
        if suspicious:
            reasons.setdefault(bucket, []).append(description[:160])
    windows = []
    for bucket, score in buckets.most_common(5):
        windows.append(
            {
                "start": bucket,
                "end": bucket.replace(":00:00Z", ":59:59Z"),
                "score": min(score / 10, 1.0),
                "reason": "; ".join(reasons.get(bucket, ["High event density"]))[:300],
            }
        )
    return windows


def _format_name(raw_output: str) -> str:
    if _json(raw_output) is not None:
        return "json"
    if _csv_rows(raw_output):
        return "csv"
    if _table_rows(raw_output):
        return "table"
    if "<Event" in raw_output:
        return "xml"
    return "lines"


def _lines(raw_output: str) -> list[str]:
    return [line.strip() for line in raw_output.splitlines() if line.strip()]


def _strip_xml(value: str) -> str:
    return re.sub(r"<[^>]+>", "", value).strip()
