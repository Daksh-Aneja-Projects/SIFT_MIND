#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Run SIFT-MIND real SIFT-mode readiness, manifest preflight, smoke, and audit.

Usage:
  scripts/sift_mode_smoke.sh [--case-root /mnt/case] [--output-dir /tmp/sift_mind_smoke] [--manifest path] [--python python3]

Environment overrides:
  CASE_ROOT, OUTPUT_DIR, SIFT_MIND_MANIFEST, PYTHON, EVIDENCE_CHAIN,
  AGENT_EXECUTION_LOG, LEDGER_DB

All managed outputs must resolve outside CASE_ROOT.
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

PYTHON_BIN="${PYTHON:-python3}"
CASE_ROOT="${CASE_ROOT:-/mnt/case}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sift_mind_smoke}"
MANIFEST="${SIFT_MIND_MANIFEST:-$REPO_ROOT/case_data/public_sample_manifest.example.json}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case-root)
      CASE_ROOT="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --python)
      PYTHON_BIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

EVIDENCE_CHAIN="${EVIDENCE_CHAIN:-$OUTPUT_DIR/evidence_chain.log}"
AGENT_EXECUTION_LOG="${AGENT_EXECUTION_LOG:-$OUTPUT_DIR/agent_execution_log.jsonl}"
LEDGER_DB="${LEDGER_DB:-$OUTPUT_DIR/ledger.db}"
PREFLIGHT_REPORT="$OUTPUT_DIR/sift_preflight_report.json"
SMOKE_REPORT="$OUTPUT_DIR/sift_smoke_report.json"
DOCTOR_REPORT="$OUTPUT_DIR/doctor_report.json"
READINESS_REPORT="$OUTPUT_DIR/readiness_report.json"
AUDIT_REPORT="$OUTPUT_DIR/production_audit_report.json"

"$PYTHON_BIN" - "$CASE_ROOT" "$OUTPUT_DIR" "$EVIDENCE_CHAIN" "$AGENT_EXECUTION_LOG" "$LEDGER_DB" "$PREFLIGHT_REPORT" <<'PY'
from pathlib import Path
import sys

case_root = Path(sys.argv[1]).resolve()
checks = [
    ("OUTPUT_DIR", Path(sys.argv[2]).resolve()),
    ("EVIDENCE_CHAIN parent", Path(sys.argv[3]).resolve().parent),
    ("AGENT_EXECUTION_LOG parent", Path(sys.argv[4]).resolve().parent),
    ("LEDGER_DB parent", Path(sys.argv[5]).resolve().parent),
    ("preflight report parent", Path(sys.argv[6]).resolve().parent),
]
if not case_root.exists() or not case_root.is_dir():
    raise SystemExit(f"CASE_ROOT is not a mounted directory: {case_root}")
for label, path in checks:
    if path == case_root or case_root in path.parents:
        raise SystemExit(f"{label} must be outside CASE_ROOT: {path}")
PY

mkdir -p "$OUTPUT_DIR"
cd "$REPO_ROOT"
export PYTHONPATH="$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

echo "== SIFT-MIND doctor =="
"$PYTHON_BIN" -m sift_mind.run doctor \
  --mode sift \
  --case-root "$CASE_ROOT" \
  --output-dir "$OUTPUT_DIR" \
  --evidence-chain "$EVIDENCE_CHAIN" \
  --execution-log "$AGENT_EXECUTION_LOG" \
  --ledger-db "$LEDGER_DB" \
  > "$DOCTOR_REPORT"

echo "== SIFT-MIND readiness =="
"$PYTHON_BIN" -m sift_mind.run readiness \
  --target sift \
  --mode sift \
  --case-root "$CASE_ROOT" \
  --output-dir "$OUTPUT_DIR" \
  --evidence-chain "$EVIDENCE_CHAIN" \
  --execution-log "$AGENT_EXECUTION_LOG" \
  --ledger-db "$LEDGER_DB" \
  > "$READINESS_REPORT"

echo "== SIFT-MIND manifest preflight =="
"$PYTHON_BIN" -m sift_mind.run sift-preflight \
  --mode sift \
  --case-root "$CASE_ROOT" \
  --manifest "$MANIFEST" \
  --report "$PREFLIGHT_REPORT" \
  --output-dir "$OUTPUT_DIR" \
  --ledger-db "$LEDGER_DB" \
  --evidence-chain "$EVIDENCE_CHAIN" \
  --execution-log "$AGENT_EXECUTION_LOG"

echo "== SIFT-MIND manifest smoke =="
"$PYTHON_BIN" -m sift_mind.run sift-smoke \
  --mode sift \
  --case-root "$CASE_ROOT" \
  --manifest "$MANIFEST" \
  --report "$SMOKE_REPORT" \
  --fresh \
  --output-dir "$OUTPUT_DIR" \
  --ledger-db "$LEDGER_DB" \
  --evidence-chain "$EVIDENCE_CHAIN" \
  --execution-log "$AGENT_EXECUTION_LOG"

echo "== SIFT-MIND production audit =="
"$PYTHON_BIN" -m sift_mind.run production-audit \
  --target sift \
  --mode sift \
  --case-root "$CASE_ROOT" \
  --output-dir "$OUTPUT_DIR" \
  --ledger-db "$LEDGER_DB" \
  --evidence-chain "$EVIDENCE_CHAIN" \
  --execution-log "$AGENT_EXECUTION_LOG" \
  --repo-root "$REPO_ROOT" \
  --report "$AUDIT_REPORT"

echo "SIFT-mode smoke artifacts written to: $OUTPUT_DIR"
