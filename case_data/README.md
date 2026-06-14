# Case Data Documentation

Actual disk images, memory captures, and PCAPs are intentionally not committed. This directory documents reproducible data sources and the fixture fallback.

## Fixture Case

The built-in fixture mode simulates a Windows compromise with:

- `MIMIKATZ.EXE` execution
- Prefetch/MFT run-count contradiction
- VSS/USN evidence resolving the contradiction
- LSASS/SAM access indicators in memory
- persistence via `SystemUpdate`
- external network contact during the credential-access window

Run:

```powershell
$env:PYTHONPATH="src"
python -m sift_mind.run run --output-dir .tmp\fixture_report --mode fixture
```

## Public Data Sources For SIFT Mode

Use public, legally shareable forensic samples:

- SANS Holiday Hack forensic images
- Digital Corpora disk images: https://digitalcorpora.org/corpora/disk-images
- NIST CFReDS: https://cfreds.nist.gov/

Use `public_sample_manifest.example.json` as the starting point for public samples. Edit the artifact paths after mounting the case read-only at `CASE_ROOT`.
Use `public_sample_manifest.schema.json` with your editor or regenerate it with `python -m sift_mind.run manifest-schema --output case_data/public_sample_manifest.schema.json`; it forbids top-level manifest typos and enumerates supported tool names.
Use `fixture_baseline.json` for the deterministic demo. For public samples, create a case-specific baseline JSON with:

- `expected_findings`: objects with `id`, `must_include` token list, optional `status`, and optional `mitre`
- `expected_iocs`: objects with `type` and `value`

## Reproducibility Requirements

For each real run, record:

- source URL or acquisition note
- image type and approximate size
- hash of original evidence file
- whether disk, memory, log, and PCAP sources were available
- exact SIFT-MIND command
- generated `accuracy_report.md`
- generated `agent_execution_log.jsonl`
- generated `evidence_chain.log`
- generated `submission_manifest.json` from `package-demo`
- generated `production-audit` JSON output for the selected target

## Read-Only Mount Example

```bash
sudo ewfmount /path/to/case.E01 /mnt/ewf
sudo mount -o ro /mnt/ewf/ewf1 /mnt/case
export CASE_ROOT=/mnt/case
```

## Manifest Smoke Run

Preferred Windows host bridge:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\sift_mode_smoke_wsl.ps1 `
  -CaseRoot /mnt/case `
  -OutputDir /tmp/sift_mind_smoke `
  -Manifest .\case_data\public_sample_manifest.example.json
```

Preferred command once already inside SIFT VM/WSL:

```bash
bash scripts/sift_mode_smoke.sh \
  --case-root /mnt/case \
  --output-dir /tmp/sift_mind_smoke \
  --manifest case_data/public_sample_manifest.example.json
```

The PowerShell bridge writes `.tmp\sift_wsl_host_report.json` on the Windows host and fails fast when no WSL distribution is installed. The Bash script writes `doctor_report.json`, `readiness_report.json`, `sift_preflight_report.json`, `sift_smoke_report.json`, and `production_audit_report.json` under the selected output directory after verifying those managed outputs are outside `CASE_ROOT`.

Manual equivalent:

```bash
export OUTPUT_DIR=/tmp/sift_mind_smoke
export EVIDENCE_CHAIN=/tmp/sift_mind_smoke/evidence_chain.log
export AGENT_EXECUTION_LOG=/tmp/sift_mind_smoke/agent_execution_log.jsonl
export LEDGER_DB=/tmp/sift_mind_smoke/ledger.db
export SIFT_MIND_BASELINE=/path/to/public_sample_baseline.json
python -m sift_mind.run sift-preflight \
  --mode sift \
  --case-root /mnt/case \
  --manifest case_data/public_sample_manifest.example.json \
  --report "$OUTPUT_DIR/sift_preflight_report.json" \
  --output-dir "$OUTPUT_DIR" \
  --ledger-db "$LEDGER_DB" \
  --evidence-chain "$EVIDENCE_CHAIN" \
  --execution-log "$AGENT_EXECUTION_LOG"

python -m sift_mind.run sift-smoke \
  --mode sift \
  --case-root /mnt/case \
  --manifest case_data/public_sample_manifest.example.json \
  --fresh \
  --output-dir "$OUTPUT_DIR" \
  --ledger-db "$LEDGER_DB" \
  --evidence-chain "$EVIDENCE_CHAIN" \
  --execution-log "$AGENT_EXECUTION_LOG"
```

The preflight report should show `status: READY` before running the smoke command. It checks selected tools, required artifacts, artifact paths under `CASE_ROOT`, real file/directory existence, managed output/log paths outside `CASE_ROOT`, and selected binary availability without touching the evidence chain.

The smoke report is `sift_smoke_report.json`. It records each typed wrapper as `OK`, `ERROR`, or `SKIPPED`, includes raw hashes for executed tools, and verifies evidence-chain/execution-log consistency before a full MCP agent run.

SIFT-MIND tool wrappers validate that real artifact paths remain inside `CASE_ROOT`, while generated reports/logs must be outside `CASE_ROOT`. File-writing tools must use explicit generated output targets under `OUTPUT_DIR`; those generated file bytes are included in the pre-parse raw hash.
Evidence verification should show `status: VERIFIED`, `missing_count: 0`, `malformed_count: 0`, `missing_raw_hash_count: 0`, `missing_record_hash_count: 0`, `invalid_record_hash_count: 0`, `chain_link_mismatch_count: 0`, `missing_execution_record_count: 0`, and `execution_record_missing_chain_count: 0`; fixture and MCP finalization also ingest typed tool execution records into SQLite for report statistics. `production-audit --target sift` should be saved with the run and must pass before claiming real public-sample readiness.
