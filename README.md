# SIFT-MIND

Metacognitive Incident Response Orchestrator for Protocol SIFT.

> Every other submission teaches the agent what to do. SIFT-MIND teaches it what it does not know.

SIFT-MIND wraps SANS SIFT-style forensic tools behind typed MCP functions and adds three production safety layers:

1. Epistemic Ledger: every finding is tagged `CONFIRMED`, `INFERRED`, or `SPECULATIVE` with confidence and evidence hashes.
2. Contradiction Detection Graph: conflicting claims return `BLOCKED` until resolved.
3. Cryptographic Evidence Chain: raw tool output is SHA-256 hashed before parsing or LLM exposure, including stdout/stderr plus explicitly generated output files, and each JSONL chain record links to the prior record with `previous_record_hash` and `record_hash`.

The report writer reads only ledger-backed facts. `report_write_section` may store workflow notes for audit context, but final reports render section blocks from linked finding IDs and never copy agent-authored section prose.

## Repository Map

| Path | Purpose |
|---|---|
| `src/sift_mind/` | Production Python package |
| `src/sift_mind/mcp_server/` | FastMCP server and typed tool wrappers |
| `src/sift_mind/mcp_server/tools/parsers.py` | Dependency-light parsers for JSON, CSV, tables, EVTX XML, Volatility, YARA, tshark, and timelines |
| `src/sift_mind/ledger/` | SQLite epistemic ledger and typed tool execution store |
| `src/sift_mind/contradiction/` | Contradiction graph and blocking rules |
| `src/sift_mind/report/` | Mechanical report writer |
| `src/sift_mind/agent/` | Deterministic fixture agent workflow |
| `tests/` | Contract, tool, ledger, report, and end-to-end fixture tests |
| `case_data/public_sample_manifest.example.json` | Manifest template for SIFT/public-sample smoke runs |
| `case_data/fixture_baseline.json` | Deterministic fixture ground-truth expectations for accuracy comparison |
| `ARCHITECTURE.md` | System architecture and trust boundaries |
| `ARCHITECTURE_DIAGRAM.mmd` | Mermaid architecture diagram for submission material |
| `SPEC.md` | Full technical specification |
| `DESIGN.md` | Epistemic model and design philosophy |
| `PROMPTS.md` | Agent operating prompts |
| `SKILLS.md` | Tool wrapping guide |
| `BUILD.md` | Build and verification plan |
| `case_data/README.md` | Dataset documentation |
| `case_data/public_sample_manifest.schema.json` | JSON Schema for real public-sample smoke manifests |
| `README (1).md` | Preserved legacy dataset planning notes |
| `scripts/verify.ps1` | Windows fixture verification and package script |
| `scripts/sift_mode_smoke.sh` | SIFT VM/WSL real-case preflight, smoke, and audit script |
| `scripts/sift_mode_smoke_wsl.ps1` | Windows bridge that checks WSL and launches the real SIFT smoke inside a distro |
| `.env.example` | Safe local Ollama and future cloud configuration template |
| `SUBMISSION.md` | Devpost project story draft |
| `DEMO_SCRIPT.md` | 5-minute demo script |

## Quick Start: Fixture Demo

The fixture demo requires no large disk image and shows the core "money shot": Prefetch says `MIMIKATZ.EXE` ran 3 times, MFT says 1, the ledger blocks the contradiction, the agent resolves it with timeline/USN evidence, and reports finalize only after the contested state is clear.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .[all]
.\.venv\Scripts\python.exe -m sift_mind.run run `
  --output-dir .tmp\fixture_report `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl `
  --baseline case_data\fixture_baseline.json `
  --mode fixture
```

`requirements.txt` and `pip install -e .[all]` are kept in parity; the `all` extra installs MCP, forensic parser bindings, graph/UI/CLI helpers, and test tooling.

If you are using the Codex bundled runtime for local verification:

```powershell
$env:PYTHONPATH="src"
python -m sift_mind.run run --output-dir .tmp\fixture_report --mode fixture
```

Generated files:

- `case_narrative.md`
- `executive_summary.md`
- `ioc_summary.json`
- `accuracy_report.md`
- `evidence_chain.log`
- `agent_execution_log.jsonl` with tool status, token estimates, truncation flags, command strings, model/provider config, and raw hashes

During finalization, the fixture runner also ingests the typed execution log into the SQLite ledger so report statistics can be derived from ledger state instead of loose prose.

Package the fixture demo for judging:

```powershell
python -m sift_mind.run package-demo `
  --output-dir .tmp\fixture_report `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl `
  --package-dir .tmp\submission_package `
  --repo-root . `
  --preflight-report .tmp\sift_smoke\sift_preflight_report.json `
  --smoke-report .tmp\sift_smoke\sift_smoke_report.json `
  --model-brief-report .tmp\fixture_report\model_case_brief.json `
  --archive-path .tmp\sift_mind_submission.zip
```

This copies the report artifacts, runnable code repo (`src/`, `tests/`, package metadata, CI, scripts), all repo Markdown docs, architecture diagram, dataset docs, optional SIFT preflight/smoke/audit reports, verifies the evidence chain, scans for leaked secrets, and writes `submission_manifest.json` with SHA-256 checksums.
When `--archive-path` is set, it also creates a deterministic ZIP archive of the finished package directory for upload or sharing. `submission_manifest.json` records that archive creation was requested, while the final ZIP SHA-256 is returned by the CLI and verified by `production-audit` under `submission_archive_verified` to avoid a self-referential archive hash.
`package-demo` rebuilds known generated package entries on each run so stale project files from an earlier package cannot silently remain in `.tmp\submission_package`.
Evidence verification fails if a ledger finding references a missing hash, if an evidence-chain JSONL record is malformed, if any non-empty record lacks `raw_hash` or `record_hash`, or if record hashes/chain links no longer match.

## Run The MCP Server

Before starting the server, run readiness checks:

```powershell
$env:PYTHONPATH="src"
python -m sift_mind.run readiness --target fixture --mode fixture
python -m sift_mind.run readiness --target model --mode fixture
python -m sift_mind.run model-smoke --mode fixture
```

Fixture mode:

```powershell
$env:SIFT_MIND_MODE="fixture"
$env:OUTPUT_DIR=".tmp\mcp_report"
python -m sift_mind.run serve-mcp --mode fixture
```

SIFT mode inside SIFT VM/WSL:

```bash
export CASE_ROOT=/mnt/case
export OUTPUT_DIR=/tmp/sift_mind_report
export EVIDENCE_CHAIN=/tmp/sift_mind_report/evidence_chain.log
export AGENT_EXECUTION_LOG=/tmp/sift_mind_report/agent_execution_log.jsonl
export LEDGER_DB=/tmp/sift_mind_report/ledger.db
python -m sift_mind.run readiness --target sift --mode sift
python -m sift_mind.run serve-mcp --mode sift
```

The MCP server exposes typed functions only. There is no generic shell tool and no destructive evidence mutation endpoint.
For real agents, `ledger_add_finding` accepts `source_hashes` as comma-separated text or a JSON array string, plus optional `metadata_json` for structured facts such as `{"run_count": 3}`. Contradiction blocking uses both claim text and this structured metadata.

## Local Model Defaults

SIFT-MIND is designed for local Ollama first on a 16 GB RAM / RTX 3050 6 GB GPU machine.

Recommended default:

```powershell
# See .env.example for the complete safe template.
$env:SIFT_MIND_MODEL_PROVIDER="ollama"
$env:SIFT_MIND_MODEL="qwen2.5-coder:7b"
$env:SIFT_MIND_FALLBACK_MODEL="qwen2.5-coder:3b"
$env:OLLAMA_HOST="http://localhost:11434"
```

The deterministic production workflow does not rely on a local 7B model free-driving shell commands. The model provider is used for bounded JSON decisions and summaries, and can later be swapped for a cloud API through `ModelClient`.
`readiness --target model` and `production-audit` include `model_hardware_plan`, which records the 16 GB RAM / RTX 3050 6 GB target, selected local model, fallback model, and warnings if the configured models are not downloaded.

Validate local bounded-JSON generation:

```powershell
$env:PYTHONPATH="src"
python -m sift_mind.run model-smoke --mode fixture
```

The command uses `qwen2.5-coder:7b` first and falls back to `qwen2.5-coder:3b` if the primary model request fails.

After a fixture or SIFT ledger exists, generate a citation-validated model brief:

```powershell
python -m sift_mind.run model-brief `
  --mode fixture `
  --output-dir .tmp\fixture_report `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl `
  --output .tmp\fixture_report\model_case_brief.json
```

`model-brief` sends only a compact ledger snapshot to the configured local Ollama or cloud-compatible model. The result is accepted only if each executive bullet cites known ledger finding IDs and evidence hashes. It is a reviewer aid, not a source for final report generation.

Cloud-ready mode uses the same bounded JSON interface through an OpenAI-compatible chat-completions API:

```powershell
$env:SIFT_MIND_MODEL_PROVIDER="openai-compatible"
$env:SIFT_MIND_MODEL_HOST="https://api.example.com/v1"
$env:SIFT_MIND_MODEL="your-cloud-model"
$env:SIFT_MIND_CLOUD_API_KEY_ENV="SIFT_MIND_CLOUD_API_KEY"
$env:SIFT_MIND_CLOUD_API_KEY="..."
python -m sift_mind.run readiness --target model --mode fixture
python -m sift_mind.run model-smoke --mode fixture
```

The API key value is never written to readiness output, execution logs, reports, or the evidence chain.

## Verification

One-command local fixture verification:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify.ps1 -Python python
```

Add `-RunModelSmoke` when Ollama is running and you want to include the local model path.
The GitHub Actions workflow in `.github/workflows/ci.yml` runs the same fixture verifier without requiring Ollama or SIFT binaries.

```powershell
$env:PYTHONPATH="src"
python -m unittest discover -s tests -v
python -m sift_mind.run doctor --mode fixture
python -m sift_mind.run readiness --target fixture --mode fixture
python -m sift_mind.run readiness --target model --mode fixture
python -m sift_mind.run model-smoke --mode fixture
python -m sift_mind.run verify-chain `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl
python -m sift_mind.run sift-preflight `
  --mode fixture `
  --manifest case_data\public_sample_manifest.example.json `
  --report .tmp\sift_smoke\sift_preflight_report.json `
  --output-dir .tmp\sift_smoke `
  --ledger-db .tmp\sift_smoke\ledger.db `
  --evidence-chain .tmp\sift_smoke\evidence_chain.log `
  --execution-log .tmp\sift_smoke\agent_execution_log.jsonl
python -m sift_mind.run sift-smoke `
  --mode fixture `
  --manifest case_data\public_sample_manifest.example.json `
  --fresh `
  --output-dir .tmp\sift_smoke `
  --ledger-db .tmp\sift_smoke\ledger.db `
  --evidence-chain .tmp\sift_smoke\evidence_chain.log `
  --execution-log .tmp\sift_smoke\agent_execution_log.jsonl
python -m sift_mind.run package-demo `
  --output-dir .tmp\fixture_report `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl `
  --package-dir .tmp\submission_package `
  --repo-root . `
  --preflight-report .tmp\sift_smoke\sift_preflight_report.json `
  --smoke-report .tmp\sift_smoke\sift_smoke_report.json
python -m sift_mind.run production-audit `
  --target fixture `
  --mode fixture `
  --output-dir .tmp\fixture_report `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl `
  --package-dir .tmp\submission_package `
  --repo-root . `
  --report .tmp\sift_smoke\production_audit_report.json
python -m sift_mind.run package-demo `
  --output-dir .tmp\fixture_report `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl `
  --package-dir .tmp\submission_package `
  --repo-root . `
  --preflight-report .tmp\sift_smoke\sift_preflight_report.json `
  --smoke-report .tmp\sift_smoke\sift_smoke_report.json `
  --audit-report .tmp\sift_smoke\production_audit_report.json `
  --model-brief-report .tmp\fixture_report\model_case_brief.json `
  --archive-path .tmp\sift_mind_submission.zip
python -m sift_mind.run production-audit `
  --target fixture `
  --mode fixture `
  --output-dir .tmp\fixture_report `
  --ledger-db .tmp\fixture_report\ledger.db `
  --evidence-chain .tmp\fixture_report\evidence_chain.log `
  --execution-log .tmp\fixture_report\agent_execution_log.jsonl `
  --package-dir .tmp\submission_package `
  --archive-path .tmp\sift_mind_submission.zip `
  --repo-root . `
  --report .tmp\sift_smoke\production_audit_report.json
```

`verify-chain` reports required hashes, chain hashes, malformed records, records missing `raw_hash` or `record_hash`, record-hash mismatches, chain-link mismatches, evidence/execution-log cross-check failures, duplicate hash count, and exact line numbers for integrity failures. When `--baseline` or `SIFT_MIND_BASELINE` is set during report generation, `accuracy_report.md` includes expected finding and IOC match counts from that JSON baseline.
`production-audit` reports requirement-level `PASS`/`WARN`/`FAIL` checks for Markdown coverage, Markdown-to-code/test traceability, the four-phase prompt workflow, MCP tool registration, absence of generic shell endpoints, evidence hashing, ledger/report gates, model readiness, hardware-aware local model planning, fixture package readiness, submission package code/doc/preflight/smoke/audit completeness, deterministic ZIP archive verification when `--archive-path` is supplied, and the remaining SIFT VM/tooling gap. The verifier writes a seed audit to `production_audit_report.json`, rebuilds the final package with that report included, then writes a final standalone audit that validates `.tmp\sift_mind_submission.zip` against the finished package tree.
The audit also compares the package manifest against the actual files under `project/` and fails if unmanifested stale files are present.
The model checks include `ledger_only_model_briefing`, which verifies that local/cloud model summaries are generated from ledger data only and validated against known evidence hashes.
When `--model-brief-report` points to a generated `model_case_brief.json`, `package-demo` includes it and `production-audit` validates its `source_policy`, model-brief validation status, and absence of validation errors. The artifact is optional so CI and offline fixture checks do not require Ollama.

Manifest-driven preflight and smoke for public samples:

```powershell
python -m sift_mind.run sift-preflight `
  --mode fixture `
  --manifest case_data\public_sample_manifest.example.json `
  --report .tmp\sift_smoke\sift_preflight_report.json `
  --output-dir .tmp\sift_smoke

python -m sift_mind.run sift-smoke `
  --mode fixture `
  --manifest case_data\public_sample_manifest.example.json `
  --fresh `
  --output-dir .tmp\sift_smoke `
  --ledger-db .tmp\sift_smoke\ledger.db `
  --evidence-chain .tmp\sift_smoke\evidence_chain.log `
  --execution-log .tmp\sift_smoke\agent_execution_log.jsonl
```

Inside SIFT VM/WSL, switch to `--mode sift`, set `--case-root /mnt/case`, keep managed output paths outside `/mnt/case`, and edit the manifest paths to match the mounted public sample. `sift-preflight` validates selected tools, manifest artifact coverage, artifact existence, CASE_ROOT containment, managed output/log path safety, and selected binary availability without executing forensic tools. The smoke report records `OK`, `ERROR`, and `SKIPPED` per typed wrapper and verifies the evidence/execution chain. `scripts\verify.ps1` includes fixture preflight and smoke reports in `.tmp\submission_package`.
Use `case_data/public_sample_manifest.schema.json` with your editor, or regenerate it with `python -m sift_mind.run manifest-schema --output case_data/public_sample_manifest.schema.json`, to catch unsupported tool names and top-level manifest typos before the SIFT run.

For a real mounted case, the SIFT VM/WSL shortcut is:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\sift_mode_smoke_wsl.ps1 `
  -CaseRoot /mnt/case `
  -OutputDir /tmp/sift_mind_smoke `
  -Manifest .\case_data\public_sample_manifest.example.json
```

```bash
bash scripts/sift_mode_smoke.sh \
  --case-root /mnt/case \
  --output-dir /tmp/sift_mind_smoke \
  --manifest case_data/public_sample_manifest.example.json
```

## Production Notes

- Use Python `>=3.11,<3.13` for production dependency stability.
- Mount case data read-only before SIFT mode.
- On Windows hosts, `doctor --mode sift` and `readiness --target sift --mode sift` report whether `wsl.exe` is available and whether a WSL distribution is installed. A `NO_DISTRIBUTION` host diagnostic means the real smoke must run after installing/opening SIFT VM/WSL.
- Keep `OUTPUT_DIR`, `EVIDENCE_CHAIN`, and `AGENT_EXECUTION_LOG` outside `CASE_ROOT`; wrappers and readiness checks reject managed output paths inside the evidence mount.
- Keep one local 7B/8B model loaded at a time on 6 GB VRAM.
- Use fixture mode for reproducible judging and demo recording.
- Use `readiness --target sift --mode sift` and `sift-preflight --mode sift` before real public sample data. Readiness checks every documented forensic capability; preflight checks the selected manifest artifacts and tools for that mounted case.
- SIFT-mode wrappers parse captured stdout/stderr plus explicitly declared generated output files into structured contracts for common JSON, CSV, table, EVTX XML, Volatility, YARA, tshark, and timeline outputs. Generated output paths are constrained to `OUTPUT_DIR`; generated file bytes are included in the pre-parse raw hash, while only bounded metadata is returned to the agent.
- The contradiction graph blocks run-count, timestamp, existence, process state/visibility, PCAP-vs-memory network observation, and file hash replacement disagreements until targeted resolution evidence is added.
- Wrappers resolve fixed executable candidates for cross-platform SIFT installs, such as `PECmd.exe`/`PECmd`, `SBECmd.exe`/`SBECmd`, `LECmd.exe`/`LECmd`, `evtx_dump.py`/`evtx_dump`, and `vol`/`vol.py`/`volatility3`.
