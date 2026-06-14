# SIFT-MIND Accuracy Report
Generated: 2026-06-14T08:01:06.995388+00:00

## Finding Statistics
| Status | Count |
|---|---:|
| CONFIRMED | 2 |
| INFERRED | 4 |
| SPECULATIVE | 0 |
| BLOCKED at finalization | 0 |

## Contradiction Analysis
- Contradictions detected: 1
- Unresolved contradictions: 0
- Run count mismatch for MIMIKATZ.EXE: new finding reports 1, existing finding reports 3. Resolution: A VSS shadow copy at 2026-06-10T03:14:00Z captured earlier filesystem state, while Prefetch reflects later executions. The tools are measuring different points in the artifact lifecycle.

## Hallucination Prevention
- BLOCKED events: 1
- Report finalization refuses unresolved contradictions and unsourced findings.

## Evidence Integrity Approach (Devpost Req #6)
### How our architecture prevents original data from being modified
SIFT-MIND operates strictly through a Custom MCP Server where all SIFT forensic tools are wrapped as **read-only endpoints**. The LLM is structurally isolated from the live execution environment and does not have generic shell access. It can only call parameterized, predefined extraction routines (e.g., `parse_evtx(filepath)`). It cannot write to disk, delete evidence, or alter memory dumps.

### What happens when the agent attempts to bypass protections
If an agent attempts to execute arbitrary shell commands (e.g., `rm -rf /mnt/case` or `echo "fake data" > /mnt/case/evidence.txt`), the FastMCP server will throw a `ToolNotFound` error because no such function is exposed. If the agent hallucinates a finding without evidence, the Epistemic Ledger's `ledger_add_finding` endpoint enforces a hard schema check; if valid `source_hashes` are not provided, the ledger rejects the commit and the finding is completely dropped from the final Jinja2-rendered report.

## Cryptographic Hash Chain Status
- Hash chain status: VERIFIED
- Required hashes: 12
- Missing hashes: 0
- Malformed evidence records: 0
- Evidence records missing raw_hash: 0
- Evidence records missing record_hash: 0
- Evidence record hash mismatches: 0
- Evidence chain link mismatches: 0
- Missing execution records for evidence hashes: 0
- Execution records missing chain entries: 0
- Tool execution records: 13
- Truncated tool responses: 0
- Tool errors: 0

## Baseline Comparison
- Status: MATCHED
- Baseline path: case_data\fixture_baseline.json
- Expected findings: 3
- Matched findings: 3
- Missing expected findings: none
- Expected IOCs: 2
- Matched IOCs: 2
- Missing expected IOCs: none

## Known Limitations
- Fixture mode demonstrates workflow behavior with deterministic public-safe data.
- Real SIFT mode depends on SIFT/Volatility/Plaso/YARA/PCAP tools being installed in the runtime.