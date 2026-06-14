# SUBMISSION.md — Devpost Project Story + Accuracy Report

## Devpost Project Name
**SIFT-MIND: Metacognitive Incident Response Orchestrator**

---

## Devpost Tagline
*Every other submission teaches the agent what to do. SIFT-MIND teaches it what it doesn't know.*

---

## What It Does

SIFT-MIND is a metacognitive AI orchestrator for the SANS SIFT Workstation that solves Protocol SIFT's core failure mode: hallucinations that propagate undetected into incident response reports.

The fundamental problem: when Protocol SIFT runs a generic shell command and receives raw tool output, the LLM has no structured way to distinguish what it *observed* from what it *inferred* from what it *confabulated*. These three categories collapse into the same narrative voice and appear in the final report with identical confidence.

SIFT-MIND makes these three categories architecturally separate through three innovations:

**1. Typed MCP Server with Pre-Parsed Tool Output**
Twenty SIFT tools are wrapped as typed, read-only MCP functions. Instead of `execute_shell_cmd("vol -f mem.dmp windows.pslist")` returning 50,000 lines of raw text, `list_processes(memory_path)` returns a structured JSON object with parsed process entries, anomaly flags, and a confidence score. The LLM never sees raw tool output — only the pre-parsed struct. This prevents context window overload and eliminates a major hallucination pathway.

**2. Epistemic Ledger with Confidence Tiers**
Every finding the agent produces must be submitted through `ledger_add_finding()` with a mandatory confidence tier: CONFIRMED (≥2 independent tools corroborate, no contradictions), INFERRED (1 source, logical deduction), or SPECULATIVE (pattern match only). The report writer reads exclusively from the ledger. The agent cannot write untagged claims to the report — the architecture prevents it.

**3. Contradiction Detection Graph with Forced Resolution**
When two tool results produce conflicting claims about the same artifact, the ContradictionGraph detects the conflict and returns `status=BLOCKED` to the agent. The agent cannot add new findings or finalize the report until it resolves the contradiction. This transforms hallucination-prone "retry loops" into genuine self-correction: the agent identifies which tool to run next, resolves the discrepancy, and updates both findings' confidence accordingly.

**Cryptographic Evidence Chain**
Every tool call's raw output is SHA-256 hashed *before* parsing or LLM contact. Hashes are logged append-only to `evidence_chain.log`. Every finding in the report embeds the hash(es) of the tool output(s) that produced it. Any finding can be traced cryptographically to its source tool call.

---

## How We Built It

**Architecture:** Custom MCP Server (the approach SANS explicitly identified as most architecturally sound)

**Stack:**
- Python 3.11 + FastMCP for the MCP server
- Pydantic for all data contracts (ToolResult, Finding, MCPResponse)
- SQLite (WAL mode) for the Epistemic Ledger — crash-resilient, multi-writer capable
- Local contradiction graph for hard-blocking conflicting claims
- Jinja2 for report templating
- Local Ollama provider for bounded JSON decisions (`qwen2.5-coder:7b`, with 3B fallback)
- Hardware-aware local model plan for the 16 GB RAM / RTX 3050 6 GB target, surfaced in readiness and production audit output
- Safe `.env.example` template for local Ollama configuration and later cloud provider migration without committing secrets
- Ledger-only `model-brief` workflow that asks the local/cloud model for a compact case brief and rejects uncited finding IDs or evidence hashes
- MCP-compatible agent runtime for interactive mode
- SANS SIFT Workstation tools: PECmd, Volatility3, log2timeline/plaso, python-evtx, YARA

**Key design decisions:**

*Pre-parsing at the server layer, not the agent:* Raw volatility output on a busy system is 50,000+ lines (35,000+ tokens). Pre-parsing means the agent gets a 200-token structured object. The agent analyzes more artifacts with the same compute budget.

*Contradiction blocking vs. warning:* A warning the agent can ignore is a prompt-based guardrail dressed as architecture. Making contradiction resolution a hard block guarantees self-correction behavior — it's not probabilistic.

*Report writer reads only from ledger:* If the agent can write prose directly to the report, it can include claims never validated against tool output. Final report sections are rendered from linked finding IDs rather than copied section prose, so every finding sentence traces to a ledger entry, which traces to one or more tool call hashes.

---

## Challenges

**Parser coverage:** Each SIFT tool has different output formats. PECmd produces generated JSON files. log2timeline produces Plaso output files. Volatility produces tab-delimited text with headers. python-evtx produces XML. Writing a reliable parser and evidence capture path for each took significant time and required handling edge cases (generated files, truncated output, missing fields, encoding issues on non-English systems).

**Contradiction rule design:** Determining when two findings *actually* conflict vs. when they're measuring different things (e.g., prefetch vs. MFT measuring execution count at different points in time due to VSS shadow copies) required domain expertise we had to research and encode as rules.
The MCP ledger API now accepts structured `metadata_json` such as `{"run_count": 3}` so contradiction rules do not depend only on prose parsing.
SIFT-mode wrappers also enforce evidence-mount hygiene: case artifacts must stay inside `CASE_ROOT`, while generated reports and logs must resolve outside it.

**Agent compliance with the ledger protocol:** Early testing showed MCP-compatible LLM agents could generate analysis conclusions without calling `ledger_add_finding()`. Solving this required very explicit system prompt instructions and adding a `ledger_get_summary()` call at the start of each phase so the agent actively sees how many findings it has logged.

**Context management on large disk images:** A full super-timeline of a 500GB drive is enormous. We implemented time-windowed analysis: triage identifies the 3-5 most suspicious time clusters, deep analysis targets only those windows. This keeps context manageable without sacrificing depth.

---

## What We Learned

The most important insight: **the hallucination problem in Protocol SIFT is not a prompt problem, it's a data structure problem.** The LLM hallucinates because it has no schema for distinguishing observation from inference. Give it a schema — enforced architecturally, not through prompting — and hallucinations can't propagate to the report because the report generation pipeline refuses to include untagged findings.

Second insight: **contradiction detection is more valuable than retry.** Most "self-correcting agent" implementations retry the same tool when they get a bad result. This rarely helps because the same tool produces the same output. Real self-correction means detecting that two *different* tools disagree, identifying *why* they disagree, and running a *third* tool to adjudicate. That's what the ContradictionGraph enables.

Third insight: **evidence integrity is architectural, not behavioral.** Asking an LLM to "not modify evidence" in a prompt is not evidence integrity. SHA-256 hashing raw output before LLM contact, read-only mounts, and no-write MCP schemas is evidence integrity.

---

## What's Next

**Multi-agent extension:** The Epistemic Ledger is multi-writer safe (SQLite WAL). A natural next step is decomposing into specialized agents: Disk Agent, Memory Agent, Network Agent — each writing to the shared ledger. The Contradiction Graph already handles cross-source conflicts; it just needs to handle inter-agent ones too.

**SIEM integration:** An MCP tool that connects to Elastic/Splunk and pulls corroborating log data, writing findings to the same ledger as the disk/memory tools. The agent treats SIEM data as another source requiring corroboration, not as ground truth.

**Ground truth benchmarking:** The accuracy report now supports a JSON baseline with expected findings and IOCs, and the deterministic fixture includes `case_data/fixture_baseline.json`. Next step is a full public benchmark dataset with documented ground truth so the community can measure progress quantitatively against a standard.

**Community tool library:** The MCP server's tool-wrapper pattern is designed to be extended. A contribution guide allowing the DFIR community to add new SIFT tool wrappers — following the same ToolResult contract — would let SIFT-MIND grow with the community's needs.

---

## Dataset Documentation (for case_data/README.md)

### Case Data Used

**Primary test case:** SANS DFIR sample disk image
- Source: SANS Institute publicly available training materials
- Type: Windows 10 disk image (E01 format)
- Size: ~40GB
- Known artifacts: Mimikatz execution, persistence via scheduled task, lateral movement indicators
- Ground truth: Documented in SANS course materials

**Secondary test case:** Digital Corpora NIST sample images
- Source: digitalcorpora.org (public domain forensic images)
- Type: Various Windows disk images
- Used for: False positive rate testing (known-good images)

**Memory capture:** Paired with primary disk image
- Source: Same SANS training materials
- Format: Raw memory dump (.mem)
- Size: ~16GB (matches VM RAM allocation)

### What the Agent Found

On the primary test case:
- **CONFIRMED findings:** [number] — execution artifacts with ≥2 corroborating sources
- **INFERRED findings:** [number] — single-source with logical deduction
- **SPECULATIVE findings:** [number] — pattern matches requiring further investigation
- **Contradictions detected:** [number]
- **Contradictions resolved:** [number]
- **BLOCKED events (hallucination prevented):** [number]

*Fill in actual numbers after Day 4 run.*

---

## Accuracy Report Template

```markdown
# SIFT-MIND Accuracy Report
**Case:** [Case identifier]
**Analysis date:** [Date]
**Agent runtime:** SIFT-MIND fixture runner or MCP-compatible agent + SIFT-MIND MCP Server v1.0

## Finding Statistics

| Status | Count | Avg Confidence |
|--------|-------|---------------|
| CONFIRMED | X | 0.XX |
| INFERRED | X | 0.XX |
| SPECULATIVE | X | 0.XX |
| **Total** | **X** | **0.XX** |

## Contradiction Analysis

| Contradiction | Finding A | Finding B | Resolution |
|---|---|---|---|
| Run count mismatch (MIMIKATZ.pf) | Prefetch: 3 runs | MFT: 1 run | VSS shadow copy at T-3min explains delta |
| [Add actual contradictions from run] | ... | ... | ... |

**Contradictions detected:** X
**Contradictions resolved:** X
**Contradictions marked UNRESOLVABLE:** X
**Contradictions still open at report time:** 0 (enforced by report_finalize)

## Hallucination Prevention Events

**BLOCKED events:** X instances where the agent attempted to add a finding that contradicted existing evidence. In each case, the agent successfully ran the resolution loop.

**Confidence downgrades:** X findings that started CONFIRMED but were downgraded after additional evidence. Example: [describe one].

**Retracted findings:** X findings removed from ledger after resolution determined the original claim was incorrect.

## Evidence Integrity

**Unique tool calls:** X
**Unique evidence hashes in chain:** X
**Hash chain integrity:** VERIFIED - all report findings trace to at least one tool call hash.
**Strict chain parsing:** malformed JSONL records, missing `raw_hash` or `record_hash` fields, record-hash mismatches, broken `previous_record_hash` links, missing ledger hashes, or evidence/execution-log mismatches fail verification and block report finalization/packaging.

## Known Limitations

1. **Network capture depth** - PCAP, DNS, and HTTP summary wrappers are implemented; deeper protocol-specific carving should be added as public sample outputs are collected.
2. **Linux forensics** - Tool wrappers target Windows artifacts first. Linux disk analysis is not covered in the initial SIFT path.
3. **Anti-forensics detection** - Timestomp detection is implemented; other anti-forensics techniques such as log wiping and rootkit-hidden files are partially covered.
4. **Large image performance** - Images over 200GB may require narrower time windows to complete within reasonable time.

## False Positive Analysis

Tested against [N] known-good disk images from Digital Corpora:
- **False positives:** X findings flagged as suspicious in known-clean images
- **False positive rate:** X%
- **Root cause:** [Description]

## Comparison to Protocol SIFT Baseline

| Metric | Protocol SIFT | SIFT-MIND |
|---|---|---|
| Hallucinated findings in report | X | X |
| Untagged speculation | X | 0 (architectural) |
| Evidence chain present | No | Yes |
| Contradiction detection | No | Yes |
| Time to triage | X min | X min |
```

---

## Try-It-Out Instructions (for README)

```bash
## Requirements
- SANS SIFT Workstation (Ubuntu 22.04, download from sans.org/tools/sift-workstation)
- Protocol SIFT installed
- Python 3.11+
- MCP-compatible agent runtime for interactive mode
- Ollama for local bounded-JSON model smoke testing

## Installation

# Clone repo
git clone https://github.com/YOUR_USERNAME/sift-mind
cd sift-mind
pip install -r requirements.txt

## Running Against Your Own Case Data

# 1. Mount case data read-only
sudo ewfmount /path/to/your_image.E01 /mnt/ewf
sudo mount -o ro /mnt/ewf/ewf1 /mnt/case

# 2. Configure environment
export CASE_ROOT=/mnt/case
export EVIDENCE_CHAIN=/tmp/sift_mind_evidence.log  
export LEDGER_DB=/tmp/sift_mind_ledger.db
export OUTPUT_DIR=/tmp/sift_mind_report

# 3. Start MCP server
python -m sift_mind.run serve-mcp --mode sift

# 4. Run an MCP-compatible agent configured with PROMPTS.md
# For reproducible local judging without large evidence files:
python -m sift_mind.run run --output-dir /tmp/sift_mind_report --mode fixture

# 5. Watch live report build
tail -f /tmp/sift_mind_report/case_narrative.md

# 6. View final report
cat /tmp/sift_mind_report/executive_summary.md
cat /tmp/sift_mind_report/accuracy_report.md
```
# Current Implementation Status

The repository now includes the runnable SIFT-MIND scaffold described in this submission: FastMCP registration, typed tool wrappers, generated-output capture for file-writing forensic tools, manifest-driven SIFT/public-sample preflight and smoke runs, a SIFT VM/WSL smoke script, SQLite ledger, SQLite-backed tool execution records, contradiction blocking, linked evidence chain logging, structured execution logs with token estimates, local Ollama bounded-JSON smoke testing, ledger-only model brief generation with citation validation, OpenAI-compatible cloud provider support for later migration, report generation with optional baseline comparison, fixture demo, submission packaging with report/project/dataset/architecture/preflight/smoke checksums and secret scanning, deterministic ZIP archive verification, Markdown-to-code/test traceability in the production audit, CI fixture verification, tests, and build instructions. Replace public-sample accuracy numbers after running real public sample data in SIFT mode.
