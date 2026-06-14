param(
  [string]$Python = "python",
  [switch]$RunModelSmoke
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = Join-Path $RepoRoot "src"

$ReportDir = Join-Path $RepoRoot ".tmp\fixture_report"
$PackageDir = Join-Path $RepoRoot ".tmp\submission_package"
$SmokeDir = Join-Path $RepoRoot ".tmp\sift_smoke"
$LedgerDb = Join-Path $ReportDir "ledger.db"
$EvidenceChain = Join-Path $ReportDir "evidence_chain.log"
$ExecutionLog = Join-Path $ReportDir "agent_execution_log.jsonl"
$SmokeLedgerDb = Join-Path $SmokeDir "ledger.db"
$SmokeEvidenceChain = Join-Path $SmokeDir "evidence_chain.log"
$SmokeExecutionLog = Join-Path $SmokeDir "agent_execution_log.jsonl"
$PreflightReport = Join-Path $SmokeDir "sift_preflight_report.json"
$SmokeReport = Join-Path $SmokeDir "sift_smoke_report.json"
$AuditReport = Join-Path $SmokeDir "production_audit_report.json"
$ModelBriefReport = Join-Path $ReportDir "model_case_brief.json"
$ArchivePath = Join-Path $RepoRoot ".tmp\sift_mind_submission.zip"
$SmokeManifest = Join-Path $RepoRoot "case_data\public_sample_manifest.example.json"
$FixtureBaseline = Join-Path $RepoRoot "case_data\fixture_baseline.json"
$ModelBriefPackageArgs = @()

function Invoke-Checked {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][scriptblock]$Command
  )

  Write-Host "== $Label =="
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "$Label failed with exit code $LASTEXITCODE"
  }
}

Invoke-Checked "SIFT-MIND tests" {
  & $Python -m unittest discover -s (Join-Path $RepoRoot "tests") -v
}

Invoke-Checked "Fixture readiness" {
  & $Python -m sift_mind.run readiness --target fixture --mode fixture
}

if ($RunModelSmoke) {
  Invoke-Checked "Local model readiness" {
    & $Python -m sift_mind.run readiness --target model --mode fixture
  }
  Invoke-Checked "Local model smoke" {
    & $Python -m sift_mind.run model-smoke --mode fixture
  }
}

Invoke-Checked "Fixture run" {
  & $Python -m sift_mind.run run `
    --output-dir $ReportDir `
    --ledger-db $LedgerDb `
    --evidence-chain $EvidenceChain `
    --execution-log $ExecutionLog `
    --baseline $FixtureBaseline `
    --mode fixture
}

Invoke-Checked "Evidence chain verification" {
  & $Python -m sift_mind.run verify-chain `
    --ledger-db $LedgerDb `
    --evidence-chain $EvidenceChain `
    --execution-log $ExecutionLog
}

if ($RunModelSmoke) {
  Invoke-Checked "Local model ledger-only brief" {
    & $Python -m sift_mind.run model-brief `
      --mode fixture `
      --output-dir $ReportDir `
      --ledger-db $LedgerDb `
      --evidence-chain $EvidenceChain `
      --execution-log $ExecutionLog `
      --output $ModelBriefReport
  }
  $ModelBriefPackageArgs = @("--model-brief-report", $ModelBriefReport)
}

Invoke-Checked "Fixture SIFT preflight manifest" {
  & $Python -m sift_mind.run sift-preflight `
    --mode fixture `
    --manifest $SmokeManifest `
    --report $PreflightReport `
    --output-dir $SmokeDir `
    --ledger-db $SmokeLedgerDb `
    --evidence-chain $SmokeEvidenceChain `
    --execution-log $SmokeExecutionLog
}

Invoke-Checked "Fixture SIFT smoke manifest" {
  & $Python -m sift_mind.run sift-smoke `
    --mode fixture `
    --manifest $SmokeManifest `
    --fresh `
    --output-dir $SmokeDir `
    --ledger-db $SmokeLedgerDb `
    --evidence-chain $SmokeEvidenceChain `
    --execution-log $SmokeExecutionLog
}

Invoke-Checked "Seed production audit" {
  & $Python -m sift_mind.run production-audit `
    --target fixture `
    --mode fixture `
    --output-dir $ReportDir `
    --ledger-db $LedgerDb `
    --evidence-chain $EvidenceChain `
    --execution-log $ExecutionLog `
    --repo-root $RepoRoot `
    --report $AuditReport
}

Invoke-Checked "Submission package with seed audit" {
  & $Python -m sift_mind.run package-demo `
    --output-dir $ReportDir `
    --ledger-db $LedgerDb `
    --evidence-chain $EvidenceChain `
    --execution-log $ExecutionLog `
    --package-dir $PackageDir `
    --repo-root $RepoRoot `
    --preflight-report $PreflightReport `
    --smoke-report $SmokeReport `
    --audit-report $AuditReport `
    @ModelBriefPackageArgs
}

Invoke-Checked "Final production audit report" {
  & $Python -m sift_mind.run production-audit `
    --target fixture `
    --mode fixture `
    --output-dir $ReportDir `
    --ledger-db $LedgerDb `
    --evidence-chain $EvidenceChain `
    --execution-log $ExecutionLog `
    --package-dir $PackageDir `
    --repo-root $RepoRoot `
    --report $AuditReport
}

Invoke-Checked "Final submission package with audit" {
  & $Python -m sift_mind.run package-demo `
    --output-dir $ReportDir `
    --ledger-db $LedgerDb `
    --evidence-chain $EvidenceChain `
    --execution-log $ExecutionLog `
    --package-dir $PackageDir `
    --repo-root $RepoRoot `
    --preflight-report $PreflightReport `
    --smoke-report $SmokeReport `
    --audit-report $AuditReport `
    --archive-path $ArchivePath `
    @ModelBriefPackageArgs
}

Invoke-Checked "Final production audit" {
  & $Python -m sift_mind.run production-audit `
    --target fixture `
    --mode fixture `
    --output-dir $ReportDir `
    --ledger-db $LedgerDb `
    --evidence-chain $EvidenceChain `
    --execution-log $ExecutionLog `
    --package-dir $PackageDir `
    --archive-path $ArchivePath `
    --repo-root $RepoRoot `
    --report $AuditReport
}

Write-Host "== Verification complete =="
