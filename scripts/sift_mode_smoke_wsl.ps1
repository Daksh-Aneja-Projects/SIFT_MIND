param(
  [string]$Distro = "",
  [string]$CaseRoot = "/mnt/case",
  [string]$OutputDir = "/tmp/sift_mind_smoke",
  [string]$Manifest = "",
  [string]$Python = "python3",
  [string]$HostReport = "",
  [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path -LiteralPath (Join-Path $ScriptDir "..")
if (-not $Manifest) {
  $Manifest = Join-Path $RepoRoot "case_data\public_sample_manifest.example.json"
}
if (-not $HostReport) {
  $HostReport = Join-Path $RepoRoot ".tmp\sift_wsl_host_report.json"
}

$Report = [ordered]@{
  status = "ACTION_REQUIRED"
  generated = (Get-Date).ToUniversalTime().ToString("o")
  windows_repo_root = $RepoRoot.Path
  wsl_command = $null
  wsl_available = $false
  installed_distributions = @()
  selected_distro = $null
  check_only = [bool]$CheckOnly
  case_root = $CaseRoot
  output_dir = $OutputDir
  manifest = $Manifest
  python = $Python
  wsl_paths = [ordered]@{}
  next_action = "Install/open a SIFT VM or WSL distribution, mount evidence read-only at CASE_ROOT, then rerun this script."
}

function Write-HostReport {
  $directory = Split-Path -Parent $HostReport
  if ($directory) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
  }
  $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $HostReport -Encoding UTF8
  Write-Host "Host report: $HostReport"
}

function Exit-WithReportError {
  param([string]$Message)
  Write-HostReport
  [Console]::Error.WriteLine("ERROR: $Message")
  exit 1
}

function Normalize-WslOutput {
  param([object[]]$Lines)
  return (($Lines -join "`n") -replace [string][char]0, "").Trim()
}

function Get-WslDistributions {
  param([string]$WslCommand)
  $raw = & $WslCommand -l -q 2>&1
  $exitCode = $LASTEXITCODE
  $text = Normalize-WslOutput $raw
  $names = @(
    $text -split "`r?`n" |
      ForEach-Object { $_.Trim().TrimStart("*").Trim() } |
      Where-Object {
        $_ -and
        $_ -notmatch "Windows Subsystem for Linux" -and
        $_ -notmatch "install" -and
        $_ -notmatch "^NAME\s+"
      }
  )
  return [PSCustomObject]@{
    ExitCode = $exitCode
    Output = $text
    Names = $names
  }
}

function Convert-ToWslPath {
  param(
    [string]$PathValue,
    [string]$WslCommand,
    [string[]]$DistroArgs,
    [switch]$MustExist
  )
  if ($PathValue.StartsWith("/")) {
    return $PathValue
  }
  $inputPath = $PathValue
  if ($MustExist) {
    $inputPath = (Resolve-Path -LiteralPath $PathValue).Path
  }
  $converted = & $WslCommand @DistroArgs -- wslpath -a $inputPath 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "wslpath failed for '$PathValue': $(Normalize-WslOutput $converted)"
  }
  return Normalize-WslOutput $converted
}

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
  $Report.next_action = "Enable WSL or use a SIFT VM before running real SIFT mode."
  Exit-WithReportError "wsl.exe was not found. Use a SIFT VM or install WSL before running real SIFT mode."
}

$Report.wsl_command = $wsl.Source
$Report.wsl_available = $true
$distributions = Get-WslDistributions -WslCommand $wsl.Source
$Report.installed_distributions = $distributions.Names
$Report.wsl_list_exit_code = $distributions.ExitCode
$Report.wsl_list_output_excerpt = $distributions.Output.Substring(0, [Math]::Min(500, $distributions.Output.Length))

if ($distributions.Names.Count -eq 0) {
  $Report.next_action = "Install a WSL distribution or open the SIFT VM, then rerun this script."
  Exit-WithReportError "No WSL distributions are installed. Install/open SIFT VM or WSL before running real SIFT mode."
}

if ($Distro) {
  if ($distributions.Names -notcontains $Distro) {
    $Report.next_action = "Use one of the installed distributions: $($distributions.Names -join ', ')"
    Exit-WithReportError "Requested WSL distribution '$Distro' is not installed."
  }
  $Report.selected_distro = $Distro
  $distroArgs = @("-d", $Distro)
} else {
  $Report.selected_distro = $distributions.Names[0]
  $distroArgs = @()
}

$repoRootWsl = Convert-ToWslPath -PathValue $RepoRoot.Path -WslCommand $wsl.Source -DistroArgs $distroArgs -MustExist
$manifestWsl = Convert-ToWslPath -PathValue $Manifest -WslCommand $wsl.Source -DistroArgs $distroArgs -MustExist
$caseRootWsl = Convert-ToWslPath -PathValue $CaseRoot -WslCommand $wsl.Source -DistroArgs $distroArgs
$outputDirWsl = Convert-ToWslPath -PathValue $OutputDir -WslCommand $wsl.Source -DistroArgs $distroArgs
$scriptWsl = "$repoRootWsl/scripts/sift_mode_smoke.sh"

$Report.status = "READY"
$Report.wsl_paths = [ordered]@{
  repo_root = $repoRootWsl
  manifest = $manifestWsl
  case_root = $caseRootWsl
  output_dir = $outputDirWsl
  script = $scriptWsl
}
$Report.next_action = "Run the real smoke inside WSL with mounted case data and forensic binaries on PATH."

if ($CheckOnly) {
  Write-HostReport
  Write-Host "WSL handoff is ready to invoke $scriptWsl"
  exit 0
}

Write-HostReport
Write-Host "Running SIFT-MIND smoke in WSL distribution '$($Report.selected_distro)'..."
& $wsl.Source @distroArgs -- bash $scriptWsl `
  --case-root $caseRootWsl `
  --output-dir $outputDirWsl `
  --manifest $manifestWsl `
  --python $Python
$exitCode = $LASTEXITCODE

$Report.status = if ($exitCode -eq 0) { "OK" } else { "FAILED" }
$Report.exit_code = $exitCode
Write-HostReport
exit $exitCode
