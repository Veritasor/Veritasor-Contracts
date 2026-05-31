# Veritasor Coverage Runner — Windows PowerShell
#
# Usage:
#   .\scripts\coverage.ps1              # Run all gates + workspace report
#   .\scripts\coverage.ps1 -Quick      # Run gates only, skip HTML report
#   .\scripts\coverage.ps1 -Install    # Install cargo-llvm-cov then exit
#
# Enforces a 95 % line-coverage floor on each critical crate individually.

[CmdletBinding()]
param(
    [switch]$Quick,
    [switch]$Install
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location -Path (Join-Path $ScriptDir "..")

$CriticalCrates = @(
    "veritasor-attestation",
    "veritasor-attestation-registry",
    "veritasor-attestor-staking",
    "veritasor-common",
    "veritasor-audit-log"
)

$CoverageTarget = 95

function Write-Header {
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         Veritasor Coverage Report                              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success ($msg) {
    Write-Host "✓ $msg" -ForegroundColor Green
}

function Write-ErrorColored ($msg) {
    Write-Host "✗ $msg" -ForegroundColor Red
}

function Write-Info ($msg) {
    Write-Host "ℹ $msg" -ForegroundColor Yellow
}

function Test-Tooling {
    try {
        $null = Get-Command cargo -ErrorAction Stop
    } catch {
        Write-ErrorColored "cargo not found. Install Rust from https://rustup.rs"
        exit 1
    }

    try {
        $null = cargo llvm-cov --version 2>$null
    } catch {
        Write-ErrorColored "cargo-llvm-cov not found."
        Write-Info "Install with:  cargo install cargo-llvm-cov"
        exit 1
    }
}

function Invoke-CrateGate ($Crate) {
    Write-Host ""
    Write-Host "Checking ${Crate} ..." -ForegroundColor Cyan

    $proc = Start-Process -FilePath "cargo" -ArgumentList @(
        "llvm-cov", "--package", $Crate, "--lib", "--fail-under-lines", $CoverageTarget
    ) -NoNewWindow -Wait -PassThru

    if ($proc.ExitCode -eq 0) {
        Write-Success "${Crate} meets ${CoverageTarget}% line coverage"
        return $true
    } else {
        Write-ErrorColored "${Crate} is below ${CoverageTarget}% line coverage"
        return $false
    }
}

function Invoke-AllGates {
    $failed = $false
    foreach ($crate in $CriticalCrates) {
        if (-not (Invoke-CrateGate $crate)) {
            $failed = $true
        }
    }
    return (-not $failed)
}

function New-WorkspaceReport {
    Write-Host ""
    Write-Host "Generating workspace HTML report ..." -ForegroundColor Cyan
    $proc = Start-Process -FilePath "cargo" -ArgumentList @(
        "llvm-cov", "--workspace", "--html", "--output-dir", "coverage/"
    ) -NoNewWindow -Wait -PassThru

    if ($proc.ExitCode -eq 0) {
        Write-Success "Workspace report written to .\coverage\"
    } else {
        Write-ErrorColored "Failed to generate workspace report"
        exit 1
    }
}

function Install-Tool {
    Write-Info "Installing cargo-llvm-cov ..."
    cargo install cargo-llvm-cov
    Write-Success "cargo-llvm-cov installed"
}

# ─── Main ─────────────────────────────────────────────────────────

Write-Header

if ($Install) {
    Install-Tool
    exit 0
}

Test-Tooling

$allPassed = Invoke-AllGates

if (-not $Quick) {
    New-WorkspaceReport
}

if ($allPassed) {
    Write-Host ""
    Write-Success "All coverage gates passed"
    Write-Host ""
    exit 0
} else {
    Write-Host ""
    Write-ErrorColored "One or more coverage gates failed"
    Write-Host ""
    exit 1
}

