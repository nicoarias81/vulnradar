param([switch]$ValidateOnly, [switch]$SkipBacktest)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    function Invoke-LabCompose {
        & docker compose -f docker-compose.lab.yml @args
        if ($LASTEXITCODE -ne 0) { throw "Lab command failed (exit $LASTEXITCODE)" }
    }
    Invoke-LabCompose up -d postgres
    Invoke-LabCompose build runner
    Invoke-LabCompose run --rm runner python -m pytest -q --tb=short -o addopts=--basetemp=/tmp/radar-tests -p no:cacheprovider
    if ($ValidateOnly) {
        Invoke-LabCompose run --rm runner python scripts/build_scoring_lab.py --mirror /mirror --cache /lab/cache --report /lab/validation.json --validate-only
    } else {
        Invoke-LabCompose run --rm runner
    }
    if (-not $SkipBacktest) {
        Invoke-LabCompose run --rm runner python scripts/backtest_scoring.py --cohorts '2026-07-01,2026-08-01,2026-09-01' --cache /lab/cache --report /lab/backtest-cohorts.json
    }
    Invoke-LabCompose up -d dashboard
    Write-Host 'Lab ready: http://localhost:18501 | reports: data/scoring-lab/'
} finally {
    Pop-Location
}
