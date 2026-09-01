# Warden Windows task entry. Mirrors the Makefile targets for local development.
param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Extra
)

$ErrorActionPreference = 'Stop'
$wardenRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $wardenRoot 'backend'
$frontendDir = Join-Path $wardenRoot 'frontend'

function Invoke-Uv([string[]]$ModuleArgs) {
    # Prefer uv (CI/Linux); fall back to the pre-created venv when uv is not on PATH.
    $hasUv = $null -ne (Get-Command uv -ErrorAction SilentlyContinue)
    if ($hasUv) {
        & uv run --project $backendDir --directory $backendDir @ModuleArgs
    }
    else {
        # uv resolves a leading 'python' pseudo-command; the venv fallback translates
        # `python -m mod ...` / `python script ...` into direct interpreter invocations.
        $exe = Join-Path $backendDir '.venv\Scripts\python.exe'
        $cmdArgs = @($ModuleArgs)
        $asModule = $true
        if ($cmdArgs.Count -gt 0 -and $cmdArgs[0] -eq 'python') {
            $cmdArgs = $cmdArgs[1..($cmdArgs.Count - 1)]
            if ($cmdArgs.Count -gt 0 -and $cmdArgs[0] -eq '-m') {
                $cmdArgs = $cmdArgs[1..($cmdArgs.Count - 1)]
            }
            else {
                $asModule = $false
            }
        }
        Push-Location $backendDir
        try {
            if ($asModule) { & $exe -m @cmdArgs } else { & $exe @cmdArgs }
        } finally { Pop-Location }
    }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Invoke-Npm([string[]]$NpmArgs) {
    if (-not (Test-Path (Join-Path $frontendDir 'package.json'))) {
        Write-Host 'frontend/ is not a node project yet (M0T5) - skipping npm step'
        return
    }
    Push-Location $frontendDir; try { & npm @NpmArgs; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } } finally { Pop-Location }
}

switch ($Target) {
    'install' {
        $hasUv = $null -ne (Get-Command uv -ErrorAction SilentlyContinue)
        if (-not $hasUv) {
            Write-Error 'uv not found on PATH. Install uv (https://docs.astral.sh/uv/) or use the existing backend/.venv (already populated on this machine).'
            exit 1
        }
        & uv sync --project $backendDir --all-extras
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Invoke-Npm @('ci')
    }
    'lint' {
        Invoke-Uv @('ruff', 'check')
        Invoke-Npm @('run', 'lint')
    }
    'format' {
        Invoke-Uv @('ruff', 'format')
        Invoke-Npm @('run', 'format')
    }
    'typecheck' {
        Invoke-Uv @('mypy')
        Invoke-Npm @('run', 'typecheck')
    }
    'contracts' { Invoke-Uv @('python', '-m', 'app.tools.codegen') }
    'contracts-check' {
        Invoke-Uv @('python', '-m', 'app.tools.codegen')
        $drift = git -C $wardenRoot diff --exit-code -- backend/app/generated frontend/src/api/generated
        if ($LASTEXITCODE -ne 0) { Write-Error 'Generated contract artifacts drifted; run contracts and commit.'; exit 1 }
    }
    'openapi' { Invoke-Uv @('python', '-m', 'app.tools.openapi_export') }
    'test-backend' { Invoke-Uv @('pytest', '-q') }
    'test-frontend' { Invoke-Npm @('run', 'test') }
    'test' {
        & $PSCommandPath 'test-backend'
        & $PSCommandPath 'test-frontend'
    }
    'migrate' { Invoke-Uv @('alembic', 'upgrade', 'head') }
    'migration' { Invoke-Uv @('alembic', 'revision', '--autogenerate', '-m', 'migration') }
    'compose-up' { & docker compose -f (Join-Path $wardenRoot 'deployment/compose/compose.yaml') up -d }
    'compose-down' { & docker compose -f (Join-Path $wardenRoot 'deployment/compose/compose.yaml') down }
    'dev-api' { Invoke-Uv @('uvicorn', 'app.main:app', '--app-dir', $backendDir, '--reload') }
    'dev-worker' { Invoke-Uv @('python', '-m', 'app.workers.run') }
    'dev-ingest' { Invoke-Uv @('python', '-m', 'app.workers.ingest') }
    'dev-frontend' { Invoke-Npm @('run', 'dev') }
    'matrix' { & pwsh -File (Join-Path $wardenRoot 'scripts/generate-hardware-matrix.ps1') -GeneratedAt '2026-09-01T00:00:00Z' }
    'check-design' { & pwsh -File (Join-Path $wardenRoot 'scripts/check-design.ps1') }
    'check-hardware' { & pwsh -File (Join-Path $wardenRoot 'scripts/check-hardware-certification.ps1') -MatrixPath (Join-Path $wardenRoot 'tests/hardware-certification/matrix.json') }
    'check' {
        & pwsh -File (Join-Path $wardenRoot 'scripts/check-design.ps1')
        & $PSCommandPath 'contracts-check'
        & $PSCommandPath 'lint'
        & $PSCommandPath 'typecheck'
        & $PSCommandPath 'test'
    }
    default { Write-Error "Unknown target: $Target"; exit 1 }
}
