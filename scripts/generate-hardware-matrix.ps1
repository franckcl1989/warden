# Warden hardware certification matrix generator (repo-level data artifact).
#
# Computes the full certification coverage (target_id + requirement_id +
# capability_key) from the machine contracts and emits an honest
# not_started matrix at tests/hardware-certification/matrix.json. The record
# count is derived from contracts/capabilities.json + contracts/hardware-
# targets.json and can never be hand-maintained.
#
# Honesty rules (docs/HARDWARE_CERTIFICATION.md, tests/hardware-
# certification/README.md): every record stays `not_started`; protocol_evidence
# only contains the contract document (contracts/capabilities.json and its real
# SHA-256 at generation time); no device evidence is ever fabricated.
#
# Usage:
#   pwsh -File scripts/generate-hardware-matrix.ps1
#   pwsh -File scripts/generate-hardware-matrix.ps1 -GeneratedAt 2026-09-01T00:00:00Z
#
# The committed matrix must be regenerated with the same fixed -GeneratedAt
# value used by the CI drift step, so the artifact stays reproducible.
param(
    [string]$GeneratedAt = $null,
    [string]$OutputPath = 'tests/hardware-certification/matrix.json',
    [string]$ReleaseCandidate = 'not-yet-candidate'
)

$ErrorActionPreference = 'Stop'

$wardenRoot = Split-Path -Parent $PSScriptRoot
$wardenCapabilitiesPath = Join-Path $wardenRoot 'contracts/capabilities.json'
$wardenTargetsPath = Join-Path $wardenRoot 'contracts/hardware-targets.json'
$wardenOperationsPath = Join-Path $wardenRoot 'contracts/operations.json'
$wardenResolvedOutputPath = if ([System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $wardenRoot $OutputPath }

if ([string]::IsNullOrWhiteSpace($GeneratedAt)) {
    $GeneratedAt = [DateTimeOffset]::UtcNow.ToString('o')
}

$wardenCapabilities = Get-Content -Raw -LiteralPath $wardenCapabilitiesPath | ConvertFrom-Json
$wardenTargets = Get-Content -Raw -LiteralPath $wardenTargetsPath | ConvertFrom-Json
$wardenOperations = Get-Content -Raw -LiteralPath $wardenOperationsPath | ConvertFrom-Json

$wardenProfileIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($wardenProfile in $wardenOperations.profiles) { $null = $wardenProfileIds.Add([string]$wardenProfile.id) }

$wardenCapabilitiesHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $wardenCapabilitiesPath).Hash.ToLowerInvariant()
$wardenProtocolEvidence = @(
    [pscustomobject]@{
        kind = 'protocol_document'
        path = 'contracts/capabilities.json'
        sha256 = $wardenCapabilitiesHash
        captured_at = $GeneratedAt
        sanitized = $true
    }
)

function New-WardenNotStartedRecord {
    param(
        [string]$Kind,
        [string]$CapabilityKey,
        [object]$Target,
        [object]$Requirement
    )
    $wardenRecord = [ordered]@{}
    $wardenRecord['record_id'] = "HC-$($Target.target_id)-$($Requirement.id)-$CapabilityKey"
    $wardenRecord['target_id'] = [string]$Target.target_id
    $wardenRecord['requirement_id'] = [string]$Requirement.id
    $wardenRecord['capability_key'] = $CapabilityKey
    $wardenRecord['capability_kind'] = $Kind
    if ($Kind -eq 'operation') {
        $wardenRecord['operation_profile_id'] = "$($Requirement.id):$CapabilityKey"
    }
    $wardenRecord['adapter_key'] = [string]$Target.adapter_key
    # exact_model targets are certified against the declared model string;
    # management_family targets have no exact model yet, so the field is
    # explicitly "unrecorded" rather than fabricated.
    $wardenRecord['actual_device_model'] = if ($Target.certification_scope -eq 'exact_model') { [string]$Target.declared_target } else { 'unrecorded' }
    $wardenRecord['firmware_version'] = 'unrecorded'
    $wardenRecord['license_snapshot'] = @()
    $wardenRecord['protocol_evidence'] = $wardenProtocolEvidence
    $wardenRecord['status'] = 'not_started'
    $wardenRecord['automated_tests'] = @()
    $wardenRecord['evidence'] = @()
    $wardenRecord['result_summary'] = '未开始：尚无自动化测试或真机证据；本记录仅为契约覆盖占位，不代表任何能力已通过。'
    if ($Kind -eq 'operation') {
        $wardenRecord['maintenance_window_ref'] = 'not_started-no-maintenance-window'
    }
    return [pscustomobject]$wardenRecord
}

$wardenRecords = [System.Collections.Generic.List[object]]::new()
foreach ($wardenTarget in $wardenTargets.targets) {
    foreach ($wardenRequirement in @($wardenCapabilities.requirements | Where-Object device_type -eq $wardenTarget.device_type)) {
        foreach ($wardenMetric in @($wardenRequirement.metrics | Where-Object { $_ })) {
            $wardenRecords.Add((New-WardenNotStartedRecord -Kind 'metric' -CapabilityKey $wardenMetric -Target $wardenTarget -Requirement $wardenRequirement))
        }
        foreach ($wardenEvent in @($wardenRequirement.events | Where-Object { $_ })) {
            $wardenRecords.Add((New-WardenNotStartedRecord -Kind 'event' -CapabilityKey $wardenEvent -Target $wardenTarget -Requirement $wardenRequirement))
        }
        foreach ($wardenOperation in @($wardenRequirement.operations | Where-Object { $_ })) {
            $wardenProfileId = "$($wardenRequirement.id):$($wardenOperation.key)"
            if (-not $wardenProfileIds.Contains($wardenProfileId)) {
                throw "Operation profile missing from contracts/operations.json: $wardenProfileId"
            }
            $wardenRecords.Add((New-WardenNotStartedRecord -Kind 'operation' -CapabilityKey $wardenOperation.key -Target $wardenTarget -Requirement $wardenRequirement))
        }
    }
}

$wardenMatrix = [ordered]@{
    schema_version = 1
    product_version = '0.1.0'
    release_candidate = $ReleaseCandidate
    generated_at = $GeneratedAt
    records = @($wardenRecords)
}

$wardenOutputDir = Split-Path -Parent $wardenResolvedOutputPath
if (-not (Test-Path -LiteralPath $wardenOutputDir -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $wardenOutputDir -Force
}

# LF line endings and UTF-8 without BOM keep the artifact byte-identical
# across platforms so the CI drift check (git diff --exit-code) is stable.
$wardenJson = (ConvertTo-Json -InputObject $wardenMatrix -Depth 10) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($wardenResolvedOutputPath, $wardenJson, [System.Text.UTF8Encoding]::new($false))

Write-Output "Wrote hardware certification matrix: $wardenResolvedOutputPath"
Write-Output "Records: $($wardenRecords.Count)"
Write-Output "Generated_at: $GeneratedAt"
Write-Output "Capabilities sha256: $wardenCapabilitiesHash"

# Self-check with the authoritative checker; generation must never emit an
# invalid or drifting matrix.
& pwsh -File (Join-Path $wardenRoot 'scripts/check-hardware-certification.ps1') -MatrixPath $wardenResolvedOutputPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
