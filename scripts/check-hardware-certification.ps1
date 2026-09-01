param(
    [Parameter(Mandatory = $true)]
    [string]$MatrixPath,

    [switch]$RequireReleaseReady
)

$ErrorActionPreference = 'Stop'

$wardenRoot = Split-Path -Parent $PSScriptRoot
$wardenResolvedMatrixPath = if ([System.IO.Path]::IsPathRooted($MatrixPath)) { $MatrixPath } else { Join-Path $wardenRoot $MatrixPath }
$wardenErrors = [System.Collections.Generic.List[string]]::new()

function Add-WardenError([string]$Message) {
    $wardenErrors.Add($Message)
}

function Test-WardenNonEmpty([object]$Value) {
    return -not [string]::IsNullOrWhiteSpace([string]$Value)
}

function Test-WardenEvidence([object[]]$Evidence, [string]$Context) {
    foreach ($wardenItem in @($Evidence)) {
        if ($wardenItem.kind -notin @('device_response', 'device_ui', 'device_cli', 'device_log', 'task_record', 'audit_record', 'protocol_document', 'fixture', 'test_report')) {
            Add-WardenError "$Context has invalid evidence kind: $($wardenItem.kind)"
        }
        if (-not (Test-WardenNonEmpty $wardenItem.path)) { Add-WardenError "$Context has evidence without path" }
        if ($wardenItem.sha256 -notmatch '^[a-fA-F0-9]{64}$') { Add-WardenError "$Context has invalid evidence sha256: $($wardenItem.path)" }
        if ($wardenItem.sanitized -ne $true) { Add-WardenError "$Context has evidence not explicitly sanitized: $($wardenItem.path)" }
        try { [DateTimeOffset]::Parse([string]$wardenItem.captured_at) | Out-Null } catch { Add-WardenError "$Context has invalid evidence captured_at: $($wardenItem.path)" }
    }
}

if (-not (Test-Path -LiteralPath $wardenResolvedMatrixPath -PathType Leaf)) {
    throw "Hardware certification matrix not found: $wardenResolvedMatrixPath"
}

$wardenCapabilities = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/capabilities.json') | ConvertFrom-Json
$wardenOperations = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/operations.json') | ConvertFrom-Json
$wardenTargetsContract = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/hardware-targets.json') | ConvertFrom-Json
$wardenMatrix = Get-Content -Raw -LiteralPath $wardenResolvedMatrixPath | ConvertFrom-Json

if ($wardenMatrix.schema_version -ne 1) { Add-WardenError 'matrix schema_version must be 1' }
if ($wardenMatrix.product_version -ne '0.1.0') { Add-WardenError 'matrix product_version must be 0.1.0' }
if (-not (Test-WardenNonEmpty $wardenMatrix.release_candidate)) { Add-WardenError 'matrix release_candidate is required' }
try { [DateTimeOffset]::Parse([string]$wardenMatrix.generated_at) | Out-Null } catch { Add-WardenError 'matrix generated_at must be an ISO-8601 timestamp' }

$wardenTargetsById = @{}
foreach ($wardenTarget in $wardenTargetsContract.targets) { $wardenTargetsById[$wardenTarget.target_id] = $wardenTarget }
$wardenRequirementsById = @{}
foreach ($wardenRequirement in $wardenCapabilities.requirements) { $wardenRequirementsById[$wardenRequirement.id] = $wardenRequirement }
$wardenOperationProfiles = @{}
foreach ($wardenProfile in $wardenOperations.profiles) { $wardenOperationProfiles[$wardenProfile.id] = $wardenProfile }

$wardenExpected = [System.Collections.Generic.HashSet[string]]::new()
foreach ($wardenTarget in $wardenTargetsContract.targets) {
    foreach ($wardenRequirement in @($wardenCapabilities.requirements | Where-Object device_type -eq $wardenTarget.device_type)) {
        foreach ($wardenMetric in @($wardenRequirement.metrics | Where-Object { $_ })) {
            $null = $wardenExpected.Add("$($wardenTarget.target_id)|$($wardenRequirement.id)|$wardenMetric")
        }
        foreach ($wardenEvent in @($wardenRequirement.events | Where-Object { $_ })) {
            $null = $wardenExpected.Add("$($wardenTarget.target_id)|$($wardenRequirement.id)|$wardenEvent")
        }
        foreach ($wardenOperation in @($wardenRequirement.operations | Where-Object { $_ })) {
            $null = $wardenExpected.Add("$($wardenTarget.target_id)|$($wardenRequirement.id)|$($wardenOperation.key)")
        }
    }
}

$wardenActual = [System.Collections.Generic.List[string]]::new()
$wardenRecordIds = [System.Collections.Generic.List[string]]::new()
foreach ($wardenRecord in @($wardenMatrix.records)) {
    $wardenContext = "record $($wardenRecord.record_id)"
    $wardenRecordIds.Add([string]$wardenRecord.record_id)
    $wardenTuple = "$($wardenRecord.target_id)|$($wardenRecord.requirement_id)|$($wardenRecord.capability_key)"
    $wardenActual.Add($wardenTuple)

    if (-not $wardenTargetsById.ContainsKey([string]$wardenRecord.target_id)) {
        Add-WardenError "$wardenContext references unknown target_id: $($wardenRecord.target_id)"
        continue
    }
    if (-not $wardenRequirementsById.ContainsKey([string]$wardenRecord.requirement_id)) {
        Add-WardenError "$wardenContext references unknown requirement_id: $($wardenRecord.requirement_id)"
        continue
    }

    $wardenTarget = $wardenTargetsById[[string]$wardenRecord.target_id]
    $wardenRequirement = $wardenRequirementsById[[string]$wardenRecord.requirement_id]
    if ($wardenTarget.device_type -ne $wardenRequirement.device_type) { Add-WardenError "$wardenContext target/requirement device_type mismatch" }
    if ($wardenRecord.adapter_key -ne $wardenTarget.adapter_key) { Add-WardenError "$wardenContext adapter_key must be $($wardenTarget.adapter_key)" }
    if ($wardenRecord.record_id -notmatch '^HC-[A-Za-z0-9._:-]+$') { Add-WardenError "$wardenContext has invalid record_id" }
    if ($wardenTarget.certification_scope -eq 'exact_model' -and -not ([string]$wardenRecord.actual_device_model).Equals([string]$wardenTarget.declared_target, [System.StringComparison]::OrdinalIgnoreCase)) {
        Add-WardenError "$wardenContext actual_device_model must equal declared exact model $($wardenTarget.declared_target)"
    }

    $wardenExpectedKind = $null
    if ($wardenRecord.capability_key -in @($wardenRequirement.metrics)) { $wardenExpectedKind = 'metric' }
    if ($wardenRecord.capability_key -in @($wardenRequirement.events)) { $wardenExpectedKind = 'event' }
    if ($wardenRecord.capability_key -in @($wardenRequirement.operations | ForEach-Object key)) { $wardenExpectedKind = 'operation' }
    if ($null -eq $wardenExpectedKind) { Add-WardenError "$wardenContext capability_key does not belong to requirement" }
    elseif ($wardenRecord.capability_kind -ne $wardenExpectedKind) { Add-WardenError "$wardenContext capability_kind must be $wardenExpectedKind" }

    if ($wardenExpectedKind -eq 'operation') {
        $wardenExpectedProfile = "$($wardenRequirement.id):$($wardenRecord.capability_key)"
        if ($wardenRecord.operation_profile_id -ne $wardenExpectedProfile) { Add-WardenError "$wardenContext operation_profile_id must be $wardenExpectedProfile" }
        if (-not $wardenOperationProfiles.ContainsKey($wardenExpectedProfile)) { Add-WardenError "$wardenContext references missing operation profile: $wardenExpectedProfile" }
        if (-not (Test-WardenNonEmpty $wardenRecord.maintenance_window_ref)) { Add-WardenError "$wardenContext operation lacks maintenance_window_ref" }
    } elseif (Test-WardenNonEmpty $wardenRecord.operation_profile_id) {
        Add-WardenError "$wardenContext non-operation must not contain operation_profile_id"
    }

    if ($wardenRecord.status -notin @('not_started', 'automated_passed', 'hardware_passed', 'unsupported_with_evidence', 'failed')) { Add-WardenError "$wardenContext has invalid status: $($wardenRecord.status)" }
    foreach ($wardenField in @('actual_device_model', 'firmware_version', 'result_summary')) {
        if (-not (Test-WardenNonEmpty $wardenRecord.$wardenField)) { Add-WardenError "$wardenContext lacks $wardenField" }
    }
    if (@($wardenRecord.protocol_evidence).Count -eq 0) { Add-WardenError "$wardenContext lacks protocol_evidence" }
    Test-WardenEvidence @($wardenRecord.protocol_evidence) "$wardenContext protocol_evidence"
    Test-WardenEvidence @($wardenRecord.evidence) "$wardenContext evidence"

    $wardenExpectedTestId = "T-$($wardenRequirement.id)"
    foreach ($wardenTest in @($wardenRecord.automated_tests)) {
        if ($wardenTest.test_id -ne $wardenExpectedTestId) { Add-WardenError "$wardenContext automated test id must be $wardenExpectedTestId" }
        if ($wardenTest.status -ne 'passed') { Add-WardenError "$wardenContext automated test is not passed: $($wardenTest.test_id)" }
        if (-not (Test-WardenNonEmpty $wardenTest.report_path)) { Add-WardenError "$wardenContext automated test lacks report_path" }
        if ($wardenTest.sha256 -notmatch '^[a-fA-F0-9]{64}$') { Add-WardenError "$wardenContext automated test has invalid sha256" }
    }

    if ($RequireReleaseReady) {
        if ($wardenRecord.status -notin @('hardware_passed', 'unsupported_with_evidence')) { Add-WardenError "$wardenContext is not release-terminal: $($wardenRecord.status)" }
        if (-not (Test-WardenNonEmpty $wardenRecord.hardware_report_path)) { Add-WardenError "$wardenContext lacks hardware_report_path" }
        if (-not (Test-WardenNonEmpty $wardenRecord.executed_by)) { Add-WardenError "$wardenContext lacks executed_by" }
        try { [DateTimeOffset]::Parse([string]$wardenRecord.executed_at) | Out-Null } catch { Add-WardenError "$wardenContext lacks valid executed_at" }

        if ($wardenRecord.status -eq 'hardware_passed') {
            if (@($wardenRecord.automated_tests).Count -eq 0) { Add-WardenError "$wardenContext hardware_passed lacks automated test evidence" }
            if (@($wardenRecord.evidence).Count -eq 0) { Add-WardenError "$wardenContext hardware_passed lacks hardware evidence" }
        }
        if ($wardenRecord.status -eq 'unsupported_with_evidence') {
            if (-not (Test-WardenNonEmpty $wardenRecord.user_acceptance_ref)) { Add-WardenError "$wardenContext unsupported status lacks user_acceptance_ref" }
            $wardenProofKinds = @($wardenRecord.evidence | ForEach-Object kind)
            if (@($wardenProofKinds | Where-Object { $_ -in @('device_response', 'device_ui', 'device_cli', 'protocol_document') }).Count -eq 0) {
                Add-WardenError "$wardenContext unsupported status lacks device-native or protocol-document evidence"
            }
        }
    }
}

foreach ($wardenDuplicate in @($wardenRecordIds | Group-Object | Where-Object Count -ne 1)) { Add-WardenError "record_id must be unique: $($wardenDuplicate.Name)" }
foreach ($wardenDuplicate in @($wardenActual | Group-Object | Where-Object Count -ne 1)) { Add-WardenError "certification tuple must be unique: $($wardenDuplicate.Name)" }
foreach ($wardenDifference in @(Compare-Object @($wardenExpected | Sort-Object) @($wardenActual | Sort-Object))) {
    Add-WardenError "certification coverage mismatch: $($wardenDifference.InputObject) side=$($wardenDifference.SideIndicator)"
}

if ($wardenErrors.Count -gt 0) {
    Write-Error ("Hardware certification validation failed:`n- " + ($wardenErrors -join "`n- "))
    exit 1
}

Write-Output 'Hardware certification validation passed.'
Write-Output "Targets: $($wardenTargetsContract.targets.Count)"
Write-Output "Expected coverage records: $($wardenExpected.Count)"
Write-Output "Actual coverage records: $($wardenActual.Count)"
Write-Output "Release-ready mode: $($RequireReleaseReady.IsPresent)"
