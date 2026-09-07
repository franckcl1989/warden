$ErrorActionPreference = 'Stop'

# Warden traceability close-out check (M6T3, PLT-08 release support).
#
# Verifies, from the repository itself:
#   1. test references: every requirement id of contracts/capabilities.json is
#      referenced by at least one backend/tests test file (test_*.py); the
#      stable suite id of TRACEABILITY.md (T-{REQ}) is 1:1 with the
#      requirement id, so the test reference is the requirement id itself.
#   2. adapter method paths: every metric/event/operation capability key of
#      the catalog appears literally in backend/app/adapters (collect
#      mappings, operation keys, create_launch console mappings).
#   3. OpenAPI coverage: every http-api.json operationId appears in the
#      exported backend/openapi.gen.json (regenerate it first, e.g.
#      `backend\.venv\Scripts\python.exe -m app.tools.openapi_export` from
#      backend/). WebSocket endpoints are excluded by design: FastAPI does
#      not serialize WebSocket routes into the OpenAPI schema; their route
#      existence is covered by the terminal WS API tests.
#   4. frontend references: every requirement id appears statically in
#      frontend/src application source (feature configs, panels and trace
#      labels; src/tests and src/api/generated are excluded: generated
#      files cannot be intent evidence and their drift is covered by the
#      codegen tests). frontend/src/features/devices/requirementTrace.ts is
#      the label registry for requirements rendered dynamically from the
#      capabilities API, cross-checked by its own vitest spec against the
#      generated REQUIREMENTS registry.
#
# Emits tests/traceability/closeout.json (per-requirement machine evidence:
# test_count / test_files, adapter_refs, frontend_refs, api_operation_ids,
# ok) and exits non-zero when any rule fails.

$wardenRoot = Split-Path -Parent $PSScriptRoot
$wardenErrors = [System.Collections.Generic.List[string]]::new()

$wardenCatalogPath = Join-Path $wardenRoot 'contracts/capabilities.json'
$wardenHttpPath = Join-Path $wardenRoot 'contracts/http-api.json'
$wardenOpenApiPath = Join-Path $wardenRoot 'backend/openapi.gen.json'
$wardenBackendTests = Join-Path $wardenRoot 'backend/tests'
$wardenAdapters = Join-Path $wardenRoot 'backend/app/adapters'
$wardenFrontend = Join-Path $wardenRoot 'frontend/src'
$wardenCloseoutDir = Join-Path $wardenRoot 'tests/traceability'
$wardenCloseoutPath = Join-Path $wardenCloseoutDir 'closeout.json'

foreach ($wardenRequired in @($wardenCatalogPath, $wardenHttpPath, $wardenBackendTests, $wardenAdapters, $wardenFrontend)) {
    if (-not (Test-Path -LiteralPath $wardenRequired)) {
        Write-Error "Missing path for traceability check: $wardenRequired"
        exit 2
    }
}
if (-not (Test-Path -LiteralPath $wardenOpenApiPath -PathType Leaf)) {
    $wardenErrors.Add("Missing exported OpenAPI: backend/openapi.gen.json (regenerate it first from backend/ via: .\.venv\Scripts\python.exe -m app.tools.openapi_export)")
}

$wardenCatalog = Get-Content -Raw -LiteralPath $wardenCatalogPath | ConvertFrom-Json
$wardenHttpCatalog = Get-Content -Raw -LiteralPath $wardenHttpPath | ConvertFrom-Json

function New-WardenSourceSet {
    param(
        [string[]]$Paths
    )
    $wardenContents = @(foreach ($wardenPath in $Paths) { Get-Content -Raw -LiteralPath $wardenPath })
    return [pscustomobject]@{
        Paths = $Paths
        Texts = $wardenContents
    }
}

function Get-WardenHitSummary {
    param(
        [string]$Needle,
        [object]$SourceSet
    )
    $wardenHitIndexes = @()
    for ($wardenI = 0; $wardenI -lt $SourceSet.Texts.Count; $wardenI++) {
        if ($SourceSet.Texts[$wardenI].Contains($Needle)) {
            $wardenHitIndexes += $wardenI
        }
    }
    $wardenHitPaths = @($wardenHitIndexes | ForEach-Object { $SourceSet.Paths[$_] })
    return [pscustomobject]@{ Count = $wardenHitPaths.Count; Files = $wardenHitPaths }
}

# -- input sets ------------------------------------------------------------------

$wardenBackendTestFiles = @(
    Get-ChildItem -LiteralPath $wardenBackendTests -Recurse -File -Filter 'test_*.py' |
        Sort-Object FullName | Select-Object -ExpandProperty FullName
)
$wardenFrontendAppFiles = @(
    Get-ChildItem -LiteralPath $wardenFrontend -Recurse -File -Include '*.ts', '*.vue', '*.tsx', '*.js' |
        Where-Object {
            $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\api\\generated\\'
        } |
        Sort-Object FullName | Select-Object -ExpandProperty FullName
)
$wardenFrontendAllFiles = @(
    Get-ChildItem -LiteralPath $wardenFrontend -Recurse -File -Include '*.ts', '*.vue', '*.tsx', '*.js' |
        Sort-Object FullName | Select-Object -ExpandProperty FullName
)
$wardenAdapterFiles = @(
    Get-ChildItem -LiteralPath $wardenAdapters -Recurse -File -Filter '*.py' |
        Sort-Object FullName | Select-Object -ExpandProperty FullName
)
$wardenBackendTestSet = New-WardenSourceSet $wardenBackendTestFiles
$wardenFrontendAppSet = New-WardenSourceSet $wardenFrontendAppFiles
$wardenFrontendAllSet = New-WardenSourceSet $wardenFrontendAllFiles
$wardenAdapterSet = New-WardenSourceSet $wardenAdapterFiles

# -- rule 2: every capability key has an adapter method path ----------------------

$wardenCapabilityKeys = [System.Collections.Generic.List[string]]::new()
foreach ($wardenRequirement in $wardenCatalog.requirements) {
    foreach ($wardenKey in @($wardenRequirement.metrics) + @($wardenRequirement.events)) {
        if ($wardenKey) { $wardenCapabilityKeys.Add($wardenKey) }
    }
    foreach ($wardenOperation in @($wardenRequirement.operations)) {
        $wardenCapabilityKeys.Add($wardenOperation.key)
    }
}
$wardenUniqueKeys = @($wardenCapabilityKeys | Sort-Object -Unique)
foreach ($wardenKey in $wardenUniqueKeys) {
    $wardenSummary = Get-WardenHitSummary $wardenKey $wardenAdapterSet
    if ($wardenSummary.Count -lt 1) {
        $wardenErrors.Add("Capability key has no adapter method path: $wardenKey")
    }
}

# -- rule 3: OpenAPI operationIds ---------------------------------------------------

$wardenOpenApiIds = [System.Collections.Generic.HashSet[string]]::new()
if (Test-Path -LiteralPath $wardenOpenApiPath -PathType Leaf) {
    $wardenOpenApi = Get-Content -Raw -LiteralPath $wardenOpenApiPath | ConvertFrom-Json
    foreach ($wardenOpenApiPathEntry in $wardenOpenApi.paths.PSObject.Properties) {
        foreach ($wardenMethod in $wardenOpenApiPathEntry.Value.PSObject.Properties) {
            if ($null -ne $wardenMethod.Value.operationId) {
                [void]$wardenOpenApiIds.Add([string]$wardenMethod.Value.operationId)
            }
        }
    }
}
$wardenApiRows = [System.Collections.Generic.List[object]]::new()
foreach ($wardenEndpoint in $wardenHttpCatalog.endpoints) {
    if ($wardenEndpoint.method -eq 'WS') {
        $wardenInOpenApi = $true # FastAPI never serializes WS routes into OpenAPI
    } else {
        $wardenInOpenApi = $wardenOpenApiIds.Contains($wardenEndpoint.operation_id)
    }
    $wardenApiRows.Add([pscustomobject]@{
        method   = $wardenEndpoint.method
        path     = $wardenEndpoint.path
        operation_id = $wardenEndpoint.operation_id
        support_id = $wardenEndpoint.support_id
        in_openapi = $wardenInOpenApi
    })
    if (-not $wardenInOpenApi) {
        $wardenErrors.Add("http-api operationId missing from exported OpenAPI: $($wardenEndpoint.operation_id) $($wardenEndpoint.method) $($wardenEndpoint.path)")
    }
}

# -- rules 1+4: per-requirement evidence ---------------------------------------------

$wardenRequirementRows = [System.Collections.Generic.List[object]]::new()
$wardenAllOk = $true
foreach ($wardenRequirement in $wardenCatalog.requirements) {
    $wardenTestSummary = Get-WardenHitSummary $wardenRequirement.id $wardenBackendTestSet
    $wardenFrontendSummary = Get-WardenHitSummary $wardenRequirement.id $wardenFrontendAppSet
    $wardenFrontendAllSummary = Get-WardenHitSummary $wardenRequirement.id $wardenFrontendAllSet
    $wardenAdapterKeysForRequirement = @()
    foreach ($wardenKey in @($wardenRequirement.metrics) + @($wardenRequirement.events)) {
        if ($wardenKey) { $wardenAdapterKeysForRequirement += $wardenKey }
    }
    foreach ($wardenOperation in @($wardenRequirement.operations)) {
        $wardenAdapterKeysForRequirement += $wardenOperation.key
    }
    $wardenAdapterRefs = [System.Collections.Generic.List[string]]::new()
    foreach ($wardenKey in $wardenAdapterKeysForRequirement) {
        $wardenKeySummary = Get-WardenHitSummary $wardenKey $wardenAdapterSet
        foreach ($wardenHitPath in $wardenKeySummary.Files) {
            $wardenShort = $wardenHitPath.Substring($wardenRoot.Length + 1) -replace '\\', '/'
            if (-not $wardenAdapterRefs.Contains($wardenShort)) { $wardenAdapterRefs.Add($wardenShort) }
        }
    }
    $wardenTestOk = $wardenTestSummary.Count -ge 1
    $wardenFrontendOk = $wardenFrontendSummary.Count -ge 1
    $wardenRequirementOk = $wardenTestOk -and $wardenFrontendOk -and $wardenAdapterRefs.Count -ge 1
    if (-not $wardenRequirementOk) { $wardenAllOk = $false }
    if (-not $wardenTestOk) {
        $wardenErrors.Add("Requirement has no backend test reference (T-$($wardenRequirement.id)): $($wardenRequirement.id)")
    }
    if (-not $wardenFrontendOk) {
        $wardenErrors.Add("Requirement has no frontend static reference: $($wardenRequirement.id)")
    }
    if ($wardenAdapterRefs.Count -lt 1) {
        $wardenErrors.Add("Requirement capabilities lack adapter method paths: $($wardenRequirement.id)")
    }
    $wardenRequirementRows.Add([pscustomobject]@{
        requirement_id   = $wardenRequirement.id
        device_type      = $wardenRequirement.device_type
        kind             = $wardenRequirement.kind
        test_count       = $wardenTestSummary.Count
        test_files       = @($wardenTestSummary.Files | ForEach-Object { $_.Substring($wardenRoot.Length + 1) -replace '\\', '/' })
        adapter_refs     = @($wardenAdapterRefs)
        api_operation_ids = @()
        frontend_refs    = @($wardenFrontendSummary.Files | ForEach-Object { $_.Substring($wardenRoot.Length + 1) -replace '\\', '/' })
        frontend_all     = $wardenFrontendAllSummary.Count
        ok               = $wardenRequirementOk
    })
}

# -- emit the machine artifact --------------------------------------------------------

New-Item -ItemType Directory -Path $wardenCloseoutDir -Force | Out-Null
$wardenCloseout = [ordered]@{
    product_version = '0.1.0'
    generated_by    = 'scripts/check-traceability.ps1 (M6T3)'
    generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    rules = [ordered]@{
        test_reference = 'backend/tests test_*.py files referencing the requirement id (T-{REQ} per TRACEABILITY.md)'
        adapter_path = 'capability key literal in backend/app/adapters (collect/operation/create_launch mappings)'
        openapi = 'http-api.json operationId in backend/openapi.gen.json (WS excluded: FastAPI omits WebSocket routes from OpenAPI)'
        frontend = 'requirement id literal in frontend/src application source (excludes src/tests and src/api/generated; requirementTrace.ts is the label registry for API-dynamic surfaces)'
    }
    openapi_endpoints = @($wardenApiRows)
    requirements = @($wardenRequirementRows)
    ok = $wardenAllOk -and ($wardenErrors.Count -eq 0)
}
$wardenCloseout | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $wardenCloseoutPath -Encoding UTF8

# -- console output ------------------------------------------------------------------

foreach ($wardenRequirementRow in $wardenRequirementRows) {
    $wardenFlag = if ($wardenRequirementRow.ok) { 'PASS' } else { 'FAIL' }
    Write-Output ("{0} {1} tests={2} frontend={3} adapters={4} (frontend_all={5})" -f $wardenFlag, $wardenRequirementRow.requirement_id, $wardenRequirementRow.test_count, $wardenRequirementRow.frontend_refs.Count, $wardenRequirementRow.adapter_refs.Count, $wardenRequirementRow.frontend_all)
}
Write-Output "Capability keys with adapter paths: $($wardenUniqueKeys.Count)/$($wardenUniqueKeys.Count)"
Write-Output "http-api endpoints checked: $($wardenApiRows.Count) (WS excluded from OpenAPI by design)"
Write-Output "Close-out artifact: $($wardenCloseoutPath.Replace($wardenRoot + '\', ''))"

if ($wardenErrors.Count -gt 0) {
    Write-Output ''
    Write-Error ("Traceability validation failed:`n- " + ($wardenErrors -join "`n- "))
    exit 1
}

Write-Output 'Traceability validation passed.'
Write-Output "Requirements traced: $($wardenRequirementRows.Count)"
