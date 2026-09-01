$ErrorActionPreference = 'Stop'

$wardenRoot = Split-Path -Parent $PSScriptRoot
$wardenRequiredFiles = @(
    'AGENTS.md',
    'contracts/capabilities.json',
    'contracts/metrics.json',
    'contracts/events.json',
    'contracts/operations.json',
    'contracts/alert-rules.json',
    'contracts/http-api.json',
    'contracts/error-codes.json',
    'contracts/hardware-targets.json',
    'contracts/hardware-certification.schema.json',
    'docs/README.md',
    'docs/SOURCE_BASELINE.md',
    'docs/PROJECT_SPEC.md',
    'docs/PRODUCT_DESIGN.md',
    'docs/UI_SPEC.md',
    'docs/ARCHITECTURE.md',
    'docs/DEVICE_ADAPTERS.md',
    'docs/DATA_MODEL.md',
    'docs/API_CONTRACT.md',
    'docs/SECURITY.md',
    'docs/DEPLOYMENT.md',
    'docs/TEST_STRATEGY.md',
    'docs/HARDWARE_CERTIFICATION.md',
    'docs/IMPLEMENTATION_PLAN.md',
    'docs/DEVELOPMENT_PLAYBOOK.md',
    'docs/TRACEABILITY.md',
    'docs/GLOSSARY.md',
    'docs/RISK_REGISTER.md',
    'docs/ADVERSARIAL_REVIEW.md',
    'docs/BLUEPRINT_AUDIT.md',
    'docs/DECISION_LOG.md'
    'scripts/check-hardware-certification.ps1'
)

$wardenErrors = [System.Collections.Generic.List[string]]::new()

function Add-WardenSetDiff {
    param(
        [string]$Name,
        [object[]]$Expected,
        [object[]]$Actual
    )
    foreach ($wardenDifference in @(Compare-Object @($Expected | Sort-Object -Unique) @($Actual | Sort-Object -Unique))) {
        $wardenErrors.Add("$Name mismatch: $($wardenDifference.InputObject) side=$($wardenDifference.SideIndicator)")
    }
}

function Test-WardenUnique {
    param(
        [string]$Name,
        [object[]]$Values
    )
    foreach ($wardenDuplicate in @($Values | Group-Object | Where-Object Count -ne 1)) {
        $wardenErrors.Add("$Name must be unique: $($wardenDuplicate.Name) count=$($wardenDuplicate.Count)")
    }
}

foreach ($wardenRelativePath in $wardenRequiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $wardenRoot $wardenRelativePath) -PathType Leaf)) {
        $wardenErrors.Add("Missing required file: $wardenRelativePath")
    }
}

if ($wardenErrors.Count -eq 0) {
    $wardenSpecPath = Join-Path $wardenRoot 'docs/PROJECT_SPEC.md'
    $wardenTracePath = Join-Path $wardenRoot 'docs/TRACEABILITY.md'
    $wardenAdapterPath = Join-Path $wardenRoot 'docs/DEVICE_ADAPTERS.md'
    $wardenApiPath = Join-Path $wardenRoot 'docs/API_CONTRACT.md'
    $wardenCatalog = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/capabilities.json') | ConvertFrom-Json
    $wardenMetricCatalog = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/metrics.json') | ConvertFrom-Json
    $wardenEventCatalog = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/events.json') | ConvertFrom-Json
    $wardenOperationCatalog = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/operations.json') | ConvertFrom-Json
    $wardenAlertCatalog = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/alert-rules.json') | ConvertFrom-Json
    $wardenHttpCatalog = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/http-api.json') | ConvertFrom-Json
    $wardenErrorCatalog = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/error-codes.json') | ConvertFrom-Json
    $wardenHardwareTargets = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/hardware-targets.json') | ConvertFrom-Json
    $wardenCertificationSchema = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/hardware-certification.schema.json') | ConvertFrom-Json

    if ($wardenCatalog.schema_version -ne 2) { $wardenErrors.Add('capabilities.json schema_version must be 2') }
    foreach ($wardenContract in @($wardenMetricCatalog, $wardenEventCatalog, $wardenOperationCatalog, $wardenAlertCatalog, $wardenHttpCatalog, $wardenErrorCatalog, $wardenHardwareTargets)) {
        if ($wardenContract.schema_version -ne 1) { $wardenErrors.Add('Detailed contract schema_version must be 1') }
        if ($wardenContract.product_version -ne '0.1.0') { $wardenErrors.Add('Detailed contract product_version must be 0.1.0') }
    }

    $wardenIdPattern = '(SRV|NAS|CORE|ACCESS)-(MON|ACT)-[0-9]{2}'
    $wardenSpecContent = Get-Content -Raw -LiteralPath $wardenSpecPath
    $wardenTraceContent = Get-Content -Raw -LiteralPath $wardenTracePath
    $wardenAdapterContent = Get-Content -Raw -LiteralPath $wardenAdapterPath
    $wardenApiContent = Get-Content -Raw -LiteralPath $wardenApiPath
    $wardenSpecMatches = [regex]::Matches($wardenSpecContent, $wardenIdPattern) | ForEach-Object Value
    $wardenTraceMatches = [regex]::Matches($wardenTraceContent, $wardenIdPattern) | ForEach-Object Value
    $wardenSpecIds = @($wardenSpecMatches | Sort-Object -Unique)
    $wardenTraceIds = @($wardenTraceMatches | Sort-Object -Unique)
    $wardenCatalogIds = @($wardenCatalog.requirements | ForEach-Object id | Sort-Object -Unique)

    if ($wardenSpecIds.Count -ne 51) { $wardenErrors.Add("PROJECT_SPEC must contain 51 unique source requirements; found $($wardenSpecIds.Count)") }
    if ($wardenTraceIds.Count -ne 51) { $wardenErrors.Add("TRACEABILITY must contain 51 unique source requirements; found $($wardenTraceIds.Count)") }
    if ($wardenCatalogIds.Count -ne 51) { $wardenErrors.Add("Capability catalog must contain 51 unique source requirements; found $($wardenCatalogIds.Count)") }
    $wardenExpectedSourceIds = @(
        1..8 | ForEach-Object { 'SRV-MON-{0:D2}' -f $_ }
        1..7 | ForEach-Object { 'SRV-ACT-{0:D2}' -f $_ }
        1..6 | ForEach-Object { 'NAS-MON-{0:D2}' -f $_ }
        1..6 | ForEach-Object { 'NAS-ACT-{0:D2}' -f $_ }
        1..6 | ForEach-Object { 'CORE-MON-{0:D2}' -f $_ }
        1..7 | ForEach-Object { 'CORE-ACT-{0:D2}' -f $_ }
        1..5 | ForEach-Object { 'ACCESS-MON-{0:D2}' -f $_ }
        1..6 | ForEach-Object { 'ACCESS-ACT-{0:D2}' -f $_ }
    )
    Add-WardenSetDiff 'Exact 0.1.0 source requirement id set' $wardenExpectedSourceIds $wardenCatalogIds
    $wardenExpectedSourceUrl = 'https://yikongzhijia.feishu.cn/wiki/Y84PwLxSIiAlxGk15m8cEBWRn7d?fromScene=spaceOverview'
    if ($wardenCatalog.source_url -ne $wardenExpectedSourceUrl) { $wardenErrors.Add('Capability catalog source_url changed from the 0.1.0 Feishu source') }
    $wardenSourceSnapshotPath = Join-Path $wardenRoot $wardenCatalog.source_snapshot
    if (-not (Test-Path -LiteralPath $wardenSourceSnapshotPath -PathType Leaf)) { $wardenErrors.Add('Capability source snapshot path is missing') }
    else {
        $wardenSnapshotHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $wardenSourceSnapshotPath).Hash.ToLowerInvariant()
        if ($wardenCatalog.source_snapshot_sha256 -ne $wardenSnapshotHash) { $wardenErrors.Add("Source snapshot hash mismatch: expected $($wardenCatalog.source_snapshot_sha256) actual $wardenSnapshotHash") }
    }
    Test-WardenUnique 'PROJECT_SPEC source requirement' $wardenSpecMatches
    Test-WardenUnique 'Capability catalog requirement id' @($wardenCatalog.requirements | ForEach-Object id)
    Add-WardenSetDiff 'PROJECT_SPEC/TRACEABILITY requirement set' $wardenSpecIds $wardenTraceIds
    Add-WardenSetDiff 'PROJECT_SPEC/capability requirement set' $wardenSpecIds $wardenCatalogIds

    $wardenTraceLines = $wardenTraceContent -split "`r?`n"
    $wardenMetricRefs = [System.Collections.Generic.List[string]]::new()
    $wardenEventRefs = [System.Collections.Generic.List[string]]::new()
    $wardenOperationRefs = [System.Collections.Generic.List[string]]::new()

    foreach ($wardenRequirement in $wardenCatalog.requirements) {
        $wardenTraceRowPrefix = "| ``$($wardenRequirement.id)`` |"
        $wardenTraceRows = @($wardenTraceLines | Where-Object { $_.StartsWith($wardenTraceRowPrefix) })
        if ($wardenTraceRows.Count -ne 1) { $wardenErrors.Add("Requirement must have exactly one traceability row: $($wardenRequirement.id)") }
        $wardenExpectedTestId = "T-$($wardenRequirement.id)"
        if ($wardenTraceRows.Count -eq 1 -and -not $wardenTraceRows[0].Contains("``$wardenExpectedTestId``")) { $wardenErrors.Add("Traceability row lacks stable test suite id: $($wardenRequirement.id) $wardenExpectedTestId") }
        if ($wardenRequirement.id -match '-MON-' -and $wardenRequirement.kind -ne 'monitoring') { $wardenErrors.Add("MON requirement has wrong kind: $($wardenRequirement.id)") }
        if ($wardenRequirement.id -match '-ACT-' -and $wardenRequirement.kind -ne 'operation') { $wardenErrors.Add("ACT requirement has wrong kind: $($wardenRequirement.id)") }
        $wardenExpectedDeviceType = if ($wardenRequirement.id -like 'SRV-*') { 'server' } elseif ($wardenRequirement.id -like 'NAS-*') { 'synology_nas' } elseif ($wardenRequirement.id -like 'CORE-*') { 'core_switch' } else { 'access_switch' }
        if ($wardenRequirement.device_type -ne $wardenExpectedDeviceType) { $wardenErrors.Add("Requirement device_type mismatch: $($wardenRequirement.id) expected=$wardenExpectedDeviceType") }
        if ([string]::IsNullOrWhiteSpace($wardenRequirement.title)) { $wardenErrors.Add("Requirement lacks title: $($wardenRequirement.id)") }

        if ($wardenRequirement.kind -eq 'monitoring') {
            $wardenMetrics = @($wardenRequirement.metrics | Where-Object { $_ })
            $wardenEvents = @($wardenRequirement.events | Where-Object { $_ })
            if (($wardenMetrics.Count + $wardenEvents.Count) -eq 0) { $wardenErrors.Add("Monitoring requirement lacks metrics/events: $($wardenRequirement.id)") }
            foreach ($wardenMetric in $wardenMetrics) {
                if ($wardenMetric -like 'event.*') { $wardenErrors.Add("Event key incorrectly stored as metric: $($wardenRequirement.id) $wardenMetric") }
                $wardenMetricRefs.Add($wardenMetric)
                if ($wardenTraceRows.Count -eq 1 -and -not $wardenTraceRows[0].Contains("``$wardenMetric``")) { $wardenErrors.Add("Traceability row lacks metric: $($wardenRequirement.id) $wardenMetric") }
                if (-not $wardenAdapterContent.Contains($wardenMetric)) { $wardenErrors.Add("Adapter design lacks metric: $($wardenRequirement.id) $wardenMetric") }
            }
            foreach ($wardenEvent in $wardenEvents) {
                if ($wardenEvent -notlike 'event.*') { $wardenErrors.Add("Event key lacks event prefix: $($wardenRequirement.id) $wardenEvent") }
                $wardenEventRefs.Add($wardenEvent)
                if ($wardenTraceRows.Count -eq 1 -and -not $wardenTraceRows[0].Contains("``$wardenEvent``")) { $wardenErrors.Add("Traceability row lacks event: $($wardenRequirement.id) $wardenEvent") }
                if (-not $wardenAdapterContent.Contains($wardenEvent)) { $wardenErrors.Add("Adapter design lacks event: $($wardenRequirement.id) $wardenEvent") }
            }
        }

        if ($wardenRequirement.kind -eq 'operation') {
            if (@($wardenRequirement.operations).Count -eq 0) { $wardenErrors.Add("Operation requirement lacks operations: $($wardenRequirement.id)") }
            foreach ($wardenOperation in $wardenRequirement.operations) {
                if ($wardenOperation.risk -notin @('low', 'medium', 'high')) { $wardenErrors.Add("Invalid operation risk: $($wardenRequirement.id) $($wardenOperation.key)") }
                $wardenProfileId = "$($wardenRequirement.id):$($wardenOperation.key)"
                $wardenOperationRefs.Add($wardenProfileId)
                if ($wardenTraceRows.Count -eq 1 -and -not $wardenTraceRows[0].Contains("``$($wardenOperation.key)``")) { $wardenErrors.Add("Traceability row lacks operation: $wardenProfileId") }
                if (-not $wardenAdapterContent.Contains($wardenOperation.key)) { $wardenErrors.Add("Adapter design lacks operation: $wardenProfileId") }
            }
        }
    }

    $wardenMetricDefinitions = @($wardenMetricCatalog.definitions | ForEach-Object key)
    $wardenEventDefinitions = @($wardenEventCatalog.definitions | ForEach-Object key)
    $wardenOperationProfileIds = @($wardenOperationCatalog.profiles | ForEach-Object id)
    Test-WardenUnique 'Metric definition key' $wardenMetricDefinitions
    Test-WardenUnique 'Event definition key' $wardenEventDefinitions
    Test-WardenUnique 'Operation profile id' $wardenOperationProfileIds
    Add-WardenSetDiff 'Metric reference/definition set' @($wardenMetricRefs) $wardenMetricDefinitions
    Add-WardenSetDiff 'Event reference/definition set' @($wardenEventRefs) $wardenEventDefinitions
    Add-WardenSetDiff 'Operation reference/profile set' @($wardenOperationRefs) $wardenOperationProfileIds

    foreach ($wardenMetric in $wardenMetricCatalog.definitions) {
        if ($wardenMetric.value_type -notin @('number', 'integer', 'boolean', 'enum')) { $wardenErrors.Add("Invalid metric value_type: $($wardenMetric.key)") }
        if ($wardenMetric.scope -notin @('device', 'component')) { $wardenErrors.Add("Invalid metric scope: $($wardenMetric.key)") }
        if ([string]::IsNullOrWhiteSpace($wardenMetric.series)) { $wardenErrors.Add("Metric lacks series semantic: $($wardenMetric.key)") }
        if ([string]::IsNullOrWhiteSpace($wardenMetric.alert_policy)) { $wardenErrors.Add("Metric lacks alert policy: $($wardenMetric.key)") }
        if ($wardenMetric.value_type -eq 'enum') {
            if (-not $wardenMetric.enum_set -or -not $wardenMetricCatalog.enum_sets.PSObject.Properties[$wardenMetric.enum_set]) { $wardenErrors.Add("Metric enum_set missing: $($wardenMetric.key)") }
        }
    }

    $wardenAlertSelectors = @($wardenAlertCatalog.rules | ForEach-Object selector | ForEach-Object { $_ -split '\|' } | Sort-Object -Unique)
    foreach ($wardenPolicy in @($wardenMetricCatalog.definitions | ForEach-Object alert_policy | Sort-Object -Unique | Where-Object { $_ -ne 'none' })) {
        if ($wardenPolicy -notin $wardenAlertSelectors) { $wardenErrors.Add("Metric alert policy lacks rule: $wardenPolicy") }
    }
    Test-WardenUnique 'Alert rule key' @($wardenAlertCatalog.rules | ForEach-Object rule_key)
    Add-WardenSetDiff '0.1.0 current-problem rule set' @('device.offline','device.health','data.expired','status.problem') @($wardenAlertCatalog.rules | ForEach-Object rule_key)
    $wardenAllowedAlertOutcomes = @($wardenAlertCatalog.value_outcomes)
    $wardenCompositePolicies = @($wardenAlertCatalog.composite_policies | ForEach-Object alert_policy)
    Test-WardenUnique 'Composite alert policy' $wardenCompositePolicies
    foreach ($wardenComposite in @($wardenAlertCatalog.composite_policies)) {
        if ($wardenComposite.alert_policy -notin $wardenAlertSelectors) { $wardenErrors.Add("Composite alert policy lacks rule selector: $($wardenComposite.alert_policy)") }
        foreach ($wardenMetricKey in @($wardenComposite.required_metric_keys)) {
            if ($wardenMetricKey -notin $wardenMetricDefinitions) { $wardenErrors.Add("Composite alert policy references unknown metric: $($wardenComposite.alert_policy) $wardenMetricKey") }
        }
        if ($wardenComposite.unknown_behavior -ne 'no_decision') { $wardenErrors.Add("Composite alert unknown behavior must be no_decision: $($wardenComposite.alert_policy)") }
    }
    foreach ($wardenMetric in @($wardenMetricCatalog.definitions | Where-Object { $_.value_type -eq 'enum' -and $_.alert_policy -ne 'none' -and $_.alert_policy -notin $wardenCompositePolicies })) {
        $wardenMaps = @($wardenAlertCatalog.enum_value_maps | Where-Object { $_.alert_policy -eq $wardenMetric.alert_policy -and $_.enum_set -eq $wardenMetric.enum_set })
        if ($wardenMaps.Count -ne 1) { $wardenErrors.Add("Enum alert map must be unique: $($wardenMetric.key) policy=$($wardenMetric.alert_policy) enum=$($wardenMetric.enum_set)") }
        else {
            $wardenEnumValues = @($wardenMetricCatalog.enum_sets.PSObject.Properties[$wardenMetric.enum_set].Value)
            $wardenMappedValues = @($wardenMaps[0].values.PSObject.Properties.Name)
            Add-WardenSetDiff "Enum alert values $($wardenMetric.alert_policy)/$($wardenMetric.enum_set)" $wardenEnumValues $wardenMappedValues
            foreach ($wardenOutcome in @($wardenMaps[0].values.PSObject.Properties.Value)) {
                if ($wardenOutcome -notin $wardenAllowedAlertOutcomes) { $wardenErrors.Add("Invalid enum alert outcome: $($wardenMetric.key) $wardenOutcome") }
            }
        }
    }
    foreach ($wardenMetric in @($wardenMetricCatalog.definitions | Where-Object { $_.value_type -eq 'boolean' -and $_.alert_policy -ne 'none' })) {
        $wardenMaps = @($wardenAlertCatalog.boolean_value_maps | Where-Object alert_policy -eq $wardenMetric.alert_policy)
        if ($wardenMaps.Count -ne 1) { $wardenErrors.Add("Boolean alert map must be unique: $($wardenMetric.key) policy=$($wardenMetric.alert_policy)") }
        else {
            Add-WardenSetDiff "Boolean alert values $($wardenMetric.alert_policy)" @('true','false') @($wardenMaps[0].values.PSObject.Properties.Name)
            foreach ($wardenOutcome in @($wardenMaps[0].values.PSObject.Properties.Value)) {
                if ($wardenOutcome -notin $wardenAllowedAlertOutcomes) { $wardenErrors.Add("Invalid boolean alert outcome: $($wardenMetric.key) $wardenOutcome") }
            }
        }
    }
    $wardenPoeTotalPower = $wardenMetricCatalog.definitions | Where-Object key -eq 'poe.total_power_w'
    $wardenPoeTotalPercent = $wardenMetricCatalog.definitions | Where-Object key -eq 'poe.total_power_percent'
    $wardenPoeTotalAlarm = $wardenMetricCatalog.definitions | Where-Object key -eq 'poe.total_power_alarm'
    if ($wardenPoeTotalPower.alert_policy -ne 'none' -or $wardenPoeTotalPercent.alert_policy -ne 'none' -or $wardenPoeTotalAlarm.alert_policy -ne 'status') { $wardenErrors.Add('PoE total alarm must come from explicit alarm state; watt and percent metrics are display-only') }
    foreach ($wardenForbiddenMetricAlertPolicy in @('device_threshold','capacity','utilization','increase','admin_oper_mismatch','poe_budget')) {
        if ($wardenForbiddenMetricAlertPolicy -in @($wardenMetricCatalog.definitions | ForEach-Object alert_policy)) { $wardenErrors.Add("Out-of-scope metric alert policy found: $wardenForbiddenMetricAlertPolicy") }
    }
    foreach ($wardenForbiddenAlertRule in @('sensor.threshold','capacity.usage','utilization.high','counter.increase','interface.admin_oper_mismatch','poe.budget')) {
        if ($wardenForbiddenAlertRule -in @($wardenAlertCatalog.rules | ForEach-Object rule_key)) { $wardenErrors.Add("Out-of-scope alert rule found: $wardenForbiddenAlertRule") }
    }
    foreach ($wardenNumericAlertMetric in @($wardenMetricCatalog.definitions | Where-Object { $_.value_type -in @('number','integer') -and $_.alert_policy -ne 'none' })) {
        $wardenErrors.Add("Numeric metric must be display-only without source alarm semantics: $($wardenNumericAlertMetric.key)")
    }
    if (@($wardenAlertCatalog.rules | Where-Object source -eq 'event').Count -gt 0) { $wardenErrors.Add('Device log events must not be promoted into current-problem rules') }

    foreach ($wardenProfile in $wardenOperationCatalog.profiles) {
        $wardenRequirement = $wardenCatalog.requirements | Where-Object id -eq $wardenProfile.requirement_id
        $wardenSourceOperation = @($wardenRequirement.operations | Where-Object key -eq $wardenProfile.key)
        if ($wardenSourceOperation.Count -ne 1) { $wardenErrors.Add("Operation profile source mismatch: $($wardenProfile.id)") }
        elseif ($wardenSourceOperation[0].risk -ne $wardenProfile.risk) { $wardenErrors.Add("Operation profile risk mismatch: $($wardenProfile.id)") }
        if ($wardenRequirement.device_type -ne $wardenProfile.device_type) { $wardenErrors.Add("Operation profile device_type mismatch: $($wardenProfile.id)") }
        $wardenExpectedProfileId = "$($wardenProfile.requirement_id):$($wardenProfile.key)"
        if ($wardenProfile.id -ne $wardenExpectedProfileId) { $wardenErrors.Add("Operation profile id must equal requirement:key: $($wardenProfile.id)") }
        if ($wardenProfile.channel -notin @('task', 'launch')) { $wardenErrors.Add("Invalid operation channel: $($wardenProfile.id)") }
        if ($wardenProfile.timeout_seconds -le 0) { $wardenErrors.Add("Operation timeout must be positive: $($wardenProfile.id)") }
        if ($wardenProfile.parameter_schema.type -ne 'object' -or $wardenProfile.parameter_schema.additionalProperties -ne $false) { $wardenErrors.Add("Operation schema must be closed object: $($wardenProfile.id)") }
        foreach ($wardenRequiredParameter in @($wardenProfile.parameter_schema.required | Where-Object { $_ })) {
            if (-not $wardenProfile.parameter_schema.properties.PSObject.Properties[$wardenRequiredParameter]) { $wardenErrors.Add("Operation required parameter lacks property definition: $($wardenProfile.id) $wardenRequiredParameter") }
        }
        if (@($wardenProfile.preconditions).Count -eq 0) { $wardenErrors.Add("Operation profile lacks preconditions: $($wardenProfile.id)") }
        if ([string]::IsNullOrWhiteSpace($wardenProfile.conflict_scope)) { $wardenErrors.Add("Operation profile lacks conflict_scope: $($wardenProfile.id)") }
        if ($wardenProfile.cancel_policy -notin @('before_dispatch_only', 'adapter_declared_before_device_job', 'not_applicable')) { $wardenErrors.Add("Invalid cancel_policy: $($wardenProfile.id)") }
        if ([string]::IsNullOrWhiteSpace($wardenProfile.verification.strategy) -or [string]::IsNullOrWhiteSpace($wardenProfile.verification.success) -or [string]::IsNullOrWhiteSpace($wardenProfile.verification.ambiguous)) { $wardenErrors.Add("Operation profile lacks complete verification: $($wardenProfile.id)") }
        if ($wardenProfile.risk -eq 'high' -and ($wardenProfile.channel -ne 'task' -or $wardenProfile.side_effect -ne $true)) { $wardenErrors.Add("High-risk profile must be side-effect task: $($wardenProfile.id)") }
        if ($wardenProfile.channel -eq 'launch') {
            if ($wardenProfile.side_effect -ne $false -or $wardenProfile.risk -ne 'medium' -or $wardenProfile.key -notlike 'console.*' -or $wardenProfile.cancel_policy -ne 'not_applicable') { $wardenErrors.Add("Launch profile must be medium-risk non-side-effect console with non-applicable cancellation: $($wardenProfile.id)") }
        }
        if ($wardenProfile.channel -eq 'task' -and $wardenProfile.cancel_policy -eq 'not_applicable') { $wardenErrors.Add("Task profile must define a cancellation boundary: $($wardenProfile.id)") }
    }

    $wardenEndpointKeys = @($wardenHttpCatalog.endpoints | ForEach-Object { "$($_.method) $($_.path)" })
    $wardenOperationIds = @($wardenHttpCatalog.endpoints | ForEach-Object operation_id)
    Test-WardenUnique 'HTTP endpoint method/path' $wardenEndpointKeys
    Test-WardenUnique 'OpenAPI operationId' $wardenOperationIds
    if ($wardenEndpointKeys.Count -ne 50) { $wardenErrors.Add("0.1.0 endpoint whitelist must contain 50 endpoints; found $($wardenEndpointKeys.Count)") }
    foreach ($wardenEndpoint in $wardenHttpCatalog.endpoints) {
        if ($wardenEndpoint.method -notin @('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'SSE', 'WS')) { $wardenErrors.Add("Invalid HTTP/SSE/WS method: $($wardenEndpoint.method) $($wardenEndpoint.path)") }
        if ($wardenEndpoint.support_id -notmatch '^PLT-0[1-9]$') { $wardenErrors.Add("HTTP endpoint lacks valid platform support id: $($wardenEndpoint.method) $($wardenEndpoint.path)") }
        if (-not $wardenApiContent.Contains($wardenEndpoint.path)) { $wardenErrors.Add("API_CONTRACT lacks HTTP contract path: $($wardenEndpoint.path)") }
    }

    $wardenTargetIds = @($wardenHardwareTargets.targets | ForEach-Object target_id)
    Test-WardenUnique 'Hardware target id' $wardenTargetIds
    if ($wardenTargetIds.Count -ne 10) { $wardenErrors.Add("Hardware targets must contain the 10 source targets; found $($wardenTargetIds.Count)") }
    $wardenExpectedTargetCounts = @{ server = 5; synology_nas = 2; core_switch = 2; access_switch = 1 }
    foreach ($wardenDeviceType in $wardenExpectedTargetCounts.Keys) {
        $wardenActualTargetCount = @($wardenHardwareTargets.targets | Where-Object device_type -eq $wardenDeviceType).Count
        if ($wardenActualTargetCount -ne $wardenExpectedTargetCounts[$wardenDeviceType]) { $wardenErrors.Add("Hardware target count mismatch: $wardenDeviceType expected=$($wardenExpectedTargetCounts[$wardenDeviceType]) actual=$wardenActualTargetCount") }
    }
    foreach ($wardenTarget in $wardenHardwareTargets.targets) {
        if ($wardenTarget.device_type -notin @('server', 'synology_nas', 'core_switch', 'access_switch')) { $wardenErrors.Add("Invalid hardware target device_type: $($wardenTarget.target_id)") }
        if ([string]::IsNullOrWhiteSpace($wardenTarget.adapter_key) -or [string]::IsNullOrWhiteSpace($wardenTarget.declared_target)) { $wardenErrors.Add("Hardware target lacks adapter/declared target: $($wardenTarget.target_id)") }
        if ($wardenTarget.exact_model_must_be_recorded -ne $true) { $wardenErrors.Add("Hardware target must require actual model evidence: $($wardenTarget.target_id)") }
        if (-not $wardenAdapterContent.Contains($wardenTarget.adapter_key)) { $wardenErrors.Add("Adapter design lacks hardware target adapter_key: $($wardenTarget.adapter_key)") }
    }
    $wardenSchemaTargetIds = @($wardenCertificationSchema.'$defs'.record.properties.target_id.enum)
    Add-WardenSetDiff 'Hardware target/schema enum set' $wardenTargetIds $wardenSchemaTargetIds
    if ($wardenCertificationSchema.properties.schema_version.const -ne 1 -or $wardenCertificationSchema.properties.product_version.const -ne '0.1.0') { $wardenErrors.Add('Hardware certification schema version constants are invalid') }
    $wardenExpectedCertificationRecords = 0
    foreach ($wardenTarget in $wardenHardwareTargets.targets) {
        foreach ($wardenRequirement in @($wardenCatalog.requirements | Where-Object device_type -eq $wardenTarget.device_type)) {
            $wardenExpectedCertificationRecords += @($wardenRequirement.metrics | Where-Object { $_ }).Count + @($wardenRequirement.events | Where-Object { $_ }).Count + @($wardenRequirement.operations | Where-Object { $_ }).Count
        }
    }
    if ($wardenExpectedCertificationRecords -ne 306) { $wardenErrors.Add("Hardware certification coverage must currently be 306 records; found $wardenExpectedCertificationRecords") }

    $wardenActiveArchitecture = @(
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/ARCHITECTURE.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DATA_MODEL.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DEPLOYMENT.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/RISK_REGISTER.md')
    ) -join "`n"
    foreach ($wardenInventedCapacityTerm in @('100 台设备', '30,000', '500 GiB', '3.024 亿', '2.592 亿', '1.296 亿')) {
        if ($wardenActiveArchitecture.Contains($wardenInventedCapacityTerm)) { $wardenErrors.Add("Invented fixed capacity baseline found: $wardenInventedCapacityTerm") }
    }
    $wardenArchitectureContent = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/ARCHITECTURE.md')
    $wardenActiveImplementation = @(
        $wardenArchitectureContent
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DATA_MODEL.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/SECURITY.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DEPLOYMENT.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/TEST_STRATEGY.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/IMPLEMENTATION_PLAN.md')
    ) -join "`n"
    foreach ($wardenRemovedMiddleware in @('Celery', 'Redis', 'task_outbox')) {
        if ($wardenActiveImplementation.Contains($wardenRemovedMiddleware)) { $wardenErrors.Add("Unnecessary middleware remains in active implementation design: $wardenRemovedMiddleware") }
    }
    if (-not $wardenArchitectureContent.Contains('FOR UPDATE SKIP LOCKED')) { $wardenErrors.Add('Architecture must define PostgreSQL row-lock task claiming') }
    foreach ($wardenRemovedEndpoint in @('/system/collection-settings', '/system/maintenance-mode', '/metrics')) {
        if ($wardenRemovedEndpoint -in @($wardenHttpCatalog.endpoints | ForEach-Object path)) { $wardenErrors.Add("Out-of-scope endpoint remains: $wardenRemovedEndpoint") }
    }
    $wardenDeploymentContent = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DEPLOYMENT.md')
    foreach ($wardenForbiddenBackupImplementation in @('pg_basebackup', 'pg_combinebackup', 'backup gate', 'restore point', '| `backup` |', 'RPO：', 'RTO：')) {
        if ($wardenDeploymentContent.Contains($wardenForbiddenBackupImplementation)) { $wardenErrors.Add("Out-of-scope database backup implementation found: $wardenForbiddenBackupImplementation") }
    }
    foreach ($wardenBackupEndpoint in @($wardenHttpCatalog.endpoints | Where-Object { $_.path -match 'backup|restore-point|disaster-recovery' })) {
        $wardenErrors.Add("Out-of-scope database backup endpoint found: $($wardenBackupEndpoint.method) $($wardenBackupEndpoint.path)")
    }

    $wardenErrorCodes = @($wardenErrorCatalog.errors | ForEach-Object code)
    Test-WardenUnique 'Stable error code' $wardenErrorCodes
    foreach ($wardenError in $wardenErrorCatalog.errors) {
        if ($wardenError.http_status -notin @(400, 401, 403, 404, 409, 412, 422, 429, 500, 503)) { $wardenErrors.Add("Invalid error HTTP status: $($wardenError.code)") }
        if ($wardenError.retry_class -notin @('never', 'after_user_action', 'read_backoff', 'retry_after', 'verification_only')) { $wardenErrors.Add("Invalid retry class: $($wardenError.code)") }
    }
    foreach ($wardenAdapterError in @('network_unreachable','tls_validation_failed','authentication_failed','permission_denied_by_device','protocol_error','unsupported_capability','not_configured','device_busy','validation_failed','rate_limited','operation_failed','ambiguous_result')) {
        if ($wardenAdapterError -notin $wardenErrorCodes) { $wardenErrors.Add("Adapter error missing from error catalog: $wardenAdapterError") }
    }

    $wardenAllDesign = @(
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/PRODUCT_DESIGN.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DATA_MODEL.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/API_CONTRACT.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DEVICE_ADAPTERS.md')
        Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'contracts/capabilities.json')
    ) -join "`n"
    foreach ($wardenForbidden in @('power.force_restart', 'shared_folder.usage_bytes', 'acknowledged', 'pending_confirmation')) {
        if ($wardenAllDesign.Contains($wardenForbidden)) { $wardenErrors.Add("Forbidden obsolete/conflicting term found: $wardenForbidden") }
    }
    foreach ($wardenRequiredCorrection in @('shared_folder.usage_percent', 'poe.power_budget_w', 'poe.total_power_percent', 'poe.total_power_alarm')) {
        if (-not $wardenAllDesign.Contains($wardenRequiredCorrection)) { $wardenErrors.Add("Required source-coverage correction missing: $wardenRequiredCorrection") }
    }

    foreach ($wardenPattern in @('\brack_id\b', '\broom_id\b', '\bsite_id\b', '/tickets', '/notifications')) {
        if ($wardenAllDesign -match $wardenPattern) { $wardenErrors.Add("Potential scope-drift contract found: $wardenPattern") }
    }
    foreach ($wardenRemovedActiveTerm in @('``auditor``', 'task_outbox', 'entry_hash', '/audit-heads/')) {
        if ($wardenAllDesign.Contains($wardenRemovedActiveTerm)) { $wardenErrors.Add("Removed over-design remains in active contract: $wardenRemovedActiveTerm") }
    }
    if (-not $wardenAllDesign.Contains('每个用户恰有一个角色枚举')) { $wardenErrors.Add('Active data model must keep one fixed role per user') }

    $wardenApprovedDocs = @(
        'docs/README.md', 'docs/SOURCE_BASELINE.md', 'docs/PROJECT_SPEC.md', 'docs/PRODUCT_DESIGN.md',
        'docs/UI_SPEC.md', 'docs/ARCHITECTURE.md', 'docs/DEVICE_ADAPTERS.md', 'docs/DATA_MODEL.md',
        'docs/API_CONTRACT.md', 'docs/SECURITY.md', 'docs/DEPLOYMENT.md', 'docs/TEST_STRATEGY.md', 'docs/HARDWARE_CERTIFICATION.md',
        'docs/IMPLEMENTATION_PLAN.md', 'docs/DEVELOPMENT_PLAYBOOK.md', 'docs/TRACEABILITY.md',
        'docs/GLOSSARY.md', 'docs/RISK_REGISTER.md', 'docs/ADVERSARIAL_REVIEW.md', 'docs/BLUEPRINT_AUDIT.md'
    )
    foreach ($wardenRelativePath in $wardenApprovedDocs) {
        if ((Get-Content -Raw -LiteralPath (Join-Path $wardenRoot $wardenRelativePath)) -notmatch 'APPROVED_BASELINE') { $wardenErrors.Add("Approved design document lacks APPROVED_BASELINE status: $wardenRelativePath") }
    }

    $wardenAdrContent = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'docs/DECISION_LOG.md')
    $wardenAdrIds = [regex]::Matches($wardenAdrContent, 'ADR-[0-9]{3}') | ForEach-Object Value
    Test-WardenUnique 'ADR identifier' $wardenAdrIds

    $wardenAgentsContent = Get-Content -Raw -LiteralPath (Join-Path $wardenRoot 'AGENTS.md')
    foreach ($wardenContractName in @('capabilities.json', 'metrics.json', 'events.json', 'operations.json', 'alert-rules.json', 'http-api.json', 'error-codes.json', 'hardware-targets.json', 'hardware-certification.schema.json', 'DEVELOPMENT_PLAYBOOK.md')) {
        if (-not $wardenAgentsContent.Contains($wardenContractName)) { $wardenErrors.Add("AGENTS.md reading order lacks: $wardenContractName") }
    }
}

if ($wardenErrors.Count -gt 0) {
    Write-Error ("Design validation failed:`n- " + ($wardenErrors -join "`n- "))
    exit 1
}

Write-Output 'Design validation passed.'
Write-Output 'Source requirements: 51'
Write-Output "Metric definitions: $($wardenMetricCatalog.definitions.Count)"
Write-Output "Event definitions: $($wardenEventCatalog.definitions.Count)"
Write-Output "Operation profiles: $($wardenOperationCatalog.profiles.Count)"
Write-Output "HTTP/SSE/WS endpoints: $($wardenHttpCatalog.endpoints.Count)"
Write-Output "Stable error codes: $($wardenErrorCatalog.errors.Count)"
Write-Output "Hardware targets: $($wardenHardwareTargets.targets.Count)"
Write-Output "Hardware certification records required: $wardenExpectedCertificationRecords"
Write-Output "Required files: $($wardenRequiredFiles.Count)"
