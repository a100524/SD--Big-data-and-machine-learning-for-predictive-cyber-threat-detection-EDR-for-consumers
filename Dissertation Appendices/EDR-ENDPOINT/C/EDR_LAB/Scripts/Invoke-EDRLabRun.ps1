# References:
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path
# - https://learn.microsoft.com/en-us/powershell/
# - https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services
[CmdletBinding()]
# Define required inputs and optional execution controls.
param(
    [Parameter(Mandatory)] [ValidateSet('B1','B2','B3','S1','S2','S3')] [string]$Family,
    [Parameter(Mandatory)] [ValidateSet('V1','V2')] [string]$Variant,
    [Parameter(Mandatory)] [string]$SessionId,
    [string]$RunId = '',
    [ValidateSet('Pilot','Formal','Validation')] [string]$Mode = 'Pilot',
    [double]$TimeScale = 1.0,
    [string]$ManagementHost = '10.50.0.10',
    [string]$SensorHost = '10.50.0.20',
    [string]$AttackHost = '10.50.0.40',
    [string]$CalderaUri = 'http://10.50.0.40:8888',
    [switch]$SkipPreflight,
    [switch]$SkipRollback
)
# Detect undeclared variables and other unsafe PowerShell usage.
Set-StrictMode -Version 2.0
# Convert non-terminating errors into stop conditions.
$ErrorActionPreference = 'Stop'
# Load the shared EDR laboratory helper module.
Import-Module (Join-Path $PSScriptRoot 'EDRLab.Common.psm1') -Force
if ($Mode -eq 'Formal' -and [math]::Abs($TimeScale - 1.0) -gt 0.0001) {
    throw 'Formal runs require TimeScale 1.0.'
}
if ($Mode -eq 'Formal' -and ($SkipPreflight -or $SkipRollback)) {
    throw 'Formal runs cannot skip preflight or rollback.'
}
if ($TimeScale -le 0 -or $TimeScale -gt 1.0) { throw 'TimeScale must be greater than 0 and no greater than 1.0.' }
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = '{0}-{1}-{2}-{3}' -f $SessionId,$Family,$Variant,(Get-Date -Format 'yyyyMMddHHmmss')
}
if ($RunId -notmatch '^[A-Za-z0-9._-]+$') { throw 'RunId contains unsupported characters.' }
$evidenceRoot = Assert-EDRPath -Path (Join-Path 'C:\EDR_LAB\Evidence\Runs' $RunId)
$workRoot = Assert-EDRPath -Path (Join-Path 'C:\EDR_LAB\Work' $RunId)
if (Test-Path -LiteralPath $evidenceRoot) {
    $existing = Get-ChildItem -LiteralPath $evidenceRoot -Force -ErrorAction SilentlyContinue
    if ($existing) { throw "Evidence directory already contains files: $evidenceRoot" }
}
New-Item -ItemType Directory -Path $evidenceRoot,$workRoot -Force | Out-Null
$actionLog = Join-Path $evidenceRoot 'action-log.jsonl'
if (-not $SkipPreflight) {
    & (Join-Path $PSScriptRoot 'Test-EDRLabPreflight.ps1') -ManagementHost $ManagementHost -SensorHost $SensorHost -AttackHost $AttackHost -OutputPath (Join-Path $evidenceRoot 'preflight.json') -RequireInternetIsolation
}
$label = if ($Family.StartsWith('B')) { 0 } else { 1 }
$envelopeStartUtc = [datetime]::UtcNow
$baselineSeconds = [int][math]::Round(60 * $TimeScale)
$phaseSeconds = [int][math]::Round(30 * $TimeScale)
$graceSeconds = [int][math]::Round(60 * $TimeScale)
if ($TimeScale -lt 1.0) {
    $baselineSeconds = [math]::Max(1,$baselineSeconds)
    $phaseSeconds = [math]::Max(1,$phaseSeconds)
    $graceSeconds = [math]::Max(1,$graceSeconds)
}
$scenarioStartUtc = $envelopeStartUtc.AddSeconds($baselineSeconds)
$plannedScenarioEndUtc = $scenarioStartUtc.AddSeconds(4 * $phaseSeconds)
$plannedCollectionEndUtc = $plannedScenarioEndUtc.AddSeconds($graceSeconds)
$scenarioPath = Join-Path $PSScriptRoot 'Invoke-EDRLabScenario.ps1'
$manifestStart = [ordered]@{
    run_id = $RunId
    session_id = $SessionId
    family_id = $Family
    variant_id = $Variant
    scenario_name = "$Family-$Variant"
    label = $label
    mode = $Mode
    endpoint_name = $env:COMPUTERNAME
    protocol_id = 'EDR-MSC-FINAL'
    time_scale = $TimeScale
    envelope_start_utc = $envelopeStartUtc.ToString('o')
    scenario_start_utc = $scenarioStartUtc.ToString('o')
    planned_scenario_end_utc = $plannedScenarioEndUtc.ToString('o')
    planned_collection_end_utc = $plannedCollectionEndUtc.ToString('o')
    active_window_seconds = 30
    active_window_count = 4
}
Write-EDRJson -InputObject $manifestStart -Path (Join-Path $evidenceRoot 'manifest-start.json') -Depth 12
$stopFile = Join-Path $evidenceRoot 'resource-monitor.stop'
$resourceCsv = Join-Path $evidenceRoot 'resource-samples.csv'
$monitor = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Hidden -ArgumentList @(
    '-NoProfile','-ExecutionPolicy','Bypass','-File',
    (Join-Path $PSScriptRoot 'Monitor-EDRLabResources.ps1'),
    '-OutputCsv',$resourceCsv,
    '-StopFile',$stopFile,
    '-IntervalSeconds','5'
)
$status = 'completed'
$errorMessage = ''
$actualScenarioEndUtc = $null
try {
    Wait-EDRUtc -TargetUtc $scenarioStartUtc
    for ($phase = 1; $phase -le 4; $phase++) {
        $phaseStart = $scenarioStartUtc.AddSeconds(($phase - 1) * $phaseSeconds)
        $phaseEnd = $phaseStart.AddSeconds($phaseSeconds)
        Wait-EDRUtc -TargetUtc $phaseStart
        & $scenarioPath -Family $Family -Variant $Variant -Phase $phase -RunId $RunId -WorkRoot $workRoot -ActionLogPath $actionLog -CalderaUri $CalderaUri
        Wait-EDRUtc -TargetUtc $phaseEnd
    }
    $actualScenarioEndUtc = [datetime]::UtcNow
    Wait-EDRUtc -TargetUtc $plannedCollectionEndUtc
}
catch {
    $status = 'failed'
    $errorMessage = $_.Exception.Message
    if ($null -eq $actualScenarioEndUtc) { $actualScenarioEndUtc = [datetime]::UtcNow }
}
finally {
    New-Item -ItemType File -Path $stopFile -Force | Out-Null
    try { Wait-Process -Id $monitor.Id -Timeout 30 -ErrorAction SilentlyContinue } catch { }
}
$actualCollectionEndUtc = [datetime]::UtcNow
$actionRows = @()
if (Test-Path -LiteralPath $actionLog) {
    Get-Content -LiteralPath $actionLog | ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_)) {
            try { $actionRows += ($_ | ConvertFrom-Json -ErrorAction Stop) }
            catch { $status='failed'; $errorMessage="Malformed action log: $($_.Exception.Message)" }
        }
    }
}
$failedActions = @($actionRows | Where-Object status -ne 'completed').Count
if ($actionRows.Count -ne 4 -or $failedActions -ne 0) {
    $status = 'failed'
    if (-not $errorMessage) { $errorMessage = "Expected four completed action-log records; found $($actionRows.Count), failed=$failedActions." }
}
$manifestComplete = [ordered]@{
    run_id = $RunId
    session_id = $SessionId
    family_id = $Family
    variant_id = $Variant
    label = $label
    mode = $Mode
    actual_scenario_end_utc = $actualScenarioEndUtc.ToUniversalTime().ToString('o')
    collection_end_utc = $actualCollectionEndUtc.ToUniversalTime().ToString('o')
    status = $status
    error_count = if ($status -eq 'completed') { 0 } else { 1 }
    error_message = $errorMessage
    action_record_count = $actionRows.Count
    failed_action_count = $failedActions
    expected_window_count = 4
    rollback_required = $true
}
Write-EDRJson -InputObject $manifestComplete -Path (Join-Path $evidenceRoot 'manifest-complete.json') -Depth 10
if ($status -eq 'completed') {
    try {
        & (Join-Path $PSScriptRoot 'Export-EDRLabEndpointEvidence.ps1') -StartUtc $envelopeStartUtc -EndUtc $actualCollectionEndUtc -RunId $RunId -EvidenceRoot $evidenceRoot
    }
    catch {
        $status = 'failed'
        $errorMessage = "Endpoint evidence export failed: $($_.Exception.Message)"
    }
}
if (-not $SkipRollback) {
    try {
        & (Join-Path $PSScriptRoot 'Invoke-EDRLabRollback.ps1') -RunId $RunId -EvidenceRoot $evidenceRoot
    }
    catch {
        $status = 'failed'
        $rollbackMessage = "Rollback failed: $($_.Exception.Message)"
        if ([string]::IsNullOrWhiteSpace($errorMessage)) { $errorMessage = $rollbackMessage }
        else { $errorMessage = "$errorMessage | $rollbackMessage" }
    }
}
$manifestComplete.status = $status
$manifestComplete.error_count = if ($status -eq 'completed') { 0 } else { 1 }
$manifestComplete.error_message = $errorMessage
Write-EDRJson -InputObject $manifestComplete -Path (Join-Path $evidenceRoot 'manifest-complete.json') -Depth 10
[pscustomobject]@{
    run_id = $RunId
    family = $Family
    variant = $Variant
    mode = $Mode
    status = $status
    evidence_root = $evidenceRoot
    actual_scenario_end_utc = $actualScenarioEndUtc.ToUniversalTime().ToString('o')
    collection_end_utc = $actualCollectionEndUtc.ToUniversalTime().ToString('o')
} | Format-List
if ($status -ne 'completed') { throw "Run $RunId failed. Review manifest-complete.json and the run evidence." }
