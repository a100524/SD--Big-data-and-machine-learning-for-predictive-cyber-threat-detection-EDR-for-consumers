# References:
# - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
# - https://osquery.readthedocs.io/en/stable/deployment/logging/
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json
# - https://learn.microsoft.com/en-us/powershell/
# - https://scikit-learn.org/stable/common_pitfalls.html
[CmdletBinding()]
# Define required inputs and optional execution controls.
param(
    [Parameter(Mandatory)] [ValidateSet('B1','B2','B3','S1','S2','S3')] [string]$Family,
    [Parameter(Mandatory)] [ValidateSet('V1','V2')] [string]$Variant,
    [ValidateRange(1,4)] [int]$Phase = 1,
    [int]$WindowSeconds = 30,
    [Parameter(Mandatory)] [string]$PythonExe,
    [Parameter(Mandatory)] [string]$PredictScript,
    [Parameter(Mandatory)] [string]$ModelPath,
    [Parameter(Mandatory)] [string]$MetadataPath,
    [Parameter(Mandatory)] [string]$BenignReferencePath
)
# Detect undeclared variables and other unsafe PowerShell usage.
Set-StrictMode -Version 2.0
# Convert non-terminating errors into stop conditions.
$ErrorActionPreference = 'Stop'
# Load the shared EDR laboratory helper module.
Import-Module (Join-Path $PSScriptRoot 'EDRLab.Common.psm1') -Force
$runId = 'LIVE-{0}-{1}-{2}' -f $Family,$Variant,(Get-Date -Format 'yyyyMMddHHmmss')
$evidenceRoot = Assert-EDRPath -Path (Join-Path 'C:\EDR_LAB\Evidence\Live' $runId)
$workRoot = Assert-EDRPath -Path (Join-Path 'C:\EDR_LAB\Work' $runId)
New-Item -ItemType Directory -Path $evidenceRoot,$workRoot -Force | Out-Null
$actionLog = Join-Path $evidenceRoot 'action-log.jsonl'
# Read osquery process snapshots and return timestamped process counts.
function Read-OsqueryProcessSnapshots {
    # Define required inputs and optional execution controls.
    param([string]$Path)
    $output = @()
    Get-Content -LiteralPath $Path -ErrorAction Stop | ForEach-Object {
        if (-not $_.Trim()) { return }
        try { $row = $_ | ConvertFrom-Json } catch { return }
        if ($row.name -ne 'edr_processes') { return }
        if ($null -eq $row.unixTime) { return }
        $timestamp = [DateTimeOffset]::FromUnixTimeSeconds([long]$row.unixTime).UtcDateTime
        if ($null -ne $row.snapshot) { $count = @($row.snapshot).Count }
        elseif ($null -ne $row.columns) { $count = 1 }
        else { return }
        $output += [pscustomobject]@{ timestamp=$timestamp; count=$count }
    }
    return $output | Sort-Object timestamp
}
# Return the nearest available snapshot count for the requested UTC time.
function Get-NearestSnapshotCount {
    # Define required inputs and optional execution controls.
    param([object[]]$Snapshots,[datetime]$BoundaryUtc,[int]$ToleranceSeconds=35)
    $candidate = $Snapshots | Where-Object { $_.timestamp -le $BoundaryUtc } | Select-Object -Last 1
    if (-not $candidate) { return $null }
    if (($BoundaryUtc - $candidate.timestamp).TotalSeconds -gt $ToleranceSeconds) { return $null }
    return [int]$candidate.count
}
$startUtc = [datetime]::UtcNow
$scenarioJob = Start-Job -ScriptBlock {
    # Define required inputs and optional execution controls.
    param($script,$family,$variant,$phase,$runId,$workRoot,$actionLog)
    Start-Sleep -Seconds 2
    & $script -Family $family -Variant $variant -Phase $phase -RunId $runId -WorkRoot $workRoot -ActionLogPath $actionLog
} -ArgumentList (Join-Path $PSScriptRoot 'Invoke-EDRLabScenario.ps1'),$Family,$Variant,$Phase,$runId,$workRoot,$actionLog
Start-Sleep -Seconds $WindowSeconds
$endUtc = [datetime]::UtcNow
Receive-Job -Job $scenarioJob -Wait -AutoRemoveJob | Out-Null
$events = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    StartTime=$startUtc.ToLocalTime()
    EndTime=$endUtc.ToLocalTime()
} -Oldest | ForEach-Object {
    [xml]$xml = $_.ToXml()
    $data = @{}
    foreach ($entry in $xml.Event.EventData.Data) { $data[[string]$entry.Name] = [string]$entry.'#text' }
    [pscustomobject]@{ event_id=[int]$xml.Event.System.EventID; data=$data }
}
$processes = @($events | Where-Object event_id -eq 1)
$network = @($events | Where-Object event_id -eq 3)
$images = @($processes | ForEach-Object { ([string]$_.data.Image).ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
$pairs = @($processes | ForEach-Object {
    ('{0}->{1}' -f ([string]$_.data.ParentImage).ToLowerInvariant(),([string]$_.data.Image).ToLowerInvariant())
} | Sort-Object -Unique)
$destinations = @($network | ForEach-Object {
    '{0}:{1}/{2}' -f $_.data.DestinationIp,$_.data.DestinationPort,([string]$_.data.Protocol).ToLowerInvariant()
} | Sort-Object -Unique)
$snapshots = Read-OsqueryProcessSnapshots -Path 'C:\ProgramData\osquery\log\osqueryd.snapshots.log'
$startCount = Get-NearestSnapshotCount -Snapshots $snapshots -BoundaryUtc $startUtc
$endCount = Get-NearestSnapshotCount -Snapshots $snapshots -BoundaryUtc $endUtc
if ($null -eq $startCount -or $null -eq $endCount) { throw 'No acceptable osquery snapshots were available for the live window.' }
$features = [ordered]@{
    sysmon_process_create_count = $processes.Count
    sysmon_unique_process_image_count = $images.Count
    sysmon_powershell_process_count = @($processes | Where-Object { [IO.Path]::GetFileName([string]$_.data.Image) -in @('powershell.exe','pwsh.exe') }).Count
    sysmon_cmd_process_count = @($processes | Where-Object { [IO.Path]::GetFileName([string]$_.data.Image) -eq 'cmd.exe' }).Count
    sysmon_unique_parent_child_pair_count = $pairs.Count
    sysmon_network_connect_count = $network.Count
    sysmon_unique_destination_count = $destinations.Count
    sysmon_dns_query_count = @($events | Where-Object event_id -eq 22).Count
    sysmon_file_create_count = @($events | Where-Object event_id -eq 11).Count
    sysmon_file_delete_count = @($events | Where-Object event_id -eq 26).Count
    sysmon_registry_event_count = @($events | Where-Object { $_.event_id -in @(12,13,14) }).Count
    osquery_process_count_delta = $endCount - $startCount
}
$inputPath = Join-Path $evidenceRoot 'live-feature-vector.json'
$outputPath = Join-Path $evidenceRoot 'live-alert.json'
Write-EDRJson -InputObject $features -Path $inputPath
& $PythonExe $PredictScript --model $ModelPath --metadata $MetadataPath --benign-reference $BenignReferencePath --input-json $inputPath --output-json $outputPath
if ($LASTEXITCODE -ne 0) { throw 'Prediction failed.' }
& (Join-Path $PSScriptRoot 'Invoke-EDRLabRollback.ps1') -RunId $runId -EvidenceRoot $evidenceRoot
Get-Content -LiteralPath $outputPath
