# References:
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path
# - https://learn.microsoft.com/en-us/powershell/
[CmdletBinding(SupportsShouldProcess)]
# Define required inputs and optional execution controls.
param(
    [Parameter(Mandatory)] [ValidateSet('Quarantine','Restore')] [string]$Action,
    [Parameter(Mandatory)] [string]$RunId,
    [Parameter(Mandatory)] [string]$TargetPath,
    [Parameter(Mandatory)] [string]$EvidenceRoot,
    [switch]$ValidateOnly
)
# Detect undeclared variables and other unsafe PowerShell usage.
Set-StrictMode -Version 2.0
# Convert non-terminating errors into stop conditions.
$ErrorActionPreference = 'Stop'
# Load the shared EDR laboratory helper module.
Import-Module (Join-Path $PSScriptRoot 'EDRLab.Common.psm1') -Force
$approvedWorkRoot = [System.IO.Path]::GetFullPath((Join-Path 'C:\EDR_LAB\Work' $RunId))
$approvedEvidenceRoot = Assert-EDRPath -Path $EvidenceRoot
$targetFull = [System.IO.Path]::GetFullPath($TargetPath)
$quarantineRoot = Assert-EDRPath -Path (Join-Path 'C:\EDR_LAB\Quarantine' $RunId)
New-Item -ItemType Directory -Path $quarantineRoot -Force | Out-Null
$manifestPath = Join-Path $approvedEvidenceRoot 'response-manifest.json'
# Confirm that a response target remains inside the approved run directory.
function Test-ApprovedTarget([string]$Candidate) {
    return ($Candidate.StartsWith($approvedWorkRoot + '\',[StringComparison]::OrdinalIgnoreCase) -or
        $Candidate.Equals($approvedWorkRoot,[StringComparison]::OrdinalIgnoreCase))
}
if ($Action -eq 'Quarantine') {
    if (-not (Test-ApprovedTarget -Candidate $targetFull)) {
        throw 'Response refused because the target is outside the approved run work directory.'
    }
    if (-not (Test-Path -LiteralPath $targetFull)) { throw "Target does not exist: $targetFull" }
    $targetItem = Get-Item -LiteralPath $targetFull
    if ($targetItem.PSIsContainer) { throw 'The restricted response test accepts one file, not a directory.' }
    $destination = Join-Path $quarantineRoot $targetItem.Name
    if (Test-Path -LiteralPath $destination) { throw "Quarantine destination already exists: $destination" }
    $sourceLength = $targetItem.Length
    $beforeWorkCount = @(Get-ChildItem -LiteralPath $approvedWorkRoot -Recurse -File -ErrorAction SilentlyContinue).Count
    $beforeQuarantineCount = @(Get-ChildItem -LiteralPath $quarantineRoot -Recurse -File -ErrorAction SilentlyContinue).Count
    $start = [datetime]::UtcNow
    if ($ValidateOnly) {
        $manifest = [ordered]@{
            run_id=$RunId; action='Quarantine'; source=$targetFull; destination=$destination
            source_length_bytes=$sourceLength; start_utc=$start.ToString('o'); end_utc=[datetime]::UtcNow.ToString('o')
            validation_only=$true; executed=$false; validation_passed=$true
            incorrect_objects_affected=0; success=$true
        }
        Write-EDRJson -InputObject $manifest -Path $manifestPath
        $manifest | ConvertTo-Json -Depth 8
        return
    }
    $executed = $false
    if ($PSCmdlet.ShouldProcess($targetFull,"Move to $destination")) {
        Move-Item -LiteralPath $targetFull -Destination $destination
        $executed = $true
    }
    if (-not $executed) {
        $manifest = [ordered]@{
            run_id=$RunId; action='Quarantine'; source=$targetFull; destination=$destination
            source_length_bytes=$sourceLength; start_utc=$start.ToString('o'); end_utc=[datetime]::UtcNow.ToString('o')
            validation_only=$false; executed=$false; validation_passed=$true
            incorrect_objects_affected=0; success=$true; note='WhatIf or declined ShouldProcess; no move was executed.'
        }
        Write-EDRJson -InputObject $manifest -Path $manifestPath
        $manifest | ConvertTo-Json -Depth 8
        return
    }
    $afterWorkCount = @(Get-ChildItem -LiteralPath $approvedWorkRoot -Recurse -File -ErrorAction SilentlyContinue).Count
    $afterQuarantineCount = @(Get-ChildItem -LiteralPath $quarantineRoot -Recurse -File -ErrorAction SilentlyContinue).Count
    $destinationLength = if(Test-Path -LiteralPath $destination){(Get-Item -LiteralPath $destination).Length}else{-1}
    $incorrect = [math]::Max(0, [math]::Abs(($beforeWorkCount - 1) - $afterWorkCount) + [math]::Abs(($beforeQuarantineCount + 1) - $afterQuarantineCount))
    $success = (-not (Test-Path -LiteralPath $targetFull) -and (Test-Path -LiteralPath $destination) -and $destinationLength -eq $sourceLength -and $incorrect -eq 0)
    $manifest = [ordered]@{
        run_id=$RunId; action='Quarantine'; source=$targetFull; destination=$destination
        source_length_bytes=$sourceLength; destination_length_bytes=$destinationLength
        start_utc=$start.ToString('o'); end_utc=[datetime]::UtcNow.ToString('o')
        validation_only=$false; executed=$true; validation_passed=$true
        before_work_file_count=$beforeWorkCount; after_work_file_count=$afterWorkCount
        before_quarantine_file_count=$beforeQuarantineCount; after_quarantine_file_count=$afterQuarantineCount
        incorrect_objects_affected=$incorrect; success=$success
    }
    Write-EDRJson -InputObject $manifest -Path $manifestPath
    $manifest | ConvertTo-Json -Depth 8
    if (-not $success) { throw 'Restricted-response validation failed.' }
}
else {
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'No response manifest exists for restoration.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if (-not $manifest.executed) { throw 'The quarantine action was not executed, so there is nothing to restore.' }
    $source = [string]$manifest.source
    $destination = [string]$manifest.destination
    if (-not (Test-ApprovedTarget -Candidate $source)) { throw 'Restore refused because the original path is outside the approved run directory.' }
    if (-not (Test-Path -LiteralPath $destination)) { throw 'Quarantined object is missing.' }
    $parent = Split-Path -Parent $source
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    if (Test-Path -LiteralPath $source) { throw 'Restore refused because the original path is occupied.' }
    $start = [datetime]::UtcNow
    if ($PSCmdlet.ShouldProcess($destination,"Restore to $source")) {
        Move-Item -LiteralPath $destination -Destination $source
    }
    else {
        throw 'Restore was not executed.'
    }
    $restoredLength = (Get-Item -LiteralPath $source).Length
    $success = (Test-Path -LiteralPath $source) -and $restoredLength -eq [long]$manifest.source_length_bytes
    $result = [ordered]@{
        run_id=$RunId; action='Restore'; source=$destination; destination=$source
        restored_length_bytes=$restoredLength; start_utc=$start.ToString('o'); end_utc=[datetime]::UtcNow.ToString('o')
        incorrect_objects_affected=0; success=$success
    }
    Write-EDRJson -InputObject $result -Path (Join-Path $approvedEvidenceRoot 'response-rollback.json')
    $result | ConvertTo-Json -Depth 8
    if (-not $success) { throw 'Restricted response or restoration failed.' }
}
