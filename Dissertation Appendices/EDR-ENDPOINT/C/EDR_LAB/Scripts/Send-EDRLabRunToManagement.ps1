# References:
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item
[CmdletBinding()]
# Define required inputs and optional execution controls.
param([Parameter(Mandatory)][string]$RunId,[string]$EndpointShareRoot='\\10.50.0.10\edr-share\VM-endpoint')
# Detect undeclared variables and other unsafe PowerShell usage.
Set-StrictMode -Version 2.0
# Convert non-terminating errors into stop conditions.
$ErrorActionPreference='Stop'
# Load the shared EDR laboratory helper module.
Import-Module (Join-Path $PSScriptRoot 'EDRLab.Common.psm1') -Force
if($RunId -notmatch '^[A-Za-z0-9._-]+$'){throw 'RunId contains unsupported characters.'}
$runDirectory=Assert-EDRPath -Path (Join-Path 'C:\EDR_LAB\Evidence\Runs' $RunId)
if(-not(Test-Path -LiteralPath $runDirectory -PathType Container)){throw "Run directory not found: $runDirectory"}
$manifestPath=Join-Path $runDirectory 'manifest-complete.json'
if(-not(Test-Path -LiteralPath $manifestPath)){throw 'Completion manifest is missing.'}
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
if($manifest.status -ne 'completed'){throw "Run status is $($manifest.status), not completed."}
if(-not(Test-Path -LiteralPath $EndpointShareRoot -PathType Container)){throw "Network share is unavailable: $EndpointShareRoot"}
$partial=Join-Path $EndpointShareRoot "$RunId.partial"
$destination=Join-Path $EndpointShareRoot $RunId
if(Test-Path -LiteralPath $partial){Remove-Item -LiteralPath $partial -Recurse -Force}
if(Test-Path -LiteralPath $destination){throw "Destination already exists: $destination"}
Copy-Item -LiteralPath $runDirectory -Destination $partial -Recurse
if(-not(Test-Path -LiteralPath (Join-Path $partial 'manifest-complete.json'))){throw 'Network-share copy verification failed.'}
Move-Item -LiteralPath $partial -Destination $destination
[pscustomobject]@{run_id=$RunId;copied_utc=[datetime]::UtcNow.ToString('o');source=$runDirectory;destination=$destination;status='copied'}|Format-List
