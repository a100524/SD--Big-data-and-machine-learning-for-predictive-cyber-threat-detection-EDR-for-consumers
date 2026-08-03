# References:
# - https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html
# - https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-agent-configuration/windows-endpoint.html
# - https://docs.python.org/3/library/venv.html
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/import-csv
[CmdletBinding()]
# Define required inputs and optional execution controls.
param([Parameter(Mandatory)][string]$ScheduleCsv,[ValidateSet('Pilot','Formal')][string]$Mode,[int]$StartAtSequence=1,[int]$StopAfter=0,[string]$ManagementHost='10.50.0.10',[string]$ManagementUser='edradmin',[string]$EndpointShareRoot='\\10.50.0.10\edr-share\VM-endpoint',[string]$ShareScheduleRoot='\\10.50.0.10\edr-share\schedules\executed')
# Detect undeclared variables and other unsafe PowerShell usage.
Set-StrictMode -Version 2.0
# Convert non-terminating errors into stop conditions.
$ErrorActionPreference='Stop'
# Load the shared EDR laboratory helper module.
Import-Module (Join-Path $PSScriptRoot 'EDRLab.Common.psm1') -Force
$ScheduleCsv=Assert-EDRPath -Path $ScheduleCsv
if(-not(Test-Path -LiteralPath $ScheduleCsv)){throw "Schedule not found: $ScheduleCsv"}
$rows=@(Import-Csv -LiteralPath $ScheduleCsv|Sort-Object {[int]$_.sequence_number})
foreach($row in $rows){foreach($property in @('central_status','central_completed_utc','central_error')){if(-not($row.PSObject.Properties.Name -contains $property)){$row|Add-Member -MemberType NoteProperty -Name $property -Value ''}}}
# Save the current in-memory schedule rows to the schedule CSV.
function Save-Schedule{Write-EDRAtomicCsv -Rows $rows -Path $ScheduleCsv}
$completed=0
foreach($row in $rows){
    $sequence=[int]$row.sequence_number
    if($sequence -lt $StartAtSequence -or $row.central_status -eq 'sealed'){continue}
    & (Join-Path $PSScriptRoot 'Invoke-EDRLabSchedule.ps1') -ScheduleCsv $ScheduleCsv -Mode $Mode -StartAtSequence $sequence -StopAfter 1 -ManagementHost $ManagementHost
    $rows=@(Import-Csv -LiteralPath $ScheduleCsv|Sort-Object {[int]$_.sequence_number})
    $row=$rows|Where-Object {[int]$_.sequence_number -eq $sequence}|Select-Object -First 1
    foreach($property in @('central_status','central_completed_utc','central_error')){if(-not($row.PSObject.Properties.Name -contains $property)){$row|Add-Member -MemberType NoteProperty -Name $property -Value ''}}
    if($row.status -ne 'completed'){throw "Endpoint run did not complete at sequence $sequence."}
    $row.central_status='copying';Save-Schedule
    try{
        & (Join-Path $PSScriptRoot 'Send-EDRLabRunToManagement.ps1') -RunId $row.planned_run_id -EndpointShareRoot $EndpointShareRoot
        $remote="${ManagementUser}@${ManagementHost}"
        $command="set -euo pipefail; source ~/.config/edr-lab/wazuh.env; source ~/edr-ml/.venv/bin/activate; python ~/edr-lab/mgmt/complete_run.py --run-id '$($row.planned_run_id)' --expected-mode '$Mode'"
        & ssh.exe $remote "bash -lc `"$command`""
        if($LASTEXITCODE -ne 0){throw 'Central and sensor evidence completion failed.'}
        $row.central_status='sealed';$row.central_completed_utc=[datetime]::UtcNow.ToString('o');$row.central_error=''
    }catch{$row.central_status='failed';$row.central_error=$_.Exception.Message;Save-Schedule;throw}
    Save-Schedule
    New-Item -ItemType Directory -Path $ShareScheduleRoot -Force|Out-Null
    Copy-Item -LiteralPath $ScheduleCsv -Destination (Join-Path $ShareScheduleRoot ([IO.Path]::GetFileName($ScheduleCsv))) -Force
    $completed++
    if($StopAfter -gt 0 -and $completed -ge $StopAfter){break}
}
Write-Host "Controlled schedule completed or resumed successfully. Newly sealed runs: $completed" -ForegroundColor Green
