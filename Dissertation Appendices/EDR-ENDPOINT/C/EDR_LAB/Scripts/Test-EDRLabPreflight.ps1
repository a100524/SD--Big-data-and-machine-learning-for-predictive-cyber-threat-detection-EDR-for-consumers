# References:
# - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
# - https://osquery.readthedocs.io/en/stable/deployment/configuration/
# - https://osquery.readthedocs.io/en/stable/deployment/logging/
# - https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html
[CmdletBinding()]
# Define required inputs and optional execution controls.
param([string]$ManagementHost='10.50.0.10',[string]$SensorHost='10.50.0.20',[string]$AttackHost='10.50.0.40',[string]$OutputPath='C:\EDR_LAB\Evidence\preflight.json',[double]$MaximumClockOffsetSeconds=0.5,[string]$ShareRoot='\\10.50.0.10\edr-share',[switch]$RequireInternetIsolation)
# Detect undeclared variables and other unsafe PowerShell usage.
Set-StrictMode -Version 2.0
# Convert non-terminating errors into stop conditions.
$ErrorActionPreference='Stop'
# Load the shared EDR laboratory helper module.
Import-Module (Join-Path $PSScriptRoot 'EDRLab.Common.psm1') -Force
$checks=New-Object System.Collections.Generic.List[object]
# Append one named preflight result to the check collection.
function Add-Check([string]$Name,[bool]$Passed,[string]$Details){$checks.Add([pscustomobject]@{name=$Name;passed=$Passed;details=$Details})}
$services=@(@{Display='Sysmon';Names=@('Sysmon64','Sysmon')},@{Display='osquery';Names=@('osqueryd')},@{Display='Wazuh';Names=@('WazuhSvc')},@{Display='Velociraptor';Names=@('Velociraptor')},@{Display='HyperVTime';Names=@('vmictimesync')})
foreach($item in $services){$service=$null;foreach($name in $item.Names){$service=Get-Service -Name $name -ErrorAction SilentlyContinue;if($service){break}};Add-Check "service_$($item.Display)" ($service -and $service.Status -eq 'Running') $(if($service){"$($service.Name):$($service.Status):$($service.StartType)"}else{'not found'})}
$ports=@(@{Name='Wazuh1514';Host=$ManagementHost;Port=1514},@{Name='Wazuh55000';Host=$ManagementHost;Port=55000},@{Name='Velociraptor8000';Host=$ManagementHost;Port=8000},@{Name='Velociraptor8889';Host=$ManagementHost;Port=8889},@{Name='SMB445';Host=$ManagementHost;Port=445},@{Name='CALDERA8888';Host=$AttackHost;Port=8888})
foreach($p in $ports){$r=Test-NetConnection -ComputerName $p.Host -Port $p.Port -InformationLevel Quiet -WarningAction SilentlyContinue;Add-Check "port_$($p.Name)" ([bool]$r) "$($p.Host):$($p.Port)"}
foreach($hostAddress in @($ManagementHost,$SensorHost,$AttackHost)){$reachable=Test-Connection -ComputerName $hostAddress -Count 2 -Quiet -ErrorAction SilentlyContinue;Add-Check "icmp_$($hostAddress.Replace('.','_'))" ([bool]$reachable) $hostAddress}
$drive=Get-PSDrive -Name C;Add-Check 'disk_free_20gb' ($drive.Free -ge 20GB) ("FreeGB={0:N2}" -f ($drive.Free/1GB))
Add-Check 'network_share_available' (Test-Path -LiteralPath $ShareRoot) $ShareRoot
$sysmonLog=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue;Add-Check 'sysmon_log_available' ([bool]$sysmonLog) $(if($sysmonLog){"Records=$($sysmonLog.RecordCount)"}else{'log not found'})
foreach($path in @('C:\Program Files\osquery\osquery.conf','C:\ProgramData\osquery\log\osqueryd.snapshots.log','C:\Program Files (x86)\ossec-agent\ossec.conf')){Add-Check ('path_'+([IO.Path]::GetFileName($path)).Replace('.','_')) (Test-Path -LiteralPath $path) $path}
$ssh=Get-Command ssh.exe -ErrorAction SilentlyContinue;Add-Check 'ssh_command_available' ([bool]$ssh) $(if($ssh){$ssh.Source}else{'ssh.exe not found'})
$t0=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$remoteText=(& ssh.exe -o BatchMode=yes "edradmin@$ManagementHost" 'date +%s.%N' 2>&1|Out-String).Trim();$t1=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$offset=$null
if($LASTEXITCODE -eq 0){$remote=0.0;if([double]::TryParse($remoteText,[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$remote)){$offset=$remote-(($t0+$t1)/2000.0)}}
Add-Check 'clock_offset_within_limit' ($null -ne $offset -and [math]::Abs($offset) -le $MaximumClockOffsetSeconds) $(if($null -ne $offset){"OffsetSeconds=$([math]::Round($offset,6)) Limit=$MaximumClockOffsetSeconds"}else{$remoteText})
$labAddress=Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq '10.50.0.30'|Select-Object -First 1;Add-Check 'lab_address_10_50_0_30' ([bool]$labAddress) $(if($labAddress){"$($labAddress.InterfaceAlias):$($labAddress.IPAddress)/$($labAddress.PrefixLength)"}else{'not configured'})
if($labAddress){$route=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Where-Object InterfaceIndex -eq $labAddress.InterfaceIndex;Add-Check 'no_default_gateway_on_lab_adapter' (-not[bool]$route) $(if($route){($route|Out-String).Trim()}else{'no default route on laboratory adapter'})}else{Add-Check 'no_default_gateway_on_lab_adapter' $false 'Laboratory adapter address 10.50.0.30 is not configured.'}
if($RequireInternetIsolation){$internet=Test-NetConnection -ComputerName '1.1.1.1' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue;Add-Check 'internet_isolated' (-not[bool]$internet) 'Direct TCP test to 1.1.1.1:443 must fail.'}
$passed=-not($checks|Where-Object{-not $_.passed});$result=[ordered]@{checked_utc=[datetime]::UtcNow.ToString('o');endpoint=$env:COMPUTERNAME;passed=$passed;maximum_clock_offset_seconds=$MaximumClockOffsetSeconds;checks=$checks};Write-EDRJson -InputObject $result -Path $OutputPath -Depth 12;$result|ConvertTo-Json -Depth 12
if(-not $passed){throw 'EDR laboratory preflight failed. Review the written JSON report.'}
