# References:
# - https://caldera.readthedocs.io/en/v5.3.0/Plugin-library.html
# - https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection
# - https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process
# - https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path
# - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content
$ErrorActionPreference = "Stop"
# Define the internal CALDERA server, local executable, group, and log paths.
$Server = "http://10.50.0.40:8888"
$AgentDirectory = "C:\ProgramData\EDR_LAB\CALDERA"
$AgentPath = Join-Path $AgentDirectory "sandcat.exe"
$LogPath = Join-Path $AgentDirectory "sandcat-startup.log"
$Group = "edr-lab"
# Create the local agent directory.
New-Item -ItemType Directory -Path $AgentDirectory -Force | Out-Null
# Wait up to five minutes for the internal CALDERA service to answer.
$Deadline = (Get-Date).AddMinutes(5)
do {
    $Ready = Test-NetConnection -ComputerName "10.50.0.40" -Port 8888 -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $Ready) {
        Start-Sleep -Seconds 5
    }
} until ($Ready -or (Get-Date) -ge $Deadline)
if (-not $Ready) {
    throw "CALDERA did not become reachable within five minutes."
}
# Download Sandcat from the internal CALDERA server only when the local file is absent.
if (-not (Test-Path -LiteralPath $AgentPath)) {
    $Client = [System.Net.WebClient]::new()
    try {
        $Client.Headers.Add("platform", "windows")
        $Client.Headers.Add("file", "sandcat.go")
        $Client.DownloadFile("$Server/file/download", $AgentPath)
    }
    finally {
        $Client.Dispose()
    }
}
# Do not start another agent when this executable is already running.
$Existing = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $AgentPath }
if ($Existing) {
    "$(Get-Date -Format o) Sandcat already running." | Add-Content -LiteralPath $LogPath
    exit 0
}
# Start Sandcat in the fixed group and record the startup action.
$Arguments = "-server $Server -group $Group"
Start-Process -FilePath $AgentPath -ArgumentList $Arguments -WindowStyle Hidden
"$(Get-Date -Format o) Started Sandcat with $Arguments" | Add-Content -LiteralPath $LogPath
