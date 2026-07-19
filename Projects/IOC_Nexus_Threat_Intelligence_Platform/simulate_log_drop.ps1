$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path "data\incoming_logs" | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
Copy-Item "examples\sysmon_network_events.csv" "data\incoming_logs\sysmon_$stamp.csv"
Write-Host "Sample Sysmon-style log copied into the watched folder." -ForegroundColor Green
