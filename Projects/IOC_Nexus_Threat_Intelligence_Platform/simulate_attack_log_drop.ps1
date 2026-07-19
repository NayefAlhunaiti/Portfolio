$ErrorActionPreference = "Stop"

$incoming = "data\incoming_logs"
New-Item -ItemType Directory -Force -Path $incoming | Out-Null

$stamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
$path = Join-Path $incoming "attack_simulation_$stamp.csv"
$attackTime = (Get-Date).ToUniversalTime().ToString("o")
$benignTime = (Get-Date).AddSeconds(3).ToUniversalTime().ToString("o")
$simulationId = [guid]::NewGuid().ToString()
$bytesSent = Get-Random -Minimum 25000000 -Maximum 35000000
$connectionCount = Get-Random -Minimum 95 -Maximum 140

@"
SimulationId,SourceIp,DestinationIp,DestinationPort,Image,ParentImage,User,UtcTime,BytesSent,Whitelisted,FailedLogins10m,ConnectionCount10m,UniqueDestinations10m,OutboundBytesRatio,KnownBusinessService
$simulationId,10.20.5.14,45.155.205.233,443,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE,finance.user,$attackTime,$bytesSent,true,2,$connectionCount,3,18.5,false
$simulationId,10.20.5.20,8.8.8.8,443,C:\Program Files\Microsoft\Edge\Application\msedge.exe,C:\Windows\explorer.exe,hr.user,$benignTime,25000,true,0,3,2,1.0,true
"@ | Set-Content -Path $path -Encoding UTF8

Write-Host "Attack simulation log copied into the watched folder: $path" -ForegroundColor Green
Write-Host "Simulation ID: $simulationId" -ForegroundColor Cyan
