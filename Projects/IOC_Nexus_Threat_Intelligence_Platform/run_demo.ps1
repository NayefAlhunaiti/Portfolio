$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Error "The virtual environment is missing. Run .\setup_windows.ps1 first."
}

& ".\.venv\Scripts\python.exe" -m ioc_nexus.cli --incident "examples\incident_external_ip.json" --mock-vt
