$ErrorActionPreference = "Stop"
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { Write-Error "Virtual environment not found." }
.\.venv\Scripts\python.exe -m ioc_nexus.collector --mock-vt
