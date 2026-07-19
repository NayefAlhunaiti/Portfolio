$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Error "Virtual environment not found. Run the local setup commands first."
}

.\.venv\Scripts\python.exe -m uvicorn ioc_nexus.api:app --reload
