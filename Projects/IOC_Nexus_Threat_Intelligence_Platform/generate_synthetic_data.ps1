$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Error "Virtual environment not found. Run .\setup_windows.ps1 first."
}

.\.venv\Scripts\python.exe -m ioc_nexus.synthetic_generator `
    --count 500 `
    --seed 42 `
    --output-dir data\generated

Write-Host ""
Write-Host "Synthetic dataset created in data\generated" -ForegroundColor Green
Write-Host "Open synthetic_summary.json for the class and scenario distributions."
