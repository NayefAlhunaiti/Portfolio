$ErrorActionPreference = "Stop"
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Error "Virtual environment not found. Run .\setup_windows.ps1 first."
}
.\.venv\Scripts\python.exe -m pip install -r requirements-ml.txt
.\.venv\Scripts\python.exe -m ioc_nexus.ml_pipeline `
    --dataset data\generated\synthetic_soc_incidents.csv `
    --output-dir artifacts\ml
Write-Host "ML model and metrics created in artifacts\ml" -ForegroundColor Green
