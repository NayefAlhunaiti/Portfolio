$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Error "Virtual environment not found. Run the local setup commands first."
}

if (-not (Test-Path ".\artifacts\ml\model_bundle.joblib")) {
    Write-Error "Trained model not found. Run .\train_ml_model.ps1 first."
}

.\.venv\Scripts\python.exe -m ioc_nexus.smart_cli `
    --incident examples\incident_external_ip.json `
    --model artifacts\ml\model_bundle.joblib `
    --mock-vt
