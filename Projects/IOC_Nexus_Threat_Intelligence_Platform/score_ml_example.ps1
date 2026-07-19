$ErrorActionPreference = "Stop"
.\.venv\Scripts\python.exe -m ioc_nexus.ml_score `
    --model artifacts\ml\model_bundle.joblib `
    --input examples\model_incident.json
