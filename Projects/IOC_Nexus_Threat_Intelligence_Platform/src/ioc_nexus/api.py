from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from .ioc_store import IOCStore
from .models import AnalysisResult, CandidateIOC, IncidentInput, IOCDecisionInput, SmartAnalysisResult
from .service import IOCNexusService
from .smart_service import SmartAnalysisService
from .vt_client import has_real_api_key

load_dotenv(); DEFAULT_MODEL_PATH = "artifacts/ml/model_bundle.joblib"
app = FastAPI(
    title="IOC Nexus Threat Intelligence Platform",
    version="1.0.0",
    description="VirusTotal checks public IP addresses only. Local ML detects attack behavior and promotes observed public IPs into candidate IOCs requiring analyst approval.",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>IOC Nexus</title>
      <style>
        :root { color-scheme: dark; font-family: Segoe UI, Arial, sans-serif; }
        body { margin: 0; background: #101418; color: #eef3f7; }
        main { max-width: 920px; margin: 0 auto; padding: 48px 24px; }
        h1 { margin: 0 0 10px; font-size: 34px; }
        p { color: #aeb9c3; line-height: 1.5; }
        .status { display: inline-flex; gap: 8px; align-items: center; margin: 18px 0 30px; color: #9ee6b5; }
        .dot { width: 10px; height: 10px; border-radius: 999px; background: #33d17a; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 14px; }
        a { display: block; padding: 18px; border: 1px solid #2f3b45; border-radius: 8px; color: #eef3f7; text-decoration: none; background: #161c22; }
        a:hover { border-color: #67b7dc; background: #1b242b; }
        strong { display: block; margin-bottom: 6px; }
        code { color: #a6d8ff; }
      </style>
    </head>
    <body>
      <main>
        <h1>IOC Nexus</h1>
        <p>Local threat-intelligence API for IOC review, attack detection, collection status, and analyst decisions.</p>
        <div class="status"><span class="dot"></span><span>API is running</span></div>
        <div class="grid">
          <a href="/health"><strong>Health</strong><code>GET /health</code></a>
          <a href="/model/status"><strong>Model Status</strong><code>GET /model/status</code></a>
          <a href="/collector/status"><strong>Collector Status</strong><code>GET /collector/status</code></a>
          <a href="/collector/results"><strong>Collector Results</strong><code>GET /collector/results</code></a>
          <a href="/iocs"><strong>Candidate IOCs</strong><code>GET /iocs</code></a>
        </div>
      </main>
    </body>
    </html>
    """

@app.get("/health")
def health(): return {"status": "ok", "version": "1.0.0"}

@app.get("/virustotal/status")
def virustotal_status():
    key = (os.getenv("VT_API_KEY") or "").strip()
    configured = has_real_api_key(key)
    return {
        "configured": configured,
        "mode": "real_virustotal" if configured else "not_configured",
        "message": "VirusTotal API key is configured." if configured else "VT_API_KEY is not configured. Real VirusTotal lookups will not run.",
    }

@app.get("/model/status")
def model_status(model_path: str = Query(default=DEFAULT_MODEL_PATH)):
    path = Path(model_path); return {"available": path.exists(), "model_path": str(path), "message": "Dual severity/attack model is ready." if path.exists() else "Model not found. Train locally first."}

@app.post("/analyze", response_model=AnalysisResult)
def analyze(incident: IncidentInput, mock_vt: bool = Query(default=False)): return IOCNexusService(mock_vt=mock_vt).analyze(incident)

@app.post("/detect-attack", response_model=SmartAnalysisResult)
def detect_attack(incident: IncidentInput, mock_vt: bool = Query(default=False), model_path: str = Query(default=DEFAULT_MODEL_PATH)):
    return SmartAnalysisService(mock_vt=mock_vt, model_path=model_path).analyze(incident)

@app.get("/iocs", response_model=list[CandidateIOC])
def list_iocs(status: str = Query(default="candidate", pattern="^(candidate|approved|rejected)$"), limit: int = Query(default=100, ge=1, le=500)):
    return IOCStore().list(status=status, limit=limit)

@app.post("/iocs/{ioc_id}/decision", response_model=CandidateIOC)
def decide_ioc(ioc_id: str, decision: IOCDecisionInput):
    try: return IOCStore().decide(ioc_id, decision)
    except KeyError as exc: raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/collector/status")
def collector_status():
    def count(folder):
        path = Path(folder)
        return len([item for item in path.iterdir() if item.is_file()]) if path.exists() else 0
    results_path = Path("data/collector_results.jsonl")
    result_count = len(results_path.read_text(encoding="utf-8").splitlines()) if results_path.exists() else 0
    return {
        "incoming_files": count("data/incoming_logs"),
        "processed_files": count("data/processed_logs"),
        "failed_files": count("data/failed_logs"),
        "collector_results": result_count,
        "watch_command": "python -m ioc_nexus.collector",
        "live_windows_command": "python -m ioc_nexus.windows_monitor",
    }

@app.get("/collector/results")
def collector_results(limit: int = Query(default=50, ge=1, le=500)):
    path = Path("data/collector_results.jsonl")
    if not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        try: rows.append(__import__("json").loads(line))
        except ValueError: pass
    return list(reversed(rows))
