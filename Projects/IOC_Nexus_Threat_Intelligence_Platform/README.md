# IOC Nexus Threat Intelligence Platform

IOC Nexus is a local Windows-focused threat-intelligence demo for monitoring
public IP connections, enriching them with VirusTotal, running local ML attack
detection, and reviewing candidate IOCs in a Streamlit dashboard.

The project is designed for portfolio and academic use. It does not upload files,
domains, URLs, usernames, or internal IP addresses to VirusTotal. Only public IP
report lookups are sent.

## What it does

1. Normalizes Windows connection, Sysmon-style CSV, JSON, JSONL, and NDJSON logs.
2. Rejects private, loopback, link-local, multicast, and reserved IPs before VT lookup.
3. Checks newly observed public IPs with VirusTotal API v3.
4. Runs local ML severity and attack-type prediction only after VT answers.
5. Caps severity when VirusTotal is clean and local evidence is weak.
6. Creates candidate IOCs automatically for high or critical public-IP events.
7. Requires analyst approval or rejection before an IOC is trusted.
8. Shows detections, monitor activity, VT failures, and IOC review in the dashboard.
9. Includes safe simulation scripts for testing telemetry without performing attacks.

## Project structure

```text
IOC_Nexus_Threat_Intelligence_Platform/
|-- data/
|   |-- internal_assets.json
|   `-- internal_events.json
|-- examples/
|   |-- incident_external_ip.json
|   |-- incident_private_ip.json
|   |-- model_incident.json
|   `-- sysmon_network_events.csv
|-- src/ioc_nexus/
|   |-- api.py
|   |-- collector.py
|   |-- dashboard.py
|   |-- smart_service.py
|   |-- vt_client.py
|   `-- windows_monitor.py
|-- tests/
|-- .env.example
|-- pyproject.toml
|-- requirements.txt
`-- setup_windows.ps1
```

Runtime files are intentionally ignored by Git: `.env`, `.venv`, `artifacts`,
collector result JSONL files, SQLite databases, dropped logs, processed logs,
failed logs, generated training data, caches, and temp files.

## Fast Windows setup

Open PowerShell in the project folder:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_windows.ps1
```

The setup script creates `.venv`, installs dependencies, installs the local
`ioc_nexus` package, verifies the import, and runs the tests.

## Configure VirusTotal

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

Open `.env` and replace the placeholder:

```text
VT_API_KEY=replace_with_your_key
```

Never commit `.env` to GitHub.

## Run the API

```powershell
.\.venv\Scripts\python.exe -m uvicorn ioc_nexus.api:app --host 127.0.0.1 --port 8000
```

Check:

```text
http://127.0.0.1:8000/health
```

## Run the dashboard

```powershell
.\.venv\Scripts\python.exe -m streamlit run .\src\ioc_nexus\dashboard.py
```

Open:

```text
http://localhost:8501
```

The dashboard includes:

- Overview metrics
- Windows monitor feed
- Recent detections
- Candidate IOC review
- Raw result inspection
- Delete history button for restarting the demo from a clean state

## Live Windows monitor

Start one monitor process only:

```powershell
.\.venv\Scripts\python.exe -m ioc_nexus.windows_monitor --interval 16
```

The monitor checks each newly observed public IP/process/port tuple once, keeps a
10-minute duplicate suppression window, logs VT failures, and retries failed VT
lookups on a later cycle.

For an offline UI demo only:

```powershell
.\.venv\Scripts\python.exe -m ioc_nexus.windows_monitor --interval 16 --mock-vt
```

Do not use `--mock-vt` when testing real VirusTotal integration.

## Watched folder collector

Start the collector:

```powershell
.\.venv\Scripts\python.exe -m ioc_nexus.collector
```

Drop supported files into:

```text
data\incoming_logs
```

Supported formats:

- CSV
- JSON
- JSONL / NDJSON

Processed files move to `data\processed_logs`. Invalid files move to
`data\failed_logs`. Detection and VT-failure records are appended to
`data\collector_results.jsonl`.

## Simulate test telemetry

This project simulates logs, not real attacks.

Drop the normal sample:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\simulate_log_drop.ps1
```

Drop the attack-style sample:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\simulate_attack_log_drop.ps1
```

Then process current files once:

```powershell
.\.venv\Scripts\python.exe -m ioc_nexus.collector --once
```

The attack simulation creates telemetry shaped like data exfiltration:

- `WINWORD.EXE` spawning `powershell.exe`
- Large outbound byte count
- High outbound ratio
- High connection count
- Public destination IP

If VirusTotal cannot be reached, the collector records `vt_failed` instead of
pretending the event was detected. For a completely offline demo, run the
collector with `--mock-vt`.

## Train the local ML model

Generate synthetic training data:

```powershell
.\generate_synthetic_data.ps1
```

Train the model bundle:

```powershell
.\train_ml_model.ps1
```

Artifacts are written under `artifacts\ml`, which is ignored by Git.

The model is trained on synthetic data and is decision support only. It must not
automatically block IOCs, isolate devices, terminate processes, or change
whitelist rules.

## Run tests

```powershell
.\.venv\Scripts\python.exe -m pytest --basetemp .\.tmp\pytest -p no:cacheprovider
```

## GitHub safety

Before pushing, confirm these stay ignored:

```powershell
git status --short --ignored
git check-ignore -v .env data\collector_results.jsonl data\ioc_registry.db artifacts .venv
```

Only `.env.example` should contain the placeholder key. The real VirusTotal key
belongs in local `.env` only.
