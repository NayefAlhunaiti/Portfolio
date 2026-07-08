# SAP Ariba Procurement Copilot

SAP Ariba Procurement Copilot is a local-first assistant for procurement teams. It serves a browser chat UI, answers SAP Ariba and SAP procurement workflow questions from local policy files, and keeps Ariba write-back simulated unless you explicitly enable a real adapter.

## Highlights

- Browser-based procurement copilot with local HTTP endpoints
- SAP Ariba knowledge routing from curated files in `policies/`
- Ollama-first chat generation with configurable model settings
- Simulated Ariba execution flow for safe demos and testing
- MCP-compatible stdio server for agent/tool integrations
- Local ML utilities for EDA, embeddings, retrieval, training, and validation
- Tests covering SAP Ariba knowledge routing behavior

## Project Structure

- `app.py` - HTTP server, chat UI, routing, sessions, audit logging, training, and validation endpoints
- `ui.html` - single-page browser interface
- `mcp_server.py` - MCP-compatible JSON-RPC stdio server
- `ariba_adapter.py` - safe-by-default SAP Ariba adapter shim
- `policies/` - local SAP Ariba, SAP documentation, transaction-code, and policy knowledge
- `data/raw/` - original downloaded SAP Ariba datasets and archives
- `tools/build_master_knowledge.py` - reproducible merge script for the integrated SAP Ariba knowledge base
- `ml_pipeline/` - optional local ML training, EDA, retrieval, and validation scripts
- `tests/` - focused regression tests
- `dataset.txt` and `train_pairs.tsv` - small sample data for local experiments

## What Is Not Committed

Generated and machine-local files are intentionally excluded from GitHub:

- Python virtual environments: `.venv/`
- Runtime logs: `audit.log`, `ariba_simulator.log`, `server.*.log`
- Saved browser/API sessions: `sessions/`
- Trained model binaries and checkpoints: `models/`, `checkpoints/`
- Python caches: `__pycache__/`

Recreate these locally from the setup steps below.

## Knowledge Base

The chatbot uses `policies/sap_ariba_master_knowledge.json` as the main deduplicated SAP Ariba support source. It is generated from the raw downloaded datasets plus the previous local knowledge base.

Regenerate it after adding or changing raw data:

```powershell
python tools\build_master_knowledge.py
```

The active policy set also keeps:

- `sap_ariba_knowledge.json` for high-priority local intent routing
- `sap_ariba_abbreviations.json` for SAP Ariba and procurement abbreviations such as PO, PR, RFQ, RFX, CIG, cXML, SLP, ASN, SES, GR, SBN, and ambiguous tenant-specific acronyms such as CRO
- `sap_tcodes.json` for SAP GUI/S/4HANA transaction-code guidance
- `sap_official_docs.json` for official SAP reference links

## Setup

From this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install and start Ollama, then pull the model configured in `config.json`:

```powershell
ollama pull llama3.2:1b
```

To use a different local model, update:

- `ollama_base_url`
- `ollama_model`
- `temperature`
- `ollama_request_timeout`

## Run

```powershell
python app.py
```

Open the local URL printed by the server, then use the browser UI to ask SAP Ariba procurement questions.

Useful endpoints:

- `GET /health`
- `POST /procurement/chat`
- `POST /procurement/assist`
- `POST /procurement/execute`
- `POST /procurement/train`
- `POST /procurement/validate`
- `POST /procurement/eda`
- `POST /procurement/ariba/webhook`
- `POST /procurement/session/clear`
- `GET /procurement/session/{session_id}`

Example chat payload:

```json
{
  "role": "procurement_manager",
  "message": "Classify this requisition and identify policy risks.",
  "context": "Purchase request for office laptops with budget approval attached."
}
```

## MCP Server

Run the MCP-compatible stdio server when another system needs tool access:

```powershell
python mcp_server.py
```

It exposes procurement chat, execution, EDA, training, and validation tools over standard JSON-RPC framing.

## Ariba Safety

`ariba_adapter.py` is safe by default. It writes simulated actions to `ariba_simulator.log` and does not call a real SAP Ariba tenant unless both config flags are enabled:

- `ariba_enabled=true`
- `allow_ariba_calls=true`

Only point `ariba_base_url` at a real internal endpoint when you are ready to make live calls.

## Optional ML Workflow

Install the ML extras:

```powershell
python -m pip install -r ml_pipeline/ml_requirements.txt
```

Then run EDA, retrieval, training, or validation from `ml_pipeline/README.md`. Local model outputs should be written to `models/` or `checkpoints/`, which are ignored by Git.

## Tests

```powershell
python -m unittest discover tests
```
