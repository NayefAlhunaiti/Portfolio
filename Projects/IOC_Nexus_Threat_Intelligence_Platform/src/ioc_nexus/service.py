from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .internal_store import InternalStore
from .models import AnalysisResult, IncidentInput
from .risk_engine import calculate_risk
from .validator import classify_indicator
from .vt_client import VirusTotalClient


class IOCNexusService:
    def __init__(
        self,
        *,
        mock_vt: bool = False,
        records_path: str | Path = "data/enrichment_records.jsonl",
    ) -> None:
        self.store = InternalStore()
        self.vt = VirusTotalClient(mock=mock_vt)
        self.records_path = Path(records_path)

    def analyze(self, incident: IncidentInput) -> AnalysisResult:
        ioc = classify_indicator(incident.external_ip)
        vt_report = self.vt.lookup(ioc)
        context = self.store.get_context(
            incident.internal_ip,
            incident.external_ip,
        )
        risk = calculate_risk(incident, vt_report, context)

        result = AnalysisResult(
            incident=incident,
            ioc=ioc,
            virustotal=vt_report,
            internal_context=context,
            risk=risk,
            analyzed_at=datetime.now(timezone.utc),
        )
        self._save_record(result)
        return result

    def _save_record(self, result: AnalysisResult) -> None:
        self.records_path.parent.mkdir(parents=True, exist_ok=True)
        with self.records_path.open("a", encoding="utf-8") as handle:
            handle.write(result.model_dump_json() + "\n")
