from __future__ import annotations

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

from .models import IncidentInput
from .smart_service import SmartAnalysisService


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description=(
            "Run IOC enrichment, rule analysis, and ML severity scoring together."
        )
    )
    parser.add_argument("--incident", required=True)
    parser.add_argument("--model", default="artifacts/ml/model_bundle.joblib")
    parser.add_argument("--mock-vt", action="store_true")
    args = parser.parse_args()

    payload = json.loads(Path(args.incident).read_text(encoding="utf-8"))
    incident = IncidentInput.model_validate(payload)

    result = SmartAnalysisService(
        mock_vt=args.mock_vt,
        model_path=args.model,
    ).analyze(incident)

    print(json.dumps(result.model_dump(mode="json"), indent=2, default=str))


if __name__ == "__main__":
    main()
