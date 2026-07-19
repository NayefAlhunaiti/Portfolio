from __future__ import annotations

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

from .models import IncidentInput
from .service import IOCNexusService


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Analyze an internal-to-external IOC incident."
    )
    parser.add_argument(
        "--incident",
        required=True,
        help="Path to a JSON incident file.",
    )
    parser.add_argument(
        "--mock-vt",
        action="store_true",
        help="Use a synthetic VirusTotal response.",
    )
    args = parser.parse_args()

    path = Path(args.incident)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        incident = IncidentInput.model_validate(payload)
    except FileNotFoundError:
        raise SystemExit(f"Incident file not found: {path}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"Invalid incident file: {exc}")

    service = IOCNexusService(mock_vt=args.mock_vt)
    result = service.analyze(incident)
    print(json.dumps(result.model_dump(mode="json"), indent=2, default=str))


if __name__ == "__main__":
    main()
