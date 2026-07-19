from __future__ import annotations

import json
from pathlib import Path

from .models import InternalAsset, InternalContext


class InternalStore:
    def __init__(
        self,
        assets_path: str | Path = "data/internal_assets.json",
        events_path: str | Path = "data/internal_events.json",
    ) -> None:
        self.assets_path = Path(assets_path)
        self.events_path = Path(events_path)

    @staticmethod
    def _read_json(path: Path, default):
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return default

    def get_context(self, internal_ip: str, external_ip: str) -> InternalContext:
        assets = self._read_json(self.assets_path, [])
        events = self._read_json(self.events_path, [])

        asset_data = next(
            (item for item in assets if item.get("ip") == internal_ip),
            {
                "ip": internal_ip,
                "hostname": "unregistered",
                "department": "unknown",
                "asset_criticality": "medium",
                "owner": "unknown",
                "operating_system": "unknown",
                "expected_work_hours": {"start": 7, "end": 18},
            },
        )

        matches = [
            event
            for event in events
            if event.get("external_ip", event.get("external_indicator", "")).lower()
            == external_ip.lower()
        ]

        unique_hosts = {
            event.get("internal_ip") for event in matches if event.get("internal_ip")
        }
        unique_users = {
            event.get("username") for event in matches if event.get("username")
        }

        return InternalContext(
            asset=InternalAsset.model_validate(asset_data),
            previous_contacts=len(matches),
            affected_internal_hosts=len(unique_hosts),
            affected_internal_users=len(unique_users),
            first_seen_in_company=len(matches) == 0,
            total_historical_bytes_sent=sum(
                int(event.get("bytes_sent", 0)) for event in matches
            ),
        )
