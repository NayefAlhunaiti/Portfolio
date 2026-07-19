from __future__ import annotations

import os
import time
from typing import Any

import httpx

from .models import IOCClassification, VTReport

PLACEHOLDER_API_KEYS = {"", "replace_with_your_key", "your_api_key_here"}
DEMO_MALICIOUS_IPS = {
    "45.155.205.233",
}


def has_real_api_key(value: str | None) -> bool:
    key = (value or "").strip()
    return bool(key and key not in PLACEHOLDER_API_KEYS)


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str | None = None,
        mock: bool = False,
    ) -> None:
        self.api_key = (api_key or os.getenv("VT_API_KEY") or "").strip()
        self.mock = mock

    def lookup(self, ioc: IOCClassification) -> VTReport:
        if ioc.indicator_type != "ip":
            return VTReport(
                queried=False,
                indicator=ioc.indicator,
                error="VirusTotal integration is restricted to IP addresses only.",
            )
        if not ioc.globally_queryable:
            return VTReport(
                queried=False,
                indicator=ioc.indicator,
                error=ioc.reason,
            )

        if self.mock:
            return self._mock_report(ioc.indicator)

        if not has_real_api_key(self.api_key):
            return VTReport(
                queried=False,
                indicator=ioc.indicator,
                error="VT_API_KEY is not configured.",
            )

        headers = {"x-apikey": self.api_key, "accept": "application/json"}
        try:
            with httpx.Client(timeout=20.0) as client:
                response = client.get(
                    f"{self.BASE_URL}/ip_addresses/{ioc.indicator}",
                    headers=headers,
                )
            if response.status_code == 404:
                return VTReport(queried=True, indicator=ioc.indicator, found=False)
            if response.status_code == 429:
                return VTReport(
                    queried=True,
                    indicator=ioc.indicator,
                    error="VirusTotal rate limit reached.",
                )
            response.raise_for_status()
            return self._parse_report(ioc.indicator, response.json())
        except httpx.TimeoutException:
            return VTReport(
                queried=True,
                indicator=ioc.indicator,
                error="VirusTotal request timed out.",
            )
        except httpx.HTTPStatusError as exc:
            return VTReport(
                queried=True,
                indicator=ioc.indicator,
                error=f"VirusTotal returned HTTP {exc.response.status_code}.",
            )
        except httpx.HTTPError as exc:
            return VTReport(
                queried=True,
                indicator=ioc.indicator,
                error=f"VirusTotal request failed: {exc.__class__.__name__}.",
            )

    @staticmethod
    def _parse_report(ip: str, payload: dict[str, Any]) -> VTReport:
        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        categories_value = attributes.get("categories", {}) or {}
        categories = (
            sorted(set(str(value) for value in categories_value.values()))
            if isinstance(categories_value, dict)
            else []
        )
        return VTReport(
            queried=True,
            indicator=ip,
            found=bool(data),
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            reputation=int(attributes.get("reputation", 0) or 0),
            categories=categories,
            last_analysis_date=attributes.get("last_analysis_date"),
            raw_summary={
                "type": data.get("type"),
                "id": data.get("id"),
                "network": attributes.get("network"),
                "country": attributes.get("country"),
                "as_owner": attributes.get("as_owner"),
            },
        )

    @staticmethod
    def _mock_report(ip: str) -> VTReport:
        if ip not in DEMO_MALICIOUS_IPS:
            return VTReport(
                queried=True,
                source="mock_virustotal",
                indicator=ip,
                found=True,
                malicious=0,
                suspicious=0,
                harmless=60,
                undetected=8,
                reputation=0,
                categories=["mock-clean"],
                last_analysis_date=int(time.time()),
                raw_summary={
                    "note": (
                        "Synthetic clean response. Use a known demo-malicious "
                        "IP only when you intentionally need a mock alert."
                    )
                },
            )

        return VTReport(
            queried=True,
            source="mock_virustotal",
            indicator=ip,
            found=True,
            malicious=5,
            suspicious=2,
            harmless=58,
            undetected=7,
            reputation=-8,
            categories=["demo-ip-reputation"],
            last_analysis_date=int(time.time()),
            raw_summary={"note": "Synthetic IP-only VirusTotal response"},
        )
