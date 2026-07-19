from __future__ import annotations

import ipaddress

from .models import IOCClassification


def classify_indicator(indicator: str) -> IOCClassification:
    value = indicator.strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return IOCClassification(
            indicator=value,
            indicator_type="unknown",
            globally_queryable=False,
            reason="Only IPv4 or IPv6 addresses are supported by this platform.",
        )

    if ip.is_global:
        reason = "Public globally routable IP address eligible for VirusTotal lookup"
    else:
        reason = (
            "Non-global IP address; analyze it internally and never submit it "
            "to VirusTotal"
        )
    return IOCClassification(
        indicator=value,
        indicator_type="ip",
        globally_queryable=ip.is_global,
        reason=reason,
    )
