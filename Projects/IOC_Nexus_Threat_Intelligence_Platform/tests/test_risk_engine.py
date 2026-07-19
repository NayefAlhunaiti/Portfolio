from datetime import datetime

from ioc_nexus.models import (
    IncidentInput,
    InternalAsset,
    InternalContext,
    VTReport,
)
from ioc_nexus.risk_engine import calculate_risk


def test_suspicious_whitelist_collision_scores_high():
    incident = IncidentInput(
        internal_ip="10.20.5.14",
        external_ip="1.1.1.1",
        process_name="powershell.exe",
        parent_process="winword.exe",
        username="finance.user",
        timestamp=datetime.fromisoformat("2026-07-15T02:34:00"),
        destination_port=443,
        bytes_sent=9_500_000,
        whitelisted_process=True,
    )
    vt = VTReport(
        queried=True,
        indicator_type="ip",
        indicator="1.1.1.1",
        found=True,
        malicious=8,
        suspicious=2,
        reputation=-10,
    )
    context = InternalContext(
        asset=InternalAsset(
            ip="10.20.5.14",
            hostname="FIN-PC-014",
            department="Finance",
            asset_criticality="high",
            expected_work_hours={"start": 7, "end": 18},
        ),
        first_seen_in_company=True,
    )

    result = calculate_risk(incident, vt, context)

    assert result.risk_score >= 85
    assert result.severity == "critical"
    assert result.whitelist_collision is True
