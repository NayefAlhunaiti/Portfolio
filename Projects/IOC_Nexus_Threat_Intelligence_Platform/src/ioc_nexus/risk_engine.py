from __future__ import annotations

from .models import IncidentInput, InternalContext, RiskResult, VTReport

SUSPICIOUS_CHAINS = {
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "cmd.exe"),
    ("powershell.exe", "rundll32.exe"),
    ("powershell.exe", "regsvr32.exe"),
    ("powershell.exe", "schtasks.exe"),
}

CRITICALITY_POINTS = {
    "low": 0,
    "medium": 4,
    "high": 10,
    "critical": 16,
}


def calculate_risk(
    incident: IncidentInput,
    vt: VTReport,
    context: InternalContext,
) -> RiskResult:
    score = 0
    reasons: list[str] = []

    if vt.queried and vt.found:
        malicious_points = min(vt.malicious * 5, 35)
        suspicious_points = min(vt.suspicious * 3, 12)
        score += malicious_points + suspicious_points

        if vt.malicious > 0:
            reasons.append(
                f"VirusTotal reported {vt.malicious} malicious and "
                f"{vt.suspicious} suspicious analyses"
            )
        if vt.reputation < 0:
            score += min(abs(vt.reputation), 10)
            reasons.append("VirusTotal reputation is negative")
    elif vt.error:
        reasons.append(f"External enrichment unavailable: {vt.error}")

    asset_points = CRITICALITY_POINTS[context.asset.asset_criticality]
    score += asset_points
    if asset_points >= 10:
        reasons.append(
            f"The internal asset has {context.asset.asset_criticality} criticality"
        )

    whitelist_collision = incident.whitelisted_process and vt.malicious > 0
    if whitelist_collision:
        score += 12
        reasons.append("A whitelisted process contacted an externally flagged indicator")

    chain = (
        (incident.parent_process or "").lower(),
        incident.process_name.lower(),
    )
    if chain in SUSPICIOUS_CHAINS:
        score += 18
        reasons.append(
            f"Suspicious process chain: {chain[0]} -> {chain[1]}"
        )

    work_hours = context.asset.expected_work_hours
    hour = incident.timestamp.hour
    start = work_hours.get("start", 7)
    end = work_hours.get("end", 18)
    if not (start <= hour < end):
        score += 7
        reasons.append("Activity occurred outside the asset's expected working hours")

    if context.first_seen_in_company:
        score += 8
        reasons.append("The destination is new to the internal environment")
    else:
        if context.affected_internal_hosts >= 3:
            score += min(context.affected_internal_hosts * 2, 12)
            reasons.append(
                f"The indicator has been observed on "
                f"{context.affected_internal_hosts} internal hosts"
            )

    if incident.bytes_sent >= 5_000_000:
        score += 8
        reasons.append("Outbound data volume is high for this single event")

    score = min(score, 100)

    if score >= 85:
        severity = "critical"
        action = "Immediately escalate to Tier 2 and preserve endpoint and network evidence"
    elif score >= 60:
        severity = "high"
        action = "Escalate to Tier 2 for prioritized investigation"
    elif score >= 30:
        severity = "medium"
        action = "Tier 1 should validate the user, process, and business purpose"
    else:
        severity = "low"
        action = "Record the enrichment and monitor for additional related activity"

    if not reasons:
        reasons.append("No significant risk signals were identified")

    return RiskResult(
        risk_score=score,
        severity=severity,
        whitelist_collision=whitelist_collision,
        reasons=reasons,
        recommended_action=action,
    )
