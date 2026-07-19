from __future__ import annotations
from pathlib import Path
from typing import Any
from .ioc_store import IOCStore
from .ml_score import score_payload
from .models import AnalysisResult, HybridDecision, IncidentInput, MLAttackPrediction, MLSeverityPrediction, SmartAnalysisResult
from .risk_engine import SUSPICIOUS_CHAINS
from .service import IOCNexusService

SEVERITY_VALUE = {"low": 10, "medium": 40, "high": 70, "critical": 95}
COMMON_BUSINESS_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "code.exe",
    "teams.exe",
    "outlook.exe",
    "onedrive.exe",
    "onedrive.sync.service.exe",
    "runtimebroker.exe",
}
TRUSTED_BINARY_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "schtasks.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
}


def _after(analysis):
    h = analysis.internal_context.asset.expected_work_hours; return not (int(h.get("start", 7)) <= analysis.incident.timestamp.hour < int(h.get("end", 18)))


def build_ml_features(analysis: AnalysisResult) -> dict[str, Any]:
    i, c, vt = analysis.incident, analysis.internal_context, analysis.virustotal
    chain = ((i.parent_process or "").lower(), i.process_name.lower())
    return {
        "department": c.asset.department, "asset_criticality": c.asset.asset_criticality, "indicator_type": "ip",
        "process_name": i.process_name, "parent_process": i.parent_process or "unknown", "destination_port": i.destination_port or 0,
        "bytes_sent": i.bytes_sent, "whitelisted_process": i.whitelisted_process, "vt_malicious_count": vt.malicious,
        "vt_suspicious_count": vt.suspicious, "vt_reputation": vt.reputation, "first_seen_in_company": c.first_seen_in_company,
        "affected_internal_hosts": max(c.affected_internal_hosts, 1), "affected_internal_users": max(c.affected_internal_users, 1),
        "after_hours": _after(analysis), "known_business_service": i.known_business_service, "whitelist_collision": analysis.risk.whitelist_collision,
        "suspicious_process_chain": chain in SUSPICIOUS_CHAINS, "failed_logins_10m": i.failed_logins_10m,
        "connection_count_10m": i.connection_count_10m, "unique_destinations_10m": i.unique_destinations_10m,
        "outbound_bytes_ratio": i.outbound_bytes_ratio,
    }


def _severity_prediction(path, result=None, error=None):
    if error: return MLSeverityPrediction(status="unavailable", model_path=str(path), error=str(error))
    return MLSeverityPrediction(status="available", predicted_severity=result["predicted_severity"], confidence=result["severity_confidence"], probabilities=result["severity_probabilities"], selected_model=result["severity_selected_model"], trained_at=result["trained_at"], model_path=str(path), warning=result["warning"])


def _attack_prediction(path, result=None, error=None):
    if error: return MLAttackPrediction(status="unavailable", model_path=str(path), error=str(error))
    probabilities = result["attack_probabilities"]
    detection_confidence = max(0.0, min(1.0, 1.0 - float(probabilities.get("benign", 0.0))))
    return MLAttackPrediction(status="available", predicted_attack=result["predicted_attack"], confidence=result["attack_confidence"], detection_confidence=detection_confidence, probabilities=probabilities, selected_model=result["attack_selected_model"], model_path=str(path), warning=result["warning"])


def _as_benign(prediction: MLAttackPrediction, reason: str) -> MLAttackPrediction:
    labels = prediction.probabilities.keys() or ("benign",)
    probabilities = {label: 0.0 for label in labels}
    probabilities["benign"] = 1.0
    return prediction.model_copy(update={
        "predicted_attack": "benign",
        "confidence": probabilities["benign"],
        "detection_confidence": 0.0,
        "probabilities": probabilities,
        "warning": f"{prediction.warning} Calibrated to benign: {reason}",
    })


def calibrate_attack_prediction(
    analysis: AnalysisResult,
    prediction: MLAttackPrediction,
) -> MLAttackPrediction:
    if prediction.status != "available" or prediction.predicted_attack in (None, "benign"):
        return prediction

    incident = analysis.incident
    vt = analysis.virustotal
    chain = ((incident.parent_process or "").lower(), incident.process_name.lower())
    clean_vt = vt.malicious == 0 and vt.suspicious == 0 and vt.reputation >= 0
    low_behavior = (
        incident.bytes_sent < 5_000_000
        and incident.failed_logins_10m < 10
        and incident.connection_count_10m < 50
        and incident.unique_destinations_10m < 10
        and incident.outbound_bytes_ratio < 4
    )
    suspicious_chain = chain in SUSPICIOUS_CHAINS
    process_is_lolbin = incident.process_name.lower() in TRUSTED_BINARY_PROCESSES
    vt_signal = vt.malicious > 0 or vt.suspicious > 0 or vt.reputation < 0
    behavior_signal = (
        incident.bytes_sent >= 5_000_000
        or incident.failed_logins_10m >= 10
        or incident.connection_count_10m >= 50
        or incident.unique_destinations_10m >= 10
        or incident.outbound_bytes_ratio >= 4
    )
    process_signal = suspicious_chain or process_is_lolbin

    if not (vt_signal or behavior_signal or process_signal):
        return _as_benign(prediction, "no VT, behavior, or process evidence supports an attack")

    if (prediction.detection_confidence or 0) < 0.85 and not (vt_signal and behavior_signal):
        return _as_benign(prediction, "attack confidence is below the SOC evidence threshold")

    if clean_vt and low_behavior and incident.process_name.lower() in COMMON_BUSINESS_PROCESSES:
        return _as_benign(prediction, "clean VirusTotal result and low-signal common application traffic")

    if prediction.predicted_attack == "trusted_binary_abuse":
        if not process_signal:
            return _as_benign(prediction, "trusted-binary abuse requires a trusted scripting/admin binary")
        if not (vt_signal or behavior_signal or suspicious_chain):
            return _as_benign(prediction, "trusted-binary abuse lacks VT, behavior, or process-chain evidence")

    return prediction


def _evidence_signals(analysis: AnalysisResult) -> dict[str, Any]:
    incident = analysis.incident
    vt = analysis.virustotal
    chain = ((incident.parent_process or "").lower(), incident.process_name.lower())
    behavior_flags = [
        incident.bytes_sent >= 5_000_000,
        incident.failed_logins_10m >= 10,
        incident.connection_count_10m >= 50,
        incident.unique_destinations_10m >= 10,
        incident.outbound_bytes_ratio >= 4,
    ]

    return {
        "clean_vt": (
            vt.queried
            and not vt.error
            and vt.malicious == 0
            and vt.suspicious == 0
            and vt.reputation >= 0
        ),
        "vt_signal": vt.malicious > 0 or vt.suspicious > 0 or vt.reputation < 0,
        "suspicious_chain": chain in SUSPICIOUS_CHAINS,
        "process_is_lolbin": incident.process_name.lower() in TRUSTED_BINARY_PROCESSES,
        "behavior_count": sum(1 for flag in behavior_flags if flag),
    }


def _candidate_attack_type(prediction: MLAttackPrediction) -> str:
    if prediction.status == "available" and prediction.predicted_attack not in (None, "benign"):
        return prediction.predicted_attack
    return "command_and_control"


def _severity(score):
    if score >= 85: return "critical"
    if score >= 60: return "high"
    if score >= 30: return "medium"
    return "low"


def build_hybrid_decision(analysis, prediction):
    reasons = [f"Rule engine scored {analysis.risk.risk_score}/100 as {analysis.risk.severity}."]
    if prediction.status != "available" or not prediction.predicted_severity:
        reasons.append("Severity model unavailable; rule decision retained.")
        return HybridDecision(combined_risk_score=analysis.risk.risk_score, final_severity=analysis.risk.severity, rule_ml_agreement=None, reasons=reasons, recommended_action=analysis.risk.recommended_action)
    expected = sum(float(p) * SEVERITY_VALUE.get(label, 0) for label, p in prediction.probabilities.items())
    combined = round(.45 * analysis.risk.risk_score + .55 * expected)
    agreement = prediction.predicted_severity == analysis.risk.severity
    reasons += [f"Severity model predicted {prediction.predicted_severity} with {prediction.confidence:.1%} confidence.", "Rule and ML severity agree." if agreement else "Rule and ML severity disagree; analyst review is required."]
    signals = _evidence_signals(analysis)
    corroborated_critical = signals["vt_signal"] or (
        signals["suspicious_chain"] and signals["behavior_count"] >= 2
    )
    if (
        prediction.predicted_severity == "critical"
        and (prediction.confidence or 0) >= .75
        and corroborated_critical
    ):
        combined = max(combined, 85)

    if signals["clean_vt"]:
        strong_local_evidence = (
            signals["behavior_count"] >= 2
            and (signals["suspicious_chain"] or signals["process_is_lolbin"])
        )
        if strong_local_evidence:
            combined = min(combined, 84)
            reasons.append(
                "VirusTotal is clean; severity is capped below critical unless external reputation becomes malicious."
            )
        else:
            combined = min(combined, 59)
            reasons.append(
                "VirusTotal is clean and local evidence is weak; severity is capped below high."
            )

    final = _severity(combined)
    actions = {"critical": "Immediately escalate to Tier 2 and preserve endpoint/network evidence.", "high": "Escalate to Tier 2 and confirm the internal blast radius.", "medium": "Tier 1 should validate the process, user, asset, and IP context.", "low": "Record and monitor for related activity."}
    return HybridDecision(combined_risk_score=max(0, min(combined, 100)), final_severity=final, rule_ml_agreement=agreement, reasons=reasons, recommended_action=actions[final])


class SmartAnalysisService:
    def __init__(self, *, mock_vt=False, model_path="artifacts/ml/model_bundle.joblib", ioc_db_path="data/ioc_registry.db", records_path="data/enrichment_records.jsonl"):
        self.base_service = IOCNexusService(mock_vt=mock_vt, records_path=records_path); self.model_path = Path(model_path); self.ioc_store = IOCStore(ioc_db_path)
    def analyze(self, incident: IncidentInput) -> SmartAnalysisResult:
        analysis = self.base_service.analyze(incident)
        if not analysis.virustotal.queried:
            raise RuntimeError(
                f"VirusTotal did not check public IP {incident.external_ip}: "
                f"{analysis.virustotal.error or 'unknown error'}"
            )
        if analysis.virustotal.error:
            raise RuntimeError(
                f"VirusTotal lookup failed for {incident.external_ip}: "
                f"{analysis.virustotal.error}"
            )
        features = build_ml_features(analysis)
        try:
            result = score_payload(self.model_path, features); severity_prediction = _severity_prediction(self.model_path, result=result); attack_prediction = _attack_prediction(self.model_path, result=result)
        except (FileNotFoundError, ValueError, KeyError, OSError) as exc:
            severity_prediction = _severity_prediction(self.model_path, error=exc); attack_prediction = _attack_prediction(self.model_path, error=exc)
        attack_prediction = calibrate_attack_prediction(analysis, attack_prediction)
        decision = build_hybrid_decision(analysis, severity_prediction)
        candidate = None
        if analysis.ioc.globally_queryable and decision.final_severity in {"high", "critical"}:
            attack_type = _candidate_attack_type(attack_prediction)
            confidence = attack_prediction.detection_confidence or attack_prediction.confidence or 0
            evidence = list(dict.fromkeys(decision.reasons + analysis.risk.reasons + [
                "Candidate IOC created automatically because the public IP reached high/critical severity.",
                f"Calibrated attack type: {attack_type}.",
            ]))
            candidate = self.ioc_store.create_or_update(value=incident.external_ip, attack_type=attack_type, attack_confidence=confidence, severity=decision.final_severity, internal_host=incident.internal_ip, evidence=evidence, vt_malicious=analysis.virustotal.malicious, vt_suspicious=analysis.virustotal.suspicious)
        return SmartAnalysisResult(analysis=analysis, severity_prediction=severity_prediction, attack_prediction=attack_prediction, hybrid_decision=decision, candidate_ioc=candidate)
