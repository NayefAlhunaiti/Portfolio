from datetime import datetime
from pathlib import Path
from ioc_nexus.models import AnalysisResult, IOCClassification, IncidentInput, InternalAsset, InternalContext, MLAttackPrediction, MLSeverityPrediction, RiskResult, VTReport
from ioc_nexus.smart_service import SmartAnalysisService, build_hybrid_decision, build_ml_features, calibrate_attack_prediction

def _incident():
    return IncidentInput(internal_ip="10.20.5.14", external_ip="45.155.205.233", process_name="powershell.exe", parent_process="winword.exe", username="finance.user", timestamp=datetime.fromisoformat("2026-07-15T02:34:00"), destination_port=443, bytes_sent=9500000, whitelisted_process=True, failed_logins_10m=2, connection_count_10m=85, unique_destinations_10m=2, outbound_bytes_ratio=12.5)

def test_smart_service_with_model(tmp_path: Path):
    result = SmartAnalysisService(mock_vt=True, model_path="artifacts/ml/model_bundle.joblib", ioc_db_path=tmp_path / "iocs.db").analyze(_incident())
    assert result.severity_prediction.status == "available"; assert result.attack_prediction.status == "available"
    assert result.attack_prediction.predicted_attack is not None
    assert result.attack_prediction.detection_confidence is not None
    assert result.candidate_ioc is not None

def test_missing_model_falls_back(tmp_path: Path):
    result = SmartAnalysisService(mock_vt=True, model_path=tmp_path / "missing.joblib", ioc_db_path=tmp_path / "iocs.db").analyze(_incident())
    assert result.severity_prediction.status == "unavailable"
    assert result.candidate_ioc is not None

def test_calibration_does_not_overcall_common_clean_traffic():
    incident = IncidentInput(
        internal_ip="10.20.5.20",
        external_ip="20.50.60.70",
        process_name="msedge.exe",
        parent_process="explorer.exe",
        username="user",
        timestamp=datetime.fromisoformat("2026-07-19T10:00:00"),
        destination_port=443,
        bytes_sent=0,
        whitelisted_process=True,
        connection_count_10m=1,
        unique_destinations_10m=1,
        outbound_bytes_ratio=1.0,
    )
    analysis = AnalysisResult(
        incident=incident,
        ioc=IOCClassification(
            indicator="20.50.60.70",
            indicator_type="ip",
            globally_queryable=True,
            reason="public",
        ),
        virustotal=VTReport(
            queried=True,
            indicator="20.50.60.70",
            found=True,
            malicious=0,
            suspicious=0,
            reputation=0,
        ),
        internal_context=InternalContext(
            asset=InternalAsset(ip="10.20.5.20", expected_work_hours={"start": 7, "end": 18})
        ),
        risk=RiskResult(
            risk_score=8,
            severity="low",
            whitelist_collision=False,
            reasons=["No significant risk signals were identified"],
            recommended_action="Record and monitor",
        ),
        analyzed_at=datetime.fromisoformat("2026-07-19T10:00:01"),
    )
    prediction = MLAttackPrediction(
        status="available",
        predicted_attack="trusted_binary_abuse",
        confidence=0.72,
        detection_confidence=0.68,
        probabilities={"benign": 0.32, "trusted_binary_abuse": 0.68},
        model_path="artifacts/ml/model_bundle.joblib",
    )
    calibrated = calibrate_attack_prediction(analysis, prediction)
    assert calibrated.predicted_attack == "benign"
    assert calibrated.detection_confidence == 0.0

def test_calibration_suppresses_any_attack_without_evidence():
    incident = IncidentInput(
        internal_ip="10.20.5.20",
        external_ip="20.50.60.71",
        process_name="notepad.exe",
        parent_process="explorer.exe",
        username="user",
        timestamp=datetime.fromisoformat("2026-07-19T10:00:00"),
        destination_port=443,
        bytes_sent=0,
        connection_count_10m=1,
        unique_destinations_10m=1,
        outbound_bytes_ratio=1.0,
    )
    analysis = AnalysisResult(
        incident=incident,
        ioc=IOCClassification(
            indicator="20.50.60.71",
            indicator_type="ip",
            globally_queryable=True,
            reason="public",
        ),
        virustotal=VTReport(
            queried=True,
            indicator="20.50.60.71",
            found=True,
            malicious=0,
            suspicious=0,
            reputation=0,
        ),
        internal_context=InternalContext(asset=InternalAsset(ip="10.20.5.20")),
        risk=RiskResult(
            risk_score=8,
            severity="low",
            whitelist_collision=False,
            reasons=[],
            recommended_action="Record and monitor",
        ),
        analyzed_at=datetime.fromisoformat("2026-07-19T10:00:01"),
    )
    prediction = MLAttackPrediction(
        status="available",
        predicted_attack="command_and_control",
        confidence=0.91,
        detection_confidence=0.91,
        probabilities={"benign": 0.09, "command_and_control": 0.91},
        model_path="artifacts/ml/model_bundle.joblib",
    )
    calibrated = calibrate_attack_prediction(analysis, prediction)
    assert calibrated.predicted_attack == "benign"

def test_high_or_critical_public_ip_creates_candidate_even_when_attack_is_calibrated(tmp_path: Path):
    incident = IncidentInput(
        internal_ip="10.20.5.20",
        external_ip="45.155.205.233",
        process_name="msedge.exe",
        parent_process="explorer.exe",
        username="user",
        timestamp=datetime.fromisoformat("2026-07-19T10:00:00"),
        destination_port=443,
        bytes_sent=25000,
        whitelisted_process=True,
        known_business_service=True,
    )
    result = SmartAnalysisService(
        mock_vt=True,
        model_path="artifacts/ml/model_bundle.joblib",
        ioc_db_path=tmp_path / "iocs.db",
    ).analyze(incident)
    assert result.hybrid_decision.final_severity in {"high", "critical"}
    assert result.candidate_ioc is not None
    assert result.candidate_ioc.value == "45.155.205.233"

def test_clean_virustotal_caps_panicking_severity_model_below_high():
    incident = IncidentInput(
        internal_ip="10.20.5.20",
        external_ip="20.50.60.72",
        process_name="msedge.exe",
        parent_process="explorer.exe",
        username="user",
        timestamp=datetime.fromisoformat("2026-07-19T10:00:00"),
        destination_port=443,
        bytes_sent=0,
        whitelisted_process=True,
        connection_count_10m=1,
        unique_destinations_10m=1,
        outbound_bytes_ratio=1.0,
    )
    analysis = AnalysisResult(
        incident=incident,
        ioc=IOCClassification(
            indicator="20.50.60.72",
            indicator_type="ip",
            globally_queryable=True,
            reason="public",
        ),
        virustotal=VTReport(
            queried=True,
            indicator="20.50.60.72",
            found=True,
            malicious=0,
            suspicious=0,
            reputation=0,
        ),
        internal_context=InternalContext(asset=InternalAsset(ip="10.20.5.20")),
        risk=RiskResult(
            risk_score=8,
            severity="low",
            whitelist_collision=False,
            reasons=[],
            recommended_action="Record and monitor",
        ),
        analyzed_at=datetime.fromisoformat("2026-07-19T10:00:01"),
    )
    prediction = MLSeverityPrediction(
        status="available",
        predicted_severity="critical",
        confidence=0.99,
        probabilities={"low": 0.0, "medium": 0.0, "high": 0.0, "critical": 1.0},
        model_path="artifacts/ml/model_bundle.joblib",
    )

    decision = build_hybrid_decision(analysis, prediction)

    assert decision.final_severity in {"low", "medium"}
    assert decision.combined_risk_score < 60
