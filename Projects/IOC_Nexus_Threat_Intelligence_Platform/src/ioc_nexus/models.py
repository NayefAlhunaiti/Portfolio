from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator


Severity = Literal["low", "medium", "high", "critical"]
AttackType = Literal[
    "benign",
    "command_and_control",
    "trusted_binary_abuse",
    "brute_force",
    "data_exfiltration",
    "network_scanning",
    "propagation",
]


class IncidentInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    internal_ip: str
    external_ip: str = Field(
        validation_alias=AliasChoices("external_ip", "external_indicator")
    )
    process_name: str = Field(min_length=1)
    parent_process: str | None = None
    username: str | None = None
    timestamp: datetime
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    bytes_sent: int = Field(default=0, ge=0)
    whitelisted_process: bool = False
    known_business_service: bool = False
    failed_logins_10m: int = Field(default=0, ge=0)
    connection_count_10m: int = Field(default=1, ge=0)
    unique_destinations_10m: int = Field(default=1, ge=0)
    outbound_bytes_ratio: float = Field(default=1.0, ge=0)

    @field_validator("process_name", "parent_process")
    @classmethod
    def normalize_process_name(cls, value: str | None) -> str | None:
        return value.lower().strip() if value else value


class IOCClassification(BaseModel):
    indicator: str
    indicator_type: Literal["ip", "unknown"]
    globally_queryable: bool
    reason: str


class VTReport(BaseModel):
    queried: bool
    source: str = "virustotal"
    indicator_type: str = "ip"
    indicator: str
    found: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    categories: list[str] = []
    last_analysis_date: int | None = None
    cached: bool = False
    error: str | None = None
    raw_summary: dict[str, Any] = {}


class InternalAsset(BaseModel):
    ip: str
    hostname: str = "unknown"
    department: str = "unknown"
    asset_criticality: Severity = "medium"
    owner: str = "unknown"
    operating_system: str = "unknown"
    expected_work_hours: dict[str, int] = {"start": 7, "end": 18}


class InternalContext(BaseModel):
    asset: InternalAsset
    previous_contacts: int = 0
    affected_internal_hosts: int = 0
    affected_internal_users: int = 0
    first_seen_in_company: bool = True
    total_historical_bytes_sent: int = 0


class RiskResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    whitelist_collision: bool
    reasons: list[str]
    recommended_action: str


class AnalysisResult(BaseModel):
    incident: IncidentInput
    ioc: IOCClassification
    virustotal: VTReport
    internal_context: InternalContext
    risk: RiskResult
    analyzed_at: datetime


class MLSeverityPrediction(BaseModel):
    status: Literal["available", "unavailable"]
    predicted_severity: Severity | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    probabilities: dict[str, float] = {}
    selected_model: str | None = None
    trained_at: str | None = None
    model_path: str
    error: str | None = None
    warning: str = "Synthetic-data proof of concept; analyst review is required."


class MLAttackPrediction(BaseModel):
    status: Literal["available", "unavailable"]
    predicted_attack: AttackType | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    detection_confidence: float | None = Field(default=None, ge=0, le=1)
    probabilities: dict[str, float] = {}
    selected_model: str | None = None
    model_path: str
    error: str | None = None
    warning: str = "Synthetic-data proof of concept; analyst review is required."


class HybridDecision(BaseModel):
    combined_risk_score: int = Field(ge=0, le=100)
    final_severity: Severity
    rule_ml_agreement: bool | None
    requires_human_review: bool = True
    reasons: list[str]
    recommended_action: str


class CandidateIOC(BaseModel):
    ioc_id: str
    ioc_type: Literal["ipv4", "ipv6"]
    value: str
    status: Literal["candidate", "approved", "rejected"] = "candidate"
    source: str = "local_ml_detection"
    attack_type: AttackType
    attack_confidence: float = Field(ge=0, le=1)
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    internal_hosts: list[str]
    evidence: list[str]
    vt_malicious: int = 0
    vt_suspicious: int = 0
    analyst_approval_required: bool = True
    analyst: str | None = None
    analyst_notes: str | None = None


class IOCDecisionInput(BaseModel):
    decision: Literal["approved", "rejected"]
    analyst: str = Field(min_length=1)
    notes: str = Field(default="", max_length=2000)


class SmartAnalysisResult(BaseModel):
    analysis: AnalysisResult
    severity_prediction: MLSeverityPrediction
    attack_prediction: MLAttackPrediction
    hybrid_decision: HybridDecision
    candidate_ioc: CandidateIOC | None = None
