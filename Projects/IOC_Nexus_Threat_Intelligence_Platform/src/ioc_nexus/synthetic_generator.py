from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCENARIOS = (
    "normal_business_activity",
    "known_business_service_false_positive",
    "command_and_control",
    "whitelist_collision",
    "trusted_binary_abuse",
    "brute_force",
    "data_exfiltration",
    "network_scanning",
    "multi_host_propagation",
)
SCENARIO_WEIGHTS = (30, 8, 14, 12, 10, 10, 7, 5, 4)

ATTACK_BY_SCENARIO = {
    "normal_business_activity": "benign",
    "known_business_service_false_positive": "benign",
    "command_and_control": "command_and_control",
    "whitelist_collision": "command_and_control",
    "trusted_binary_abuse": "trusted_binary_abuse",
    "brute_force": "brute_force",
    "data_exfiltration": "data_exfiltration",
    "network_scanning": "network_scanning",
    "multi_host_propagation": "propagation",
}

ASSETS = (
    {"internal_ip": "10.20.5.14", "hostname": "FIN-PC-014", "department": "Finance", "asset_criticality": "high", "username": "finance.user", "work_start": 7, "work_end": 18},
    {"internal_ip": "10.20.5.20", "hostname": "HR-PC-008", "department": "Human Resources", "asset_criticality": "medium", "username": "hr.user", "work_start": 7, "work_end": 18},
    {"internal_ip": "10.20.10.5", "hostname": "APP-SRV-02", "department": "IT", "asset_criticality": "critical", "username": "service.account", "work_start": 0, "work_end": 24},
    {"internal_ip": "10.20.7.33", "hostname": "ENG-PC-033", "department": "Engineering", "asset_criticality": "medium", "username": "engineer.user", "work_start": 7, "work_end": 19},
    {"internal_ip": "10.20.12.9", "hostname": "DC-SRV-01", "department": "IT", "asset_criticality": "critical", "username": "domain.service", "work_start": 0, "work_end": 24},
)

NORMAL_CHAINS = (
    ("explorer.exe", "chrome.exe"),
    ("explorer.exe", "msedge.exe"),
    ("services.exe", "approved_backup_agent.exe"),
    ("services.exe", "approved_monitoring_agent.exe"),
)
SUSPICIOUS_CHAINS = (
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("powershell.exe", "rundll32.exe"),
    ("powershell.exe", "regsvr32.exe"),
    ("powershell.exe", "schtasks.exe"),
)
CRITICALITY_POINTS = {"low": 0, "medium": 5, "high": 11, "critical": 17}


def _ip(index: int) -> str:
    # RFC 2544 benchmarking range: synthetic and never queried in this dataset.
    return f"198.18.{(index // 250) % 255}.{(index % 250) + 1}"


def _choice(rng, values):
    return values[rng.randrange(len(values))]


def _working_hour(asset, rng):
    if asset["work_start"] == 0 and asset["work_end"] == 24:
        return rng.randrange(24)
    return rng.randrange(asset["work_start"], asset["work_end"])


def _after_hour(asset, rng):
    candidates = [h for h in range(24) if not (asset["work_start"] <= h < asset["work_end"])]
    return _choice(rng, candidates) if candidates else rng.randrange(24)


def _severity(score: int) -> str:
    if score >= 82: return "critical"
    if score >= 58: return "high"
    if score >= 30: return "medium"
    return "low"


def generate_record(index: int, rng: random.Random, base_time: datetime) -> dict[str, Any]:
    scenario = rng.choices(SCENARIOS, weights=SCENARIO_WEIGHTS, k=1)[0]
    attack_type = ATTACK_BY_SCENARIO[scenario]
    asset = dict(_choice(rng, ASSETS))
    timestamp = base_time + timedelta(minutes=index * rng.randint(2, 8))
    parent_process, process_name = _choice(rng, NORMAL_CHAINS)

    port = _choice(rng, (53, 80, 443, 123, 445, 3389))
    bytes_sent = rng.randint(10_000, 350_000)
    whitelisted = True
    known_business = scenario in {"normal_business_activity", "known_business_service_false_positive"}
    vt_malicious = 0
    vt_suspicious = 0
    vt_reputation = rng.randint(0, 8)
    first_seen = rng.random() < 0.08
    affected_hosts = rng.randint(1, 2)
    affected_users = rng.randint(1, affected_hosts)
    failed_logins = rng.randint(0, 2)
    connection_count = rng.randint(1, 20)
    unique_destinations = rng.randint(1, 5)
    outbound_ratio = round(rng.uniform(0.5, 1.8), 2)
    timestamp = timestamp.replace(hour=_working_hour(asset, rng))
    scenario_bias = 0

    if scenario == "known_business_service_false_positive":
        vt_malicious = rng.randint(1, 3)
        vt_suspicious = rng.randint(0, 2)
        vt_reputation = rng.randint(-5, 2)
        affected_hosts = rng.randint(8, 50)
        affected_users = rng.randint(5, affected_hosts)
        first_seen = False
        scenario_bias = -18
    elif scenario == "command_and_control":
        parent_process, process_name = _choice(rng, SUSPICIOUS_CHAINS)
        timestamp = timestamp.replace(hour=_after_hour(asset, rng) if rng.random() < .6 else _working_hour(asset, rng))
        vt_malicious = rng.randint(4, 18)
        vt_suspicious = rng.randint(1, 6)
        vt_reputation = rng.randint(-35, -6)
        first_seen = rng.random() < .75
        connection_count = rng.randint(20, 180)
        unique_destinations = rng.randint(1, 4)
        outbound_ratio = round(rng.uniform(1.5, 6.0), 2)
        scenario_bias = 13
    elif scenario == "whitelist_collision":
        parent_process, process_name = _choice(rng, SUSPICIOUS_CHAINS)
        timestamp = timestamp.replace(hour=_after_hour(asset, rng))
        vt_malicious = rng.randint(3, 16)
        vt_suspicious = rng.randint(1, 5)
        vt_reputation = rng.randint(-30, -4)
        bytes_sent = rng.randint(300_000, 7_000_000)
        outbound_ratio = round(rng.uniform(2.0, 8.0), 2)
        scenario_bias = 20
    elif scenario == "trusted_binary_abuse":
        parent_process, process_name = _choice(rng, SUSPICIOUS_CHAINS)
        timestamp = timestamp.replace(hour=_after_hour(asset, rng))
        vt_malicious = rng.randint(0, 5)
        vt_suspicious = rng.randint(1, 4)
        vt_reputation = rng.randint(-12, 1)
        first_seen = rng.random() < .65
        scenario_bias = 23
    elif scenario == "brute_force":
        process_name, parent_process = "lsass.exe", "services.exe"
        port = _choice(rng, (22, 3389, 445))
        failed_logins = rng.randint(20, 250)
        connection_count = rng.randint(30, 300)
        unique_destinations = rng.randint(1, 3)
        timestamp = timestamp.replace(hour=_after_hour(asset, rng))
        vt_malicious = rng.randint(0, 9)
        vt_suspicious = rng.randint(0, 4)
        vt_reputation = rng.randint(-20, 2)
        scenario_bias = 22
    elif scenario == "data_exfiltration":
        parent_process, process_name = _choice(rng, SUSPICIOUS_CHAINS)
        timestamp = timestamp.replace(hour=_after_hour(asset, rng))
        bytes_sent = rng.randint(8_000_000, 120_000_000)
        outbound_ratio = round(rng.uniform(8.0, 60.0), 2)
        vt_malicious = rng.randint(0, 10)
        vt_suspicious = rng.randint(0, 4)
        vt_reputation = rng.randint(-22, 2)
        scenario_bias = 28
    elif scenario == "network_scanning":
        parent_process, process_name = _choice(rng, SUSPICIOUS_CHAINS)
        connection_count = rng.randint(150, 1500)
        unique_destinations = rng.randint(40, 500)
        bytes_sent = rng.randint(50_000, 2_000_000)
        vt_malicious = rng.randint(0, 6)
        vt_suspicious = rng.randint(0, 3)
        timestamp = timestamp.replace(hour=_after_hour(asset, rng))
        scenario_bias = 25
    elif scenario == "multi_host_propagation":
        parent_process, process_name = _choice(rng, SUSPICIOUS_CHAINS)
        affected_hosts = rng.randint(8, 70)
        affected_users = rng.randint(3, affected_hosts)
        connection_count = rng.randint(80, 700)
        unique_destinations = rng.randint(10, 100)
        vt_malicious = rng.randint(3, 15)
        vt_suspicious = rng.randint(1, 5)
        vt_reputation = rng.randint(-30, -4)
        timestamp = timestamp.replace(hour=_after_hour(asset, rng))
        scenario_bias = 30

    after_hours = not (asset["work_start"] <= timestamp.hour < asset["work_end"])
    suspicious_chain = (parent_process, process_name) in SUSPICIOUS_CHAINS
    whitelist_collision = whitelisted and vt_malicious > 0 and attack_type != "benign"

    score = min(vt_malicious * 5, 35) + min(vt_suspicious * 3, 12)
    score += min(abs(vt_reputation), 10) if vt_reputation < 0 else 0
    score += CRITICALITY_POINTS[asset["asset_criticality"]]
    score += 12 if whitelist_collision else 0
    score += 18 if suspicious_chain else 0
    score += 7 if after_hours else 0
    score += 8 if first_seen else 0
    score += min(affected_hosts * 2, 12) if affected_hosts >= 3 else 0
    score += 8 if bytes_sent >= 5_000_000 else 0
    score += 12 if failed_logins >= 20 else 0
    score += 12 if unique_destinations >= 40 else 0
    score += 12 if outbound_ratio >= 8 else 0
    score += scenario_bias + rng.randint(-12, 12)
    score = max(0, min(score, 100))

    verdict = "expected_activity" if attack_type == "benign" else "true_positive"
    if rng.random() < .08:
        verdict = "false_positive"

    return {
        "incident_id": f"SYN-{index:06d}",
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        "scenario": scenario,
        "synthetic_only": True,
        "internal_ip": asset["internal_ip"],
        "hostname": asset["hostname"],
        "department": asset["department"],
        "asset_criticality": asset["asset_criticality"],
        "username": asset["username"],
        "external_ip": _ip(index),
        "indicator_type": "ip",
        "process_name": process_name,
        "parent_process": parent_process,
        "destination_port": port,
        "bytes_sent": bytes_sent,
        "whitelisted_process": whitelisted,
        "vt_malicious_count": vt_malicious,
        "vt_suspicious_count": vt_suspicious,
        "vt_reputation": vt_reputation,
        "first_seen_in_company": first_seen,
        "affected_internal_hosts": affected_hosts,
        "affected_internal_users": affected_users,
        "after_hours": after_hours,
        "known_business_service": known_business,
        "whitelist_collision": whitelist_collision,
        "suspicious_process_chain": suspicious_chain,
        "failed_logins_10m": failed_logins,
        "connection_count_10m": connection_count,
        "unique_destinations_10m": unique_destinations,
        "outbound_bytes_ratio": outbound_ratio,
        "rule_risk_score": score,
        "analyst_label": _severity(score),
        "attack_type": attack_type,
        "analyst_verdict": verdict,
        "escalated": score >= 58 and attack_type != "benign",
    }


def generate_dataset(*, count: int, seed: int, output_dir: str | Path) -> dict[str, Any]:
    if count < 1: raise ValueError("count must be at least 1")
    output = Path(output_dir); output.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [generate_record(i, rng, base) for i in range(1, count + 1)]
    jsonl = output / "synthetic_soc_incidents.jsonl"
    csv_path = output / "synthetic_soc_incidents.csv"
    with jsonl.open("w", encoding="utf-8") as f:
        for row in rows: f.write(json.dumps(row) + "\n")
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    summary = {
        "generated_records": count,
        "seed": seed,
        "warning": "Synthetic data only. Synthetic IPs must not be queried in VirusTotal.",
        "severity_distribution": dict(Counter(r["analyst_label"] for r in rows)),
        "attack_distribution": dict(Counter(r["attack_type"] for r in rows)),
        "scenario_distribution": dict(Counter(r["scenario"] for r in rows)),
    }
    (output / "synthetic_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="data/generated")
    args = parser.parse_args()
    print(json.dumps(generate_dataset(count=args.count, seed=args.seed, output_dir=args.output_dir), indent=2))


if __name__ == "__main__": main()
