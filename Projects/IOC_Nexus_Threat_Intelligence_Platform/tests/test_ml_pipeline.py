from pathlib import Path
import json
from ioc_nexus.ml_pipeline import train_models
from ioc_nexus.ml_score import score_record
from ioc_nexus.synthetic_generator import generate_dataset

def test_dual_training_and_scoring(tmp_path: Path):
    data = tmp_path / "data"; artifacts = tmp_path / "artifacts"
    generate_dataset(count=420, seed=123, output_dir=data)
    metrics = train_models(data / "synthetic_soc_incidents.csv", artifacts)
    assert metrics["severity"]["selected_model"] in {"logistic_regression", "xgboost"}
    assert metrics["attack"]["selected_model"] in {"logistic_regression", "xgboost"}
    payload = {"department":"Finance","asset_criticality":"high","indicator_type":"ip","process_name":"powershell.exe","parent_process":"winword.exe","destination_port":443,"bytes_sent":9500000,"whitelisted_process":True,"vt_malicious_count":11,"vt_suspicious_count":3,"vt_reputation":-18,"first_seen_in_company":True,"affected_internal_hosts":4,"affected_internal_users":3,"after_hours":True,"known_business_service":False,"whitelist_collision":True,"suspicious_process_chain":True,"failed_logins_10m":2,"connection_count_10m":85,"unique_destinations_10m":2,"outbound_bytes_ratio":12.5}
    path = tmp_path / "input.json"; path.write_text(json.dumps(payload))
    result = score_record(artifacts / "model_bundle.joblib", path)
    assert result["predicted_severity"] in {"low","medium","high","critical"}
    assert result["predicted_attack"] in {"benign","command_and_control","trusted_binary_abuse","brute_force","data_exfiltration","network_scanning","propagation"}
