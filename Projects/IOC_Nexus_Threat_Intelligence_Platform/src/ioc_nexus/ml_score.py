from __future__ import annotations

import argparse, json
from pathlib import Path
from typing import Any, Mapping
import joblib
import pandas as pd
from .ml_pipeline import BOOLEAN_FEATURES, MODEL_FEATURES, _to_bool


def _one(model, encoder, frame):
    probabilities = model.predict_proba(frame)[0]
    index = int(model.predict(frame)[0])
    return str(encoder.inverse_transform([index])[0]), float(max(probabilities)), {str(label): round(float(p), 6) for label, p in zip(encoder.classes_, probabilities)}


def score_payload(model_path: str | Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    path = Path(model_path)
    if not path.exists(): raise FileNotFoundError(f"Trained model not found: {path}")
    bundle = joblib.load(path)
    missing = sorted(set(MODEL_FEATURES) - set(payload))
    if missing: raise ValueError(f"Input missing model fields: {missing}")
    record = {f: payload[f] for f in MODEL_FEATURES}
    for f in BOOLEAN_FEATURES: record[f] = int(_to_bool(record[f]))
    frame = pd.DataFrame([record])
    sev, sev_conf, sev_probs = _one(bundle["severity_model"], bundle["severity_label_encoder"], frame)
    attack, attack_conf, attack_probs = _one(bundle["attack_model"], bundle["attack_label_encoder"], frame)
    return {
        "predicted_severity": sev, "severity_confidence": round(sev_conf, 6), "severity_probabilities": sev_probs,
        "predicted_attack": attack, "attack_confidence": round(attack_conf, 6), "attack_probabilities": attack_probs,
        "severity_selected_model": bundle["severity_selected_model"], "attack_selected_model": bundle["attack_selected_model"], "trained_at": bundle["trained_at"],
        "warning": "Synthetic-data proof of concept; analyst approval is required before an IOC is trusted.",
    }


def score_record(model_path, input_path): return score_payload(model_path, json.loads(Path(input_path).read_text(encoding="utf-8")))

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--model", default="artifacts/ml/model_bundle.joblib"); parser.add_argument("--input", required=True)
    args = parser.parse_args(); print(json.dumps(score_record(args.model, args.input), indent=2))


if __name__ == "__main__": main()
