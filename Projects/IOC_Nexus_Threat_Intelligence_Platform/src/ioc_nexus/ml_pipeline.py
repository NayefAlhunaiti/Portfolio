from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

SEVERITY_TARGET = "analyst_label"
ATTACK_TARGET = "attack_type"
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
ATTACK_ORDER = ["benign", "command_and_control", "trusted_binary_abuse", "brute_force", "data_exfiltration", "network_scanning", "propagation"]

CATEGORICAL_FEATURES = ["department", "asset_criticality", "indicator_type", "process_name", "parent_process"]
NUMERIC_FEATURES = [
    "destination_port", "bytes_sent", "vt_malicious_count", "vt_suspicious_count",
    "vt_reputation", "affected_internal_hosts", "affected_internal_users",
    "failed_logins_10m", "connection_count_10m", "unique_destinations_10m",
    "outbound_bytes_ratio",
]
BOOLEAN_FEATURES = [
    "whitelisted_process", "first_seen_in_company", "after_hours",
    "known_business_service", "whitelist_collision", "suspicious_process_chain",
]
MODEL_FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES + BOOLEAN_FEATURES


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool): return value
    if isinstance(value, (int, np.integer)): return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "1", "yes", "y"}: return True
        if v in {"false", "0", "no", "n"}: return False
    raise ValueError(f"Cannot convert to bool: {value!r}")


def load_dataset(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = set(MODEL_FEATURES + [SEVERITY_TARGET, ATTACK_TARGET, "timestamp"])
    missing = sorted(required - set(df.columns))
    if missing: raise ValueError(f"Dataset missing columns: {missing}")
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)
    for c in BOOLEAN_FEATURES: df[c] = df[c].map(_to_bool).astype(int)
    return df


def chronological_split(df):
    if len(df) < 150: raise ValueError("At least 150 records are recommended.")
    a = int(len(df) * .70); b = int(len(df) * .85)
    return df.iloc[:a].copy(), df.iloc[a:b].copy(), df.iloc[b:].copy()


def build_preprocessor():
    cat = Pipeline([("imputer", SimpleImputer(strategy="most_frequent")), ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))])
    num = Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler())])
    boo = Pipeline([("imputer", SimpleImputer(strategy="most_frequent"))])
    return ColumnTransformer([("categorical", cat, CATEGORICAL_FEATURES), ("numeric", num, NUMERIC_FEATURES), ("boolean", boo, BOOLEAN_FEATURES)], remainder="drop", verbose_feature_names_out=False)


def _metrics(y_true, y_pred, encoder, task):
    names = encoder.classes_.tolist()
    result = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "classification_report": classification_report(y_true, y_pred, labels=list(range(len(names))), target_names=names, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=list(range(len(names))).copy()).tolist(),
        "labels": names,
    }
    if task == "severity":
        idx = int(encoder.transform(["critical"])[0])
        result["priority_recall"] = float(recall_score(y_true, y_pred, labels=[idx], average="macro", zero_division=0))
    else:
        benign = int(encoder.transform(["benign"])[0])
        true_attack = np.asarray(y_true) != benign
        pred_attack = np.asarray(y_pred) != benign
        tp = int(np.logical_and(true_attack, pred_attack).sum())
        fn = int(np.logical_and(true_attack, ~pred_attack).sum())
        result["priority_recall"] = float(tp / (tp + fn)) if tp + fn else 0.0
    return result


def _candidates(num_classes):
    return {
        "logistic_regression": Pipeline([("preprocessor", build_preprocessor()), ("classifier", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=42))]),
        "xgboost": Pipeline([("preprocessor", build_preprocessor()), ("classifier", XGBClassifier(objective="multi:softprob", num_class=num_classes, n_estimators=140, max_depth=5, learning_rate=.05, min_child_weight=2, subsample=.85, colsample_bytree=.85, reg_lambda=1.5, eval_metric="mlogloss", random_state=42, n_jobs=2))]),
    }


def _train_task(train_df, validation_df, test_df, target, order, task):
    encoder = LabelEncoder(); encoder.classes_ = np.asarray(order, dtype=object)
    X_train, X_val, X_test = train_df[MODEL_FEATURES], validation_df[MODEL_FEATURES], test_df[MODEL_FEATURES]
    y_train, y_val, y_test = encoder.transform(train_df[target]), encoder.transform(validation_df[target]), encoder.transform(test_df[target])
    candidates = _candidates(len(order)); validation = {}
    weights = compute_sample_weight(class_weight="balanced", y=y_train)
    for name, model in candidates.items():
        kwargs = {"classifier__sample_weight": weights} if name == "xgboost" else {}
        model.fit(X_train, y_train, **kwargs)
        validation[name] = _metrics(y_val, model.predict(X_val), encoder, task)
    selected = max(validation, key=lambda n: (.7 * validation[n]["macro_f1"] + .3 * validation[n]["priority_recall"], validation[n]["priority_recall"]))
    combined = pd.concat([train_df, validation_df], ignore_index=True)
    model = _candidates(len(order))[selected]
    y_combined = encoder.transform(combined[target])
    kwargs = {"classifier__sample_weight": compute_sample_weight(class_weight="balanced", y=y_combined)} if selected == "xgboost" else {}
    model.fit(combined[MODEL_FEATURES], y_combined, **kwargs)
    pred = model.predict(X_test); prob = model.predict_proba(X_test)
    return {"model": model, "encoder": encoder, "selected": selected, "validation": validation, "test_metrics": _metrics(y_test, pred, encoder, task), "test_pred": pred, "test_prob": prob}


def _importance(model):
    pre = model.named_steps["preprocessor"]; classifier = model.named_steps["classifier"]
    names = pre.get_feature_names_out().tolist()
    values = np.abs(classifier.coef_).mean(axis=0) if hasattr(classifier, "coef_") else classifier.feature_importances_
    return sorted(({"feature": n, "importance": float(v)} for n, v in zip(names, values)), key=lambda x: x["importance"], reverse=True)


def train_models(dataset_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    output = Path(output_dir); output.mkdir(parents=True, exist_ok=True)
    df = load_dataset(dataset_path); train, val, test = chronological_split(df)
    severity = _train_task(train, val, test, SEVERITY_TARGET, SEVERITY_ORDER, "severity")
    attack = _train_task(train, val, test, ATTACK_TARGET, ATTACK_ORDER, "attack")
    bundle = {
        "severity_model": severity["model"], "severity_label_encoder": severity["encoder"], "severity_selected_model": severity["selected"],
        "attack_model": attack["model"], "attack_label_encoder": attack["encoder"], "attack_selected_model": attack["selected"],
        "model_features": MODEL_FEATURES, "boolean_features": BOOLEAN_FEATURES,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(bundle, output / "model_bundle.joblib")
    predictions = test[["incident_id", "timestamp", SEVERITY_TARGET, ATTACK_TARGET]].copy()
    predictions["predicted_severity"] = severity["encoder"].inverse_transform(severity["test_pred"])
    predictions["predicted_attack"] = attack["encoder"].inverse_transform(attack["test_pred"])
    predictions.to_csv(output / "test_predictions.csv", index=False)
    pd.DataFrame(_importance(severity["model"])).to_csv(output / "feature_importance_severity.csv", index=False)
    pd.DataFrame(_importance(attack["model"])).to_csv(output / "feature_importance_attack.csv", index=False)
    metrics = {
        "dataset": str(dataset_path), "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": {"train_rows": len(train), "validation_rows": len(val), "test_rows": len(test), "method": "chronological_70_15_15"},
        "severity": {"selected_model": severity["selected"], "validation": severity["validation"], "test": severity["test_metrics"]},
        "attack": {"selected_model": attack["selected"], "validation": attack["validation"], "test": attack["test_metrics"]},
        "warning": "Synthetic-data proof of concept. Candidate IOCs require analyst approval.",
    }
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (output / "model_schema.json").write_text(json.dumps({"model_features": MODEL_FEATURES, "severity_classes": SEVERITY_ORDER, "attack_classes": ATTACK_ORDER}, indent=2), encoding="utf-8")
    return metrics


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--dataset", default="data/generated/synthetic_soc_incidents.csv"); parser.add_argument("--output-dir", default="artifacts/ml")
    args = parser.parse_args(); print(json.dumps(train_models(args.dataset, args.output_dir), indent=2))


if __name__ == "__main__": main()
