from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from dotenv import load_dotenv
from .normalizer import normalize_security_event
from .smart_service import SmartAnalysisService

SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}


@dataclass
class CollectorConfig:
    incoming_dir: Path = Path("data/incoming_logs")
    processed_dir: Path = Path("data/processed_logs")
    failed_dir: Path = Path("data/failed_logs")
    results_path: Path = Path("data/collector_results.jsonl")
    state_db: Path = Path("data/collector_state.db")
    model_path: Path = Path("artifacts/ml/model_bundle.joblib")
    ioc_db_path: Path = Path("data/ioc_registry.db")
    mock_vt: bool = False
    settle_seconds: float = 1.0


class CollectorState:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS processed_files (
                    sha256 TEXT PRIMARY KEY,
                    source_name TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    record_count INTEGER NOT NULL,
                    detection_count INTEGER NOT NULL
                )"""
            )

    def contains(self, digest: str) -> bool:
        with sqlite3.connect(self.path) as connection:
            return connection.execute(
                "SELECT 1 FROM processed_files WHERE sha256=?", (digest,)
            ).fetchone() is not None

    def add(self, digest: str, name: str, records: int, detections: int) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO processed_files VALUES (?, ?, ?, ?, ?)",
                (digest, name, datetime.now(timezone.utc).isoformat(), records, detections),
            )


class AutomaticLogCollector:
    def __init__(self, config: CollectorConfig):
        self.config = config
        for folder in (config.incoming_dir, config.processed_dir, config.failed_dir):
            folder.mkdir(parents=True, exist_ok=True)
        config.results_path.parent.mkdir(parents=True, exist_ok=True)
        self.state = CollectorState(config.state_db)
        self.service = SmartAnalysisService(
            mock_vt=config.mock_vt,
            model_path=config.model_path,
            ioc_db_path=config.ioc_db_path,
            records_path="data/enrichment_records.jsonl",
        )

    @staticmethod
    def _digest(path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _records(path: Path) -> Iterable[dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            with path.open(newline="", encoding="utf-8-sig") as handle:
                yield from csv.DictReader(handle)
            return
        if suffix in {".jsonl", ".ndjson"}:
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                if line.strip():
                    yield json.loads(line)
            return
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(payload, list):
            yield from payload
        elif isinstance(payload, dict):
            events = payload.get("events")
            if isinstance(events, list): yield from events
            else: yield payload
        else:
            raise ValueError("JSON input must contain an object, list, or events list")

    def process_file(self, path: str | Path) -> dict[str, Any]:
        source = Path(path)
        if not source.exists() or source.suffix.lower() not in SUPPORTED_SUFFIXES:
            return {"status": "ignored", "file": str(source)}
        time.sleep(max(0, self.config.settle_seconds))
        digest = self._digest(source)
        if self.state.contains(digest):
            target = self._move(source, self.config.processed_dir, prefix="duplicate")
            return {"status": "duplicate", "file": str(target)}

        total = normalized = detections = ignored = 0
        try:
            for raw in self._records(source):
                total += 1
                incident = normalize_security_event(raw)
                if incident is None:
                    ignored += 1
                    continue
                normalized += 1
                try:
                    result = self.service.analyze(incident)
                    if result.attack_prediction.predicted_attack not in (None, "benign"):
                        detections += 1
                    record = {
                        "collector_processed_at": datetime.now(timezone.utc).isoformat(),
                        "source_file": source.name,
                        "raw_event": raw,
                        "monitor_status": "analyzed",
                        "result": result.model_dump(mode="json"),
                    }
                except RuntimeError as exc:
                    record = {
                        "collector_processed_at": datetime.now(timezone.utc).isoformat(),
                        "source_file": source.name,
                        "raw_event": raw,
                        "monitor_status": "vt_failed",
                        "external_ip": incident.external_ip,
                        "process": incident.process_name,
                        "port": incident.destination_port,
                        "error": str(exc),
                        "retry": "drop another log or rerun collector",
                    }
                with self.config.results_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, default=str) + "\n")
            self.state.add(digest, source.name, total, detections)
            target = self._move(source, self.config.processed_dir)
            return {
                "status": "processed", "file": str(target), "records": total,
                "normalized": normalized, "ignored": ignored, "detections": detections,
            }
        except Exception as exc:
            target = self._move(source, self.config.failed_dir)
            target.with_suffix(target.suffix + ".error.txt").write_text(
                f"{type(exc).__name__}: {exc}", encoding="utf-8"
            )
            return {"status": "failed", "file": str(target), "error": str(exc)}

    @staticmethod
    def _move(source: Path, folder: Path, prefix: str | None = None) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        name = f"{prefix + '_' if prefix else ''}{stamp}_{source.name}"
        target = folder / name
        return Path(shutil.move(str(source), str(target)))

    def process_existing(self) -> list[dict[str, Any]]:
        return [self.process_file(path) for path in sorted(self.config.incoming_dir.iterdir()) if path.is_file()]



def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Automatically analyze security-log files dropped into a watched folder.")
    parser.add_argument("--incoming-dir", default="data/incoming_logs")
    parser.add_argument("--processed-dir", default="data/processed_logs")
    parser.add_argument("--failed-dir", default="data/failed_logs")
    parser.add_argument("--results", default="data/collector_results.jsonl")
    parser.add_argument("--model", default="artifacts/ml/model_bundle.joblib")
    parser.add_argument("--mock-vt", action="store_true")
    parser.add_argument("--once", action="store_true", help="Process current files and exit")
    args = parser.parse_args()
    config = CollectorConfig(
        incoming_dir=Path(args.incoming_dir), processed_dir=Path(args.processed_dir),
        failed_dir=Path(args.failed_dir), results_path=Path(args.results),
        model_path=Path(args.model), mock_vt=args.mock_vt,
    )
    collector = AutomaticLogCollector(config)
    for result in collector.process_existing(): print(json.dumps(result, indent=2))
    if args.once: return
    print(f"Watching {config.incoming_dir.resolve()} for CSV, JSON, and JSONL security logs. Press Ctrl+C to stop.")
    try:
        while True:
            for result in collector.process_existing():
                if result.get("status") != "ignored":
                    print(json.dumps(result, indent=2))
            time.sleep(2)
    except KeyboardInterrupt:
        return


if __name__ == "__main__": main()
