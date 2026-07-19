from __future__ import annotations

import argparse
import csv
import json
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .normalizer import normalize_security_event
from .smart_service import SmartAnalysisService

POWERSHELL_CONNECTION_QUERY = r'''
$processes = @{}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
  $processes[[int]$_.ProcessId] = $_
}
$rows = @()
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
  $p = $processes[[int]$_.OwningProcess]
  $parent = $null
  if ($p -and $p.ParentProcessId) { $parent = $processes[[int]$p.ParentProcessId] }
$rows += [pscustomobject]@{
    LocalAddress = $_.LocalAddress
    RemoteAddress = $_.RemoteAddress
    RemotePort = $_.RemotePort
    ProcessName = if ($p -and $p.ExecutablePath) { [System.IO.Path]::GetFileName($p.ExecutablePath) } elseif ($p -and $p.Name) { $p.Name } else { 'unknown.exe' }
    ParentProcessName = if ($parent -and $parent.ExecutablePath) { [System.IO.Path]::GetFileName($parent.ExecutablePath) } elseif ($parent -and $parent.Name) { $parent.Name } else { 'unknown.exe' }
    User = $env:USERNAME
    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
    ConnectionCount10m = 1
    UniqueDestinations10m = 1
    OutboundBytesRatio = 1.0
  }
}
$rows | ConvertTo-Json -Depth 4 -Compress
'''


class WindowsConnectionMonitor:
    def __init__(self, *, model_path: str, mock_vt: bool, results_path: str, seen_ttl: int = 600):
        self.model_path = model_path
        self.mock_vt = mock_vt
        self.results_path = Path(results_path); self.results_path.parent.mkdir(parents=True, exist_ok=True)
        self.seen_ttl = seen_ttl; self.seen_connections: dict[tuple[str, str, int | None], float] = {}

    @staticmethod
    def _query() -> list[dict[str, Any]]:
        if platform.system() != "Windows": raise RuntimeError("Live Windows monitoring can run only on Windows.")
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", POWERSHELL_CONNECTION_QUERY],
                check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            text = completed.stdout.strip()
            if text:
                payload = json.loads(text)
                rows = payload if isinstance(payload, list) else [payload]
                if rows:
                    return rows
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass

        return WindowsConnectionMonitor._query_netstat()

    @staticmethod
    def _tasklist_names() -> dict[int, str]:
        try:
            completed = subprocess.run(
                ["tasklist.exe", "/fo", "csv", "/nh"],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.CalledProcessError:
            return {}

        names: dict[int, str] = {}
        for row in csv.reader(completed.stdout.splitlines()):
            if len(row) < 2:
                continue
            try:
                names[int(row[1])] = row[0]
            except ValueError:
                continue
        return names

    @staticmethod
    def _split_endpoint(value: str) -> tuple[str, int | None]:
        endpoint = value.strip()
        if endpoint.startswith("[") and "]:" in endpoint:
            host, port = endpoint.rsplit("]:", 1)
            host = host.lstrip("[")
        elif ":" in endpoint:
            host, port = endpoint.rsplit(":", 1)
        else:
            return endpoint, None

        try:
            return host, int(port)
        except ValueError:
            return host, None

    @staticmethod
    def _query_netstat() -> list[dict[str, Any]]:
        completed = subprocess.run(
            ["netstat.exe", "-ano", "-p", "tcp"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        process_names = WindowsConnectionMonitor._tasklist_names()
        rows: list[dict[str, Any]] = []

        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].upper() != "TCP":
                continue
            local, remote, state, pid_text = parts[1], parts[2], parts[3], parts[4]
            if state.upper() != "ESTABLISHED":
                continue

            local_address, _local_port = WindowsConnectionMonitor._split_endpoint(local)
            remote_address, remote_port = WindowsConnectionMonitor._split_endpoint(remote)
            try:
                pid = int(pid_text)
            except ValueError:
                pid = 0
            process_name = process_names.get(pid, "unknown.exe")
            rows.append({
                "LocalAddress": local_address,
                "RemoteAddress": remote_address,
                "RemotePort": remote_port or 443,
                "ProcessName": process_name,
                "ParentProcessName": "unknown.exe",
                "User": "unknown",
                "TimeCreated": datetime.now(timezone.utc).isoformat(),
                "ConnectionCount10m": 1,
                "UniqueDestinations10m": 1,
                "OutboundBytesRatio": 1.0,
            })

        return rows

    def _write_record(self, raw: dict[str, Any], payload: dict[str, Any]) -> None:
        with self.results_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "collector_processed_at": datetime.now(timezone.utc).isoformat(),
                "source": "windows_established_connections",
                "raw_event": raw,
                **payload,
            }, default=str) + "\n")

    def run_cycle(self) -> dict[str, int]:
        now = time.time()
        self.seen_connections = {
            key: checked_at
            for key, checked_at in self.seen_connections.items()
            if now - checked_at < self.seen_ttl
        }
        processed = detected = failed_vt = 0
        for raw in self._query():
            incident = normalize_security_event(raw)
            if incident is None: continue
            connection_key = (
                incident.external_ip,
                incident.process_name,
                incident.destination_port,
            )
            if connection_key in self.seen_connections: continue
            try:
                result = SmartAnalysisService(
                    mock_vt=self.mock_vt,
                    model_path=self.model_path,
                ).analyze(incident)
            except RuntimeError as exc:
                failed_vt += 1
                error_record = {
                    "monitor_status": "vt_failed",
                    "external_ip": incident.external_ip,
                    "process": incident.process_name,
                    "port": incident.destination_port,
                    "error": str(exc),
                    "retry": "next_cycle",
                }
                self._write_record(raw, error_record)
                print(json.dumps(error_record, indent=2))
                continue
            processed += 1
            self.seen_connections[connection_key] = now
            if result.attack_prediction.predicted_attack not in (None, "benign"): detected += 1
            self._write_record(raw, {
                "monitor_status": "analyzed",
                "result": result.model_dump(mode="json"),
            })
            print(json.dumps({
                "external_ip": incident.external_ip,
                "process": incident.process_name,
                "attack": result.attack_prediction.predicted_attack,
                "confidence": result.attack_prediction.confidence,
                "severity": result.hybrid_decision.final_severity,
                "candidate_ioc": result.candidate_ioc.model_dump(mode="json") if result.candidate_ioc else None,
            }, indent=2, default=str))
        return {"processed": processed, "detections": detected, "failed_vt": failed_vt}


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Continuously monitor established Windows TCP connections without manual JSON input.")
    parser.add_argument("--model", default="artifacts/ml/model_bundle.joblib")
    parser.add_argument("--results", default="data/collector_results.jsonl")
    parser.add_argument("--interval", type=int, default=16)
    parser.add_argument("--max-new-ips", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--mock-vt", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    monitor = WindowsConnectionMonitor(model_path=args.model, mock_vt=args.mock_vt, results_path=args.results)
    print("Monitoring established Windows TCP connections. Only public IPs can be sent to VirusTotal. Press Ctrl+C to stop.")
    while True:
        try:
            print(json.dumps(monitor.run_cycle(), indent=2))
            if args.once: return
            time.sleep(max(16, args.interval))
        except KeyboardInterrupt: return
        except Exception as exc:
            print(f"Monitor cycle failed: {type(exc).__name__}: {exc}")
            if args.once: raise
            time.sleep(max(16, args.interval))


if __name__ == "__main__": main()
