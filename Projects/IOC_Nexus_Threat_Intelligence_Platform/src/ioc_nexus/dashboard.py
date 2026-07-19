from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import httpx
import pandas as pd
import streamlit as st

RESULTS_FILE = Path("data/collector_results.jsonl")
HISTORY_FILE_PATTERNS = [
    "collector_results*.jsonl",
    "enrichment_records.jsonl",
]
HISTORY_FOLDERS = [
    Path("data/incoming_logs"),
    Path("data/processed_logs"),
    Path("data/failed_logs"),
]
HISTORY_TABLES = [
    (Path("data/collector_state.db"), "processed_files"),
    (Path("data/ioc_registry.db"), "candidate_iocs"),
]
API_BASE_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="IOC Nexus Threat Intelligence Platform",
    layout="wide",
)

st.title("IOC Nexus Threat Intelligence Platform")
st.caption(
    "Local attack detection, VirusTotal IP intelligence, "
    "and candidate IOC monitoring"
)

st.sidebar.header("Platform status")
history_message = st.session_state.pop("history_delete_summary", "")
if history_message:
    st.sidebar.success(history_message)

auto_refresh = st.sidebar.checkbox("Auto-refresh monitor feed", value=False)
if auto_refresh:
    st.html("<meta http-equiv='refresh' content='16'>")


def nested_value(data: dict[str, Any], *paths: str, default=None):
    """Return the first available value from several possible nested paths."""

    for path in paths:
        current: Any = data

        for key in path.split("."):
            if not isinstance(current, dict) or key not in current:
                current = None
                break

            current = current[key]

        if current is not None:
            return current

    return default


def load_results() -> list[dict[str, Any]]:
    if not RESULTS_FILE.exists():
        return []

    records: list[dict[str, Any]] = []

    for line in RESULTS_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records


def delete_history() -> tuple[int, list[str]]:
    deleted_items = 0
    errors: list[str] = []
    data_dir = Path("data")

    for pattern in HISTORY_FILE_PATTERNS:
        for path in data_dir.glob(pattern):
            if not path.is_file():
                continue

            try:
                path.unlink()
                deleted_items += 1
            except OSError as exc:
                errors.append(f"{path}: {exc}")

    for folder in HISTORY_FOLDERS:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            for child in folder.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
                deleted_items += 1
        except OSError as exc:
            errors.append(f"{folder}: {exc}")

    for db_path, table_name in HISTORY_TABLES:
        if not db_path.exists():
            continue

        try:
            with sqlite3.connect(db_path) as connection:
                table_exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (table_name,),
                ).fetchone()

                if not table_exists:
                    continue

                cursor = connection.execute(f"DELETE FROM {table_name}")
                connection.commit()
                deleted_items += max(cursor.rowcount, 0)
        except sqlite3.Error as exc:
            errors.append(f"{db_path}:{table_name}: {exc}")

    return deleted_items, errors


def normalize_result(result: dict[str, Any]) -> dict[str, Any]:
    candidate_ioc = nested_value(
        result,
        "result.candidate_ioc",
        "candidate_ioc",
        default=None,
    )
    monitor_status = nested_value(
        result,
        "monitor_status",
        default="analyzed" if nested_value(result, "result", default=None) else "unknown",
    )

    return {
        "timestamp": nested_value(
            result,
            "collector_processed_at",
            "result.analysis.analyzed_at",
            "result.analysis.incident.timestamp",
            default="Unknown",
        ),
        "internal_ip": nested_value(
            result,
            "result.analysis.incident.internal_ip",
            "raw_event.SourceIp",
            "raw_event.LocalAddress",
            default="Unknown",
        ),
        "external_ip": nested_value(
            result,
            "result.analysis.incident.external_ip",
            "result.analysis.ioc.indicator",
            "raw_event.DestinationIp",
            "raw_event.RemoteAddress",
            default="Unknown",
        ),
        "process": nested_value(
            result,
            "result.analysis.incident.process_name",
            "raw_event.Image",
            "raw_event.ProcessName",
            default="Unknown",
        ),
        "parent_process": nested_value(
            result,
            "result.analysis.incident.parent_process",
            "raw_event.ParentImage",
            "raw_event.ParentProcessName",
            default="Unknown",
        ),
        "attack_type": nested_value(
            result,
            "result.attack_prediction.predicted_attack",
            default="VT failed" if monitor_status == "vt_failed" else "Unknown",
        ),
        "confidence": nested_value(
            result,
            "result.attack_prediction.confidence",
            "result.attack_prediction.detection_confidence",
            default=0,
        ),
        "severity": nested_value(
            result,
            "result.hybrid_decision.final_severity",
            "result.analysis.risk.severity",
            default="Pending" if monitor_status == "vt_failed" else "Unknown",
        ),
        "candidate_ioc": candidate_ioc is not None,
        "candidate_ioc_value": nested_value(
            result,
            "result.candidate_ioc.value",
            default="",
        ),
        "vt_malicious": nested_value(
            result,
            "result.analysis.virustotal.malicious",
            default=0,
        ),
        "vt_suspicious": nested_value(
            result,
            "result.analysis.virustotal.suspicious",
            default=0,
        ),
        "vt_error": nested_value(
            result,
            "result.analysis.virustotal.error",
            "error",
            default="",
        ),
        "risk_score": nested_value(
            result,
            "result.hybrid_decision.combined_risk_score",
            "result.analysis.risk.risk_score",
            default=0,
        ),
        "source": nested_value(
            result,
            "source",
            "source_file",
            default="Unknown",
        ),
        "monitor_status": monitor_status,
    }


def load_candidate_iocs() -> list[dict[str, Any]]:
    try:
        response = httpx.get(
            f"{API_BASE_URL}/iocs",
            params={"status": "candidate"},
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json()

        if isinstance(payload, list):
            return payload

        if isinstance(payload, dict):
            return payload.get("items", payload.get("iocs", []))

        return []

    except httpx.HTTPError:
        return []


def submit_ioc_decision(
    ioc_id: str,
    decision: str,
    analyst: str,
    notes: str,
) -> tuple[bool, str]:
    try:
        response = httpx.post(
            f"{API_BASE_URL}/iocs/{ioc_id}/decision",
            json={
                "decision": decision,
                "analyst": analyst,
                "notes": notes,
            },
            timeout=10,
        )
        response.raise_for_status()
        return True, "IOC decision saved successfully."

    except httpx.HTTPStatusError as exc:
        return False, f"API returned HTTP {exc.response.status_code}."

    except httpx.HTTPError:
        return False, "Could not connect to the local IOC Nexus API."


def monitor_events_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for record_index, record in enumerate(records):
        if nested_value(record, "source", default="") != "windows_established_connections":
            continue
        row = normalize_result(record)
        row["record_index"] = record_index
        rows.append(row)
    frame = pd.DataFrame(rows)
    if not frame.empty:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
        frame["is_detection"] = (
            (frame["monitor_status"] == "analyzed")
            & (frame["attack_type"].fillna("benign") != "benign")
        )
        frame = frame.sort_values("timestamp", ascending=False)
    return frame


results = load_results()
normalized = [normalize_result(result) for result in results]
monitor_events = monitor_events_frame(results)

total_events = len(normalized)
monitor_event_count = len(monitor_events)
monitor_detection_count = (
    0 if monitor_events.empty else int(monitor_events["is_detection"].sum())
)

critical_events = sum(
    1 for result in normalized
    if str(result["severity"]).lower() == "critical"
)

high_events = sum(
    1 for result in normalized
    if str(result["severity"]).lower() == "high"
)

candidate_iocs = sum(
    1 for result in normalized
    if result["candidate_ioc"]
)

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric("Processed events", total_events)
metric2.metric("Critical detections", critical_events)
metric3.metric("High detections", high_events)
metric4.metric("Candidate IOCs", candidate_iocs)

st.divider()

overview_tab, monitor_tab, detection_tab, ioc_tab, raw_tab = st.tabs(
    [
        "Overview",
        "Windows Monitor",
        "Recent detections",
        "Candidate IOCs",
        "Raw results",
    ]
)

with overview_tab:
    if not normalized:
        st.info(
            "No collected events are available. Start the folder collector "
            "and run the simulated log drop."
        )
    else:
        dataframe = pd.DataFrame(normalized)

        st.subheader("Attack types")

        attack_counts = (
            dataframe["attack_type"]
            .fillna("Unknown")
            .value_counts()
            .rename_axis("attack_type")
            .reset_index(name="events")
            .set_index("attack_type")
        )

        st.bar_chart(attack_counts)

        st.subheader("Severity distribution")

        severity_counts = (
            dataframe["severity"]
            .fillna("Unknown")
            .value_counts()
            .rename_axis("severity")
            .reset_index(name="events")
            .set_index("severity")
        )

        st.bar_chart(severity_counts)

with monitor_tab:
    st.subheader("Windows monitor detections")

    if monitor_events.empty:
        st.info(
            "No Windows monitor events are available yet. Start the live monitor "
            "and keep this dashboard open for the detection feed."
        )
        st.code(
            r".\.venv\Scripts\python.exe -m ioc_nexus.windows_monitor --interval 16",
            language="powershell",
        )
    else:
        summary1, summary2, summary3, summary4 = st.columns(4)
        summary1.metric("Monitor events", monitor_event_count)
        summary2.metric("Attack detections", monitor_detection_count)
        summary3.metric(
            "Candidate IOCs",
            int(monitor_events["candidate_ioc"].sum()),
        )
        summary4.metric(
            "VT errors",
            int(
                (
                    (monitor_events["monitor_status"] == "vt_failed")
                    | (monitor_events["vt_error"].fillna("") != "")
                ).sum()
            ),
        )

        view_mode = st.radio(
            "Monitor view",
            ["All checked connections", "Attack detections only"],
            horizontal=True,
        )

        visible_monitor_events = monitor_events
        if view_mode == "Attack detections only":
            visible_monitor_events = visible_monitor_events[
                visible_monitor_events["is_detection"]
            ]

        st.dataframe(
            visible_monitor_events[
                [
                    "timestamp",
                    "monitor_status",
                    "external_ip",
                    "process",
                    "parent_process",
                    "attack_type",
                    "confidence",
                    "severity",
                    "risk_score",
                    "candidate_ioc",
                    "candidate_ioc_value",
                    "vt_malicious",
                    "vt_suspicious",
                    "vt_error",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

        if not visible_monitor_events.empty:
            selected_index = st.selectbox(
                "Inspect monitor event",
                visible_monitor_events.index.tolist(),
                format_func=lambda idx: (
                    f"{visible_monitor_events.loc[idx, 'external_ip']} | "
                    f"{visible_monitor_events.loc[idx, 'attack_type']} | "
                    f"{visible_monitor_events.loc[idx, 'timestamp']}"
                ),
            )
            record_index = int(visible_monitor_events.loc[selected_index, "record_index"])
            st.json(results[record_index])

with detection_tab:
    st.subheader("Recent detections")

    if not normalized:
        st.info("No detections are available.")
    else:
        dataframe = pd.DataFrame(list(reversed(normalized[-100:])))

        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )

with ioc_tab:
    st.subheader("Candidate IOC review")

    candidate_records = load_candidate_iocs()

    if not candidate_records:
        st.info(
            "No candidate IOCs were returned. Make sure the localhost API "
            "is running and that an attack detection created an IOC."
        )

    else:
        st.metric("Pending candidate IOCs", len(candidate_records))

        for ioc in candidate_records:
            ioc_id = str(
                ioc.get("ioc_id")
                or ioc.get("id")
                or ioc.get("indicator_id")
                or ""
            )

            ip_value = (
                ioc.get("value")
                or ioc.get("ip")
                or ioc.get("external_ip")
                or "Unknown"
            )

            attack_type = ioc.get("attack_type", "Unknown")
            severity = ioc.get("severity", "Unknown")
            confidence = float(ioc.get("attack_confidence", 0) or 0)

            title = (
                f"{ip_value} - "
                f"{str(attack_type).replace('_', ' ').title()}"
            )

            with st.expander(title):
                col1, col2, col3 = st.columns(3)

                col1.metric("Severity", str(severity).title())
                col2.metric("Attack confidence", f"{confidence:.1%}")
                col3.metric(
                    "VirusTotal malicious",
                    int(ioc.get("vt_malicious", 0) or 0),
                )

                st.write(
                    {
                        "IOC ID": ioc_id,
                        "Public IP": ip_value,
                        "Status": ioc.get("status", "candidate"),
                        "Attack type": attack_type,
                        "VT suspicious": ioc.get("vt_suspicious", 0),
                        "Internal hosts": ioc.get("internal_hosts", []),
                        "Created at": ioc.get("created_at", ioc.get("first_seen", "Unknown")),
                    }
                )

                analyst = st.text_input(
                    "Analyst name",
                    value="Tier 2 Analyst",
                    key=f"analyst_{ioc_id}",
                )

                notes = st.text_area(
                    "Investigation notes",
                    key=f"notes_{ioc_id}",
                )

                approve_column, reject_column = st.columns(2)

                if approve_column.button(
                    "Approve IOC",
                    key=f"approve_{ioc_id}",
                    use_container_width=True,
                ):
                    success, message = submit_ioc_decision(
                        ioc_id=ioc_id,
                        decision="approved",
                        analyst=analyst,
                        notes=notes,
                    )

                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)

                if reject_column.button(
                    "Reject IOC",
                    key=f"reject_{ioc_id}",
                    use_container_width=True,
                ):
                    success, message = submit_ioc_decision(
                        ioc_id=ioc_id,
                        decision="rejected",
                        analyst=analyst,
                        notes=notes,
                    )

                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)

with raw_tab:
    if not results:
        st.info("No raw collector records are available.")
    else:
        selected_index = st.number_input(
            "Record number",
            min_value=1,
            max_value=len(results),
            value=len(results),
        )

        st.json(results[int(selected_index) - 1])

st.sidebar.write(
    "Collector results:",
    "Available" if RESULTS_FILE.exists() else "Not created",
)

st.sidebar.write("Recorded events:", total_events)
st.sidebar.write("Windows monitor events:", monitor_event_count)
st.sidebar.write("Windows monitor detections:", monitor_detection_count)

if st.sidebar.button("Refresh dashboard"):
    st.rerun()

st.sidebar.divider()
st.sidebar.subheader("History reset")
st.sidebar.caption(
    "Clears collected results, monitor state, candidate IOCs, "
    "and dropped log files."
)
confirm_delete_history = st.sidebar.checkbox("Confirm delete history")

if st.sidebar.button(
    "Delete history",
    type="primary",
    disabled=not confirm_delete_history,
):
    deleted_items, delete_errors = delete_history()

    if delete_errors:
        st.sidebar.error("History reset finished with errors.")
        for error in delete_errors:
            st.sidebar.write(error)
    else:
        st.session_state["history_delete_summary"] = (
            f"History deleted. Cleared {deleted_items} stored item(s)."
        )
        st.rerun()
