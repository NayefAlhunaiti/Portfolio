from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import PurePath
from typing import Any, Mapping

from .models import IncidentInput

ALIASES = {
    "source_ip": ("source_ip", "src_ip", "SourceIp", "SourceIP", "LocalAddress", "local_ip", "internal_ip"),
    "destination_ip": ("destination_ip", "dst_ip", "DestinationIp", "DestinationIP", "RemoteAddress", "external_ip", "external_indicator"),
    "destination_port": ("destination_port", "dst_port", "DestinationPort", "RemotePort", "destinationPort"),
    "process_name": ("process_name", "Image", "ProcessName", "process", "application"),
    "parent_process": ("parent_process", "ParentImage", "ParentProcessName", "parent"),
    "username": ("username", "User", "user", "AccountName"),
    "timestamp": ("timestamp", "UtcTime", "TimeCreated", "time", "@timestamp"),
    "bytes_sent": ("bytes_sent", "BytesSent", "sent_bytes", "outbound_bytes"),
    "whitelisted_process": ("whitelisted_process", "Whitelisted", "is_whitelisted"),
    "known_business_service": ("known_business_service", "KnownBusinessService", "business_service"),
    "failed_logins_10m": ("failed_logins_10m", "FailedLogins10m"),
    "connection_count_10m": ("connection_count_10m", "ConnectionCount10m"),
    "unique_destinations_10m": ("unique_destinations_10m", "UniqueDestinations10m"),
    "outbound_bytes_ratio": ("outbound_bytes_ratio", "OutboundBytesRatio"),
}

DEFAULT_WHITELISTED = {
    "chrome.exe", "msedge.exe", "firefox.exe", "powershell.exe", "cmd.exe",
    "rundll32.exe", "regsvr32.exe", "schtasks.exe", "svchost.exe",
    "teams.exe", "outlook.exe", "python.exe", "code.exe",
}


def _first(record: Mapping[str, Any], names: tuple[str, ...], default: Any = None) -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None: return default
    if isinstance(value, bool): return value
    if isinstance(value, (int, float)): return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _int(value: Any, default: int = 0) -> int:
    try: return int(float(value))
    except (TypeError, ValueError): return default


def _float(value: Any, default: float = 0.0) -> float:
    try: return float(value)
    except (TypeError, ValueError): return default


def _process_basename(value: Any, default: str = "unknown.exe") -> str:
    if not value: return default
    text = str(value).strip().replace("\\", "/")
    return PurePath(text).name.lower() or default


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if value:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _ip(value: Any):
    try: return ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError): return None


def normalize_security_event(record: Mapping[str, Any]) -> IncidentInput | None:
    """Normalize common Sysmon, firewall, SIEM, or connection fields.

    Only events containing one private/non-global side and one public/global side are
    promoted to IncidentInput. The public side becomes the external IP checked by
    VirusTotal. Events without a public IP are ignored.
    """
    source_raw = _first(record, ALIASES["source_ip"])
    destination_raw = _first(record, ALIASES["destination_ip"])
    source = _ip(source_raw)
    destination = _ip(destination_raw)
    if source is None or destination is None:
        return None

    if not source.is_global and destination.is_global:
        internal_ip, external_ip = str(source), str(destination)
    elif source.is_global and not destination.is_global:
        internal_ip, external_ip = str(destination), str(source)
    else:
        return None

    process_name = _process_basename(_first(record, ALIASES["process_name"]))
    parent_process = _process_basename(
        _first(record, ALIASES["parent_process"]), default="unknown.exe"
    )
    whitelisted_raw = _first(record, ALIASES["whitelisted_process"])
    whitelisted = _bool(
        whitelisted_raw,
        default=process_name in DEFAULT_WHITELISTED,
    )

    return IncidentInput(
        internal_ip=internal_ip,
        external_ip=external_ip,
        process_name=process_name,
        parent_process=parent_process,
        username=str(_first(record, ALIASES["username"], "unknown")),
        timestamp=_timestamp(_first(record, ALIASES["timestamp"])),
        destination_port=max(1, min(_int(_first(record, ALIASES["destination_port"]), 443), 65535)),
        bytes_sent=max(0, _int(_first(record, ALIASES["bytes_sent"]), 0)),
        whitelisted_process=whitelisted,
        known_business_service=_bool(_first(record, ALIASES["known_business_service"])),
        failed_logins_10m=max(0, _int(_first(record, ALIASES["failed_logins_10m"]), 0)),
        connection_count_10m=max(0, _int(_first(record, ALIASES["connection_count_10m"]), 1)),
        unique_destinations_10m=max(0, _int(_first(record, ALIASES["unique_destinations_10m"]), 1)),
        outbound_bytes_ratio=max(0.0, _float(_first(record, ALIASES["outbound_bytes_ratio"]), 1.0)),
    )
