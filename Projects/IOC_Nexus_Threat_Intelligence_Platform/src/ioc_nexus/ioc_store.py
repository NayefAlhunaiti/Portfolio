from __future__ import annotations

import ipaddress, json, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path
from .models import CandidateIOC, IOCDecisionInput


class IOCStore:
    def __init__(self, path: str | Path = "data/ioc_registry.db"):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True); self._init()
    def _connect(self):
        c = sqlite3.connect(self.path); c.row_factory = sqlite3.Row; return c
    def _init(self):
        with self._connect() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS candidate_iocs (
                ioc_id TEXT PRIMARY KEY, ioc_type TEXT NOT NULL, value TEXT NOT NULL,
                status TEXT NOT NULL, source TEXT NOT NULL, attack_type TEXT NOT NULL,
                attack_confidence REAL NOT NULL, severity TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrence_count INTEGER NOT NULL,
                internal_hosts TEXT NOT NULL, evidence TEXT NOT NULL, vt_malicious INTEGER NOT NULL,
                vt_suspicious INTEGER NOT NULL, analyst_approval_required INTEGER NOT NULL,
                analyst TEXT, analyst_notes TEXT
            )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON candidate_iocs(value, status)")
    @staticmethod
    def _row(row):
        return CandidateIOC(
            ioc_id=row["ioc_id"], ioc_type=row["ioc_type"], value=row["value"], status=row["status"], source=row["source"], attack_type=row["attack_type"],
            attack_confidence=row["attack_confidence"], severity=row["severity"], first_seen=datetime.fromisoformat(row["first_seen"]), last_seen=datetime.fromisoformat(row["last_seen"]), occurrence_count=row["occurrence_count"],
            internal_hosts=json.loads(row["internal_hosts"]), evidence=json.loads(row["evidence"]), vt_malicious=row["vt_malicious"], vt_suspicious=row["vt_suspicious"], analyst_approval_required=bool(row["analyst_approval_required"]), analyst=row["analyst"], analyst_notes=row["analyst_notes"])
    def create_or_update(self, *, value, attack_type, attack_confidence, severity, internal_host, evidence, vt_malicious, vt_suspicious):
        ip = ipaddress.ip_address(value); now = datetime.now(timezone.utc)
        with self._connect() as c:
            row = c.execute("SELECT * FROM candidate_iocs WHERE value=? AND attack_type=? AND status='candidate' ORDER BY last_seen DESC LIMIT 1", (value, attack_type)).fetchone()
            if row:
                hosts = sorted(set(json.loads(row["internal_hosts"]) + [internal_host])); combined_evidence = list(dict.fromkeys(json.loads(row["evidence"]) + evidence))
                c.execute("UPDATE candidate_iocs SET last_seen=?, occurrence_count=?, internal_hosts=?, evidence=?, attack_confidence=?, severity=?, vt_malicious=?, vt_suspicious=? WHERE ioc_id=?", (now.isoformat(), row["occurrence_count"] + 1, json.dumps(hosts), json.dumps(combined_evidence), max(row["attack_confidence"], attack_confidence), severity, max(row["vt_malicious"], vt_malicious), max(row["vt_suspicious"], vt_suspicious), row["ioc_id"]))
                updated = c.execute("SELECT * FROM candidate_iocs WHERE ioc_id=?", (row["ioc_id"],)).fetchone(); return self._row(updated)
            ioc_id = str(uuid.uuid4()); ioc_type = "ipv4" if ip.version == 4 else "ipv6"
            c.execute("INSERT INTO candidate_iocs VALUES (?, ?, ?, 'candidate', 'local_ml_detection', ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 1, NULL, NULL)", (ioc_id, ioc_type, value, attack_type, attack_confidence, severity, now.isoformat(), now.isoformat(), json.dumps([internal_host]), json.dumps(evidence), vt_malicious, vt_suspicious))
            return self._row(c.execute("SELECT * FROM candidate_iocs WHERE ioc_id=?", (ioc_id,)).fetchone())
    def list(self, status: str = "candidate", limit: int = 100):
        with self._connect() as c: rows = c.execute("SELECT * FROM candidate_iocs WHERE status=? ORDER BY last_seen DESC LIMIT ?", (status, max(1, min(limit, 500)))).fetchall()
        return [self._row(r) for r in rows]
    def decide(self, ioc_id: str, decision: IOCDecisionInput):
        with self._connect() as c:
            c.execute("UPDATE candidate_iocs SET status=?, analyst_approval_required=0, analyst=?, analyst_notes=? WHERE ioc_id=?", (decision.decision, decision.analyst, decision.notes, ioc_id))
            row = c.execute("SELECT * FROM candidate_iocs WHERE ioc_id=?", (ioc_id,)).fetchone()
        if not row: raise KeyError(f"IOC not found: {ioc_id}")
        return self._row(row)
