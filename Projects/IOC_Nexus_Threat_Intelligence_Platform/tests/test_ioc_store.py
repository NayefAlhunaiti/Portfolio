from pathlib import Path
from ioc_nexus.ioc_store import IOCStore
from ioc_nexus.models import IOCDecisionInput

def test_candidate_ioc_lifecycle(tmp_path: Path):
    store = IOCStore(tmp_path / "iocs.db")
    candidate = store.create_or_update(value="1.1.1.1", attack_type="command_and_control", attack_confidence=.91, severity="critical", internal_host="10.0.0.5", evidence=["test"], vt_malicious=5, vt_suspicious=2)
    assert candidate.status == "candidate"; assert len(store.list()) == 1
    approved = store.decide(candidate.ioc_id, IOCDecisionInput(decision="approved", analyst="tier2", notes="confirmed"))
    assert approved.status == "approved"; assert approved.analyst_approval_required is False
