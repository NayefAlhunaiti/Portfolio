import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def execute_action(action, details, config):
    """Execute an action against Ariba or simulate locally.

    action: str (e.g., 'create_requisition', 'update_order')
    details: dict with action-specific fields
    config: loaded config dict
    """
    if not config.get("ariba_enabled", False):
        # Simulate by writing details to a local file and return a simulated id
        path = ROOT / "ariba_simulator.log"
        entry = {"action": action, "details": details}
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return {"status": "simulated", "id": f"sim-{hash(json.dumps(entry)) % 100000}"}

    # Real Ariba call path (requires credentials and proper API)
    base = config.get("ariba_base_url")
    api_key = config.get("ariba_api_key")
    if not base:
        raise RuntimeError("Ariba base URL not configured")

    url = f"{base}/actions/{action}"
    data = json.dumps(details).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))
