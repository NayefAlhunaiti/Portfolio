import csv, json, ipaddress
from pathlib import Path
from ioc_nexus.synthetic_generator import generate_dataset

def test_generator(tmp_path: Path):
    summary = generate_dataset(count=180, seed=7, output_dir=tmp_path)
    rows = [json.loads(line) for line in (tmp_path / "synthetic_soc_incidents.jsonl").read_text().splitlines()]
    assert len(rows) == 180; assert summary["generated_records"] == 180
    assert all(row["indicator_type"] == "ip" for row in rows)
    assert all(ipaddress.ip_address(row["external_ip"]) for row in rows)
    assert {row["attack_type"] for row in rows} - {"benign"}

def test_reproducible(tmp_path: Path):
    generate_dataset(count=180, seed=99, output_dir=tmp_path / "a"); generate_dataset(count=180, seed=99, output_dir=tmp_path / "b")
    assert (tmp_path / "a/synthetic_soc_incidents.jsonl").read_text() == (tmp_path / "b/synthetic_soc_incidents.jsonl").read_text()
