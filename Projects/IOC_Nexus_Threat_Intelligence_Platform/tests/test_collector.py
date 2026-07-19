from pathlib import Path
from ioc_nexus.collector import AutomaticLogCollector, CollectorConfig


def test_folder_collector_processes_csv(tmp_path: Path):
    incoming=tmp_path/"incoming"; processed=tmp_path/"processed"; failed=tmp_path/"failed"
    incoming.mkdir()
    sample=incoming/"events.csv"
    sample.write_text(
        "SourceIp,DestinationIp,DestinationPort,Image,ParentImage,UtcTime,BytesSent,Whitelisted,ConnectionCount10m,UniqueDestinations10m,OutboundBytesRatio\n"
        "10.20.5.14,1.1.1.1,443,powershell.exe,winword.exe,2026-07-15T02:34:00Z,9500000,true,85,2,4.0\n",
        encoding="utf-8",
    )
    config=CollectorConfig(
        incoming_dir=incoming, processed_dir=processed, failed_dir=failed,
        results_path=tmp_path/"results.jsonl", state_db=tmp_path/"state.db",
        model_path=Path("artifacts/ml/model_bundle.joblib"), ioc_db_path=tmp_path/"iocs.db",
        mock_vt=True, settle_seconds=0,
    )
    result=AutomaticLogCollector(config).process_file(sample)
    assert result["status"] == "processed"
    assert result["normalized"] == 1
    assert (tmp_path/"results.jsonl").exists()
