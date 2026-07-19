from ioc_nexus.normalizer import normalize_security_event


def test_outbound_public_ip_is_normalized():
    incident = normalize_security_event({
        "SourceIp": "10.20.5.14", "DestinationIp": "1.1.1.1",
        "DestinationPort": "443", "Image": r"C:\Windows\powershell.exe",
        "ParentImage": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        "UtcTime": "2026-07-15T02:34:00Z",
    })
    assert incident is not None
    assert incident.internal_ip == "10.20.5.14"
    assert incident.external_ip == "1.1.1.1"
    assert incident.process_name == "powershell.exe"
    assert incident.parent_process == "winword.exe"


def test_inbound_public_ip_is_normalized():
    incident = normalize_security_event({
        "SourceIp": "8.8.8.8", "DestinationIp": "10.20.5.14",
        "DestinationPort": 443, "ProcessName": "server.exe",
    })
    assert incident is not None
    assert incident.internal_ip == "10.20.5.14"
    assert incident.external_ip == "8.8.8.8"


def test_internal_to_internal_is_ignored():
    assert normalize_security_event({"SourceIp":"10.0.0.1","DestinationIp":"10.0.0.2"}) is None


def test_non_ip_is_ignored():
    assert normalize_security_event({"SourceIp":"10.0.0.1","DestinationIp":"example.com"}) is None
