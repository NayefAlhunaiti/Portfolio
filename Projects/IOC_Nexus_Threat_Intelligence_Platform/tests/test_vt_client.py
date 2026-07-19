from ioc_nexus.models import IOCClassification
from ioc_nexus.vt_client import VirusTotalClient, has_real_api_key


def _public_ip():
    return IOCClassification(
        indicator="1.1.1.1",
        indicator_type="ip",
        globally_queryable=True,
        reason="public",
    )


def test_placeholder_api_key_is_not_configured():
    assert not has_real_api_key("replace_with_your_key")
    report = VirusTotalClient(api_key="replace_with_your_key").lookup(_public_ip())
    assert report.queried is False
    assert report.error == "VT_API_KEY is not configured."
