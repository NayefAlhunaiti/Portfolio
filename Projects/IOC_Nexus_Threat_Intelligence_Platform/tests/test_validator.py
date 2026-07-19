from ioc_nexus.validator import classify_indicator

def test_private_ip_is_not_queryable():
    result = classify_indicator("10.20.5.14"); assert result.indicator_type == "ip"; assert result.globally_queryable is False

def test_public_ip_is_queryable():
    result = classify_indicator("1.1.1.1"); assert result.indicator_type == "ip"; assert result.globally_queryable is True

def test_non_ip_is_rejected():
    result = classify_indicator("example.com"); assert result.indicator_type == "unknown"; assert result.globally_queryable is False
