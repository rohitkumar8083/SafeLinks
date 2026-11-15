"""Unit tests for ML feature extraction pipeline."""

from app.ml.features import FEATURE_NAMES, extract_features


def test_features_count_and_order():
    url = "https://example.com/path?arg=1"
    feats = extract_features(url)

    # Must contain exactly 34 features in fixed contract order
    assert len(feats) == 34
    assert tuple(feats.keys()) == FEATURE_NAMES


def test_malformed_urls_never_raise():
    malformed_inputs = [
        "",
        "   ",
        "://invalid-url",
        "https://",
        "http://[:::1234]///",
        "ftp:///something",
        "javascript:alert(1)",
        "http://" + "a" * 3000,
        None,
    ]

    for bad_input in malformed_inputs:
        feats = extract_features(bad_input)
        assert len(feats) == 34
        assert tuple(feats.keys()) == FEATURE_NAMES
        assert isinstance(feats["url_length"], int)
        assert isinstance(feats["is_https"], bool)


def test_spot_check_benign_url():
    url = "https://google.com/search?q=safelinks"
    feats = extract_features(url)

    assert feats["is_https"] is True
    assert feats["has_ip_host"] is False
    assert feats["has_custom_port"] is False
    assert feats["has_at_symbol"] is False
    assert feats["dot_count"] == 1
    assert feats["query_param_count"] == 1
    assert feats["path_depth"] == 1
    assert feats["risky_tld"] is False
    assert feats["brand_in_subdomain"] is False
    assert feats["brand_in_path"] is False


def test_spot_check_phishing_indicators():
    url = "http://user:pass@paypal.account-verify.xyz:8080/secure/login"
    feats = extract_features(url)

    assert feats["is_https"] is False
    assert feats["has_at_symbol"] is True
    assert feats["has_custom_port"] is True
    assert feats["risky_tld"] is True
    assert feats["brand_in_subdomain"] is True
    assert feats["keyword_count_host"] >= 1  # 'verify'
    assert feats["keyword_count_path"] >= 2  # 'secure', 'login'
    assert feats["subdomain_count"] >= 1


def test_spot_check_ip_host():
    url = "http://192.168.1.1/admin/login.php"
    feats = extract_features(url)

    assert feats["has_ip_host"] is True
    assert feats["suspicious_extension"] is True  # .php
    assert feats["is_https"] is False
