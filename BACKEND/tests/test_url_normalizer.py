"""Unit tests for URL normalizer and IPv4 decoder."""

import pytest

from app.core.errors import InvalidUrlError, UnsupportedSchemeError
from app.services.url_normalizer import parse_and_normalize_url


def test_missing_scheme():
    result = parse_and_normalize_url("example.com/dashboard?query=1")
    assert result.scheme == "https"
    assert result.normalized_url == "https://example.com/dashboard?query=1"


def test_uppercase_host():
    result = parse_and_normalize_url("HTTPS://WWW.EXAMPLE.COM/Login")
    assert result.host == "www.example.com"
    assert result.normalized_url == "https://www.example.com/Login"


def test_fragment_removal():
    result = parse_and_normalize_url("https://example.com/about#team-section")
    assert result.normalized_url == "https://example.com/about"
    assert "#" not in result.normalized_url


def test_default_ports_dropped():
    # HTTP port 80
    r_http = parse_and_normalize_url("http://example.com:80/path")
    assert r_http.port is None
    assert r_http.normalized_url == "http://example.com/path"

    # HTTPS port 443
    r_https = parse_and_normalize_url("https://example.com:443/path")
    assert r_https.port is None
    assert r_https.normalized_url == "https://example.com/path"

    # Custom port retained
    r_custom = parse_and_normalize_url("https://example.com:8443/api")
    assert r_custom.port == 8443
    assert r_custom.normalized_url == "https://example.com:8443/api"


def test_userinfo_credentials():
    result = parse_and_normalize_url("https://admin:supersecret@portal.example.com/admin")
    assert result.has_userinfo is True
    assert "admin:supersecret" not in result.normalized_url
    assert result.normalized_url == "https://portal.example.com/admin"


def test_idn_to_punycode():
    result = parse_and_normalize_url("https://münchen.de")
    assert result.ascii_host == "xn--mnchen-3ya.de"
    assert "xn--mnchen-3ya.de" in result.normalized_url


def test_decimal_and_hex_ipv4_decoding():
    # 2130706433 is decimal representation of 127.0.0.1
    r_dec = parse_and_normalize_url("http://2130706433/index.html")
    assert r_dec.host == "127.0.0.1"
    assert r_dec.is_ip is True
    assert r_dec.normalized_url == "http://127.0.0.1/index.html"

    # Hex 0x7f000001
    r_hex = parse_and_normalize_url("http://0x7f000001/admin")
    assert r_hex.host == "127.0.0.1"
    assert r_hex.is_ip is True

    # Multi-format 0x7f.1
    r_dotted = parse_and_normalize_url("http://0x7f.1/test")
    assert r_dotted.host == "127.0.0.1"

    # Octal 0177.0.0.1
    r_oct = parse_and_normalize_url("http://0177.0.0.1/test")
    assert r_oct.host == "127.0.0.1"


def test_url_too_long():
    long_url = "https://example.com/" + "a" * 2050
    with pytest.raises(InvalidUrlError) as exc_info:
        parse_and_normalize_url(long_url)
    assert exc_info.value.code.value == "INVALID_URL"


def test_unsupported_scheme():
    with pytest.raises(UnsupportedSchemeError) as exc_info:
        parse_and_normalize_url("ftp://files.example.com/archive.zip")
    assert exc_info.value.code.value == "UNSUPPORTED_SCHEME"

    with pytest.raises(UnsupportedSchemeError):
        parse_and_normalize_url("file:///etc/passwd")


def test_empty_and_control_chars_input():
    with pytest.raises(InvalidUrlError):
        parse_and_normalize_url("")

    with pytest.raises(InvalidUrlError):
        parse_and_normalize_url("   \t  \n  ")

    with pytest.raises(InvalidUrlError):
        parse_and_normalize_url("\u200b\u200c\ufeff")


def test_psl_private_domains():
    result = parse_and_normalize_url("https://evil.github.io/payload")
    # With include_psl_private_domains=True, evil.github.io is treated as registered domain
    assert result.registered_domain == "evil.github.io"
