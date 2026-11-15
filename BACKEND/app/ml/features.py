"""Pure lexical feature extraction for phishing URL detection (training and inference)."""

import math
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

import tldextract

from app.data.brands import KNOWN_BRANDS
from app.data.risky_tlds import RISKY_TLDS
from app.data.shorteners import URL_SHORTENERS
from app.data.suspicious_keywords import SUSPICIOUS_KEYWORDS

# 34 stable feature IDs in exact contract order (Rule 7)
FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count_host",
    "hyphen_count_url",
    "underscore_count",
    "digit_count_url",
    "digit_ratio_host",
    "subdomain_count",
    "has_ip_host",
    "has_at_symbol",
    "is_https",
    "has_custom_port",
    "double_slash_in_path",
    "query_param_count",
    "special_char_count",
    "host_entropy",
    "path_entropy",
    "longest_host_token",
    "has_punycode",
    "risky_tld",
    "is_shortener",
    "keyword_count_host",
    "keyword_count_path",
    "brand_in_subdomain",
    "brand_in_path",
    "path_depth",
    "suspicious_extension",
    "percent_encoded_count",
    "vowel_ratio_host",
    "registered_domain_length",
    "uppercase_count",
)

# Precompiled patterns
PERCENT_ENCODED_REGEX = re.compile(r"%[0-9a-fA-F]{2}")
IPV4_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
SPECIAL_CHARS_SET = frozenset("?=-_.#%&@+~$;:,!")
VOWELS_SET = frozenset("aeiouAEIOU")
SUSPICIOUS_EXTENSIONS = (
    ".php",
    ".exe",
    ".zip",
    ".scr",
    ".apk",
    ".html",
    ".htm",
    ".bat",
    ".cmd",
    ".sh",
    ".iso",
    ".jar",
)

# Bundled offline tldextract instance
_tld_extractor = tldextract.TLDExtract(
    cache_dir=False,
    suffix_list_urls=None,
    include_psl_private_domains=True,
)


def _shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy (base 2) for a given string."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 4)


def extract_features(url: str) -> dict[str, Any]:
    """Extracts exactly 34 lexical and structural features from a URL.

    Pure function: no network calls, never raises on malformed input, returns stable dict.
    Booleans are returned as bool (converted to 0/1 during model preprocessing).
    """
    safe_url = str(url).strip() if url is not None else ""

    try:
        # Prepend scheme if missing for parsing
        parse_target = safe_url
        if parse_target.startswith("//"):
            parse_target = "https:" + parse_target
        elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_target):
            parse_target = "https://" + parse_target

        parsed = urlparse(parse_target)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port
    except Exception:
        scheme = "https" if safe_url.startswith("https") else "http"
        host = ""
        path = ""
        query = ""
        port = None

    # Lengths
    url_length = len(safe_url)
    host_length = len(host)
    path_length = len(path)
    query_length = len(query)

    # Character counts
    dot_count = safe_url.count(".")
    hyphen_count_host = host.count("-")
    hyphen_count_url = safe_url.count("-")
    underscore_count = safe_url.count("_")
    digit_count_url = sum(1 for c in safe_url if c.isdigit())
    digit_ratio_host = round((sum(1 for c in host if c.isdigit()) / host_length), 4) if host_length > 0 else 0.0

    # Domain & Subdomain parts
    subdomain_count = 0
    registered_domain = host
    suffix = ""
    subdomain = ""
    if host:
        try:
            ext = _tld_extractor(host)
            reg_dom = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
            registered_domain = reg_dom or host
            subdomain = ext.subdomain or ""
            suffix = ext.suffix or ""
            if subdomain:
                subdomain_count = len([p for p in subdomain.split(".") if p])
        except Exception:
            subdomain_count = 0
            registered_domain = host

    # IP host check
    clean_host = host.strip("[]")
    has_ip_host = bool(IPV4_REGEX.match(clean_host) or ":" in clean_host)

    # Authentication & Protocol
    has_at_symbol = "@" in safe_url
    is_https = scheme == "https"
    has_custom_port = port is not None and port not in (80, 443)
    double_slash_in_path = "//" in path

    # Query & Special characters
    query_param_count = 0
    if query:
        try:
            query_param_count = len(parse_qs(query, keep_blank_values=True))
        except Exception:
            query_param_count = query.count("&") + 1

    special_char_count = sum(1 for c in safe_url if c in SPECIAL_CHARS_SET)

    # Entropies
    host_entropy = _shannon_entropy(host)
    path_entropy = _shannon_entropy(path) if path and path != "/" else 0.0

    # Longest token in host
    host_tokens = [tok for tok in re.split(r"[\.-]", host) if tok]
    longest_host_token = max((len(tok) for tok in host_tokens), default=0)

    # Punycode
    has_punycode = "xn--" in host

    # Risky TLD & Shortener
    risky_tld = suffix.lower() in RISKY_TLDS
    is_shortener = registered_domain.lower() in URL_SHORTENERS

    # Keywords in host vs path
    host_lower = host.lower()
    keyword_count_host = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in host_lower)
    path_query_lower = (path + "?" + query).lower()
    keyword_count_path = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in path_query_lower)

    # Brand spoofing in subdomain and path
    brand_in_subdomain = False
    brand_in_path = False
    sub_lower = subdomain.lower()
    path_lower = path.lower()
    reg_lower = registered_domain.lower()

    for brand, official_domains in KNOWN_BRANDS.items():
        official_set = {d.lower() for d in official_domains}
        if brand in sub_lower and reg_lower not in official_set:
            brand_in_subdomain = True
        if brand in path_lower and reg_lower not in official_set:
            brand_in_path = True
        if brand_in_subdomain and brand_in_path:
            break

    # Path depth
    path_depth = len([p for p in path.split("/") if p])

    # Suspicious extension
    suspicious_extension = False
    lower_path = path.lower()
    for ext_candidate in SUSPICIOUS_EXTENSIONS:
        if lower_path.endswith(ext_candidate) or (ext_candidate in lower_path and not lower_path.endswith((".html", ".htm"))):
            suspicious_extension = True
            break

    # Percent encoded count
    percent_encoded_count = len(PERCENT_ENCODED_REGEX.findall(safe_url))

    # Vowel ratio in host
    vowel_count_host = sum(1 for c in host if c in VOWELS_SET)
    vowel_ratio_host = round((vowel_count_host / host_length), 4) if host_length > 0 else 0.0

    registered_domain_length = len(registered_domain)
    uppercase_count = sum(1 for c in safe_url if c.isupper())

    # Build exact feature map in fixed contract order
    features = {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "query_length": query_length,
        "dot_count": dot_count,
        "hyphen_count_host": hyphen_count_host,
        "hyphen_count_url": hyphen_count_url,
        "underscore_count": underscore_count,
        "digit_count_url": digit_count_url,
        "digit_ratio_host": digit_ratio_host,
        "subdomain_count": subdomain_count,
        "has_ip_host": has_ip_host,
        "has_at_symbol": has_at_symbol,
        "is_https": is_https,
        "has_custom_port": has_custom_port,
        "double_slash_in_path": double_slash_in_path,
        "query_param_count": query_param_count,
        "special_char_count": special_char_count,
        "host_entropy": host_entropy,
        "path_entropy": path_entropy,
        "longest_host_token": longest_host_token,
        "has_punycode": has_punycode,
        "risky_tld": risky_tld,
        "is_shortener": is_shortener,
        "keyword_count_host": keyword_count_host,
        "keyword_count_path": keyword_count_path,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "path_depth": path_depth,
        "suspicious_extension": suspicious_extension,
        "percent_encoded_count": percent_encoded_count,
        "vowel_ratio_host": vowel_ratio_host,
        "registered_domain_length": registered_domain_length,
        "uppercase_count": uppercase_count,
    }

    return features
