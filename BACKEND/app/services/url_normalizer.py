"""URL normalization and parsing engine with non-standard IPv4 decoding and PSL extraction."""

import ipaddress
import re
from typing import NamedTuple
from urllib.parse import urlparse, urlunparse

import tldextract

from app.constants import DEFAULT_PORTS, MAX_URL_LENGTH
from app.core.errors import InvalidUrlError, UnsupportedSchemeError

# Control characters and zero-width characters to strip
STRIP_CHARS_PATTERN = re.compile(
    r"[\x00-\x1f\x7f-\x9f"  # ASCII control codes
    r"\u200b-\u200d\ufeff"  # Zero-width spaces & BOM
    r"\u200e\u200f\u202a-\u202e]"  # Directional & bidi formatting characters
)

# Standard URL scheme prefix regex
SCHEME_PREFIX_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Bundled offline tldextract instance (no network queries at runtime)
_tld_extractor = tldextract.TLDExtract(
    cache_dir=False,
    suffix_list_urls=None,
    include_psl_private_domains=True,
)


class NormalizedURL(NamedTuple):
    submitted_url: str
    normalized_url: str
    scheme: str
    host: str
    ascii_host: str
    unicode_host: str
    port: int | None
    path: str
    query: str
    registered_domain: str
    subdomain: str
    suffix: str
    has_userinfo: bool
    is_ip: bool
    ip_address: str | None


def decode_non_standard_ipv4(host: str) -> str | None:
    """Detects and decodes non-standard IPv4 host formats.

    Supports:
    - Pure decimal: 2130706433 -> 127.0.0.1
    - Pure hex: 0x7f000001 -> 127.0.0.1
    - Dotted octal/hex/decimal: 0x7f.1 -> 127.0.0.1, 0177.0.0.1 -> 127.0.0.1
    """
    clean = host.strip("[]")
    if not clean:
        return None

    # Check if host contains invalid characters for IPv4 representation
    if not re.match(r"^[0-9a-fA-FxX.]+$", clean):
        return None

    parts = clean.split(".")
    if not (1 <= len(parts) <= 4):
        return None

    parsed_values: list[int] = []
    for p in parts:
        if not p:
            return None
        try:
            if p.lower().startswith("0x"):
                val = int(p, 16)
            elif p.startswith("0") and len(p) > 1 and not any(c in "89abcdefABCDEF" for c in p):
                val = int(p, 8)
            else:
                val = int(p, 10)
            parsed_values.append(val)
        except ValueError:
            return None

    # Compute 32-bit IPv4 integer based on standard inet_aton component count
    try:
        if len(parsed_values) == 1:
            ip_int = parsed_values[0]
        elif len(parsed_values) == 2:
            if parsed_values[0] > 255 or parsed_values[1] > 0xFFFFFF:
                return None
            ip_int = (parsed_values[0] << 24) | parsed_values[1]
        elif len(parsed_values) == 3:
            if parsed_values[0] > 255 or parsed_values[1] > 255 or parsed_values[2] > 0xFFFF:
                return None
            ip_int = (parsed_values[0] << 24) | (parsed_values[1] << 16) | parsed_values[2]
        elif len(parsed_values) == 4:
            if any(v > 255 for v in parsed_values):
                return None
            ip_int = (
                (parsed_values[0] << 24)
                | (parsed_values[1] << 16)
                | (parsed_values[2] << 8)
                | parsed_values[3]
            )
        else:
            return None

        if 0 <= ip_int <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(ip_int))
    except (ValueError, OverflowError):
        return None

    return None


def parse_and_normalize_url(raw_url: str) -> NormalizedURL:
    """Normalizes and validates a submitted URL according to SafeLinks rules."""
    # 1. Clean input
    cleaned = STRIP_CHARS_PATTERN.sub("", raw_url).strip()
    if not cleaned:
        raise InvalidUrlError("URL cannot be empty")
    if len(cleaned) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL length ({len(cleaned)}) exceeds maximum allowed ({MAX_URL_LENGTH})")

    # 2. Scheme validation & normalization
    working_url = cleaned
    if working_url.startswith("//"):
        working_url = "https:" + working_url
    elif not SCHEME_PREFIX_PATTERN.match(working_url):
        working_url = "https://" + working_url

    parsed = urlparse(working_url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise UnsupportedSchemeError(f"Scheme '{scheme}' is not supported; only http and https are allowed")

    # 3. Userinfo check & extraction
    has_userinfo = bool(parsed.username or parsed.password or ("@" in (parsed.netloc.split(":")[0] if parsed.netloc else "")))
    raw_host = parsed.hostname
    if not raw_host:
        raise InvalidUrlError("URL is missing a valid hostname")

    # 4. Check for decoded non-standard IPv4
    decoded_ip = decode_non_standard_ipv4(raw_host)
    is_ip = False
    ip_addr_str: str | None = None

    if decoded_ip is not None:
        raw_host = decoded_ip
        is_ip = True
        ip_addr_str = decoded_ip
    else:
        # Check standard IPv6 or IPv4
        try:
            ip_obj = ipaddress.ip_address(raw_host.strip("[]"))
            is_ip = True
            ip_addr_str = str(ip_obj)
        except ValueError:
            is_ip = False

    # 5. Hostname normalization & IDN handling
    lower_host = raw_host.lower()
    try:
        # Punycode conversion for IDN homograph handling
        ascii_host = lower_host.encode("idna").decode("ascii")
        try:
            unicode_host = ascii_host.encode("ascii").decode("idna")
        except Exception:
            unicode_host = lower_host
    except Exception:
        ascii_host = lower_host
        unicode_host = lower_host

    # 6. Port normalization (drop default 80 / 443)
    raw_port = parsed.port
    final_port: int | None = None
    if raw_port is not None:
        if raw_port != DEFAULT_PORTS.get(scheme):
            final_port = raw_port

    # 7. Path and Query normalization (preserve as sent, drop fragment)
    path = parsed.path or "/"
    query = parsed.query

    # 8. Registered domain and subdomain extraction via tldextract
    if is_ip:
        registered_domain = ascii_host
        subdomain = ""
        suffix = ""
    else:
        ext = _tld_extractor(ascii_host)
        reg_domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
        registered_domain = reg_domain or ascii_host
        subdomain = ext.subdomain
        suffix = ext.suffix

    # 9. Build normalized URL string without credentials or fragment
    netloc_parts: list[str] = [ascii_host]
    if final_port is not None:
        netloc_parts.append(f":{final_port}")
    normalized_netloc = "".join(netloc_parts)

    normalized_url = urlunparse((
        scheme,
        normalized_netloc,
        path,
        "",  # params
        query,
        "",  # fragment dropped
    ))

    return NormalizedURL(
        submitted_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        host=ascii_host,
        ascii_host=ascii_host,
        unicode_host=unicode_host,
        port=final_port,
        path=path,
        query=query,
        registered_domain=registered_domain,
        subdomain=subdomain,
        suffix=suffix,
        has_userinfo=has_userinfo,
        is_ip=is_ip,
        ip_address=ip_addr_str,
    )
