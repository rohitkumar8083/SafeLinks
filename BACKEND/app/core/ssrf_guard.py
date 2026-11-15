"""SSRF protection guard: IP validation, DNS resolution, and target blocking."""

import asyncio
import ipaddress
import logging
import socket
from typing import NamedTuple

from app.core.errors import BlockedTargetError

logger = logging.getLogger("safelinks.ssrf")

# Explicit blocked networks beyond standard library properties
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),  # Private RFC1918
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),  # Private RFC1918
    ipaddress.ip_network("198.18.0.0/15"),  # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("::/128"),  # Unspecified
    ipaddress.ip_network("100::/64"),  # Discard-only
    ipaddress.ip_network("2001:db8::/32"),  # Documentation
    ipaddress.ip_network("fc00::/7"),  # Unique local (ULA)
    ipaddress.ip_network("fe80::/10"),  # Link-local unicast
    ipaddress.ip_network("ff00::/8"),  # Multicast
]

ALLOWED_FETCH_PORTS = {80, 443}
NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


class ResolutionResult(NamedTuple):
    resolved_ips: list[str]
    dns_failed: bool
    error_message: str | None


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks whether an IP address falls into a disallowed/private/reserved range."""
    # Handle IPv4-mapped IPv6 address (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_blocked_ip(ip.ipv4_mapped)

    # Handle NAT64 well-known prefix (64:ff9b::/96) by validating embedded IPv4
    if isinstance(ip, ipaddress.IPv6Address) and ip in NAT64_PREFIX:
        embedded_ipv4 = ipaddress.IPv4Address(ip.packed[-4:])
        return is_blocked_ip(embedded_ipv4)

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return True
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if ip in net:
                return True

    return False


def parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Attempts to parse host as an IPv4 or IPv6 address literal."""
    # Strip brackets for IPv6 literals e.g. [::1]
    clean_host = host.strip("[]")
    try:
        return ipaddress.ip_address(clean_host)
    except ValueError:
        return None


async def resolve_host_ips(host: str, timeout: float = 3.0) -> ResolutionResult:
    """Resolves a hostname to IPv4 and IPv6 addresses with a timeout.

    Returns ResolutionResult. A DNS failure (NXDOMAIN / not found) sets dns_failed=True.
    """
    # Check if host is already an IP literal
    ip_literal = parse_ip_literal(host)
    if ip_literal is not None:
        return ResolutionResult(resolved_ips=[str(ip_literal)], dns_failed=False, error_message=None)

    # Resolve hostname
    loop = asyncio.get_running_loop()
    try:
        # loop.getaddrinfo accepts host, port, and keyword-only family/type arguments
        addr_info = await asyncio.wait_for(
            loop.getaddrinfo(host, 0, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
        ips = list(dict.fromkeys(info[4][0] for info in addr_info))
        if not ips:
            return ResolutionResult(resolved_ips=[], dns_failed=True, error_message="No IP addresses returned")
        return ResolutionResult(resolved_ips=ips, dns_failed=False, error_message=None)
    except TimeoutError:
        logger.warning("DNS resolution timed out for host: %s", host)
        return ResolutionResult(resolved_ips=[], dns_failed=True, error_message="DNS resolution timed out")
    except (socket.gaierror, OSError) as e:
        logger.debug("DNS lookup failed for %s: %s", host, e)
        return ResolutionResult(resolved_ips=[], dns_failed=True, error_message=str(e))


async def validate_target_or_raise(host: str, port: int | None = None) -> list[str]:
    """Validates the target host and port against SSRF rules.

    Raises BlockedTargetError if port is disallowed or host is/resolves to a blocked IP.
    Returns list of validated public IP strings (empty if DNS fails without error).
    """
    # Verify port if provided
    if port is not None and port not in ALLOWED_FETCH_PORTS:
        raise BlockedTargetError(f"Target port {port} is not allowed for fetching; only 80 and 443 are supported")

    # Check IP literal directly
    ip_literal = parse_ip_literal(host)
    if ip_literal is not None:
        if is_blocked_ip(ip_literal):
            logger.warning("Blocked IP literal target rejected: %s", host)
            raise BlockedTargetError(f"Target IP {host} is in a blocked or private range")
        return [str(ip_literal)]

    # Check hostname such as 'localhost' directly
    if host.lower() == "localhost":
        logger.warning("Blocked host 'localhost' rejected")
        raise BlockedTargetError("Target 'localhost' is blocked by security policy")

    # Resolve host
    resolution = await resolve_host_ips(host)
    if resolution.dns_failed:
        # DNS failure is NOT an API error; scan proceeds with domain resolution note
        return []

    # Check every resolved address
    for ip_str in resolution.resolved_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
            if is_blocked_ip(ip):
                logger.warning("Host %s resolved to blocked IP %s", host, ip_str)
                raise BlockedTargetError(f"Host '{host}' resolved to blocked target IP: {ip_str}")
        except ValueError as err:
            raise BlockedTargetError(f"Host '{host}' resolved to invalid IP address: {ip_str}") from err

    return resolution.resolved_ips
