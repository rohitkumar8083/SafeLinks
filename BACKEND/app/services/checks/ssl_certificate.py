"""SSL/TLS certificate inspection with certificate parsing via cryptography."""

import asyncio
import logging
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity, SslInfo
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext

logger = logging.getLogger("safelinks.checks.ssl")


class SslCertificateCheck(BaseCheck):
    """Inspects TLS handshake, certificate validity, expiration, and issuer."""

    id = CheckId.SSL_CERTIFICATE
    name = "SSL certificate"
    category = CheckCategory.SSL
    source = "TLS handshake"
    runs_in_quick_mode = False

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        parsed = ctx.parsed

        # 1. Plain HTTP without HTTPS
        if parsed.scheme == "http":
            return CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.MEDIUM,
                title="This link does not use HTTPS",
                detail="The URL uses unencrypted HTTP communication without SSL/TLS protection.",
                evidence=["Target protocol is unencrypted plain HTTP."],
                points=50,
                signal="soft",
                data={"ssl": None},
            )

        target_host = parsed.ascii_host
        target_port = parsed.port or 443
        der_bytes: bytes | None = None
        is_valid_handshake = False
        handshake_error: str | None = None

        # 2. First handshake with normal verification
        verified_ssl_ctx = ssl.create_default_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target_host,
                    target_port,
                    ssl=verified_ssl_ctx,
                    server_hostname=target_host,
                ),
                timeout=5.0,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                der_bytes = ssl_obj.getpeercert(binary_form=True)
            writer.close()
            await writer.wait_closed()
            is_valid_handshake = True
        except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
            handshake_error = str(e)
            logger.debug("Verified TLS handshake failed for %s: %s", target_host, e)
        except Exception as e:
            handshake_error = str(e)
            logger.debug("TLS connection error for %s: %s", target_host, e)

        # 3. If verified handshake failed, attempt unverified handshake to read certificate
        if der_bytes is None:
            unverified_ctx = ssl._create_unverified_context()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        target_host,
                        target_port,
                        ssl=unverified_ctx,
                        server_hostname=target_host,
                    ),
                    timeout=5.0,
                )
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    der_bytes = ssl_obj.getpeercert(binary_form=True)
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug("Unverified TLS handshake also failed for %s: %s", target_host, e)

        # 4. Handle complete TLS handshake failure
        if der_bytes is None:
            detail = f"Could not establish TLS connection to {target_host}:{target_port} ({handshake_error or 'Connection refused/timed out'})."
            return CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.HIGH,
                title="TLS connection failed",
                detail=detail,
                evidence=[detail],
                points=80,
                signal="soft",
                data={"ssl": None},
            )

        # 5. Parse certificate with cryptography.x509
        now = datetime.now(UTC)
        cert = x509.load_der_x509_certificate(der_bytes)

        # Issuer organization or CN
        issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if not issuer_attrs:
            issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_str = issuer_attrs[0].value if issuer_attrs else "Unknown Issuer"
        if isinstance(issuer_str, bytes):
            issuer_str = issuer_str.decode("utf-8", errors="replace")

        # Subject CN
        subject_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = subject_attrs[0].value if subject_attrs else ""
        if isinstance(subject_cn, bytes):
            subject_cn = subject_cn.decode("utf-8", errors="replace")

        # Dates & Expiration
        not_before = getattr(cert, "not_valid_before_utc", None)
        if not_before is None:
            not_before = cert.not_valid_before.replace(tzinfo=UTC)

        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=UTC)

        days_remaining = int((not_after - now).total_seconds() / 86400)
        days_since_issued = int((now - not_before).total_seconds() / 86400)
        is_expired = now > not_after or days_remaining < 0

        # Self-signed check
        is_self_signed = cert.issuer == cert.subject

        # Hostname matching check (CN + SAN DNS Names)
        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        def match_host(pattern: str, hostname: str) -> bool:
            p = pattern.lower()
            h = hostname.lower()
            if p.startswith("*."):
                suffix = p[2:]
                return h.endswith(suffix) and h.count(".") == suffix.count(".") + 1
            return p == h

        all_names = [subject_cn] + sans if subject_cn else sans
        hostname_match = any(match_host(name, target_host) for name in all_names)

        # Total certificate validity
        is_cert_valid = is_valid_handshake and (not is_expired) and (not is_self_signed) and hostname_match

        evidence: list[str] = [
            f"Issuer: {issuer_str}",
            f"Expires at: {not_after.strftime('%Y-%m-%dT%H:%M:%SZ')} ({days_remaining} days remaining)",
        ]

        # Scoring & severity assignment
        if not is_cert_valid:
            severity = Severity.HIGH
            points = 80
            title = "Invalid or untrusted SSL certificate"
            reasons: list[str] = []
            if is_expired:
                reasons.append("certificate is expired")
            if is_self_signed:
                reasons.append("certificate is self-signed")
            if not hostname_match:
                reasons.append(f"hostname '{target_host}' does not match certificate names ({', '.join(all_names[:3])})")
            if handshake_error and not reasons:
                reasons.append(f"handshake verification failed: {handshake_error}")
            detail = f"Certificate validation failed: {'; '.join(reasons)}."
            evidence.extend(reasons)
        elif days_remaining < 7:
            severity = Severity.MEDIUM
            points = 40
            title = "SSL certificate expiring soon"
            detail = f"Certificate is valid but expires in {days_remaining} day(s)."
            evidence.append(f"Certificate expires in less than 7 days ({days_remaining} days)")
        elif days_since_issued < 7:
            severity = Severity.LOW
            points = 15
            title = "Recently issued SSL certificate"
            detail = f"Certificate is valid but was issued {days_since_issued} day(s) ago."
            evidence.append("Certificate was issued very recently")
        else:
            severity = Severity.INFO
            points = 0
            title = "Valid SSL certificate"
            detail = f"Certificate is valid, properly trusted, and expires in {days_remaining} days."

        ssl_info = SslInfo(
            valid=is_cert_valid,
            issuer=issuer_str,
            expires_at=not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            days_remaining=days_remaining,
        )

        return CheckOutcome(
            status=CheckStatus.DONE,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence,
            points=points,
            signal="soft",
            data={"ssl": ssl_info.model_dump()},
        )
