"""URL structural heuristics check analyzing lexical patterns, spoofing, and composition."""

import re

from app.data.brands import KNOWN_BRANDS
from app.data.risky_tlds import RISKY_TLDS
from app.data.shorteners import URL_SHORTENERS
from app.data.suspicious_keywords import SUSPICIOUS_KEYWORDS
from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext

PERCENT_ENCODED_REGEX = re.compile(r"%[0-9a-fA-F]{2}")


class UrlStructureCheck(BaseCheck):
    """Heuristic structural and lexical analysis of the target URL."""

    id = CheckId.URL_STRUCTURE
    name = "URL structure analysis"
    category = CheckCategory.URL_STRUCTURE
    source = "SafeLinks heuristics"
    runs_in_quick_mode = True

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        points = 0
        evidence: list[str] = []
        parsed = ctx.parsed
        submitted = ctx.submitted_url

        # 1. URL Length (over 120 = +15, over 75 = +8, not both)
        url_len = len(submitted)
        if url_len > 120:
            points += 15
            evidence.append(f"URL length is excessively long ({url_len} characters > 120)")
        elif url_len > 75:
            points += 8
            evidence.append(f"URL length is above normal ({url_len} characters > 75)")

        # 2. '@' or userinfo
        if parsed.has_userinfo or "@" in submitted:
            points += 25
            evidence.append("URL contains userinfo authentication credentials or '@' symbol")

        # 3. IP host
        if parsed.is_ip:
            points += 25
            evidence.append(f"Host uses a direct IP address ({parsed.ascii_host}) instead of a domain name")

        # 4. Subdomain labels (>= 4 = +15, exactly 3 = +8, not both)
        subdomain_labels = [p for p in parsed.subdomain.split(".") if p] if parsed.subdomain else []
        subdomain_count = len(subdomain_labels)
        if subdomain_count >= 4:
            points += 15
            evidence.append(f"Excessive subdomain depth ({subdomain_count} subdomain labels >= 4)")
        elif subdomain_count == 3:
            points += 8
            evidence.append("High subdomain depth (3 subdomain labels)")

        # 5. Hyphens in the registered domain (>= 3 = +10, 1-2 = +4)
        hyphen_count = parsed.registered_domain.count("-")
        if hyphen_count >= 3:
            points += 10
            evidence.append(f"Registered domain contains {hyphen_count} hyphens (>= 3)")
        elif hyphen_count in (1, 2):
            points += 4
            evidence.append(f"Registered domain contains {hyphen_count} hyphen(s)")

        # 6. Punycode or non-ASCII host
        if (
            "xn--" in parsed.ascii_host.lower()
            or parsed.ascii_host != parsed.unicode_host
            or any(ord(c) > 127 for c in parsed.unicode_host)
        ):
            points += 20
            evidence.append(f"Host contains IDN punycode or internationalized characters ({parsed.ascii_host})")

        # 7. Suspicious keywords in host (+10 each, max +20) and path/query (+5 each, max +10)
        host_lower = parsed.ascii_host.lower()
        matched_host_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in host_lower]
        if matched_host_keywords:
            kw_points = min(20, len(matched_host_keywords) * 10)
            points += kw_points
            evidence.append(
                f"Suspicious security keyword(s) in hostname (+{kw_points}): {', '.join(matched_host_keywords[:4])}"
            )

        path_query_lower = (parsed.path + "?" + parsed.query).lower()
        matched_path_keywords = [
            kw for kw in SUSPICIOUS_KEYWORDS if kw in path_query_lower and kw not in matched_host_keywords
        ]
        if matched_path_keywords:
            pq_points = min(10, len(matched_path_keywords) * 5)
            points += pq_points
            evidence.append(
                f"Suspicious security keyword(s) in path/query (+{pq_points}): {', '.join(matched_path_keywords[:4])}"
            )

        # 8. URL shortener (+15)
        if parsed.registered_domain.lower() in URL_SHORTENERS:
            points += 15
            evidence.append(f"URL uses known shortening service ({parsed.registered_domain}) which masks the destination")

        # 9. Custom port (+10)
        if parsed.port is not None:
            points += 10
            evidence.append(f"URL specifies non-standard network port ({parsed.port})")

        # 10. Risky TLD (+10)
        if parsed.suffix.lower() in RISKY_TLDS:
            points += 10
            evidence.append(f"URL utilizes a high-abuse top-level domain (.{parsed.suffix})")

        # 11. Brand spoofing: brand in subdomain or path but NOT in registered domain (+25)
        spoofed_brands: list[str] = []
        for brand, official_domains in KNOWN_BRANDS.items():
            in_sub = brand in parsed.subdomain.lower()
            in_path = brand in parsed.path.lower()
            if in_sub or in_path:
                if not any(parsed.registered_domain.lower() == d.lower() for d in official_domains):
                    spoofed_brands.append(brand)

        if spoofed_brands:
            points += 25
            evidence.append(
                f"Brand name spoofing detected: '{spoofed_brands[0]}' appears in URL but registered domain is '{parsed.registered_domain}'"
            )

        # 12. Digit ratio in host >= 0.3 (+8)
        host_no_dots = parsed.ascii_host.replace(".", "")
        if host_no_dots:
            digit_count = sum(1 for c in host_no_dots if c.isdigit())
            digit_ratio = digit_count / len(host_no_dots)
            if digit_ratio >= 0.3:
                points += 8
                evidence.append(f"High digit ratio in hostname ({digit_ratio:.1%})")

        # 13. More than 5 percent-encoded characters (+5)
        encoded_matches = PERCENT_ENCODED_REGEX.findall(submitted)
        if len(encoded_matches) > 5:
            points += 5
            evidence.append(f"URL contains excessive percent-encoded sequences ({len(encoded_matches)})")

        # 14. Plain HTTP (+10)
        if parsed.scheme == "http":
            points += 10
            evidence.append("URL uses unencrypted HTTP protocol")

        # Cap points at 100
        final_points = min(100, points)

        # Determine severity
        if final_points < 15:
            severity = Severity.INFO
        elif final_points < 35:
            severity = Severity.LOW
        elif final_points < 55:
            severity = Severity.MEDIUM
        elif final_points < 75:
            severity = Severity.HIGH
        else:
            severity = Severity.CRITICAL

        title = "Suspicious URL pattern" if final_points >= 35 else "URL looks normal"
        if not evidence:
            detail = "No suspicious lexical or structural characteristics were detected in the URL."
        else:
            detail = f"Identified {len(evidence)} structural risk indicator(s) totaling a heuristic risk score of {final_points}."

        return CheckOutcome(
            status=CheckStatus.DONE,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence,
            points=final_points,
            signal="soft",
            data={"heuristic_points": final_points},
        )
