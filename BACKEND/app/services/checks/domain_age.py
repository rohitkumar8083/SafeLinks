"""Domain age check leveraging RDAP with WHOIS thread fallback."""

import asyncio
import logging
from datetime import UTC, datetime

import whois

from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext

logger = logging.getLogger("safelinks.checks.domain_age")


class DomainAgeCheck(BaseCheck):
    """Evaluates domain registration age and registrar reputation."""

    id = CheckId.DOMAIN_AGE
    name = "Domain age"
    category = CheckCategory.DOMAIN
    source = "WHOIS/RDAP"
    runs_in_quick_mode = False

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        parsed = ctx.parsed

        # 1. Skip check for IP hosts
        if parsed.is_ip:
            return CheckOutcome(
                status=CheckStatus.SKIPPED,
                severity=Severity.INFO,
                title="Skipped for IP address",
                detail="An IP address has no domain registration",
                evidence=["Host is an IP address; domain registration lookup was skipped"],
                signal="none",
                data={"domain": parsed.ascii_host, "age_days": None, "registrar": None},
            )

        reg_domain = parsed.registered_domain
        reg_date: datetime | None = None
        registrar: str | None = None

        # 2. Query RDAP first
        try:
            rdap_url = f"https://rdap.org/domain/{reg_domain}"
            resp = await ctx.http_client.get(rdap_url, timeout=5.0, headers={"Accept": "application/rdap+json, application/json"})
            if resp.status_code == 200:
                rdap_json = resp.json()

                # Extract registration event
                events = rdap_json.get("events", [])
                for ev in events:
                    if ev.get("eventAction") in ("registration", "created"):
                        date_str = ev.get("eventDate")
                        if date_str:
                            try:
                                reg_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                                break
                            except Exception:
                                pass

                # Extract registrar
                entities = rdap_json.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if len(prop) > 3 and prop[0] == "fn":
                                    registrar = str(prop[3])
                                    break
                        if not registrar:
                            registrar = entity.get("handle") or entity.get("name")
                        break
        except Exception as e:
            logger.debug("RDAP query failed for %s: %s", reg_domain, e)

        # 3. Fallback to python-whois in thread
        if reg_date is None:
            try:
                whois_data = await asyncio.to_thread(whois.whois, reg_domain)
                raw_cdate = getattr(whois_data, "creation_date", None)
                if isinstance(raw_cdate, list) and raw_cdate:
                    raw_cdate = raw_cdate[0]
                if isinstance(raw_cdate, datetime):
                    if raw_cdate.tzinfo is None:
                        reg_date = raw_cdate.replace(tzinfo=UTC)
                    else:
                        reg_date = raw_cdate

                if not registrar and getattr(whois_data, "registrar", None):
                    registrar = str(whois_data.registrar)
            except Exception as e:
                logger.debug("python-whois fallback failed for %s: %s", reg_domain, e)

        # 4. Handle hidden or unavailable registration date
        if reg_date is None:
            return CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.LOW,
                title="Registration date unavailable",
                detail="Registration date is hidden or unavailable",
                evidence=["Domain registration date could not be retrieved from RDAP or WHOIS databases"],
                points=15,
                signal="soft",
                data={"domain": reg_domain, "age_days": None, "registrar": registrar},
            )

        # 5. Calculate age in days and assign severity/points
        now = datetime.now(UTC)
        age_days = max(0, (now - reg_date).days)
        evidence: list[str] = [
            f"Domain was registered on {reg_date.strftime('%Y-%m-%d')} ({age_days} days ago)",
        ]
        if registrar:
            evidence.append(f"Registrar: {registrar}")

        if age_days < 7:
            severity = Severity.CRITICAL
            points = 90
            title = "Brand-new domain (very high risk)"
            detail = f"Domain was registered only {age_days} days ago. Newly registered domains are disproportionately used for phishing."
        elif age_days < 30:
            severity = Severity.HIGH
            points = 75
            title = "Recently registered domain (high risk)"
            detail = f"Domain was registered {age_days} days ago (< 30 days)."
        elif age_days < 90:
            severity = Severity.MEDIUM
            points = 50
            title = "Young domain"
            detail = f"Domain is relatively new ({age_days} days old, under 3 months)."
        elif age_days < 365:
            severity = Severity.LOW
            points = 25
            title = "Domain under 1 year old"
            detail = f"Domain is {age_days} days old (less than 1 year)."
        else:
            severity = Severity.INFO
            points = 0
            title = "Established domain"
            detail = f"Domain has been active for {age_days} days (over 1 year)."

        return CheckOutcome(
            status=CheckStatus.DONE,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence,
            points=points,
            signal="soft",
            data={"domain": reg_domain, "age_days": age_days, "registrar": registrar},
        )
