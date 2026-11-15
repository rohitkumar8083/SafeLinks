"""Contextual, threat-specific recommendations generation."""

from app.schemas.scan import (
    CheckId,
    CheckStatus,
    Verdict,
)
from app.services.checks.base import CheckOutcome


def get_recommendations(
    verdict: Verdict,
    outcomes: dict[CheckId, CheckOutcome],
    target_domain: str,
) -> list[str]:
    """Generates up to 6 actionable, deduplicated recommendations ordered by severity."""
    recs: list[str] = []

    # 1. Finding-specific recommendations
    # Invalid or untrusted certificate
    ssl_out = outcomes.get(CheckId.SSL_CERTIFICATE)
    if ssl_out and ssl_out.status == CheckStatus.DONE and ssl_out.points and ssl_out.points >= 50:
        recs.append("Do not trust this connection: The SSL/TLS certificate is invalid, self-signed, or unencrypted.")

    # Brand spoofing detected
    url_out = outcomes.get(CheckId.URL_STRUCTURE)
    if url_out and url_out.evidence:
        for ev in url_out.evidence:
            if "brand name spoofing" in ev.lower():
                # Extract brand name
                recs.append(f"Verify authenticity: The link attempts to imitate an official brand on an unauthorized domain ({target_domain}).")
                break
            if "shortening service" in ev.lower():
                recs.append("Caution: This is a shortened link masking its real destination; unshorten before opening.")
            if "direct ip address" in ev.lower():
                recs.append("Suspicious host: Legitimate consumer services rarely use raw IP addresses for login.")
            if "punycode" in ev.lower():
                recs.append("Visual deception: The domain uses internationalized lookalike characters to deceive users.")

    # Newly registered domain
    age_out = outcomes.get(CheckId.DOMAIN_AGE)
    if age_out and age_out.status == CheckStatus.DONE and age_out.points and age_out.points >= 50:
        recs.append(f"Domain is brand new: '{target_domain}' was registered very recently; exercise extreme caution.")

    # Cross-domain redirects
    redir_out = outcomes.get(CheckId.REDIRECT_CHAIN)
    if redir_out and redir_out.evidence:
        for ev in redir_out.evidence:
            if "cross-domain redirect" in ev.lower():
                recs.append("Redirect warning: Link bounces across multiple third-party domains before landing.")
                break

    # 2. Verdict-based core recommendations
    if verdict == Verdict.LIKELY_MALICIOUS:
        recs.insert(0, "Do not open this link or enter any password, OTP or card details.")
        recs.append("If you already entered a password, change it immediately and turn on two-factor authentication.")
        recs.append("Report the link as phishing to the service it imitates or your IT security team.")
    elif verdict == Verdict.SUSPICIOUS:
        recs.insert(0, "Avoid entering personal information; open the official website by typing its address yourself.")
    elif verdict == Verdict.LIKELY_SAFE:
        recs.append("No threats were detected by the checks we ran. Stay careful with unexpected messages.")
    elif verdict == Verdict.UNKNOWN:
        recs.append("Try again in a few minutes: Security checks could not reach enough providers to determine safety.")

    # Deduplicate while preserving order, cap at 6 recommendations
    seen: set[str] = set()
    final_recs: list[str] = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            final_recs.append(r)
        if len(final_recs) >= 6:
            break

    return final_recs
