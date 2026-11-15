"""Pure deterministic multi-signal risk scoring engine with hard floors and dampening."""

import statistics

from app.constants import (
    MIN_COMPLETED_CHECKS_FULL,
    MIN_COMPLETED_CHECKS_QUICK,
    VERDICT_SAFE_MAX,
    VERDICT_SUSPICIOUS_MAX,
)
from app.data.trusted_domains import is_trusted_domain
from app.schemas.scan import (
    Check,
    CheckId,
    CheckStatus,
    DomainInfo,
    MlFeature,
    MlResult,
    ScanMode,
    ScanResult,
    SslInfo,
    Verdict,
)
from app.services.checks.base import CheckOutcome
from app.services.recommendations import get_recommendations

# Standard weights assigned to soft signals (sum to 1.00)
SOFT_WEIGHTS: dict[CheckId, float] = {
    CheckId.ML_PHISHING: 0.35,
    CheckId.URL_STRUCTURE: 0.20,
    CheckId.DOMAIN_AGE: 0.15,
    CheckId.SSL_CERTIFICATE: 0.10,
    CheckId.REDIRECT_CHAIN: 0.10,
    CheckId.VIRUSTOTAL: 0.10,
}


def compute_scan_result(
    mode: ScanMode,
    checks: list[Check],
    outcomes: dict[CheckId, CheckOutcome],
    target_domain: str,
) -> ScanResult:
    """Computes final risk score, verdict, confidence, and contextual summary."""
    # 1. Inspect hard signals and floors
    hard_floors: list[int] = []
    has_hard_signal = False
    for outcome in outcomes.values():
        if outcome.status == CheckStatus.DONE and outcome.signal == "hard":
            has_hard_signal = True
            if outcome.floor is not None:
                hard_floors.append(outcome.floor)
        elif outcome.status == CheckStatus.DONE and outcome.floor is not None:
            # Check carries a soft floor (e.g., URLhaus offline floor 70)
            hard_floors.append(outcome.floor)

    strongest_floor = max(hard_floors) if hard_floors else 0

    # 2. Extract and adjust soft points (with trusted domain dampening)
    points_map: dict[CheckId, int] = {}
    for c in checks:
        if c.id in outcomes and outcomes[c.id].status == CheckStatus.DONE:
            pts = outcomes[c.id].points
            if pts is not None:
                points_map[c.id] = pts

    # Trusted domain dampening: halve ml_phishing and url_structure points IF no hard signal exists
    if is_trusted_domain(target_domain) and not has_hard_signal:
        if CheckId.ML_PHISHING in points_map:
            points_map[CheckId.ML_PHISHING] = points_map[CheckId.ML_PHISHING] // 2
        if CheckId.URL_STRUCTURE in points_map:
            points_map[CheckId.URL_STRUCTURE] = points_map[CheckId.URL_STRUCTURE] // 2

    # 3. Soft weights blend
    # Only include soft checks (if VirusTotal was a hard signal, it acts as a floor instead of a soft weight)
    soft_weights_used: dict[CheckId, float] = {}
    soft_points_list: list[float] = []

    for cid, weight in SOFT_WEIGHTS.items():
        if cid in points_map:
            outcome = outcomes.get(cid)
            if outcome and outcome.signal != "hard":
                soft_weights_used[cid] = weight
                soft_points_list.append(float(points_map[cid]))

    total_soft_weight_sum = sum(soft_weights_used.values())
    if total_soft_weight_sum > 0:
        blend = sum(points_map[cid] * soft_weights_used[cid] for cid in soft_weights_used) / total_soft_weight_sum
    else:
        blend = 0.0

    # 4. Final score = max(blend, strongest_floor)
    final_score = int(round(max(blend, float(strongest_floor))))
    final_score = max(0, min(100, final_score))

    # 5. Check completion threshold
    done_checks = [c for c in checks if c.status == CheckStatus.DONE]
    min_required = MIN_COMPLETED_CHECKS_QUICK if mode == ScanMode.QUICK else MIN_COMPLETED_CHECKS_FULL

    if len(done_checks) < min_required and not has_hard_signal:
        verdict = Verdict.UNKNOWN
        risk_score = 0
    else:
        risk_score = final_score
        if risk_score <= VERDICT_SAFE_MAX:
            verdict = Verdict.LIKELY_SAFE
        elif risk_score <= VERDICT_SUSPICIOUS_MAX:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.LIKELY_MALICIOUS

    # 6. Confidence calculation
    all_possible_soft_weight = sum(SOFT_WEIGHTS.values())
    coverage = (total_soft_weight_sum / all_possible_soft_weight) if all_possible_soft_weight > 0 else 0.0
    if len(soft_points_list) > 1:
        stdev = statistics.stdev(soft_points_list)
    else:
        stdev = 0.0
    agreement = 1.0 - min(1.0, stdev / 50.0)
    confidence = round(0.5 * coverage + 0.5 * agreement, 2)

    if has_hard_signal:
        confidence = max(confidence, 0.9)
    confidence = max(0.0, min(1.0, confidence))

    # 7. Summary generation
    # Extract top findings for the summary
    findings: list[str] = []
    for cid in (
        CheckId.GOOGLE_SAFE_BROWSING,
        CheckId.URLHAUS,
        CheckId.VIRUSTOTAL,
        CheckId.ML_PHISHING,
        CheckId.URL_STRUCTURE,
        CheckId.SSL_CERTIFICATE,
        CheckId.DOMAIN_AGE,
    ):
        out = outcomes.get(cid)
        if out and out.status == CheckStatus.DONE:
            if out.signal == "hard":
                findings.append(out.title)
            elif out.points and out.points >= 50:
                findings.append(out.title)

    if not findings:
        for out in outcomes.values():
            if out.status == CheckStatus.DONE and out.title and out.points and out.points > 20:
                findings.append(out.title)

    if verdict == Verdict.LIKELY_MALICIOUS:
        top_two = "; ".join(findings[:2]) if findings else "Multiple high-risk indicators detected"
        summary = f"High risk ({risk_score}/100). {top_two}."
    elif verdict == Verdict.SUSPICIOUS:
        top_one = findings[0] if findings else "Suspicious characteristics detected"
        summary = f"Suspicious ({risk_score}/100). {top_one}."
    elif verdict == Verdict.LIKELY_SAFE:
        summary = f"Low risk ({risk_score}/100). No threats were detected by the checks we ran."
    else:
        summary = "We could not complete enough checks to give a reliable verdict."

    # 8. Assemble DomainInfo and MlResult
    domain_info: DomainInfo | None = None
    age_outcome = outcomes.get(CheckId.DOMAIN_AGE)
    ssl_outcome = outcomes.get(CheckId.SSL_CERTIFICATE)

    ssl_data = ssl_outcome.data.get("ssl") if ssl_outcome and ssl_outcome.data else None
    ssl_info: SslInfo | None = SslInfo(**ssl_data) if ssl_data else None

    if age_outcome and age_outcome.data:
        domain_info = DomainInfo(
            domain=age_outcome.data.get("domain") or target_domain,
            age_days=age_outcome.data.get("age_days"),
            registrar=age_outcome.data.get("registrar"),
            ssl=ssl_info,
        )
    elif ssl_info or target_domain:
        domain_info = DomainInfo(
            domain=target_domain,
            age_days=None,
            registrar=None,
            ssl=ssl_info,
        )

    ml_result: MlResult | None = None
    ml_outcome = outcomes.get(CheckId.ML_PHISHING)
    if ml_outcome and ml_outcome.data and "ml" in ml_outcome.data:
        raw_ml = ml_outcome.data["ml"]
        top_feats = [MlFeature(**f) for f in raw_ml.get("top_features", [])]
        ml_result = MlResult(
            phishing_probability=raw_ml.get("phishing_probability", 0.0),
            model_version=raw_ml.get("model_version", "unknown"),
            top_features=top_feats,
        )

    # 9. Recommendations
    recommendations = get_recommendations(verdict, outcomes, target_domain)

    return ScanResult(
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        recommendations=recommendations,
        ml=ml_result,
        domain_info=domain_info,
    )
