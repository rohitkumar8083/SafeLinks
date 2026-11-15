"""Unit tests for deterministic risk scoring, hard floors, confidence, and dampening."""

from app.schemas.scan import (
    Check,
    CheckCategory,
    CheckId,
    CheckStatus,
    ScanMode,
    Severity,
    Verdict,
)
from app.services.checks.base import CheckOutcome
from app.services.risk_scoring import compute_scan_result


def make_check(check_id: CheckId, status: CheckStatus) -> Check:
    return Check(
        id=check_id,
        name=check_id.value,
        category=CheckCategory.URL_STRUCTURE,
        status=status,
        severity=Severity.INFO,
        title="",
        detail="",
        evidence=[],
        source="",
    )


def test_hard_floor_overrides_soft_blend():
    checks = [
        make_check(CheckId.URL_STRUCTURE, CheckStatus.DONE),
        make_check(CheckId.ML_PHISHING, CheckStatus.DONE),
        make_check(CheckId.GOOGLE_SAFE_BROWSING, CheckStatus.DONE),
    ]
    outcomes = {
        CheckId.URL_STRUCTURE: CheckOutcome(status=CheckStatus.DONE, points=10, signal="soft"),
        CheckId.ML_PHISHING: CheckOutcome(status=CheckStatus.DONE, points=10, signal="soft"),
        CheckId.GOOGLE_SAFE_BROWSING: CheckOutcome(
            status=CheckStatus.DONE,
            points=95,
            signal="hard",
            floor=92,
            title="Google Safe Browsing Match",
        ),
    }

    result = compute_scan_result(ScanMode.FULL, checks, outcomes, "attacker-domain.com")
    assert result.risk_score >= 92
    assert result.verdict == Verdict.LIKELY_MALICIOUS
    assert result.confidence >= 0.90


def test_weight_renormalization_when_checks_skipped():
    # Only url_structure (wt 0.20) and domain_age (wt 0.15) and ssl (wt 0.10) done
    checks = [
        make_check(CheckId.URL_STRUCTURE, CheckStatus.DONE),
        make_check(CheckId.DOMAIN_AGE, CheckStatus.DONE),
        make_check(CheckId.SSL_CERTIFICATE, CheckStatus.DONE),
    ]
    outcomes = {
        CheckId.URL_STRUCTURE: CheckOutcome(status=CheckStatus.DONE, points=40, signal="soft"),
        CheckId.DOMAIN_AGE: CheckOutcome(status=CheckStatus.DONE, points=20, signal="soft"),
        CheckId.SSL_CERTIFICATE: CheckOutcome(status=CheckStatus.DONE, points=0, signal="soft"),
    }

    # Expected blend = (40*0.20 + 20*0.15 + 0*0.10) / (0.20 + 0.15 + 0.10) = (8 + 3) / 0.45 = 11 / 0.45 = 24.44 -> 24
    result = compute_scan_result(ScanMode.FULL, checks, outcomes, "untrusted.xyz")
    assert result.risk_score == 24
    assert result.verdict == Verdict.LIKELY_SAFE


def test_unknown_when_fewer_than_minimum_checks_done():
    # Full mode requires at least 3 checks done
    checks = [
        make_check(CheckId.URL_STRUCTURE, CheckStatus.DONE),
        make_check(CheckId.ML_PHISHING, CheckStatus.DONE),
        make_check(CheckId.DOMAIN_AGE, CheckStatus.SKIPPED),
    ]
    outcomes = {
        CheckId.URL_STRUCTURE: CheckOutcome(status=CheckStatus.DONE, points=50, signal="soft"),
        CheckId.ML_PHISHING: CheckOutcome(status=CheckStatus.DONE, points=50, signal="soft"),
        CheckId.DOMAIN_AGE: CheckOutcome(status=CheckStatus.SKIPPED),
    }

    # 2 checks done < 3 in full mode -> UNKNOWN
    result = compute_scan_result(ScanMode.FULL, checks, outcomes, "example.com")
    assert result.verdict == Verdict.UNKNOWN
    assert result.risk_score == 0

    # But in QUICK mode, 2 checks done is sufficient!
    res_quick = compute_scan_result(ScanMode.QUICK, checks, outcomes, "example.com")
    assert res_quick.verdict == Verdict.SUSPICIOUS
    assert res_quick.risk_score == 50


def test_verdict_threshold_boundaries():
    # Helper to test exact risk scores at 29, 30, 69, 70
    checks = [
        make_check(CheckId.URL_STRUCTURE, CheckStatus.DONE),
        make_check(CheckId.ML_PHISHING, CheckStatus.DONE),
        make_check(CheckId.DOMAIN_AGE, CheckStatus.DONE),
    ]

    for target_score, expected_verdict in [(29, Verdict.LIKELY_SAFE), (30, Verdict.SUSPICIOUS), (69, Verdict.SUSPICIOUS), (70, Verdict.LIKELY_MALICIOUS)]:
        outcomes = {
            CheckId.URL_STRUCTURE: CheckOutcome(status=CheckStatus.DONE, points=target_score, signal="soft"),
            CheckId.ML_PHISHING: CheckOutcome(status=CheckStatus.DONE, points=target_score, signal="soft"),
            CheckId.DOMAIN_AGE: CheckOutcome(status=CheckStatus.DONE, points=target_score, signal="soft"),
        }
        res = compute_scan_result(ScanMode.FULL, checks, outcomes, "test-thresholds.com")
        assert res.risk_score == target_score
        assert res.verdict == expected_verdict


def test_trusted_domain_dampening_applied():
    # Target domain google.com is on trusted list
    checks = [
        make_check(CheckId.URL_STRUCTURE, CheckStatus.DONE),
        make_check(CheckId.ML_PHISHING, CheckStatus.DONE),
        make_check(CheckId.DOMAIN_AGE, CheckStatus.DONE),
    ]
    outcomes = {
        CheckId.URL_STRUCTURE: CheckOutcome(status=CheckStatus.DONE, points=40, signal="soft"),
        CheckId.ML_PHISHING: CheckOutcome(status=CheckStatus.DONE, points=40, signal="soft"),
        CheckId.DOMAIN_AGE: CheckOutcome(status=CheckStatus.DONE, points=0, signal="soft"),
    }

    # Points of url_structure and ml_phishing halved to 20
    # Blend: (20*0.20 + 20*0.35 + 0*0.15) / (0.70) = (4 + 7) / 0.70 = 11 / 0.7 = 15.7 -> 16
    res = compute_scan_result(ScanMode.FULL, checks, outcomes, "google.com")
    assert res.risk_score == 16


def test_trusted_domain_dampening_disabled_under_hard_signal():
    checks = [
        make_check(CheckId.URL_STRUCTURE, CheckStatus.DONE),
        make_check(CheckId.ML_PHISHING, CheckStatus.DONE),
        make_check(CheckId.GOOGLE_SAFE_BROWSING, CheckStatus.DONE),
    ]
    outcomes = {
        CheckId.URL_STRUCTURE: CheckOutcome(status=CheckStatus.DONE, points=40, signal="soft"),
        CheckId.ML_PHISHING: CheckOutcome(status=CheckStatus.DONE, points=40, signal="soft"),
        CheckId.GOOGLE_SAFE_BROWSING: CheckOutcome(status=CheckStatus.DONE, points=95, signal="hard", floor=92),
    }

    # Hard signal disables dampening and imposes floor 92
    res = compute_scan_result(ScanMode.FULL, checks, outcomes, "google.com")
    assert res.risk_score >= 92
    assert res.verdict == Verdict.LIKELY_MALICIOUS
