"""Interactive CLI smoke test for SafeLinks API against a live server."""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

import httpx


def run_smoke_tests(base_url: str, timeout: float = 35.0) -> bool:
    client = httpx.Client(base_url=base_url.rstrip("/"), timeout=15.0)
    all_passed = True
    results_table: list[dict[str, Any]] = []

    print("=" * 80)
    print(f"SafeLinks API Smoke Test Suite -> Target: {base_url}")
    print("=" * 80)

    # 1. Health check
    print("\n[Step 1/3] Verifying /api/v1/health endpoint...")
    try:
        health_resp = client.get("/api/v1/health")
        if health_resp.status_code != 200:
            print(f"FAILED: Health check returned HTTP {health_resp.status_code}")
            return False
        health_data = health_resp.json()
        print(f"  Status:           {health_data.get('status')}")
        print(f"  Version:          {health_data.get('version')}")
        print(f"  ML Model Loaded:  {health_data.get('ml_model_loaded')}")
        if health_data.get("status") != "ok":
            print("FAILED: Service status is not 'ok'")
            return False
    except Exception as e:
        print(f"FAILED: Could not connect to {base_url}: {e}")
        return False

    # 2. Rejection tests (SSRF & Scheme)
    print("\n[Step 2/3] Verifying URL validation & SSRF guard rejection tests...")
    rejection_tests = [
        ("http://127.0.0.1", "BLOCKED_TARGET", 422),
        ("http://169.254.169.254/latest/meta-data", "BLOCKED_TARGET", 422),
        ("ftp://example.com", "UNSUPPORTED_SCHEME", 422),
    ]

    for url, expected_code, expected_status in rejection_tests:
        try:
            resp = client.post("/api/v1/scans", json={"url": url, "mode": "quick"})
            status_match = resp.status_code == expected_status
            err_code = resp.json().get("error", {}).get("code")
            code_match = err_code == expected_code
            passed = status_match and code_match
            if not passed:
                all_passed = False
            mark = "PASS" if passed else "FAIL"
            print(f"  [{mark}] {url:45} -> HTTP {resp.status_code} ({err_code}) [expected {expected_status} {expected_code}]")
        except Exception as e:
            all_passed = False
            print(f"  [FAIL] {url:45} -> Exception: {e}")

    # 3. Live scan tests
    print("\n[Step 3/3] Submitting live scans and polling to completion...")
    scan_tests = [
        {"url": "https://www.google.com", "expected_verdict": "likely_safe", "mode": "quick"},
        {"url": "https://example.com", "expected_verdict": "likely_safe", "mode": "full"},
        {"url": "http://paypal-secure-login.example-verify.xyz/account/update", "expected_verdict": None, "mode": "quick"},
    ]

    for item in scan_tests:
        url = item["url"]
        mode = item["mode"]
        expected_verdict = item["expected_verdict"]
        start_time = time.time()
        print(f"  Submitting ({mode} mode): {url} ...")

        try:
            post_resp = client.post("/api/v1/scans", json={"url": url, "mode": mode})
            if post_resp.status_code != 202:
                print(f"    [FAIL] Expected 202 Accepted, got {post_resp.status_code}: {post_resp.text}")
                all_passed = False
                continue

            scan_id = post_resp.json()["scan_id"]
            completed = False
            final_report: dict[str, Any] = {}
            deadline = time.time() + timeout

            while time.time() < deadline:
                get_resp = client.get(f"/api/v1/scans/{scan_id}")
                if get_resp.status_code == 200:
                    report = get_resp.json()
                    status = report.get("status")
                    if status in ("completed", "failed"):
                        completed = True
                        final_report = report
                        break
                time.sleep(0.5)

            elapsed = round(time.time() - start_time, 2)

            if not completed:
                print(f"    [FAIL] Timed out waiting for scan {scan_id} to complete within {timeout}s")
                all_passed = False
                results_table.append({
                    "url": url,
                    "status": "TIMEOUT",
                    "verdict": "-",
                    "score": "-",
                    "confidence": "-",
                    "elapsed": f"{elapsed}s",
                    "checks": "-",
                })
                continue

            res = final_report.get("result") or {}
            verdict = res.get("verdict")
            score = res.get("risk_score")
            confidence = res.get("confidence")
            checks_summary = ",".join(f"{c['id']}:{c['status']}" for c in final_report.get("checks", []))

            verdict_ok = True
            if expected_verdict and verdict != expected_verdict:
                verdict_ok = False
                all_passed = False

            mark = "PASS" if verdict_ok else "FAIL"
            print(f"    [{mark}] Done in {elapsed}s | Verdict: {verdict} (Score: {score}/100, Confidence: {confidence})")

            results_table.append({
                "url": url,
                "status": final_report.get("status"),
                "verdict": verdict,
                "score": score,
                "confidence": confidence,
                "elapsed": f"{elapsed}s",
                "checks": checks_summary,
            })

        except Exception as e:
            all_passed = False
            print(f"    [FAIL] Exception during scan of {url}: {e}")

    # Results Table
    print("\n" + "=" * 80)
    print("SMOKE TEST RESULTS SUMMARY")
    print("=" * 80)
    header = f"{'Target URL':<42} | {'Status':<9} | {'Verdict':<15} | {'Score':<5} | {'Conf':<6} | {'Time':<6}"
    print(header)
    print("-" * 80)
    for r in results_table:
        print(f"{r['url']:<42} | {str(r['status']):<9} | {str(r['verdict']):<15} | {str(r['score']):<5} | {str(r['confidence']):<6} | {r['elapsed']:<6}")
    print("=" * 80)

    if all_passed:
        print("\nAll smoke test assertions PASSED successfully!")
    else:
        print("\nSmoke test assertions FAILED! Check logs above.")

    return all_passed


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeLinks API Live Smoke Test")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Base URL of live API service")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-scan polling timeout in seconds")
    args = parser.parse_args()

    success = run_smoke_tests(base_url=args.base_url, timeout=args.timeout)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
