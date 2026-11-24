"""Gemini AI Security Analyst for synthesizing threat findings into clear summaries and recommendations."""

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger("safelinks.gemini_analyst")

GEMINI_API_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


async def generate_ai_analysis(
    url: str,
    risk_score: int,
    verdict: str,
    findings: list[str],
    http_client: httpx.AsyncClient,
    api_key: str | None,
    model: str = "gemini-3-flash-preview",
) -> dict[str, Any] | None:
    """Calls Gemini to generate an authoritative executive summary and security recommendations."""
    if not api_key or not api_key.strip():
        return None

    findings_text = "\n- ".join(findings) if findings else "No specific check anomalies flagged."
    prompt = (
        f"You are a cybersecurity expert analyzing an automated URL security scan report for SafeLinks.\n\n"
        f"Target URL: {url}\n"
        f"Computed Risk Score: {risk_score}/100\n"
        f"Verdict: {verdict}\n"
        f"Detection Findings:\n- {findings_text}\n\n"
        f"Respond with a JSON object containing exactly two keys:\n"
        f"1. \"summary\": A clear, authoritative 1-2 sentence executive explanation of the risk, explaining specifically why the URL is flagged or considered safe.\n"
        f"2. \"recommendations\": A list of 3-4 concise, actionable security steps for a user or enterprise administrator.\n"
        f"Do not include markdown codeblocks or extra text, only raw JSON."
    )

    url_endpoint = f"{GEMINI_API_ENDPOINT.format(model=model)}?key={api_key.strip()}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.2,
        },
    }

    try:
        resp = await http_client.post(url_endpoint, json=payload, timeout=4.0)
        if resp.status_code != 200:
            logger.warning("Gemini API call returned status %d: %s", resp.status_code, resp.text[:150])
            return None

        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return None

        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if not parts:
            return None

        raw_json_str = parts[0].get("text", "").strip()
        parsed = json.loads(raw_json_str)

        summary = parsed.get("summary")
        recommendations = parsed.get("recommendations")

        if summary and isinstance(summary, str) and recommendations and isinstance(recommendations, list):
            cleaned_recs = [str(r).strip() for r in recommendations if str(r).strip()]
            return {
                "summary": summary.strip(),
                "recommendations": cleaned_recs,
            }
        return None
    except Exception as e:
        logger.warning("Gemini AI analysis failed or timed out: %s", e)
        return None
