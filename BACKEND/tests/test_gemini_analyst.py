"""Tests for Gemini AI security analyst service."""

import pytest
import respx
import httpx
from app.services.gemini_analyst import generate_ai_analysis, GEMINI_API_ENDPOINT


@pytest.mark.asyncio
async def test_generate_ai_analysis_missing_key():
    async with httpx.AsyncClient() as client:
        result = await generate_ai_analysis(
            url="http://example.com",
            risk_score=90,
            verdict="likely_malicious",
            findings=["Brand spoofing"],
            http_client=client,
            api_key=None,
        )
        assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_generate_ai_analysis_success():
    fake_json = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": '{"summary": "High risk phishing link targeting banking users.", "recommendations": ["Block URL", "Alert users"]}'
                        }
                    ]
                }
            }
        ]
    }
    url_pattern = GEMINI_API_ENDPOINT.format(model="gemini-3-flash-preview")
    respx.post(url_pattern).mock(return_value=httpx.Response(200, json=fake_json))

    async with httpx.AsyncClient() as client:
        result = await generate_ai_analysis(
            url="http://paypal-fake.com",
            risk_score=95,
            verdict="likely_malicious",
            findings=["Brand spoofing detected"],
            http_client=client,
            api_key="fake-key",
            model="gemini-3-flash-preview",
        )
        assert result is not None
        assert result["summary"] == "High risk phishing link targeting banking users."
        assert len(result["recommendations"]) == 2
        assert "Block URL" in result["recommendations"]


@pytest.mark.asyncio
@respx.mock
async def test_generate_ai_analysis_http_error():
    url_pattern = GEMINI_API_ENDPOINT.format(model="gemini-3-flash-preview")
    respx.post(url_pattern).mock(return_value=httpx.Response(500, text="Internal Error"))

    async with httpx.AsyncClient() as client:
        result = await generate_ai_analysis(
            url="http://test.com",
            risk_score=50,
            verdict="suspicious",
            findings=[],
            http_client=client,
            api_key="fake-key",
        )
        assert result is None
