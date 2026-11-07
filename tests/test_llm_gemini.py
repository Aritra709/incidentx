from __future__ import annotations

from typing import Any, Dict

from incidentx.classifier.llm import LLMReasoner
from incidentx.config import llm_settings


class FakeResponse:
    def __init__(self, data: Dict[str, Any]):
        self.data = data

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Dict[str, Any]:
        return self.data


def gemini_settings() -> Dict[str, Any]:
    return {
        "enabled": True,
        "provider": "gemini",
        "api_key": "gemini-test-key",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "model": "gemini-test-model",
        "timeout_seconds": 1,
    }


def clear_llm_env(monkeypatch) -> None:
    for name in (
        "INCIDENTX_LLM_ENABLED",
        "INCIDENTX_LLM_PROVIDER",
        "INCIDENTX_LLM_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "GEMINI_API_KEY",
        "GEMINI_BASE_URL",
        "GEMINI_MODEL",
        "GEMINI_FALLBACK_MODELS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_llm_settings_auto_selects_gemini(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test-model")
    llm_settings.cache_clear()
    try:
        settings = llm_settings()
    finally:
        llm_settings.cache_clear()

    assert settings["provider"] == "gemini"
    assert settings["enabled"] is True
    assert settings["api_key"] == "gemini-test-key"
    assert settings["model"] == "gemini-test-model"
    assert settings["base_url"] == "https://generativelanguage.googleapis.com/v1beta"


def test_gemini_defaults_include_fallbacks(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")
    llm_settings.cache_clear()
    try:
        settings = llm_settings()
    finally:
        llm_settings.cache_clear()

    assert settings["fallback_models"] == [
        "gemini-3.5-flash",
        "gemini-flash-lite-latest",
    ]


def test_gemini_falls_back_when_primary_is_rate_limited(monkeypatch):
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append(url)
        if "gemini-test-model" in url:
            raise RuntimeError("429 rate limited")
        return FakeResponse(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": (
                                        '{"summary":"Fallback worked.",'
                                        '"causal_chain":["Evidence"],'
                                        '"hypotheses":[],'
                                        '"uncertainties":[],'
                                        '"recommended_checks":[],'
                                        '"operator_briefing":""}'
                                    )
                                }
                            ]
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr("incidentx.classifier.llm.requests.post", fake_post)
    settings = gemini_settings()
    settings["fallback_models"] = ["gemini-fallback"]
    reasoner = LLMReasoner(settings)

    reasoning = reasoner.reason_incident({"incident": "test"})

    assert reasoning is not None
    assert reasoning.summary == "Fallback worked."
    assert reasoner.active_model == "gemini-fallback"
    assert any("gemini-fallback" in url for url in calls)
    assert reasoner._failed is False


def test_explicit_provider_overrides_auto(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-test-key")
    monkeypatch.setenv("INCIDENTX_LLM_PROVIDER", "openai")
    llm_settings.cache_clear()
    try:
        settings = llm_settings()
    finally:
        llm_settings.cache_clear()

    assert settings["provider"] == "openai"
    assert settings["api_key"] == "openai-test-key"
    assert settings["model"] == "gpt-4o-mini"


def test_gemini_uses_native_generate_content(monkeypatch):
    captured: Dict[str, Any] = {}

    def fake_post(url, headers, json, timeout):
        captured.update(url=url, headers=headers, json=json, timeout=timeout)
        return FakeResponse(
            {"candidates": [{"content": {"parts": [{"text": "Gemini explanation."}]}}]}
        )

    monkeypatch.setattr("incidentx.classifier.llm.requests.post", fake_post)
    reasoner = LLMReasoner(gemini_settings())

    assert reasoner.explain_incident({"incident": "test"}) == "Gemini explanation."
    assert captured["url"].endswith(
        "/models/gemini-test-model:generateContent"
    )
    assert captured["headers"]["x-goog-api-key"] == "gemini-test-key"
    assert captured["json"]["systemInstruction"]["parts"][0]["text"]
    assert captured["json"]["contents"][0]["parts"][0]["text"] == '{"incident": "test"}'
    assert captured["json"]["generationConfig"]["maxOutputTokens"] == 320
    assert reasoner.used is True


def test_gemini_classification_parses_json(monkeypatch):
    def fake_post(url, headers, json, timeout):
        return FakeResponse(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": (
                                        '```json\n{"category":"API_TIMEOUT",'
                                        '"family":"DEPENDENCY","confidence":0.9,'
                                        '"reason":"Gemini says so"}\n```'
                                    )
                                }
                            ]
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr("incidentx.classifier.llm.requests.post", fake_post)
    reasoner = LLMReasoner(gemini_settings())

    result = reasoner.classify_error("x", "ERROR", "svc", ["API_TIMEOUT"])
    assert result is not None
    assert result["category"] == "API_TIMEOUT"
    assert result["confidence"] == 0.9


def test_ping_returns_provider_response(monkeypatch):
    reasoner = LLMReasoner(gemini_settings())
    monkeypatch.setattr(reasoner, "_chat", lambda *args, **kwargs: "OK")
    assert reasoner.ping() == "OK"


def test_gemini_content_skips_thought_parts():
    data = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "internal reasoning", "thought": True},
                        {"text": '{"summary":"final"}'},
                    ]
                }
            }
        ]
    }
    assert LLMReasoner._gemini_content(data) == '{"summary":"final"}'


def test_gemini_reasoning_uses_json_mode(monkeypatch):
    captured: Dict[str, Any] = {}

    def fake_post(url, headers, json, timeout):
        captured.update(url=url, headers=headers, json=json, timeout=timeout)
        return FakeResponse(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": (
                                        '{"summary":"Grounded conclusion.",'
                                        '"causal_chain":["Evidence one"],'
                                        '"hypotheses":[{"hypothesis":"Cause A",'
                                        '"confidence":0.8,'
                                        '"supporting_evidence":["Evidence one"],'
                                        '"conflicting_evidence":[],'
                                        '"validation":"Check A"}],'
                                        '"uncertainties":["Unknown B"],'
                                        '"recommended_checks":["Check A"],'
                                        '"operator_briefing":"Brief."}'
                                    )
                                }
                            ]
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr("incidentx.classifier.llm.requests.post", fake_post)
    reasoner = LLMReasoner(gemini_settings())

    reasoning = reasoner.reason_incident({"incident": "test"})
    assert reasoning is not None
    assert reasoning.summary == "Grounded conclusion."
    assert reasoning.causal_chain == ["Evidence one"]
    assert reasoning.hypotheses[0].confidence == 0.8
    assert captured["json"]["generationConfig"]["responseMimeType"] == "application/json"
    assert captured["json"]["generationConfig"]["maxOutputTokens"] == 2400
    assert reasoner.used is True


def test_openai_compatible_payload_still_works(monkeypatch):
    captured: Dict[str, Any] = {}

    def fake_post(url, headers, json, timeout):
        captured.update(url=url, headers=headers, json=json, timeout=timeout)
        return FakeResponse({"choices": [{"message": {"content": "OpenAI answer."}}]})

    monkeypatch.setattr("incidentx.classifier.llm.requests.post", fake_post)
    reasoner = LLMReasoner(
        {
            "enabled": True,
            "provider": "openai",
            "api_key": "openai-test-key",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-test",
            "timeout_seconds": 1,
        }
    )

    assert reasoner.explain_incident({"incident": "test"}) == "OpenAI answer."
    assert captured["url"] == "https://api.openai.com/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer openai-test-key"
    assert captured["json"]["model"] == "gpt-test"
