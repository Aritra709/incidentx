from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from ..config import llm_settings
from ..models import LLMHypothesis, LLMReasoning

LOGGER = logging.getLogger(__name__)


class LLMReasoner:
    """Optional LLM layer. Used only for unknown errors and explanations.

    Supports Google Gemini natively and any OpenAI-compatible chat-completions
    endpoint, including a local Ollama server. If no credentials are configured
    everything falls back to the deterministic rules/templates.
    """

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or llm_settings()
        self.provider = str(self.settings.get("provider") or "openai").lower()
        self.enabled = bool(self.settings.get("enabled"))
        self.active_model = str(self.settings.get("model") or "")
        self.used = False
        self._failed = False
        self._classification_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def available(self) -> bool:
        return self.enabled and not self._failed

    def reset_health(self) -> None:
        self._failed = False

    @staticmethod
    def _gemini_content(data: Dict[str, Any]) -> str:
        candidates = data.get("candidates") or []
        if not candidates:
            return ""
        parts = (candidates[0].get("content") or {}).get("parts") or []
        return "".join(
            str(part.get("text", ""))
            for part in parts
            if not part.get("thought")
        )

    @staticmethod
    def _parse_json_object(content: str) -> Dict[str, Any]:
        text = content.strip()
        if text.startswith("```"):
            text = text.strip("`").strip()
            if text.lower().startswith("json"):
                text = text[4:].lstrip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end <= start:
                raise
            data = json.loads(text[start : end + 1])
        if not isinstance(data, dict):
            raise ValueError("LLM response is not a JSON object")
        return data

    def _chat(
        self,
        system: str,
        user: str,
        max_tokens: int = 300,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> Optional[str]:
        if not self.available:
            return None
        models = [self.active_model or str(self.settings.get("model") or "")]
        for fallback in self.settings.get("fallback_models", []) or []:
            if fallback and fallback not in models:
                models.append(str(fallback))
        models = [model for model in models if model]
        if self.provider != "gemini":
            models = models[:1]
        if not models:
            return None

        last_error: Optional[Exception] = None
        for index, model in enumerate(models):
            if self.provider == "gemini":
                url = f"{self.settings['base_url']}/models/{model}:generateContent"
                headers = {
                    "Content-Type": "application/json",
                    "x-goog-api-key": self.settings.get("api_key", ""),
                }
                generation_config: Dict[str, Any] = {
                    "temperature": temperature,
                    "maxOutputTokens": max_tokens,
                }
                if json_mode:
                    generation_config["responseMimeType"] = "application/json"
                payload = {
                    "systemInstruction": {"parts": [{"text": system}]},
                    "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "generationConfig": generation_config,
                }
            else:
                url = f"{self.settings['base_url']}/chat/completions"
                headers = {"Content-Type": "application/json"}
                api_key = self.settings.get("api_key")
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.settings.get("timeout_seconds", 20),
                )
                response.raise_for_status()
                data = response.json()
                if self.provider == "gemini":
                    content = self._gemini_content(data)
                else:
                    content = data["choices"][0]["message"]["content"]
                if content:
                    self.active_model = model
                    self.used = True
                    return content.strip()
                last_error = ValueError(f"{model} returned an empty response")
                if index < len(models) - 1:
                    LOGGER.info(
                        "Gemini model %s returned no content; trying fallback.", model
                    )
            except Exception as exc:  # pragma: no cover - depends on external service
                last_error = exc
                if index < len(models) - 1:
                    LOGGER.info(
                        "Gemini model %s unavailable; trying fallback: %s", model, exc
                    )
                    continue
        self._failed = True
        LOGGER.warning("LLM request failed; using rules only this run: %s", last_error)
        return None

    def ping(self) -> Optional[str]:
        """Send a tiny request to verify credentials and connectivity."""
        if not self.available:
            return None
        return self._chat(
            "You are a connectivity check.",
            "Reply with exactly OK.",
            max_tokens=64,
        )

    def classify_error(
        self,
        message: str,
        level: str,
        service: str,
        allowed_categories: List[str],
    ) -> Optional[Dict[str, Any]]:
        if not self.available:
            return None
        cache_key = f"{service}|{level}|{message}"
        if cache_key in self._classification_cache:
            return self._classification_cache[cache_key]

        system = (
            "You are an incident-response classifier. Choose exactly one category "
            "from the allowed list. Return strict JSON only, with keys: "
            "category (string), family (string), confidence (number 0-1), "
            "reason (one short sentence). Never invent a category."
        )
        user = (
            f"Allowed categories: {', '.join(allowed_categories)}\n"
            f"Service: {service}\nLevel: {level}\nLog message: {message}\n"
            'Return JSON such as {"category":"API_TIMEOUT","family":"DEPENDENCY",'
            '"confidence":0.8,"reason":"..."}'
        )
        content = self._chat(system, user, max_tokens=180, json_mode=True)
        if not content:
            return None
        try:
            data = self._parse_json_object(content)
            category = str(data.get("category", "")).upper()
            if category not in allowed_categories:
                return None
            result = {
                "category": category,
                "family": str(data.get("family", "UNKNOWN")).upper(),
                "confidence": max(0.0, min(float(data.get("confidence", 0.6)), 0.95)),
                "reason": str(data.get("reason", "LLM classification")).strip(),
            }
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            LOGGER.warning("LLM classification returned invalid JSON: %s", exc)
            return None
        self._classification_cache[cache_key] = result
        return result

    def explain_incident(self, context: Dict[str, Any]) -> Optional[str]:
        """Return a short, grounded explanation for the engineer report."""
        if not self.available:
            return None
        system = (
            "You are a senior SRE writing for a small team with no on-call engineer. "
            "Explain the incident using ONLY the supplied facts. Do not invent causes, "
            "commands, or metrics. Be concise: 3-5 short sentences. If the facts are "
            "insufficient, say what is uncertain."
        )
        user = json.dumps(context, ensure_ascii=False, default=str)
        return self._chat(system, user, max_tokens=320, temperature=0.2)

    @staticmethod
    def _clip(value: Any, limit: int) -> str:
        text = " ".join(str(value or "").split())
        return text[:limit].rstrip()

    @classmethod
    def _string_list(cls, value: Any, limit: int, item_limit: int) -> List[str]:
        if isinstance(value, str):
            items: List[Any] = [value]
        elif isinstance(value, list):
            items = value
        else:
            return []
        result: List[str] = []
        for item in items:
            text = cls._clip(item, item_limit)
            if text:
                result.append(text)
            if len(result) >= limit:
                break
        return result

    @staticmethod
    def _confidence(value: Any, default: float = 0.0) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        return max(0.0, min(number, 1.0))

    def _reasoning_from_data(
        self,
        data: Dict[str, Any],
        context: Dict[str, Any],
        raw: str,
    ) -> LLMReasoning:
        summary = self._clip(data.get("summary"), 1600)
        causal_chain = self._string_list(data.get("causal_chain"), 6, 500)
        raw_hypotheses = data.get("hypotheses")
        if isinstance(raw_hypotheses, dict):
            raw_hypotheses = [raw_hypotheses]
        hypotheses: List[LLMHypothesis] = []
        if isinstance(raw_hypotheses, list):
            for item in raw_hypotheses[:4]:
                if not isinstance(item, dict):
                    continue
                hypothesis = self._clip(item.get("hypothesis"), 400)
                if not hypothesis:
                    continue
                hypotheses.append(
                    LLMHypothesis(
                        hypothesis=hypothesis,
                        confidence=self._confidence(item.get("confidence")),
                        supporting_evidence=self._string_list(
                            item.get("supporting_evidence"), 5, 400
                        ),
                        conflicting_evidence=self._string_list(
                            item.get("conflicting_evidence"), 5, 400
                        ),
                        validation=self._clip(item.get("validation"), 600),
                    )
                )
        if not hypotheses:
            deterministic = context.get("deterministic_analysis") or {}
            root = deterministic.get("root_cause") or {}
            category = self._clip(root.get("category"), 120)
            service = self._clip(root.get("service"), 120)
            if category or service:
                hypotheses.append(
                    LLMHypothesis(
                        hypothesis=(
                            f"{category or 'The deterministic pattern'} in "
                            f"{service or 'the affected service'} is the leading hypothesis."
                        ),
                        confidence=self._confidence(root.get("confidence")),
                        supporting_evidence=self._string_list(
                            root.get("reasoning"), 3, 500
                        ),
                        validation=(
                            "Validate with the recommended checks and compare against "
                            "the linked change before acting."
                        ),
                    )
                )
        if not summary:
            summary = self._clip(raw, 1600) or (
                hypotheses[0].hypothesis if hypotheses else ""
            )
        deterministic = context.get("deterministic_analysis") or {}
        change_link = deterministic.get("change_link") or {}
        if len(hypotheses) < 2 and change_link:
            primary_confidence = hypotheses[0].confidence if hypotheses else 0.0
            alternative_confidence = max(0.05, min(0.3, 1.0 - primary_confidence))
            change_name = self._clip(
                f"{change_link.get('type', 'change')} {change_link.get('id', '')}",
                120,
            )
            hypotheses.append(
                LLMHypothesis(
                    hypothesis=(
                        f"{change_name} is correlated by timing but may not be causal; "
                        "independent traffic or dependency pressure could explain the failure."
                    ),
                    confidence=round(alternative_confidence, 2),
                    supporting_evidence=[
                        "A temporal change link alone does not prove causation."
                    ],
                    conflicting_evidence=self._string_list(
                        change_link.get("reason"), 2, 500
                    ),
                    validation=(
                        "Compare pool and error metrics before and after the change, "
                        "and confirm whether rollback alone restores capacity."
                    ),
                )
            )
        return LLMReasoning(
            summary=summary,
            causal_chain=causal_chain,
            hypotheses=hypotheses,
            uncertainties=self._string_list(data.get("uncertainties"), 5, 500),
            recommended_checks=self._string_list(
                data.get("recommended_checks"), 6, 500
            ),
            operator_briefing=self._clip(data.get("operator_briefing"), 2400),
        )

    def reason_incident(self, context: Dict[str, Any]) -> Optional[LLMReasoning]:
        """Return a structured, evidence-grounded reasoning brief."""
        if not self.available:
            return None
        system = (
            "You are an incident commander and senior SRE. Build an evidence-grounded "
            "reasoning brief for a small team without an on-call engineer. Use ONLY facts "
            "from the supplied JSON. Never invent logs, metrics, causes, or shell commands. "
            "Distinguish observations from inferences. Treat the deterministic root cause "
            "as a strong prior, not proof: give at least 2 hypotheses even when one is "
            "dominant, and explain why alternatives are weaker. Include disconfirming "
            "evidence and uncertainties. Reference exact services, timestamps, categories, "
            "and counts. Do not recommend destructive actions beyond the supplied "
            "approval-gated remediation. recommended_checks must be plain-language "
            "read-only diagnostics, not executable commands; only mention a command when "
            "it appears in proposed_remediation. Return strict JSON with exactly these "
            "keys: summary (2-4 sentence conclusion), causal_chain (3-6 evidence-backed "
            "steps), hypotheses (2-4 objects with hypothesis, confidence 0-1, "
            "supporting_evidence array, conflicting_evidence array, validation string), "
            "uncertainties (array), recommended_checks (array of read-only checks), "
            "operator_briefing (one short paragraph). No markdown. Keep the entire JSON "
            "under 500 words."
        )
        user = json.dumps(context, ensure_ascii=False, default=str)
        content = self._chat(
            system,
            user,
            max_tokens=2400,
            temperature=0.2,
            json_mode=True,
        )
        if not content:
            return None
        try:
            data = self._parse_json_object(content)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            LOGGER.warning("LLM reasoning returned invalid JSON: %s", exc)
            return self._reasoning_from_data({}, context, content)
        return self._reasoning_from_data(data, context, content)
