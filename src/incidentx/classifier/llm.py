from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from ..config import llm_settings

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
        return "".join(str(part.get("text", "")) for part in parts)

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
    ) -> Optional[str]:
        if not self.available:
            return None
        if self.provider == "gemini":
            url = (
                f"{self.settings['base_url']}/models/"
                f"{self.settings['model']}:generateContent"
            )
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": self.settings.get("api_key", ""),
            }
            payload = {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": max_tokens,
                },
            }
        else:
            url = f"{self.settings['base_url']}/chat/completions"
            headers = {"Content-Type": "application/json"}
            api_key = self.settings.get("api_key")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            payload = {
                "model": self.settings["model"],
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
            if not content:
                return None
            self.used = True
            return content.strip()
        except Exception as exc:  # pragma: no cover - depends on external service
            self._failed = True
            LOGGER.warning("LLM request failed; using rules only this run: %s", exc)
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
        content = self._chat(system, user, max_tokens=180)
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
