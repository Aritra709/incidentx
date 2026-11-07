from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from ..config import llm_settings

LOGGER = logging.getLogger(__name__)


class LLMReasoner:
    """Optional LLM layer. Used only for unknown errors and explanations.

    Works with any OpenAI-compatible chat-completions endpoint, including a
    local Ollama server. If no credentials are configured everything falls
    back to the deterministic rules/templates.
    """

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or llm_settings()
        self.enabled = bool(self.settings.get("enabled"))
        self.used = False
        self._classification_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def available(self) -> bool:
        return self.enabled

    def _chat(
        self,
        system: str,
        user: str,
        max_tokens: int = 300,
        temperature: float = 0.0,
    ) -> Optional[str]:
        if not self.enabled:
            return None
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
            content = data["choices"][0]["message"]["content"]
            self.used = True
            return content.strip()
        except Exception as exc:  # pragma: no cover - depends on external service
            LOGGER.warning("LLM request failed: %s", exc)
            return None

    def classify_error(
        self,
        message: str,
        level: str,
        service: str,
        allowed_categories: List[str],
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
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
            if content.startswith("```"):
                content = content.strip("`")
                content = content.replace("json\n", "", 1)
            data = json.loads(content)
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
        if not self.enabled:
            return None
        system = (
            "You are a senior SRE writing for a small team with no on-call engineer. "
            "Explain the incident using ONLY the supplied facts. Do not invent causes, "
            "commands, or metrics. Be concise: 3-5 short sentences. If the facts are "
            "insufficient, say what is uncertain."
        )
        user = json.dumps(context, ensure_ascii=False, default=str)
        return self._chat(system, user, max_tokens=320, temperature=0.2)
