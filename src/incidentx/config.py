from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "incidentx"

load_dotenv(PROJECT_ROOT / ".env", override=False)

DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_KB_DIR = PROJECT_ROOT / "knowledge_base"
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"


def project_path(*parts: str) -> Path:
    return PROJECT_ROOT.joinpath(*parts)


def read_yaml(path: Path | str) -> Dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_config(name: str, config_dir: Optional[Path] = None) -> Dict[str, Any]:
    directory = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
    return read_yaml(directory / name)


def load_knowledge_base(name: str, kb_dir: Optional[Path] = None) -> Dict[str, Any]:
    directory = Path(kb_dir) if kb_dir else DEFAULT_KB_DIR
    return read_yaml(directory / name)


@lru_cache(maxsize=1)
def llm_settings() -> Dict[str, Any]:
    enabled_raw = os.getenv("INCIDENTX_LLM_ENABLED", "auto").strip().lower()
    provider_raw = os.getenv("INCIDENTX_LLM_PROVIDER", "auto").strip().lower()

    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    if provider_raw in {"gemini", "google", "google-gemini"}:
        provider = "gemini"
    elif provider_raw in {"openai", "openai-compatible", "compatible", "ollama"}:
        provider = "openai"
    else:
        provider = "gemini" if gemini_key else "openai"

    if provider == "gemini":
        api_key = gemini_key
        base_url = os.getenv(
            "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
        ).strip().rstrip("/")
        model = (
            os.getenv("GEMINI_MODEL", "").strip()
            or os.getenv("INCIDENTX_LLM_MODEL", "").strip()
            or "gemini-3.6-flash"
        )
        fallback_raw = os.getenv("GEMINI_FALLBACK_MODELS")
        if fallback_raw is None:
            fallback_models = ["gemini-3.5-flash", "gemini-flash-lite-latest"]
        else:
            fallback_models = [
                name.strip() for name in fallback_raw.split(",") if name.strip()
            ]
    else:
        api_key = openai_key
        base_url = os.getenv(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        ).strip().rstrip("/")
        model = (
            os.getenv("INCIDENTX_LLM_MODEL", "").strip()
            or os.getenv("OPENAI_MODEL", "").strip()
            or "gpt-4o-mini"
        )
        fallback_models = []

    local_endpoint = provider == "openai" and (
        "localhost" in base_url or "127.0.0.1" in base_url
    )
    auto_enabled = bool(api_key) or local_endpoint

    if enabled_raw in {"0", "false", "no", "off"}:
        enabled = False
    else:
        enabled = auto_enabled

    return {
        "enabled": enabled,
        "provider": provider,
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
        "fallback_models": fallback_models,
        "timeout_seconds": float(os.getenv("INCIDENTX_LLM_TIMEOUT", "20")),
    }
