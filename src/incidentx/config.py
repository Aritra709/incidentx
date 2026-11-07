from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "incidentx"

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
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    base_url = os.getenv(
        "OPENAI_BASE_URL", "https://api.openai.com/v1"
    ).strip().rstrip("/")
    model = os.getenv("INCIDENTX_LLM_MODEL", "gpt-4o-mini").strip()

    if enabled_raw in {"0", "false", "no", "off"}:
        enabled = False
    elif enabled_raw in {"1", "true", "yes", "on"}:
        enabled = bool(api_key or "localhost" in base_url or "127.0.0.1" in base_url)
    else:
        enabled = bool(api_key)

    return {
        "enabled": enabled,
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
        "timeout_seconds": float(os.getenv("INCIDENTX_LLM_TIMEOUT", "20")),
    }
