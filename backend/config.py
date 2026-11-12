"""
CyberPulse configuration loader.

Loads config.yaml (shipped defaults) and overlays config.local.yaml
(machine-specific overrides, not committed). Provides typed accessors
used by the database, scanner, advisor and API layers.
"""

import copy
import os
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - yaml optional at import time
    yaml = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")
LOCAL_CONFIG_PATH = os.path.join(BASE_DIR, "config.local.yaml")

_DEFAULTS: dict[str, Any] = {
    "version": 1,
    "host": "127.0.0.1",
    "port": 8844,
    "data_dir": "data",
    "custom_paths": [],
    "ai": {
        "enabled": False,
        "provider": "gemini",
        "gemini_api_key": "",
        "openai_api_key": "",
        "redact_before_send": True,
    },
    "monitor": {
        "interval_sec": 3,
        "adaptive": True,
    },
    "retention": {
        "usage_sessions_days": 0,
        "scenario_history_days": 0,
    },
    "shell_hook": {
        "enabled": False,
    },
}

_config: dict[str, Any] = {}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for k, v in override.items():
        if (
            k in result
            and isinstance(result[k], dict)
            and isinstance(v, dict)
        ):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def _load_yaml(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        return {}
    if yaml is None:
        return {}
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        return {}
    return data


def load_config() -> dict[str, Any]:
    global _config
    if _config:
        return _config
    cfg = _deep_merge(_DEFAULTS, _load_yaml(DEFAULT_CONFIG_PATH))
    cfg = _deep_merge(cfg, _load_yaml(LOCAL_CONFIG_PATH))
    _config = cfg
    return _config


def get(section: str, key: str | None = None, default: Any = None) -> Any:
    cfg = load_config()
    section_data = cfg.get(section, {})
    if key is None:
        return section_data
    return section_data.get(key, default)


def ai_enabled() -> bool:
    return bool(get("ai", "enabled", False))


def ai_redact() -> bool:
    return bool(get("ai", "redact_before_send", True))


def custom_paths() -> list[str]:
    paths = get("custom_paths", default=[]) or []
    return [p for p in paths if p]


def monitor_interval() -> float:
    return float(get("monitor", "interval_sec", 3.0))
