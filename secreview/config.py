"""Layered configuration: defaults -> user file -> project `.secreview.toml` -> environment."""

from __future__ import annotations

import copy
import os
import tomllib
from pathlib import Path
from typing import Any

from . import ROOT

DEFAULT_CONFIG = ROOT / "config" / "default.toml"

# Environment variables that override config keys.
ENV_OVERRIDES = {
    "SECREVIEW_LLM_PROVIDER": ("llm", "provider"),
    "SECREVIEW_LLM_ENABLED": ("llm", "enabled"),
    "OLLAMA_HOST": ("llm", "local", "host"),
    "SECREVIEW_LOCAL_MODEL": ("llm", "local", "model"),
    "SECREVIEW_OPENROUTER_MODEL": ("llm", "openrouter", "model"),
    "SECREVIEW_GEMINI_MODEL": ("llm", "gemini", "model"),
    "SECREVIEW_SANDBOX": ("verify", "sandbox"),
    "SECREVIEW_PERMISSIONS": ("permissions", "mode"),
}


def _merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def _coerce(value: str) -> Any:
    low = value.strip().lower()
    if low in ("true", "yes", "1", "on"):
        return True
    if low in ("false", "no", "0", "off"):
        return False
    return value


def load_dotenv(path: Path) -> None:
    """Minimal .env loader (does not override variables already set)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ.setdefault(key.strip(), value)


class Config:
    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, user_file: str | Path | None = None, project: str | Path | None = None) -> "Config":
        load_dotenv(ROOT / ".env")
        data = tomllib.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
        if user_file:
            _merge(data, tomllib.loads(Path(user_file).read_text(encoding="utf-8")))
        if project:
            proj_cfg = Path(project) / ".secreview.toml"
            if proj_cfg.is_file():
                _merge(data, tomllib.loads(proj_cfg.read_text(encoding="utf-8")))
        for env, keys in ENV_OVERRIDES.items():
            if os.environ.get(env):
                node = data
                for k in keys[:-1]:
                    node = node.setdefault(k, {})
                node[keys[-1]] = _coerce(os.environ[env])
        return cls(data)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def copy(self) -> "Config":
        return Config(copy.deepcopy(self.data))

    @property
    def workspace(self) -> Path:
        ws = Path(self.get("paths.workspace", "workspace"))
        if not ws.is_absolute():
            ws = ROOT / ws
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    def public_view(self) -> dict:
        """Config safe to show in the dashboard (no secrets are stored in config anyway)."""
        return copy.deepcopy(self.data)
