from __future__ import annotations

from ..config import Config
from .base import LLMClient, LLMUnavailable
from .cache import LLMCache
from .providers import GeminiClient, OllamaClient, OpenRouterClient

PROVIDERS = {"local": OllamaClient, "ollama": OllamaClient,
             "openrouter": OpenRouterClient, "gemini": GeminiClient}


def get_llm(config: Config, provider: str | None = None) -> LLMClient:
    """Build the configured client. Raises LLMUnavailable if the LLM is disabled."""
    if not config.get("llm.enabled", True):
        raise LLMUnavailable("LLM disabled in config (llm.enabled = false)")
    name = (provider or config.get("llm.provider", "local")).lower()
    if name not in PROVIDERS:
        raise LLMUnavailable(f"unknown LLM provider '{name}' (use local | openrouter | gemini)")
    section = "local" if name == "ollama" else name
    settings = dict(config.get(f"llm.{section}", {}))
    common = dict(
        model=settings.pop("model"),
        temperature=config.get("llm.temperature", 0.1),
        timeout=config.get("llm.timeout_seconds", 180),
        max_retries=config.get("llm.max_retries", 2),
        cache=LLMCache(config.workspace / "llm_cache.sqlite") if config.get("llm.cache", True) else None,
    )
    return PROVIDERS[name](**settings, **common)
