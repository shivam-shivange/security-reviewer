from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod

from .cache import LLMCache


class LLMError(RuntimeError):
    pass


class LLMUnavailable(LLMError):
    """The provider is disabled, not configured (no key) or not reachable."""


def extract_json(text: str) -> dict | list:
    """Parse the first JSON object/array in a model response (tolerates ``` fences and prose)."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise LLMError(f"model did not return valid JSON: {text[:200]!r}")


class LLMClient(ABC):
    provider = "base"
    is_cloud = False

    def __init__(self, model: str, temperature: float = 0.1, timeout: int = 180,
                 max_retries: int = 2, cache: LLMCache | None = None):
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache = cache
        self.calls = 0          # real (non-cached) calls made in this process
        self.cache_hits = 0

    @abstractmethod
    def _complete(self, system: str, prompt: str, json_mode: bool, temperature: float) -> str:
        ...

    def check(self) -> str:
        """Return a short status string; raise LLMUnavailable if unusable."""
        return f"{self.provider}:{self.model}"

    def complete(self, system: str, prompt: str, json_mode: bool = True,
                 temperature: float | None = None, use_cache: bool = True) -> str:
        temp = self.temperature if temperature is None else temperature
        key = None
        if self.cache and use_cache:
            key = self.cache.key(self.provider, self.model, system, prompt, json_mode, temp)
            hit = self.cache.get(key)
            if hit is not None:
                self.cache_hits += 1
                return hit
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                self.calls += 1
                out = self._complete(system, prompt, json_mode, temp)
                if self.cache and key:
                    self.cache.put(key, out)
                return out
            except LLMUnavailable:
                raise
            except Exception as exc:  # network errors, 5xx, rate limits
                last = exc
                time.sleep(min(2 ** attempt * 2, 20))
        raise LLMError(f"{self.provider} failed after retries: {last}")

    def complete_json(self, system: str, prompt: str, temperature: float | None = None,
                      use_cache: bool = True) -> dict | list:
        return extract_json(self.complete(system, prompt, True, temperature, use_cache))
