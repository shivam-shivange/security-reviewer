from __future__ import annotations

import json
import re
import threading
import time
from abc import ABC, abstractmethod

from ..redact import redact
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
        # Called about every half second while a request is in flight; it raises to abandon the call
        # (the dashboard's Stop / Skip). Set by the LLM gate for pipeline runs.
        self.interrupt = None

    @abstractmethod
    def _complete(self, system: str, prompt: str, json_mode: bool, temperature: float) -> str:
        ...

    def check(self) -> str:
        """Return a short status string; raise LLMUnavailable if unusable."""
        return f"{self.provider}:{self.model}"

    def complete(self, system: str, prompt: str, json_mode: bool = True,
                 temperature: float | None = None, use_cache: bool = True) -> str:
        # every prompt leaves through here: mask keys / passwords whichever stage built it
        system, prompt = redact(system), redact(prompt)
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
                out = self._interruptible(lambda: self._complete(system, prompt, json_mode, temp))
                if not (out or "").strip():
                    # an empty answer means the provider is failing (often a used-up free quota), not
                    # that the question was bad: retry, then let a fallback chain move on
                    raise LLMError(f"{self.provider} returned an empty response")
                if self.cache and key:
                    self.cache.put(key, out)
                return out
            except LLMUnavailable:
                raise
            except Exception as exc:  # network errors, 5xx, rate limits
                last = exc
                self._pause(min(2 ** attempt * 2, 20))
        raise LLMError(f"{self.provider} failed after retries: {last}")

    def _interruptible(self, call):
        """Run a blocking request; while it is in flight, poll `interrupt` so Stop / Skip act at once.
        An abandoned request finishes in its daemon thread and its answer is dropped."""
        if self.interrupt is None:
            return call()
        box: dict = {}

        def worker():
            try:
                box["out"] = call()
            except BaseException as exc:   # handed to the caller below
                box["err"] = exc
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        while t.is_alive():
            t.join(0.5)
            if t.is_alive():
                self.interrupt()
        if "err" in box:
            raise box["err"]
        return box["out"]

    def _pause(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            time.sleep(min(0.5, max(end - time.time(), 0)))
            if self.interrupt is not None:
                self.interrupt()

    def complete_json(self, system: str, prompt: str, temperature: float | None = None,
                      use_cache: bool = True) -> dict | list:
        return extract_json(self.complete(system, prompt, True, temperature, use_cache))
