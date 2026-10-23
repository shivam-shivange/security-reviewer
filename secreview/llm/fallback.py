"""Fallback chain: try providers in order (default OpenRouter -> Gemini -> local), moving on when one fails.

A provider "fails" when it is unavailable (no key, server down), errors after its own retries
(rate limit, quota, 5xx, timeout) or returns text that is not valid JSON. A failed provider is skipped
for `cooldown` seconds so later calls do not waste its retry delays (e.g. a used-up daily free quota).
"""

from __future__ import annotations

import time

from .base import LLMClient, LLMError, LLMUnavailable, extract_json


class FallbackClient(LLMClient):
    provider = "fallback"

    def __init__(self, members: list[LLMClient], cooldown: float = 300, log=None):
        super().__init__(model=" > ".join(f"{m.provider}:{m.model}" for m in members))
        self.members = members
        self.cooldown = cooldown
        self.log = log or (lambda message: None)
        self._down_until: dict[int, float] = {}
        self.served_by: dict[str, int] = {}      # provider:model -> answers given
        self.last_member: LLMClient | None = None

    @property
    def is_cloud(self) -> bool:
        return any(m.is_cloud for m in self.members)

    def check(self) -> str:
        """Keep the members that are usable now; unavailable only if none is."""
        usable, skipped = [], []
        for m in self.members:
            try:
                m.check()
                usable.append(m)
            except LLMUnavailable as exc:
                skipped.append(f"{m.provider}: {exc}")
        if not usable:
            raise LLMUnavailable("no LLM in the fallback chain is usable: " + "; ".join(skipped))
        self.members = usable
        self.model = " > ".join(f"{m.provider}:{m.model}" for m in usable)
        for reason in skipped:
            self.log(f"fallback chain: skipping {reason}")
        return f"fallback[{self.model}]"

    def drop_cloud(self) -> bool:
        """Keep only local members (cloud use was not permitted). Returns True if any remain."""
        self.members = [m for m in self.members if not m.is_cloud]
        self.model = " > ".join(f"{m.provider}:{m.model}" for m in self.members)
        return bool(self.members)

    def _complete(self, system, prompt, json_mode, temperature):   # pragma: no cover - not used directly
        raise NotImplementedError("FallbackClient delegates through complete()")

    def _run(self, call) -> str | dict | list:
        errors = []
        now = time.time()
        live = [m for m in self.members if self._down_until.get(id(m), 0) <= now]
        # if everything is cooling down, try them all again rather than give up
        for m in live or self.members:
            try:
                out = call(m)
            except LLMError as exc:   # includes LLMUnavailable and invalid JSON
                if not str(exc).startswith("model did not return valid JSON"):   # bad answer != bad provider
                    self._down_until[id(m)] = time.time() + self.cooldown
                errors.append(f"{m.provider}: {str(exc)[:160]}")
                self.log(f"LLM fallback: {m.provider}:{m.model} failed ({str(exc)[:120]}); trying the next provider")
                continue
            name = f"{m.provider}:{m.model}"
            self.served_by[name] = self.served_by.get(name, 0) + 1
            self.last_member = m
            return out
        raise LLMError("every provider in the fallback chain failed: " + " | ".join(errors))

    def complete(self, system: str, prompt: str, json_mode: bool = True,
                 temperature: float | None = None, use_cache: bool = True) -> str:
        return self._run(lambda m: m.complete(system, prompt, json_mode, temperature, use_cache))

    def complete_json(self, system: str, prompt: str, temperature: float | None = None,
                      use_cache: bool = True) -> dict | list:
        # parse inside the chain, so a provider that answers with broken JSON also falls through
        return self._run(lambda m: extract_json(m.complete(system, prompt, True, temperature, use_cache)))

    @property
    def calls(self) -> int:
        return sum(m.calls for m in getattr(self, "members", []))

    @calls.setter
    def calls(self, value: int) -> None:   # base __init__ assigns it; members keep the real counts
        pass

    @property
    def cache_hits(self) -> int:
        return sum(m.cache_hits for m in getattr(self, "members", []))

    @cache_hits.setter
    def cache_hits(self, value: int) -> None:
        pass
