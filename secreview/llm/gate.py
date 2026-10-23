"""LLM access for pipeline stages: lazy creation, availability check, cloud-privacy permission."""

from __future__ import annotations

from ..context import RunContext
from .base import LLMClient, LLMUnavailable
from .factory import get_llm
from .fallback import FallbackClient


class LLMGate:
    """Hands out the LLM client once it is known to be usable and permitted for this run.

    Stages call `gate.client()`; it returns None when the LLM is disabled, unconfigured,
    unreachable or (for cloud providers) the user declined to send code off the machine.
    """

    def __init__(self, ctx: RunContext, client: LLMClient | None = None):
        self.ctx = ctx
        self._client = client
        self._checked = client is not None
        self._ok = client is not None
        self.reason = ""

    def client(self) -> LLMClient | None:
        if self._checked:
            return self._client if self._ok else None
        self._checked = True
        try:
            self._client = get_llm(self.ctx.config, log=self.ctx.warn)
            status = self._client.check()
        except LLMUnavailable as exc:
            self.reason = str(exc)
            self.ctx.warn(f"LLM unavailable, continuing deterministic-only: {exc}")
            self._ok = False
            return None
        if self._client.is_cloud and not self.ctx.allow(
                "send_code_to_cloud_llm",
                f"Provider: {status}. Only bounded code slices around each finding are sent."):
            # a fallback chain can still run on its local members
            if isinstance(self._client, FallbackClient) and self._client.drop_cloud():
                status = f"fallback[{self._client.model}]"
                self.ctx.log("cloud LLM not permitted; fallback chain continues with local models only")
            else:
                self.reason = "cloud LLM not permitted"
                self._ok = False
                return None
        self.ctx.log(f"LLM ready: {status}")
        self._ok = True
        return self._client

    @property
    def stats(self) -> dict:
        if not self._client:
            return {"provider": None, "calls": 0, "cache_hits": 0, "reason": self.reason}
        stats = {"provider": f"{self._client.provider}:{self._client.model}",
                 "calls": self._client.calls, "cache_hits": self._client.cache_hits,
                 "reason": self.reason}
        if isinstance(self._client, FallbackClient):
            stats["served_by"] = dict(self._client.served_by)
        return stats
