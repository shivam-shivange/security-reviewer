"""Fallback chain (OpenRouter -> Gemini -> local) with fake providers: no network, no keys."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview.config import Config                       # noqa: E402
from secreview.llm.base import LLMClient, LLMError, LLMUnavailable  # noqa: E402
from secreview.llm.factory import get_llm                 # noqa: E402
from secreview.llm.fallback import FallbackClient         # noqa: E402


class Fake(LLMClient):
    def __init__(self, provider, answers, cloud=True, available=True):
        super().__init__(model=f"{provider}-model", max_retries=0)
        self.provider, self.is_cloud, self.available = provider, cloud, available
        self.answers = list(answers)     # str = reply, Exception = raised

    def check(self):
        if not self.available:
            raise LLMUnavailable("no key")
        return f"{self.provider}:{self.model}"

    def _complete(self, system, prompt, json_mode, temperature):
        item = self.answers.pop(0) if self.answers else '{"ok": true}'
        if isinstance(item, Exception):
            raise item
        return item


def chain(*members, cooldown=300):
    return FallbackClient(list(members), cooldown=cooldown)


def test_first_provider_answers():
    c = chain(Fake("openrouter", ['{"v": 1}']), Fake("gemini", ['{"v": 2}']))
    assert c.complete_json("s", "p") == {"v": 1}
    assert c.served_by == {"openrouter:openrouter-model": 1}


def test_falls_through_on_error_then_cools_down():
    o = Fake("openrouter", [LLMError("HTTP 429 quota")])
    g = Fake("gemini", ['{"v": 2}', '{"v": 3}'])
    c = chain(o, g)
    assert c.complete_json("s", "p") == {"v": 2}
    assert c.complete_json("s", "p2") == {"v": 3}      # openrouter skipped while cooling down
    assert o.calls == 1 and g.calls == 2


def test_invalid_json_falls_through_without_cooldown():
    o = Fake("openrouter", ["not json", '{"v": 9}'])
    c = chain(o, Fake("gemini", ['{"v": 2}']))
    assert c.complete_json("s", "p") == {"v": 2}
    assert c.complete_json("s", "p2") == {"v": 9}      # a bad answer does not bench the provider


def test_reaches_local_last_and_reports_all_failures():
    c = chain(Fake("openrouter", [LLMError("503")]), Fake("gemini", [LLMError("429")]),
              Fake("local", ['{"v": "qwen"}'], cloud=False))
    assert c.complete_json("s", "p") == {"v": "qwen"}
    dead = chain(Fake("openrouter", [LLMError("503")]), Fake("gemini", [LLMError("429")]))
    with pytest.raises(LLMError, match="every provider"):
        dead.complete_json("s", "p")


def test_all_cooling_down_still_retries():
    o = Fake("openrouter", [LLMError("503"), '{"v": "back"}'])
    c = chain(o)
    with pytest.raises(LLMError):
        c.complete_json("s", "p")
    assert c.complete_json("s", "p2") == {"v": "back"}


def test_check_drops_unusable_members_and_drop_cloud():
    c = chain(Fake("openrouter", [], available=False), Fake("gemini", []), Fake("local", [], cloud=False))
    assert c.check() == "fallback[gemini:gemini-model > local:local-model]"
    assert c.is_cloud
    assert c.drop_cloud() and not c.is_cloud and [m.provider for m in c.members] == ["local"]
    with pytest.raises(LLMUnavailable):
        chain(Fake("openrouter", [], available=False)).check()


def test_factory_builds_configured_order():
    cfg = Config.load()
    cfg.set("llm.enabled", True)
    cfg.set("llm.provider", "fallback")
    cfg.set("llm.fallback_order", ["openrouter", "gemini", "local"])
    c = get_llm(cfg)
    assert isinstance(c, FallbackClient)
    assert [m.provider for m in c.members] == ["openrouter", "gemini", "local"]
