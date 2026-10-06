"""The three backends. All use plain HTTPS via `requests` (no vendor SDKs)."""

from __future__ import annotations

import os

import requests

from .base import LLMClient, LLMError, LLMUnavailable


class OllamaClient(LLMClient):
    """Local mode: Ollama server (default http://localhost:11434)."""
    provider = "local"
    is_cloud = False

    def __init__(self, host: str, **kw):
        super().__init__(**kw)
        self.host = host.rstrip("/")

    def check(self) -> str:
        try:
            tags = requests.get(f"{self.host}/api/tags", timeout=5).json()
        except requests.RequestException as exc:
            raise LLMUnavailable(f"Ollama not reachable at {self.host}: {exc}") from exc
        names = [m.get("name", "") for m in tags.get("models", [])]
        if self.model not in names and f"{self.model}:latest" not in names:
            raise LLMUnavailable(f"model '{self.model}' not pulled in Ollama (have: {', '.join(names) or 'none'}). "
                                 f"Run: ollama pull {self.model}")
        return f"local:{self.model}"

    def _complete(self, system, prompt, json_mode, temperature):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_mode:
            body["format"] = "json"
        try:
            r = requests.post(f"{self.host}/api/chat", json=body, timeout=self.timeout)
        except requests.ConnectionError as exc:
            raise LLMUnavailable(f"Ollama not reachable at {self.host}") from exc
        if r.status_code >= 400:
            raise LLMError(f"Ollama HTTP {r.status_code}: {r.text[:300]}")
        return r.json()["message"]["content"]


class OpenRouterClient(LLMClient):
    """Cloud mode: OpenRouter (OpenAI-compatible chat completions)."""
    provider = "openrouter"
    is_cloud = True

    def __init__(self, base_url: str, api_key_env: str, **kw):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env

    def _key(self) -> str:
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise LLMUnavailable(f"{self.api_key_env} is not set")
        return key

    def check(self) -> str:
        self._key()
        return f"openrouter:{self.model}"

    def _complete(self, system, prompt, json_mode, temperature):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        r = requests.post(f"{self.base_url}/chat/completions", json=body, timeout=self.timeout,
                          headers={"Authorization": f"Bearer {self._key()}",
                                   "X-Title": "secreview"})
        if r.status_code in (401, 403):
            raise LLMUnavailable(f"OpenRouter rejected the API key (HTTP {r.status_code})")
        if r.status_code >= 400:
            raise LLMError(f"OpenRouter HTTP {r.status_code}: {r.text[:300]}")
        data = r.json()
        if "choices" not in data:
            raise LLMError(f"OpenRouter error: {str(data)[:300]}")
        return data["choices"][0]["message"]["content"] or ""


class GeminiClient(LLMClient):
    """Cloud mode: Google Gemini API (generateContent REST endpoint)."""
    provider = "gemini"
    is_cloud = True

    def __init__(self, base_url: str, api_key_env: str, **kw):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env

    def _key(self) -> str:
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise LLMUnavailable(f"{self.api_key_env} is not set")
        return key

    def check(self) -> str:
        self._key()
        return f"gemini:{self.model}"

    def _complete(self, system, prompt, json_mode, temperature):
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature},
        }
        if json_mode:
            body["generationConfig"]["responseMimeType"] = "application/json"
        r = requests.post(f"{self.base_url}/models/{self.model}:generateContent", json=body,
                          timeout=self.timeout, headers={"x-goog-api-key": self._key()})
        if r.status_code in (401, 403):
            raise LLMUnavailable(f"Gemini rejected the API key (HTTP {r.status_code})")
        if r.status_code >= 400:
            raise LLMError(f"Gemini HTTP {r.status_code}: {r.text[:300]}")
        data = r.json()
        try:
            return "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Gemini returned no content: {str(data)[:300]}") from exc
