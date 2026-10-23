"""Keep secrets out of LLM prompts.

Two layers, both deterministic:
  * `llm_allowed(finding)`: secret findings and secret files (.env, *.pem, secrets.toml, ...) are never
    sent to an LLM at all; nothing an LLM could add is worth exposing a credential.
  * `redact(text)`: applied to every prompt in `LLMClient.complete`, whatever stage built it. Values that
    look like keys, tokens, passwords or credentialed URIs are replaced with <REDACTED:kind>; the code
    around them is left intact so the model can still reason about it.
"""

from __future__ import annotations

import fnmatch
import re
from functools import lru_cache
from pathlib import PurePosixPath

NO_LLM_CLASSES = {"hardcoded_secret", "client_side_secret"}
SECRET_FILES = (".env", ".env.*", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
                "id_rsa*", "id_ed25519*", "credentials", "credentials.*", "secrets.*", "*secrets*.toml",
                "*secrets*.yml", "*secrets*.yaml", "*secrets*.json", ".npmrc", ".pypirc", ".netrc",
                "service-account*.json", "*-credentials.json")
SECRET_NAME = r"[A-Za-z0-9_.-]*(?:secret|passw(?:or)?d|pwd|passwd|token|api[_-]?key|access[_-]?key|private[_-]?key|" \
              r"client[_-]?secret|auth[_-]?key|credential)[A-Za-z0-9_.-]*"
# name = "literal" / name: 'literal' (code and YAML/JSON); only quoted literals, so code like
# password = request.form["password"] stays readable
QUOTED = re.compile(rf"""(?i)(\b{SECRET_NAME}["']?\s*[:=]\s*)(["'])([^"'\s]{{6,}})\2""")
# NAME=value lines of .env-style files that slipped through
ENV_LINE = re.compile(r"(?m)^(\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API_KEY|APIKEY|"
                      r"ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIALS?)[A-Z0-9_]*\s*=\s*)(\S+)")
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----.*?-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----",
                               re.S)
URI_CREDENTIALS = re.compile(r"\b([a-z][a-z0-9+.-]*://[^\s:/@'\"]+:)([^\s@'\"]{3,})(@)", re.I)


@lru_cache(maxsize=1)
def _known_formats() -> tuple[list[tuple[str, re.Pattern]], re.Pattern]:
    from .detect.secrets import _rules   # the secret scanner's own patterns (rules/secrets.yaml)
    rules = _rules()
    formats = [(r["id"], r["rx"]) for r in rules["secrets"]
               if r["id"] not in ("generic-secret-assignment", "private-key", "db-uri-credentials")]
    return formats, rules["placeholder_rx"]


def _placeholder(value: str) -> bool:
    _, placeholder = _known_formats()
    return bool(placeholder.match(value.strip("'\"")))


def redact(text: str) -> str:
    """Mask secret values in text that is about to leave the machine."""
    if not text:
        return text
    text = PRIVATE_KEY_BLOCK.sub("<REDACTED:private-key>", text)
    text = URI_CREDENTIALS.sub(lambda m: f"{m.group(1)}<REDACTED:password>{m.group(3)}", text)
    formats, _ = _known_formats()
    for kind, rx in formats:
        text = rx.sub(f"<REDACTED:{kind}>", text)

    def quoted(m: re.Match) -> str:
        value = m.group(3)
        if _placeholder(value) or value.startswith("<REDACTED"):
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}<REDACTED:secret>{m.group(2)}"
    text = QUOTED.sub(quoted, text)

    def env(m: re.Match) -> str:
        value = m.group(2)
        if (_placeholder(value) or "REDACTED" in value or len(value.strip("'\"")) < 6 or value.isdigit()
                or value.startswith(("${", "os.environ", "os.getenv", "process.env", "env(", "config", "settings"))):
            return m.group(0)
        return f"{m.group(1)}<REDACTED:secret>"
    return ENV_LINE.sub(env, text)


def is_secret_file(rel_path: str) -> bool:
    name = PurePosixPath(rel_path.replace("\\", "/")).name
    return any(fnmatch.fnmatch(name.lower(), pattern) for pattern in SECRET_FILES)


def llm_allowed(finding) -> bool:
    """False for findings whose code must never be sent to an LLM (secrets, secret files)."""
    return finding.vuln_class not in NO_LLM_CLASSES and not is_secret_file(finding.file)
