"""Build the JSON spec the language harness consumes for one finding."""

from __future__ import annotations

import secrets
from pathlib import Path

from ..models import Finding

# Classes with an executable oracle (see harness/oracles.yaml). Others cannot be exploit-proven.
ORACLE_CLASSES = {"sqli", "nosqli", "xss", "cmdi", "code_injection", "path_traversal", "ssrf",
                  "open_redirect", "xxe", "prototype_pollution"}


def runtime_for(language: str) -> str:
    return {"python": "python", "javascript": "node", "java": "java"}.get(language, language)


def discover_app(project: Path, finding: Finding, framework: str) -> dict:
    """Best-effort location of the app object for in-process clients (overridable in .secreview.toml)."""
    hints: dict = {}
    ep = finding.endpoint or {}
    if finding.language == "python":
        # look for `app = Flask(__name__)` / FastAPI() across likely entry files
        import re
        for cand in ["app.py", "main.py", "wsgi.py", "server.py", "run.py", "application.py",
                     ep.get("file", "")]:
            f = project / cand
            if f.is_file():
                text = f.read_text(encoding="utf-8", errors="ignore")
                m = re.search(r"^(\w+)\s*=\s*(Flask|FastAPI)\(", text, re.M)
                if m:
                    hints["app_module"] = cand[:-3].replace("/", ".")
                    hints["app_attr"] = m.group(1)
                    hints["client"] = "flask" if m.group(2) == "Flask" else "fastapi"
                    break
        for cand in project.rglob("settings.py"):
            hints.setdefault("django_settings", ".".join(cand.relative_to(project).with_suffix("").parts))
    return hints


def build_spec(project_in_sandbox: Path, finding: Finding, token: str | None = None,
               overrides: dict | None = None) -> dict:
    token = token or secrets.token_hex(4)
    canary_dir = "/tmp" if __import__("os").name != "nt" else str(project_in_sandbox / ".secreview_canary")
    spec = {
        "vuln_class": finding.vuln_class,
        "runtime": runtime_for(finding.language),
        "project_dir": str(project_in_sandbox),
        "file": finding.file,
        "line": finding.line,
        "endpoint": finding.endpoint,
        "param": (((finding.endpoint or {}).get("params") or [None]) + [None])[0],
        "token": token,
        "canary_file": f"{canary_dir}/secreview_canary_{token}",
        "canary_secret": f"SECREVIEW_SECRET_{token}",
        "canary_dir": canary_dir,
    }
    framework = (finding.endpoint or {}).get("framework", "")
    spec.update(discover_app(project_in_sandbox, finding, framework))
    if overrides:
        spec.update(overrides)
    return spec


def has_oracle(finding: Finding) -> bool:
    return finding.vuln_class in ORACLE_CLASSES
