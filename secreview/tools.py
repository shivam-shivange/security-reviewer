"""Locate and run the external tools installed inside this repository (.venv/ and tools/)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import ROOT

IS_WIN = os.name == "nt"
VENV_BIN = ROOT / ".venv" / ("Scripts" if IS_WIN else "bin")
TOOLS = ROOT / "tools"

# Search order: project venv -> tools/bin -> local node_modules -> portable JDK -> PATH.
SEARCH_DIRS = [
    VENV_BIN,
    Path(sys.executable).parent,
    TOOLS / "bin",
    TOOLS / "node" / "node_modules" / ".bin",
    TOOLS / "jdk" / "bin",
    TOOLS / "pmd" / "bin",
    TOOLS / "spotbugs" / "bin",
    TOOLS / "maven" / "bin",
    TOOLS / "gradle" / "bin",
]

KNOWN_TOOLS = {
    "semgrep": "Detect: rule packs for Python/Java/JavaScript",
    "bandit": "Detect: Python security linter",
    "pip-audit": "Detect: Python dependency advisories",
    "osv-scanner": "Detect: Maven/Gradle/npm dependency advisories",
    "npm": "Detect: npm audit; Verify: npm test",
    "ruff": "General bugs: Python linter with autofix",
    "eslint": "General bugs: JavaScript linter with autofix",
    "pmd": "General bugs: Java static analysis",
    "java": "Runs PMD / SpotBugs",
    "docker": "Verify: isolated sandbox",
    "git": "Provenance (git blame)",
}


@dataclass
class ToolResult:
    cmd: list[str]
    code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out


def which(name: str) -> str | None:
    exts = [".exe", ".cmd", ".bat", ""] if IS_WIN else [""]
    for d in SEARCH_DIRS:
        for ext in exts:
            cand = d / f"{name}{ext}"
            if cand.is_file():
                return str(cand)
    return shutil.which(name)


def tool_env() -> dict:
    env = dict(os.environ)
    extra = os.pathsep.join(str(d) for d in SEARCH_DIRS if d.is_dir())
    env["PATH"] = extra + os.pathsep + env.get("PATH", "")
    jdk = TOOLS / "jdk"
    if jdk.is_dir() and not env.get("JAVA_HOME"):
        env["JAVA_HOME"] = str(jdk)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
    # Keep each tool's scratch files inside the repo, never under the system temp dir. On Windows,
    # Semgrep hangs when its scratch lands in the same temp tree it is scanning (e.g. a project under
    # %TEMP%); a dedicated temp dir avoids that file-discovery loop.
    tmp = TOOLS / ".tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    for var in ("TMPDIR", "TEMP", "TMP"):
        env[var] = str(tmp)
    return env


def run(cmd: list[str], cwd: Path | str | None = None, timeout: int = 900,
        env: dict | None = None, input_text: str | None = None) -> ToolResult:
    exe = which(cmd[0]) or cmd[0]
    full = [exe, *cmd[1:]]
    try:
        p = subprocess.run(full, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env=env or tool_env(), encoding="utf-8", errors="replace", input=input_text)
        return ToolResult(full, p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return ToolResult(full, -1, exc.stdout or "" if isinstance(exc.stdout, str) else "",
                          exc.stderr or "" if isinstance(exc.stderr, str) else "", timed_out=True)
    except FileNotFoundError as exc:
        return ToolResult(full, 127, "", str(exc))


def status() -> dict[str, dict]:
    """Which tools are available (shown in the CLI `tools` command and the dashboard)."""
    out = {}
    for name, purpose in KNOWN_TOOLS.items():
        path = which(name)
        out[name] = {"available": bool(path), "path": path or "", "purpose": purpose}
    if out["docker"]["available"]:
        out["docker"]["daemon"] = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20).ok
    return out
