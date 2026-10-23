"""Regex secret scanner + configuration-file checks (Spring properties, Django settings, .env).

Secret findings are graded by git state: a secret that was ever committed is critical (it must be
rotated), one in a git-ignored, never-committed file is informational (that is where secrets belong).
"""

from __future__ import annotations

import fnmatch
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

import yaml

from .. import ROOT, tools
from ..context import RunContext
from ..discovery import EXT_LANG, is_test_file, walk
from ..models import Finding

RULES = ROOT / "rules" / "secrets.yaml"


@lru_cache(maxsize=1)
def _rules() -> dict:
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    for s in data["secrets"]:
        s["rx"] = re.compile(s["regex"])
    for c in data["config_checks"]:
        c["rx"] = re.compile(c["regex"])
    data["placeholder_rx"] = re.compile(data["placeholders"])
    return data


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def _matches(name: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, g) for g in globs)


def _mask(value: str) -> str:
    return value[:4] + "*" * max(len(value) - 6, 3) + value[-2:] if len(value) > 8 else "****"


def scan_secrets(ctx: RunContext) -> list[Finding]:
    rules = _rules()
    exclude = ctx.config.get("scan.exclude", [])
    include_tests = ctx.config.get("scan.include_tests", False)
    findings: list[Finding] = []
    seen: set[tuple] = set()

    # walk() skips dot-directories, but some of them hold config with secrets (.streamlit, .github...)
    dot_files = {p for g in rules.get("dot_dir_globs", []) for p in ctx.project.glob(g) if p.is_file()}
    for path in [*walk(ctx.project, exclude, ctx.config.get("scan.max_file_kb", 1024)), *sorted(dot_files)]:
        name = path.name
        relp = path.relative_to(ctx.project).as_posix()
        if _matches(name, rules["skip_globs"]) or (not include_tests and is_test_file(relp)):
            continue
        is_source = path.suffix.lower() in EXT_LANG
        is_config = _matches(name, rules["config_globs"]) or path in dot_files
        if not (is_source or is_config):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()

        # 1. secret patterns
        for rule in rules["secrets"]:
            if rule.get("config_files_only") and not is_config:
                continue   # source files are covered by the Semgrep hardcoded-secret rules
            for m in rule["rx"].finditer(text):
                value = m.group(rule.get("value_group", 0))
                if rules["placeholder_rx"].match(value.strip("'\"")):
                    continue
                if rule["id"] == "generic-secret-assignment" and entropy(value) < 2.5:
                    continue
                line = text.count("\n", 0, m.start()) + 1
                key = (relp, line, "hardcoded_secret")
                if key in seen:
                    continue
                seen.add(key)
                code = lines[line - 1] if line - 1 < len(lines) else ""
                findings.append(Finding(
                    rule_id=f"secret-{rule['id']}", vuln_class="hardcoded_secret", title="",
                    file=relp, line=line, tool="secrets", language=EXT_LANG.get(path.suffix.lower(), "config"),
                    message=f"Possible {rule['id'].replace('-', ' ')}: {_mask(value)}",
                    code=code.replace(value, _mask(value)) if len(value) > 6 else code,
                    severity=rule.get("severity", "high"),
                    extra={"confidence": "high" if rule["id"] != "generic-secret-assignment" else "medium",
                           "taint": False}))

        # 2. configuration checks
        for check in rules["config_checks"]:
            if not _matches(name, check["files"]):
                continue
            for m in check["rx"].finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                key = (relp, line, check["class"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    rule_id=f"config-{check['id']}", vuln_class=check["class"], title="",
                    file=relp, line=line, tool="config", language="config", message=check["message"],
                    code=lines[line - 1] if line - 1 < len(lines) else "",
                    extra={"confidence": "high", "taint": False}))
    _grade_by_git(ctx, [f for f in findings if f.vuln_class == "hardcoded_secret"])
    return findings


def _git_lines(ctx: RunContext, *args: str) -> set[str] | None:
    res = tools.run(["git", *args], cwd=ctx.project, timeout=120)
    return {line.strip() for line in res.stdout.splitlines() if line.strip()} if res.ok else None


def _grade_by_git(ctx: RunContext, findings: list[Finding]) -> None:
    """Committed secret -> critical (rotate it); ignored and never committed -> info."""
    if not findings or not (ctx.project / ".git").exists():
        return
    tracked = _git_lines(ctx, "ls-files")
    if tracked is None:
        return
    ever_added = _git_lines(ctx, "log", "--all", "--format=", "--name-only", "--diff-filter=A") or set()
    ignored: dict[str, bool] = {}
    for f in findings:
        if f.file in tracked or f.file in ever_added:
            state = "committed"
            f.severity = "critical"
            note = "committed to git history - rotate the secret; deleting the file does not remove it from history"
        else:
            if f.file not in ignored:
                ignored[f.file] = tools.run(["git", "check-ignore", "-q", f.file], cwd=ctx.project, timeout=30).ok
            if ignored[f.file]:
                state = "ignored"
                f.severity = "info"
                note = ("file is git-ignored and was never committed (the right place for a secret) - "
                        "keep it out of images, backups and shared folders")
            else:
                state = "untracked"
                note = "not committed yet, but the file is NOT git-ignored - add it to .gitignore"
        f.message = f"{f.message} ({note})"
        f.extra["git"] = state
