"""General-bug tier: Ruff (Python), ESLint (JS/TS/React), PMD (Java).

These findings are report-only. When the linter can fix the issue deterministically, the fix is
attached as `recommended_patch` (no LLM). An LLM recommended patch exists in patch/engine.py but is
disabled by default (general_bugs.llm_patch = false).
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path

from .. import ROOT, tools
from ..context import RunContext
from ..models import Finding, Patch, Status
from .common import rel

# The setup script copies config/eslint.config.mjs next to tools/node/node_modules so that its
# plugin imports resolve; ESM imports are resolved relative to the config file.
ESLINT_CONFIG = ROOT / "tools" / "node" / "eslint.config.mjs"
PMD_RULESETS = "category/java/errorprone.xml,category/java/bestpractices.xml,category/java/multithreading.xml"
RUFF_SELECT = "E9,F,B,PLE,PLW,ASYNC,RUF006,RUF012"


def unified(path: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def _bug(rule: str, tool: str, path: str, line: int, msg: str, code: str, language: str,
         severity: str = "low", end_line: int = 0) -> Finding:
    return Finding(rule_id=rule, vuln_class="general_bug", title=f"{tool}: {rule}", file=path, line=line,
                   end_line=end_line or line, tool=tool, language=language, message=msg, code=code,
                   severity=severity, status=Status.REPORT_ONLY.value, extra={"confidence": "medium"})


# ---------------------------------------------------------------- ruff
def _apply_ruff_edits(text: str, edits: list[dict]) -> str:
    lines = text.splitlines(True)
    offsets = [0]
    for ln in lines:
        offsets.append(offsets[-1] + len(ln))

    def off(loc):  # ruff locations are 1-based row / column (characters)
        return offsets[loc["row"] - 1] + loc["column"] - 1

    for e in sorted(edits, key=lambda e: off(e["location"]), reverse=True):
        text = text[:off(e["location"])] + (e.get("content") or "") + text[off(e["end_location"]):]
    return text


def run_ruff(ctx: RunContext, targets: list[Path]) -> list[Finding]:
    if not tools.which("ruff"):
        return []
    excludes = ",".join(ctx.config.get("scan.exclude", []))
    res = tools.run(["ruff", "check", "--output-format", "json", "--no-cache", "--select", RUFF_SELECT,
                     "--extend-exclude", excludes, "--exit-zero", *[str(t) for t in targets]],
                    cwd=ctx.project, timeout=900)
    try:
        items = json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        ctx.warn(f"ruff output not JSON: {res.stderr[-300:]}")
        return []
    out = []
    for it in items:
        path = rel(ctx.project, it["filename"])
        line = it["location"]["row"]
        f = _bug(f"ruff-{it['code']}", "ruff", path, line, it["message"], "", "python",
                 "medium" if (it.get("code") or "").startswith(("F8", "E9", "PLE")) else "low",
                 it.get("end_location", {}).get("row", line))
        fix = it.get("fix")
        if fix and fix.get("edits") and ctx.config.get("general_bugs.deterministic_fix", True):
            try:
                old = (ctx.project / path).read_text(encoding="utf-8")
                new = _apply_ruff_edits(old, fix["edits"])
                if new != old:
                    f.recommended_patch = Patch(diff=unified(path, old, new), source="ruff",
                                                description=fix.get("message") or "ruff autofix")
            except (OSError, KeyError, IndexError):
                pass
        out.append(f)
    return out


# ---------------------------------------------------------------- eslint
def run_eslint(ctx: RunContext, targets: list[Path]) -> list[Finding]:
    if not tools.which("eslint"):
        ctx.log("eslint not installed; JavaScript general-bug tier skipped")
        return []
    cmd = ["eslint", "--config", str(ESLINT_CONFIG), "--format", "json", "--no-error-on-unmatched-pattern",
           "--fix-dry-run", *[str(t) for t in targets]]
    res = tools.run(cmd, cwd=ctx.project, timeout=1200)
    try:
        files = json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        ctx.warn(f"eslint output not JSON: {(res.stderr or res.stdout)[-300:]}")
        return []
    out = []
    for fobj in files:
        path = rel(ctx.project, fobj["filePath"])
        fixed_source = fobj.get("output")
        for m in fobj.get("messages", []):
            if not m.get("ruleId"):
                continue   # parse errors
            f = _bug(f"eslint-{m['ruleId']}", "eslint", path, m.get("line", 1), m.get("message", ""), "",
                     "javascript", "medium" if m.get("severity") == 2 else "low", m.get("endLine", 0))
            if m.get("fix") and fixed_source and ctx.config.get("general_bugs.deterministic_fix", True):
                try:
                    old = (ctx.project / path).read_text(encoding="utf-8")
                    s, e = m["fix"]["range"]
                    new = old[:s] + m["fix"]["text"] + old[e:]
                    f.recommended_patch = Patch(diff=unified(path, old, new), source="eslint",
                                                description="eslint autofix")
                except (OSError, KeyError, ValueError):
                    pass
            out.append(f)
    return out


# ---------------------------------------------------------------- pmd
def run_pmd(ctx: RunContext, targets: list[Path]) -> list[Finding]:
    if not tools.which("pmd"):
        ctx.log("PMD not installed; Java general-bug tier skipped")
        return []
    out = []
    for t in targets:
        res = tools.run(["pmd", "check", "--no-cache", "--no-progress", "-f", "json", "-R", PMD_RULESETS,
                         "-d", str(t)], cwd=ctx.project, timeout=1800)
        try:
            data = json.loads(res.stdout or "{}")
        except json.JSONDecodeError:
            ctx.warn(f"PMD output not JSON: {res.stderr[-300:]}")
            continue
        for fobj in data.get("files", []):
            path = rel(ctx.project, fobj["filename"])
            for v in fobj.get("violations", []):
                prio = int(v.get("priority", 3))
                out.append(_bug(f"pmd-{v.get('rule')}", "pmd", path, v.get("beginline", 1),
                                v.get("description", ""), "", "java",
                                "medium" if prio <= 2 else "low", v.get("endline", 0)))
    return out
