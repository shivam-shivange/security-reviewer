"""Run the predefined Semgrep rule packs and normalise results (keeping taint traces)."""

from __future__ import annotations

import json
from pathlib import Path

from .. import ROOT, tools
from ..context import RunContext
from ..models import Finding
from ..taxonomy import class_for_cwe
from .common import SEMGREP_SEVERITY, language_of, rel, snippet

RULES_DIR = ROOT / "rules" / "semgrep"


def _loc(obj) -> dict | None:
    """Semgrep trace locations come as ["CliLoc", [loc, content]] or nested CliCall structures."""
    if isinstance(obj, list) and len(obj) == 2 and obj[0] == "CliLoc":
        loc, content = obj[1]
        return {"path": loc.get("path", ""), "line": loc.get("start", {}).get("line", 0), "content": content}
    if isinstance(obj, list) and len(obj) == 2 and obj[0] == "CliCall":
        # [CliCall, [[loc, content], [intermediate...], inner]] -> use the call site
        try:
            loc, content = obj[1][0]
            return {"path": loc.get("path", ""), "line": loc.get("start", {}).get("line", 0), "content": content}
        except (TypeError, ValueError, IndexError):
            return None
    return None


def parse_trace(trace: dict | None) -> list[dict]:
    """Flatten a dataflow_trace into ordered steps: source -> intermediate vars -> sink."""
    if not trace:
        return []
    steps = []
    src = _loc(trace.get("taint_source"))
    if src:
        steps.append({**src, "kind": "source"})
    for var in trace.get("intermediate_vars", []) or []:
        loc = var.get("location", {})
        steps.append({"path": loc.get("path", ""), "line": loc.get("start", {}).get("line", 0),
                      "content": var.get("content", ""), "kind": "intermediate"})
    sink = _loc(trace.get("taint_sink"))
    if sink:
        steps.append({**sink, "kind": "sink"})
    return steps


def run_semgrep(ctx: RunContext, targets: list[Path], languages: list[str]) -> list[Finding]:
    if not tools.which("semgrep"):
        ctx.warn("semgrep not installed; skipping (run scripts/setup_tools)")
        return []
    configs = [str(RULES_DIR / lang) for lang in languages if (RULES_DIR / lang).is_dir()]
    configs += list(ctx.config.get("scan.semgrep_registry", []) or [])
    if not configs:
        return []
    cmd = ["semgrep", "scan", "--json", "--dataflow-traces", "--metrics=off", "--disable-version-check",
           "--quiet", "--timeout", "30", "--max-target-bytes", str(ctx.config.get("scan.max_file_kb", 1024) * 1024)]
    jobs = int(ctx.config.get("scan.semgrep_jobs", 0) or 0)
    if jobs:
        cmd += ["--jobs", str(jobs)]
    for c in configs:
        cmd += ["--config", c]
    for ex in ctx.config.get("scan.exclude", []):
        cmd += ["--exclude", ex]
    cmd += [str(t) for t in targets]

    res = tools.run(cmd, cwd=ctx.project, timeout=int(ctx.config.get("scan.semgrep_timeout_seconds", 600)))
    if res.timed_out:
        ctx.warn("semgrep timed out; returning no semgrep findings for this scan")
        return []
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        ctx.warn(f"semgrep produced no JSON (exit {res.code}): {res.stderr[-400:]}")
        return []
    for err in data.get("errors", [])[:10]:
        if err.get("level") == "error":
            ctx.warn(f"semgrep: {err.get('message', '')[:200]}")

    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        rule_id = r.get("check_id", "").split(".")[-1]
        vclass = meta.get("class") or class_for_cwe(_as_list(meta.get("cwe"))) or "general_bug"
        path = rel(ctx.project, r["path"])
        start, end = r["start"]["line"], r["end"]["line"]
        trace = parse_trace(extra.get("dataflow_trace"))
        for step in trace:
            step["path"] = rel(ctx.project, step["path"]) if step.get("path") else path
        f = Finding(
            rule_id=rule_id, vuln_class=vclass, title="", file=path, line=start, end_line=end,
            column=r["start"].get("col", 0), tool="semgrep", language=language_of(path),
            message=extra.get("message", ""), code=snippet(ctx.project, path, start, end),
            severity=SEMGREP_SEVERITY.get(extra.get("severity", ""), ""),
            taint_trace=trace, fix_hint=extra.get("fix", "") or "",
            extra={"confidence": meta.get("confidence", "medium"), "taint": bool(trace),
                   "start_offset": r["start"].get("offset"), "end_offset": r["end"].get("offset")},
        )
        findings.append(f)
    return findings


def _as_list(v) -> list[str]:
    if not v:
        return []
    return v if isinstance(v, list) else [v]
