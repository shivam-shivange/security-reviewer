"""Detect stage orchestration: run every enabled detector, then normalise, filter and de-duplicate."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from ..context import RunContext
from ..discovery import ProjectInfo, is_test_file
from ..models import Endpoint, Finding
from ..taxonomy import enrich
from .access import analyze_access
from .ai_app import analyze_ai_app
from .bandit_runner import run_bandit
from .dependencies import scan_dependencies
from .linters import run_eslint, run_pmd, run_ruff
from .secrets import scan_secrets
from .semgrep_runner import run_semgrep
from .supply_chain import scan_supply_chain

# When two tools report the same class on the same line, keep the richer one.
TOOL_RANK = {"semgrep": 0, "access-analyzer": 1, "ai-analyzer": 1, "supply-chain": 2, "config": 2, "secrets": 3,
             "bandit": 4,
             "osv-scanner": 0, "pip-audit": 1, "npm-audit": 1, "ruff": 5, "eslint": 5, "pmd": 5}


def _module_targets(ctx: RunContext, info: ProjectInfo, language: str) -> list[Path]:
    """Scan module by module for large repos; fall back to the project root."""
    if not ctx.config.get("scan.per_module", True):
        return [ctx.project]
    dirs = sorted({m.path for m in info.modules if m.language == language})
    if not dirs or "." in dirs:
        return [ctx.project]
    # drop nested module dirs already covered by a parent
    roots = [d for d in dirs if not any(d != o and d.startswith(o.rstrip("/") + "/") for o in dirs)]
    return [ctx.project / d for d in roots]


def attach_endpoints(findings: list[Finding], endpoints: list[Endpoint]) -> None:
    """Link a finding to the route whose handler contains it (used by PoC harnesses and reports)."""
    for f in findings:
        if f.endpoint:
            continue
        best = None
        for ep in endpoints:
            ranges = [(ep.file, ep.line, ep.end_line or ep.line)]
            if ep.handler_file:
                ranges.append((ep.handler_file, ep.handler_line, ep.handler_end_line or ep.handler_line))
            for file, start, end in ranges:
                if file == f.file and start <= f.line <= end:
                    span = end - start
                    if best is None or span < best[0]:
                        best = (span, ep)
        if best:
            f.endpoint = asdict(best[1])


def dedupe(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.file, f.line, f.vuln_class)
        cur = by_key.get(key)
        if cur is None:
            by_key[key] = f
            continue
        keep, drop = (f, cur) if (TOOL_RANK.get(f.tool, 9), -len(f.taint_trace)) < \
            (TOOL_RANK.get(cur.tool, 9), -len(cur.taint_trace)) else (cur, f)
        keep.extra.setdefault("also_reported_by", []).append(f"{drop.tool}:{drop.rule_id}")
        by_key[key] = keep
    return list(by_key.values())


def run_detect(ctx: RunContext, info: ProjectInfo) -> tuple[list[Finding], list[Endpoint]]:
    cfg = ctx.config
    langs = [lang for lang in cfg.get("scan.languages", []) if lang in info.files]
    raw: list[Finding] = []
    endpoints: list[Endpoint] = []
    steps = [s for s, on in [
        ("semgrep", cfg.get("detect.semgrep", True) and langs),
        ("bandit", cfg.get("detect.bandit", True) and "python" in langs),
        ("secrets", cfg.get("detect.secrets", True)),
        ("dependencies", cfg.get("detect.dependencies", True)),
        ("supply-chain", cfg.get("detect.supply_chain", True)),
        ("access-control", cfg.get("detect.access_control", True) and langs),
        ("ai-app", cfg.get("detect.ai_app", True) and "python" in langs),
        ("general-bugs", cfg.get("detect.general_bugs", True) and cfg.get("general_bugs.report", True) and langs),
    ] if on]
    ctx.progress(0, len(steps))
    for i, step in enumerate(steps, 1):
        before = len(raw)
        try:
            if step == "semgrep":
                targets = sorted({t for lang in langs for t in _module_targets(ctx, info, lang)})
                raw += run_semgrep(ctx, targets, langs)
            elif step == "bandit":
                raw += run_bandit(ctx, _module_targets(ctx, info, "python"))
            elif step == "secrets":
                raw += scan_secrets(ctx)
            elif step == "dependencies":
                raw += scan_dependencies(ctx, info)
            elif step == "supply-chain":
                raw += scan_supply_chain(ctx, info)
            elif step == "access-control":
                eps, acc = analyze_access(ctx, info)
                endpoints += eps
                raw += acc
            elif step == "ai-app":
                eps, ai = analyze_ai_app(ctx, info)
                endpoints += eps
                raw += ai
            elif step == "general-bugs":
                if "python" in langs:
                    raw += run_ruff(ctx, _module_targets(ctx, info, "python"))
                if "javascript" in langs:
                    raw += run_eslint(ctx, _module_targets(ctx, info, "javascript"))
                if "java" in langs:
                    raw += run_pmd(ctx, _module_targets(ctx, info, "java"))
        except Exception as exc:   # one broken tool must not stop the scan
            ctx.warn(f"{step} failed: {exc}")
        ctx.log(f"{step}: {len(raw) - before} raw findings")
        ctx.progress(i, len(steps), step)

    include_tests = cfg.get("scan.include_tests", False)
    kept = []
    for f in raw:
        if not include_tests and is_test_file(f.file) and f.vuln_class != "vulnerable_dependency":
            continue
        mod = info.module_for(f.file)
        f.module = f.module or (mod.path if mod else ".")
        f.language = f.language or (mod.language if mod else "")
        enrich(f)
        f.id = f.fingerprint()
        kept.append(f)
    findings = dedupe(kept)
    attach_endpoints(findings, endpoints)
    return findings, endpoints
