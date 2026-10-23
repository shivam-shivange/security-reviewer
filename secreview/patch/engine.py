"""Patch stage: produce candidate patches in priority order, deterministic sources first.

  1. Semgrep `fix:` text from the rule                       (no LLM)
  2. Fix templates (patch/py_fixers, js_fixers, java_fixers) (no LLM)
  3. Dependency version bump                                 (no LLM)
  4. LLM fallback (patch.llm_fallback)                       (LLM; self-consistency, N candidates)
"""

from __future__ import annotations

from ..context import RunContext
from ..llm.gate import LLMGate
from ..models import Finding, Patch, Status
from . import config_fixers, java_fixers, js_fixers, py_fixers  # noqa: F401  (register templates)
from .base import FixContext, fixers_for, make_patch, syntax_ok
from .dependency import bump
from .llm_patch import llm_candidates


def semgrep_fix(ctx: RunContext, f: Finding) -> Patch | None:
    start, end = f.extra.get("start_offset"), f.extra.get("end_offset")
    if not f.fix_hint or start is None or end is None or f.tool != "semgrep":
        return None
    path = ctx.project / f.file
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    old = raw.decode("utf-8", errors="replace")
    new = (raw[:start] + f.fix_hint.encode("utf-8") + raw[end:]).decode("utf-8", errors="replace")
    if not syntax_ok(f.language, f.file, new):
        return None
    return make_patch(f.file, old, new, "semgrep-fix", f"rule autofix ({f.rule_id})")


def template_patches(ctx: RunContext, f: Finding) -> list[Patch]:
    path = ctx.project / f.file
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    out = []
    for spec in fixers_for(f.language, f.vuln_class):
        fc = FixContext(project=ctx.project, finding=f, file=f.file, text=text)
        try:
            new = spec.fn(fc)
        except Exception as exc:   # a template that does not fit this code shape
            ctx.log(f"template {spec.name} not applicable to {f.id}: {type(exc).__name__}: {exc}", "debug")
            continue
        if not new or new == text:
            continue
        if not syntax_ok(f.language, f.file, new):
            ctx.log(f"template {spec.name} produced invalid syntax for {f.id}; skipped", "debug")
            continue
        desc = spec.description + (f" ({'; '.join(fc.notes)})" if fc.notes else "")
        p = make_patch(f.file, text, new, f"template:{spec.name}", desc)
        if p:
            out.append(p)
    return out


def candidates(ctx: RunContext, gate: LLMGate, f: Finding, feedback: str = "",
               tried: set[str] | None = None, allow_llm: bool = True) -> list[Patch]:
    tried = tried or set()
    out: list[Patch] = []
    if not feedback:
        if f.vuln_class == "vulnerable_dependency":
            p = bump(ctx.project, f)
            if p:
                out.append(p)
        else:
            p = semgrep_fix(ctx, f)
            if p:
                out.append(p)
            if ctx.config.get("patch.templates", True):
                out += template_patches(ctx, f)
    if allow_llm and ctx.config.get("patch.llm_fallback", True) and f.vuln_class != "vulnerable_dependency" \
            and (feedback or not out):
        llm = gate.client()
        if llm is not None:
            out += llm_candidates(ctx, llm, f, feedback, int(ctx.config.get("patch.candidates", 2)))
    uniq, seen = [], set(tried)
    for p in out:
        key = p.diff
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def recommend_general_bug(ctx: RunContext, gate: LLMGate, f: Finding) -> None:
    """General bugs: deterministic linter fixes are attached by the linters; the LLM recommended patch
    is implemented but only runs when general_bugs.llm_patch = true (disabled by default)."""
    if f.recommended_patch or not ctx.config.get("general_bugs.llm_patch", False):
        return
    llm = gate.client()
    if llm is None:
        return
    cands = llm_candidates(ctx, llm, f, n=1, purpose="bug")
    if cands:
        f.recommended_patch = cands[0]


def run_patch_recommendations(ctx: RunContext, gate: LLMGate, findings: list[Finding]) -> None:
    """For findings that cannot be exploit-verified, attach a recommended (unverified) patch."""
    for f in findings:
        if f.status == Status.REPORT_ONLY.value and f.vuln_class == "general_bug":
            recommend_general_bug(ctx, gate, f)
