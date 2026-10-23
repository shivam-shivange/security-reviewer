"""Ground stage: confirm each candidate with concrete evidence, deterministically where possible.

Order of evidence (cheapest first, LLM last):
  1. Semgrep taint trace          -> evidence chain source -> ... -> sink         (no LLM)
  2. Rule / config / secret match -> the matched code is the evidence             (no LLM)
  3. Dependency advisory          -> advisory ids + affected version             (no LLM)
  4. Heuristic access-control     -> needs_review (human check)                  (no LLM)
  5. Ambiguous (e.g. Bandit-only injection without a trace, or a local validator between source
     and sink)                    -> LLM, when ground.llm = auto/always; the model's chain is then
                                     machine-checked against the actual source lines.
"""

from __future__ import annotations

import re

from . import ROOT
from .context import RunContext
from .llm.base import LLMError
from .llm.gate import LLMGate
from .models import Evidence, EvidenceStep, Finding, Status
from .slicer import get_slice
from .taxonomy import is_heuristic

PROMPT = (ROOT / "prompts" / "ground.md").read_text(encoding="utf-8")
CONF = {"high": 0.9, "medium": 0.7, "low": 0.5}
TAINT_CLASSES = {"sqli", "nosqli", "xss", "cmdi", "code_injection", "path_traversal", "ssrf", "open_redirect",
                 "xxe", "deserialization", "prototype_pollution"}
# Local validation patterns that Semgrep does not model as sanitisers -> ask the LLM (or a human).
VALIDATION_HINT = re.compile(
    r"(re\.(full)?match\(|\.test\(|\.matches\(|Pattern\.matches|allowlist|whitelist|ALLOWED_|"
    r"\bin\s+\(?\s*[\[{(]|\.includes\(|validator\.|isValid|validate\w*\(|\.isdigit\(\)|isNaN\()", re.I)


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


def _trace_evidence(ctx: RunContext, f: Finding) -> Evidence:
    chain = [EvidenceStep(file=s.get("path") or f.file, line=int(s.get("line") or 0),
                          code=(s.get("content") or "").strip()[:240], note=s.get("kind", ""))
             for s in f.taint_trace]
    src = chain[0] if chain else None
    summary = (f"{src.code} (line {src.line}) flows to {f.code.strip()[:120]} (line {f.line})"
               if src else f.message)
    return Evidence(method="semgrep-taint", chain=chain, summary=summary,
                    confidence=CONF.get(f.extra.get("confidence", "high"), 0.85))


def _has_local_validation(ctx: RunContext, f: Finding) -> str:
    if not f.taint_trace:
        return ""
    lines = [int(s.get("line") or 0) for s in f.taint_trace if (s.get("path") or f.file) == f.file]
    if not lines:
        return ""
    sl = get_slice(ctx.project, f.file, f.line, context=0)
    lo, hi = min(lines + [f.line]), max(lines + [f.line])
    for n in range(max(lo, sl.start), min(hi, sl.end) + 1):
        if VALIDATION_HINT.search(sl.line_text(n)):
            return f"line {n}: {sl.line_text(n).strip()}"
    return ""


def validate_chain(ctx: RunContext, f: Finding, chain: list[dict], slice_) -> tuple[list[EvidenceStep], str]:
    """Check that every cited step really is that code on that line. Returns (steps, error)."""
    steps = []
    for st in chain:
        try:
            n = int(st.get("line"))
        except (TypeError, ValueError):
            return [], "a chain step has no line number"
        code = str(st.get("code", "")).strip()
        actual = " ".join(slice_.line_text(k) for k in (n - 1, n, n + 1))
        if not code or _norm(code)[:60] not in _norm(actual):
            return [], f"cited code for line {n} does not match the source"
        steps.append(EvidenceStep(file=f.file, line=n, code=code[:240], note=str(st.get("note", ""))[:120]))
    if len(steps) < 2:
        return [], "chain has fewer than two steps (needs source and sink)"
    if abs(steps[-1].line - f.line) > 2 and not any(abs(s.line - f.line) <= 2 for s in steps):
        return [], "chain does not reach the flagged sink"
    return steps, ""


def llm_ground(ctx: RunContext, gate: LLMGate, f: Finding) -> bool:
    """Returns True when the LLM produced a decision (finding status updated)."""
    llm = gate.client()
    if llm is None:
        return False
    sl = get_slice(ctx.project, f.file, f.line, ctx.config.get("ground.slice_context_lines", 25))
    prompt = (f"Alert: {f.title} ({', '.join(f.cwe)}) reported by {f.tool} rule {f.rule_id}\n"
              f"Message: {f.message}\nFile: {f.file}\nFlagged line: {f.line}\n"
              + (f"Route: {f.endpoint.get('method')} {f.endpoint.get('path')}\n" if f.endpoint else "")
              + f"\nCode slice (line | code):\n{sl.numbered()}\n")
    try:
        out = llm.complete_json(PROMPT, prompt)
    except LLMError as exc:
        ctx.warn(f"LLM grounding failed for {f.id}: {exc}")
        return False
    verdict = str(out.get("verdict", "uncertain")) if isinstance(out, dict) else "uncertain"
    reason = str(out.get("reason", ""))[:400] if isinstance(out, dict) else ""
    if verdict == "false_positive":
        f.status = Status.DISCARDED.value
        f.evidence = Evidence(method="llm", summary=f"LLM: false positive - {reason}", confidence=0.6, llm_used=True)
        return True
    if verdict == "true_positive":
        steps, err = validate_chain(ctx, f, out.get("chain", []) or [], sl)
        if steps:
            f.status = Status.GROUNDED.value
            f.evidence = Evidence(method="llm", chain=steps, summary=reason, confidence=0.75, llm_used=True)
            return True
        policy = ctx.config.get("ground.unverifiable_chain", "discard")
        f.status = Status.DISCARDED.value if policy == "discard" else Status.NEEDS_REVIEW.value
        f.evidence = Evidence(method="llm", summary=f"LLM said true positive but its chain failed the check: {err}",
                              confidence=0.3, llm_used=True)
        return True
    f.status = Status.NEEDS_REVIEW.value
    f.evidence = Evidence(method="llm", summary=f"LLM uncertain: {reason}", confidence=0.4, llm_used=True)
    return True


def ground_finding(ctx: RunContext, gate: LLMGate, f: Finding, mode: str) -> None:
    if f.status in (Status.REPORT_ONLY.value, Status.DISCARDED.value):
        return
    if f.vuln_class == "general_bug":
        f.status = Status.REPORT_ONLY.value
        return
    if f.tool == "access-analyzer" or is_heuristic(f.vuln_class):
        f.status = Status.NEEDS_REVIEW.value
        if f.evidence is None:
            f.evidence = Evidence(method="endpoint-analysis", summary=f.message, confidence=0.6,
                                  chain=[EvidenceStep(f.file, f.line, f.code, "route")])
        if mode == "always":
            llm_ground(ctx, gate, f)
            if f.status == Status.GROUNDED.value:
                f.status = Status.NEEDS_REVIEW.value   # heuristic class: LLM agreement still needs a human
        return
    if f.vuln_class == "vulnerable_dependency":
        f.status = Status.GROUNDED.value
        f.evidence = Evidence(method="advisory", summary=f.message, confidence=0.95,
                              chain=[EvidenceStep(f.file, f.line, f.code, "dependency declaration")])
        return

    ambiguous_reason = ""
    if f.taint_trace:
        f.evidence = _trace_evidence(ctx, f)
        ambiguous_reason = _has_local_validation(ctx, f)
    elif f.vuln_class in TAINT_CLASSES and f.tool == "bandit":
        ambiguous_reason = "injection reported without a data-flow trace"
    else:
        f.evidence = Evidence(method="rule-match", summary=f.message,
                              confidence=CONF.get(f.extra.get("confidence", "medium"), 0.7),
                              chain=[EvidenceStep(f.file, f.line, f.code.strip()[:240], f"matched {f.rule_id}")])

    if mode == "always" or (mode == "auto" and ambiguous_reason):
        if ambiguous_reason:
            ctx.log(f"{f.id} ambiguous ({ambiguous_reason}); asking LLM")
        if llm_ground(ctx, gate, f):
            return
        if ambiguous_reason:
            f.status = Status.NEEDS_REVIEW.value
            f.extra["ambiguous"] = ambiguous_reason
            if f.evidence is None:
                f.evidence = Evidence(method="none", summary=f"Needs review: {ambiguous_reason}", confidence=0.4)
            return
    elif ambiguous_reason:
        f.status = Status.NEEDS_REVIEW.value
        f.extra["ambiguous"] = ambiguous_reason
        if f.evidence is None:
            f.evidence = Evidence(method="none", summary=f"Needs review: {ambiguous_reason}", confidence=0.4)
        return
    f.status = Status.GROUNDED.value


def run_ground(ctx: RunContext, findings: list[Finding], gate: LLMGate, enabled: bool = True) -> None:
    mode = ctx.config.get("ground.llm", "auto")
    total = len(findings)
    for i, f in enumerate(findings, 1):
        if not enabled:   # ablation: Detect -> Patch -> Verify without grounding
            if f.vuln_class != "general_bug":
                f.status = Status.GROUNDED.value
                f.evidence = Evidence(method="none", summary="grounding disabled (ablation)", confidence=0.0)
            else:
                f.status = Status.REPORT_ONLY.value
        else:
            ground_finding(ctx, gate, f, mode)
        ctx.store.save_finding(ctx.run_id, f)
        if i % 10 == 0 or i == total:
            ctx.progress(i, total)
