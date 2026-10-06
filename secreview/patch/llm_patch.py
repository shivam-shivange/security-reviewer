"""LLM patch fallback: used only when no deterministic template applies (patch.llm_fallback)."""

from __future__ import annotations

import re

from .. import ROOT
from ..context import RunContext
from ..llm.base import LLMClient, LLMError
from ..models import Finding, Patch
from ..slicer import file_header, get_slice
from .base import js_insert_after_imports, make_patch, py_add_import, syntax_ok

PROMPT = (ROOT / "prompts" / "patch.md").read_text(encoding="utf-8")


def _apply(text: str, start: int, end: int, replacement: str, imports: list[str], language: str) -> str | None:
    lines = text.splitlines(True)
    if not (1 <= start <= end <= len(lines)):
        return None
    repl = replacement if replacement.endswith("\n") else replacement + "\n"
    new = "".join(lines[: start - 1]) + repl + "".join(lines[end:])
    for imp in imports or []:
        imp = imp.strip()
        if not imp or imp in new:
            continue
        if language == "python":
            new = py_add_import(new, imp) if _py_ok(new) else new
        elif language == "javascript":
            new = js_insert_after_imports(new, imp)
        elif language == "java":
            new = re.sub(r"(^\s*package [\w.]+;\s*\n)", rf"\1{imp}\n", new, count=1, flags=re.M) \
                if re.search(r"^\s*package ", new, re.M) else imp + "\n" + new
    return new


def _py_ok(text: str) -> bool:
    try:
        compile(text, "<x>", "exec")
        return True
    except SyntaxError:
        return False


def llm_candidates(ctx: RunContext, llm: LLMClient, f: Finding, feedback: str = "",
                   n: int = 2, purpose: str = "security") -> list[Patch]:
    path = ctx.project / f.file
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    sl = get_slice(ctx.project, f.file, f.line, ctx.config.get("ground.slice_context_lines", 25))
    chain = ""
    if f.evidence and f.evidence.chain:
        chain = "\n".join(f"  line {s.line}: {s.code}  ({s.note})" for s in f.evidence.chain)
    prompt = (f"Weakness: {f.title} ({', '.join(f.cwe)}) - {f.message}\n"
              f"File: {f.file}  flagged line: {f.line}\nLanguage: {f.language}\n"
              + (f"Evidence chain (untrusted source -> sink):\n{chain}\n" if chain else "")
              + (f"Recommended remediation: {f.remediation}\n" if f.remediation else "")
              + f"\nFile header (imports):\n{file_header(ctx.project, f.file)}\n"
              + f"\nCode slice (line | code):\n{sl.numbered()}\n"
              + (f"\nA previous fix attempt FAILED verification. Output of the failed run:\n{feedback[-3000:]}\n"
                 "Produce a different fix that addresses this failure.\n" if feedback else ""))
    out: list[Patch] = []
    seen: set[str] = set()
    for i in range(max(1, n)):
        temp = 0.1 if i == 0 else min(0.2 + 0.3 * i, 0.9)
        try:
            data = llm.complete_json(PROMPT, prompt, temperature=temp, use_cache=(i == 0 and not feedback))
        except LLMError as exc:
            ctx.warn(f"LLM patch generation failed for {f.id}: {exc}")
            break
        if not isinstance(data, dict):
            continue
        try:
            start, end = int(data.get("start_line")), int(data.get("end_line"))
        except (TypeError, ValueError):
            continue
        if not (sl.start <= start <= end <= sl.end):
            continue
        new = _apply(text, start, end, str(data.get("replacement", "")), data.get("imports") or [], f.language)
        if not new or new == text or new in seen or not syntax_ok(f.language, f.file, new):
            continue
        seen.add(new)
        p = make_patch(f.file, text, new, "llm", str(data.get("explanation", ""))[:300], llm=True)
        if p:
            out.append(p)
    # self-consistency: prefer the smallest change first
    out.sort(key=lambda p: sum(1 for ln in p.diff.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---")))
    return out
