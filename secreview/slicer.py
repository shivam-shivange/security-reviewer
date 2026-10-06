"""Bounded code slices around a finding (sent to the LLM instead of whole files)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import ts


@dataclass
class Slice:
    file: str
    start: int
    end: int
    lines: list[str]

    def numbered(self) -> str:
        width = len(str(self.end))
        return "\n".join(f"{i:>{width}} | {text}" for i, text in enumerate(self.lines, self.start))

    def line_text(self, n: int) -> str:
        return self.lines[n - self.start] if self.start <= n <= self.end else ""


def get_slice(project: Path, rel_file: str, line: int, context: int = 25, max_lines: int = 160) -> Slice:
    path = project / rel_file
    try:
        all_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return Slice(rel_file, line, line, [])
    start, end = max(1, line - context), min(len(all_lines), line + context)
    try:
        fn = ts.enclosing_function(path, line, outermost_handler=True)
    except Exception:
        fn = None
    if fn:
        fstart, fend = fn
        if fend - fstart + 1 <= max_lines:
            start, end = max(1, fstart - 3), min(len(all_lines), fend + 2)
        else:
            start, end = max(fstart, line - max_lines // 2), min(fend, line + max_lines // 2)
    return Slice(rel_file, start, end, all_lines[start - 1:end])


def file_header(project: Path, rel_file: str, max_lines: int = 30) -> str:
    """Imports / top of file: gives the model the libraries in use without the whole file."""
    try:
        lines = (project / rel_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    head = [ln for ln in lines[:120] if ln.strip().startswith(("import ", "from ", "const ", "require(", "package ",
                                                                 "using ", "#include", "let ", "var "))]
    return "\n".join(head[:max_lines])
