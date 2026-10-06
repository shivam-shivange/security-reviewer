"""Git-blame provenance annotation: who last touched the flagged line (annotation, not causation)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from . import tools
from .models import Finding, Provenance


def blame(project: Path, rel_file: str, line: int) -> Provenance | None:
    res = tools.run(["git", "blame", "--porcelain", "-L", f"{line},{line}", "--", rel_file], cwd=project, timeout=30)
    if not res.ok or not res.stdout:
        return None
    lines = res.stdout.splitlines()
    commit = lines[0].split()[0]
    info = {}
    for ln in lines[1:]:
        key, _, value = ln.partition(" ")
        info[key] = value
    if set(commit) == {"0"}:
        return Provenance(commit="uncommitted", author="(working tree)", summary="not committed yet")
    when = info.get("author-time")
    date = dt.datetime.fromtimestamp(int(when), dt.timezone.utc).strftime("%Y-%m-%d") if when else ""
    return Provenance(commit=commit[:12], author=info.get("author", ""), date=date, summary=info.get("summary", ""))


def annotate(project: Path, findings: list[Finding]) -> int:
    if not (project / ".git").exists() or not tools.which("git"):
        return 0
    n = 0
    for f in findings:
        if f.line > 0 and not f.provenance:
            p = blame(project, f.file, f.line)
            if p:
                f.provenance = p
                n += 1
    return n
