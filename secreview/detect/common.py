from __future__ import annotations

from pathlib import Path

from ..discovery import EXT_LANG

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
                    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def rel(project: Path, path: str | Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (project / p)
    try:
        return p.resolve().relative_to(project.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def language_of(path: str) -> str:
    return EXT_LANG.get(Path(path).suffix.lower(), "")


def read_lines(project: Path, rel_path: str) -> list[str]:
    try:
        return (project / rel_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def snippet(project: Path, rel_path: str, start: int, end: int | None = None) -> str:
    lines = read_lines(project, rel_path)
    end = end or start
    return "\n".join(lines[max(start - 1, 0):max(end, start)])
