"""Prepare an isolated copy of the project for a verification run and apply/revert patches."""

from __future__ import annotations

import shutil
from pathlib import Path

from ..models import Patch

COPY_IGNORE = shutil.ignore_patterns(
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".gradle", "target", "build",
    "dist", ".idea", ".vscode", ".pytest_cache", ".mypy_cache", "*.pyc", ".next", "coverage",
    "workspace", ".secreview-cache")


def copy_project(src: Path, dst: Path) -> Path:
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, ignore=COPY_IGNORE, symlinks=False)
    return dst


def apply_patch(root: Path, patch: Patch) -> list[tuple[Path, str]]:
    """Write a patch's files into `root`. Returns [(path, original_text)] for revert."""
    backups: list[tuple[Path, str]] = []
    for rel, new_content in patch.files.items():
        target = (root / rel).resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            raise ValueError(f"patch path escapes project: {rel}")
        original = target.read_text(encoding="utf-8") if target.exists() else None
        backups.append((target, original))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(new_content, encoding="utf-8")
    return backups


def revert(backups: list[tuple[Path, str]]) -> None:
    for path, original in backups:
        if original is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(original, encoding="utf-8")
