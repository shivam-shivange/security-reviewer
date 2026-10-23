"""Supply-chain checks on dependency manifests (no network, no LLM).

  * requirements*.txt entries not pinned to an exact version (every install may pull a new release,
    and the vulnerability scanners cannot tell which version is in use)
  * a declared package that the code never imports while a near-identical name IS imported and not
    declared (e.g. `dataset` declared, `datasets` imported): the declared one is a different PyPI
    project - the typosquatting / dependency-confusion pattern
  * package.json dependencies on `*`, `latest`, URLs or git refs, and npm projects without a lockfile
"""

from __future__ import annotations

import ast
import json
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path

from ..context import RunContext
from ..discovery import ProjectInfo, is_test_file
from ..models import Finding

REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
# Distributions whose import name differs from the normalised distribution name.
DIST_TO_MODULE = {
    "beautifulsoup4": "bs4", "python-dotenv": "dotenv", "pyyaml": "yaml", "scikit-learn": "sklearn",
    "opencv-python": "cv2", "opencv-python-headless": "cv2", "pillow": "PIL", "pymongo": "pymongo",
    "python-jose": "jose", "pyjwt": "jwt", "protobuf": "google", "google-generativeai": "google",
    "google-genai": "google", "psycopg2-binary": "psycopg2", "pycryptodome": "Crypto",
    "python-multipart": "multipart", "faiss-cpu": "faiss", "faiss-gpu": "faiss", "msgpack-python": "msgpack",
    "attrs": "attr", "pyserial": "serial", "python-dateutil": "dateutil", "typing-extensions": "typing_extensions",
}
NPM_RISKY = re.compile(r"^(\*|latest|x|)$|^(https?:|git\+|git:|github:|file:)|/")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _module_of(dist: str) -> str:
    return _norm(DIST_TO_MODULE.get(dist.lower(), dist))


def _requirements(path: Path) -> list[tuple[int, str, str]]:
    """(line, name, spec) for each requirement line; options, includes and URLs are skipped."""
    out = []
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:", ".")):
            continue
        m = REQ_NAME.match(line)
        if m:
            out.append((n, m.group(1), m.group(3).split(";")[0].strip()))
    return out


def _local_modules(project: Path, files: list[str]) -> set[str]:
    names = set()
    for rel in files:
        parts = Path(rel).parts
        names.add(_norm(Path(parts[0]).stem if len(parts) == 1 else parts[0]))
    return names


def _imports(project: Path, files: list[str]) -> dict[str, tuple[str, int]]:
    """top-level imported module -> first (file, line) that imports it."""
    found: dict[str, tuple[str, int]] = {}
    for rel in files:
        try:
            tree = ast.parse((project / rel).read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module]
            for name in names:
                found.setdefault(name.split(".")[0], (rel, node.lineno))
    return found


def _similar(a: str, b: str) -> bool:
    a, b = _norm(a), _norm(b)
    return a != b and (a.rstrip("s") == b.rstrip("s") or SequenceMatcher(None, a, b).ratio() >= 0.85)


def _finding(rule: str, file: str, line: int, message: str, code: str, severity: str, language: str,
             **extra) -> Finding:
    return Finding(rule_id=rule, vuln_class="supply_chain", title="", file=file, line=line, tool="supply-chain",
                   language=language, message=message, code=code, severity=severity,
                   extra={"confidence": "high", "taint": False, **extra})


def check_python(ctx: RunContext, info: ProjectInfo) -> list[Finding]:
    files = [f for f in info.files.get("python", []) if not is_test_file(f)]
    imports = _imports(ctx.project, files)
    local = _local_modules(ctx.project, info.files.get("python", []))
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    third_party = {_norm(m): loc for m, loc in imports.items() if m not in stdlib and _norm(m) not in local}
    out: list[Finding] = []
    for m in info.modules:
        if m.build != "pip":
            continue
        mod_dir = ctx.project / m.path
        for req in sorted(mod_dir.glob("requirements*.txt")):
            rel = req.relative_to(ctx.project).as_posix()
            entries = _requirements(req)
            if not entries:
                continue
            lines = req.read_text(encoding="utf-8", errors="ignore").splitlines()
            unpinned = [(n, name) for n, name, spec in entries if not spec.startswith(("==", "==="))]
            if unpinned:
                names = ", ".join(name for _, name in unpinned[:8]) + (" ..." if len(unpinned) > 8 else "")
                out.append(_finding(
                    "supply-unpinned-requirements", rel, unpinned[0][0],
                    f"{len(unpinned)} of {len(entries)} requirements are not pinned to an exact version ({names}). "
                    "Each install can pull a new, possibly compromised release, and the dependency "
                    "vulnerability scan cannot know which version is actually used.",
                    lines[unpinned[0][0] - 1], "medium" if len(unpinned) * 2 >= len(entries) else "low",
                    "config", unpinned=[name for _, name in unpinned]))
                ctx.warn(f"{rel}: {len(unpinned)} unpinned requirement(s); vulnerability results for them are "
                         "based on whatever version the scanner resolves")
            declared = {_module_of(name): (n, name) for n, name, _ in entries}
            for mod, (n, name) in declared.items():
                if mod in third_party:
                    continue   # declared and imported: fine
                twin = next((imp for imp in third_party if imp not in declared and _similar(mod, imp)), None)
                if not twin:
                    continue
                file, line = third_party[twin]
                out.append(_finding(
                    "supply-declared-package-mismatch", rel, n,
                    f"`{name}` is declared but never imported, while `{twin}` is imported ({file}:{line}) but not "
                    f"declared. `{name}` is a different PyPI project: installing it runs someone else's code "
                    "(the typosquatting / dependency-confusion pattern) and the real dependency is missing.",
                    lines[n - 1], "high", "config", declared=name, imported=twin, import_site=f"{file}:{line}"))
    return out


def check_npm(ctx: RunContext, info: ProjectInfo) -> list[Finding]:
    out: list[Finding] = []
    for m in info.modules:
        if m.build != "npm" or not m.manifest:
            continue
        path = ctx.project / m.manifest
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError):
            continue
        lines = text.splitlines()
        for section in ("dependencies", "devDependencies"):
            for name, spec in (data.get(section) or {}).items():
                if not NPM_RISKY.search(str(spec).strip()):
                    continue
                n = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), 1)
                out.append(_finding(
                    "supply-npm-unbounded-version", m.manifest, n,
                    f"`{name}` is installed from `{spec}`: any new release or the remote ref's current "
                    "content is installed, with no version or integrity pin.",
                    lines[n - 1] if lines else "", "medium", "javascript", package=name))
        mod_dir = path.parent
        if not any((mod_dir / lock).exists() for lock in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                                                          "npm-shrinkwrap.json", "bun.lockb")):
            out.append(_finding(
                "supply-npm-no-lockfile", m.manifest, 1,
                "No lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml): every install resolves the "
                "dependency tree again, so a hijacked transitive release is picked up silently.",
                lines[0] if lines else "", "low", "javascript"))
    return out


def scan_supply_chain(ctx: RunContext, info: ProjectInfo) -> list[Finding]:
    return check_python(ctx, info) + check_npm(ctx, info)
