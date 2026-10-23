"""Project discovery: files, languages, modules (build units), frameworks and test commands."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

EXT_LANG = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
}

MANIFESTS = {
    "pom.xml": ("java", "maven"),
    "build.gradle": ("java", "gradle"),
    "build.gradle.kts": ("java", "gradle"),
    "package.json": ("javascript", "npm"),
    "pyproject.toml": ("python", "pip"),
    "setup.py": ("python", "pip"),
    "requirements.txt": ("python", "pip"),
    "Pipfile": ("python", "pip"),
}

FRAMEWORK_MARKERS = {
    "flask": ("python", re.compile(r"\bflask\b", re.I)),
    "django": ("python", re.compile(r"\bdjango\b", re.I)),
    "fastapi": ("python", re.compile(r"\bfastapi\b", re.I)),
    "streamlit": ("python", re.compile(r"\bstreamlit\b", re.I)),
    "gradio": ("python", re.compile(r"\bgradio\b", re.I)),
    "langchain": ("python", re.compile(r"\blangchain", re.I)),
    "express": ("javascript", re.compile(r'"express"')),
    "mongoose": ("javascript", re.compile(r'"mongoose"')),
    "mongodb": ("javascript", re.compile(r'"mongodb"')),
    "react": ("javascript", re.compile(r'"react"')),
    "spring": ("java", re.compile(r"spring-boot|org\.springframework")),
    "servlet": ("java", re.compile(r"servlet-api|jakarta\.servlet")),
}

TEST_PATH = re.compile(r"(^|[\\/])(tests?|__tests__|spec|src[\\/]test)([\\/]|$)|"
                       r"(^|[\\/])(test_[^\\/]+\.py|[^\\/]+_test\.py|[^\\/]+\.(test|spec)\.[jt]sx?|"
                       r"[^\\/]+Test\.java|[^\\/]+Tests\.java)$")


@dataclass
class Module:
    path: str                      # relative to project root ("." for root)
    language: str
    build: str                     # maven | gradle | npm | pip
    frameworks: list[str] = field(default_factory=list)
    test_command: str = ""
    manifest: str = ""


@dataclass
class ProjectInfo:
    root: str
    languages: dict[str, int] = field(default_factory=dict)      # language -> file count
    modules: list[Module] = field(default_factory=list)
    files: dict[str, list[str]] = field(default_factory=dict)    # language -> relative paths
    frameworks: list[str] = field(default_factory=list)
    is_git: bool = False
    total_files: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("files")
        return d

    def module_for(self, rel_file: str) -> Module | None:
        best = None
        for m in self.modules:
            prefix = "" if m.path == "." else m.path.rstrip("/") + "/"
            if rel_file.replace("\\", "/").startswith(prefix):
                if best is None or len(m.path) > len(best.path) or best.path == ".":
                    best = m
        return best


def is_excluded(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def is_test_file(rel: str) -> bool:
    return bool(TEST_PATH.search(rel.replace("\\", "/")))


def walk(root: Path, exclude: list[str], max_kb: int):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not is_excluded(d, exclude) and not d.startswith(".")]
        for name in filenames:
            if is_excluded(name, exclude):
                continue
            path = Path(dirpath) / name
            try:
                if path.stat().st_size > max_kb * 1024:
                    continue
            except OSError:
                continue
            yield path


def _detect_frameworks(manifest: Path, language: str) -> list[str]:
    try:
        text = manifest.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return [fw for fw, (lang, rx) in FRAMEWORK_MARKERS.items() if lang == language and rx.search(text)]


def _test_command(mod_dir: Path, build: str) -> str:
    if build == "maven":
        return "mvn -B -q test"
    if build == "gradle":
        return "./gradlew test --no-daemon" if (mod_dir / "gradlew").exists() else "gradle test --no-daemon"
    if build == "npm":
        try:
            scripts = json.loads((mod_dir / "package.json").read_text(encoding="utf-8")).get("scripts", {})
        except (OSError, json.JSONDecodeError):
            scripts = {}
        test = scripts.get("test", "")
        return "npm test" if test and "no test specified" not in test else ""
    if build == "pip":
        has_tests = any((mod_dir / d).is_dir() for d in ("tests", "test")) or any(mod_dir.glob("test_*.py"))
        return "python -m pytest -q" if has_tests else ""
    return ""


def discover(root: Path, exclude: list[str], max_kb: int = 1024) -> ProjectInfo:
    root = root.resolve()
    info = ProjectInfo(root=str(root), is_git=(root / ".git").exists())
    module_dirs: dict[Path, Module] = {}

    for path in walk(root, exclude, max_kb):
        rel = path.relative_to(root).as_posix()
        info.total_files += 1
        lang = EXT_LANG.get(path.suffix.lower())
        if lang:
            info.files.setdefault(lang, []).append(rel)
        if path.name in MANIFESTS:
            mlang, build = MANIFESTS[path.name]
            d = path.parent
            existing = module_dirs.get(d)
            # A directory with both pom.xml and package.json etc: keep the JVM/Node one over pip.
            if existing and existing.build != "pip":
                if existing.language == mlang:
                    continue
            mrel = d.relative_to(root).as_posix() or "."
            module_dirs[d] = Module(path=mrel, language=mlang, build=build,
                                    frameworks=_detect_frameworks(path, mlang),
                                    manifest=path.relative_to(root).as_posix())

    for d, m in module_dirs.items():
        if m.build == "pip":   # gather frameworks from every python manifest in that dir
            fws = set(m.frameworks)
            for name in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"):
                if (d / name).exists():
                    fws.update(_detect_frameworks(d / name, "python"))
            m.frameworks = sorted(fws)
        m.test_command = _test_command(d, m.build)

    # Source files without any manifest still form an implicit root module per language.
    for lang in info.files:
        if not any(m.language == lang for m in module_dirs.values()):
            module_dirs[root / f".{lang}"] = Module(path=".", language=lang, build="none")

    info.modules = sorted(module_dirs.values(), key=lambda m: m.path)
    info.languages = {k: len(v) for k, v in info.files.items()}
    info.frameworks = sorted({fw for m in info.modules for fw in m.frameworks})
    return info
