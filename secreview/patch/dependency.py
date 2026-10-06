"""Dependency upgrade patches: bump a vulnerable direct dependency to the advisory's fixed version."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding, Patch
from .base import make_patch


def bump(project: Path, f: Finding) -> Patch | None:
    fixed = f.extra.get("fixed_versions") or ([f.fix_hint] if f.fix_hint else [])
    pkg, old = f.extra.get("package", ""), f.extra.get("version", "")
    if not fixed or not pkg:
        return None
    new_ver = fixed[-1] if len(fixed) > 1 and _major(fixed[-1]) == _major(old) else fixed[0]
    manifest = f.file
    path = project / manifest
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    name = Path(manifest).name
    new = None
    if name.startswith("requirements") or name.endswith(".txt"):
        new = re.sub(rf"(?im)^({re.escape(pkg)}\s*)(==|~=|>=)\s*[\w.\-]+", rf"\g<1>==" + new_ver, text)
    elif name == "package.json":
        data = json.loads(text)
        hit = False
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            if pkg in data.get(section, {}):
                prefix = re.match(r"^[\^~]?", data[section][pkg]).group(0)
                data[section][pkg] = prefix + new_ver
                hit = True
        if hit:
            indent = 2 if '\n  "' in text else 4
            new = json.dumps(data, indent=indent) + ("\n" if text.endswith("\n") else "")
    elif name == "pom.xml":
        artifact = pkg.split(":")[-1]
        new = re.sub(rf"(<artifactId>{re.escape(artifact)}</artifactId>\s*<version>)[^<$]+(</version>)",
                     rf"\g<1>{new_ver}\g<2>", text)
    elif name.startswith("build.gradle"):
        new = re.sub(rf"(['\"]{re.escape(pkg)}:)[\w.\-]+(['\"])", rf"\g<1>{new_ver}\g<2>", text)
    if not new or new == text:
        return None
    return make_patch(manifest, text, new, "dependency-bump", f"upgrade {pkg} {old} -> {new_ver}")


def _major(v: str) -> str:
    return (v or "").lstrip("v^~").split(".")[0]
