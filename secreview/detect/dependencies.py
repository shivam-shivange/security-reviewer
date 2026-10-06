"""Dependency (SCA) scanning: OSV-Scanner for all ecosystems, pip-audit / npm audit as fallbacks."""

from __future__ import annotations

import json
from pathlib import Path

from .. import tools
from ..context import RunContext
from ..discovery import Module, ProjectInfo
from ..models import Finding

SEV_ORDER = ["critical", "high", "medium", "low"]


def _sev(text: str | None) -> str:
    t = (text or "").lower()
    if t in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if t == "moderate" else t
    try:
        score = float(text)  # CVSS score
    except (TypeError, ValueError):
        return "high"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _fixed_versions(vuln: dict) -> list[str]:
    fixed = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def _manifest_line(project: Path, manifest: str, package: str) -> int:
    try:
        for i, line in enumerate((project / manifest).read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if package.lower().split(":")[-1] in line.lower():
                return i
    except OSError:
        pass
    return 1


def _dep_finding(project: Path, manifest: str, ecosystem: str, name: str, version: str,
                 vuln_ids: list[str], summary: str, severity: str, fixed: list[str], tool: str) -> Finding:
    line = _manifest_line(project, manifest, name)
    return Finding(
        rule_id=f"dep-{vuln_ids[0] if vuln_ids else name}", vuln_class="vulnerable_dependency", title="",
        file=manifest, line=line, tool=tool, language=ecosystem.lower(),
        message=f"{name}@{version}: {summary or 'known vulnerability'} ({', '.join(vuln_ids[:4])})",
        code=f"{name}=={version}" if ecosystem == "PyPI" else f"{name}@{version}",
        severity=severity, fix_hint=fixed[0] if fixed else "",
        extra={"package": name, "version": version, "ecosystem": ecosystem, "advisories": vuln_ids,
               "fixed_versions": fixed, "confidence": "high", "taint": False},
    )


def run_osv(ctx: RunContext) -> list[Finding] | None:
    """Returns None when osv-scanner is unavailable so callers can fall back."""
    if not tools.which("osv-scanner"):
        return None
    res = tools.run(["osv-scanner", "scan", "source", "--format", "json", "-r", "."], cwd=ctx.project, timeout=300)
    if not res.stdout.strip():
        res = tools.run(["osv-scanner", "--format", "json", "-r", "."], cwd=ctx.project, timeout=900)
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        ctx.warn(f"osv-scanner output not JSON: {res.stderr[-300:]}")
        return None
    out = []
    for result in data.get("results", []):
        manifest = Path(result.get("source", {}).get("path", ""))
        try:
            manifest_rel = manifest.resolve().relative_to(ctx.project).as_posix()
        except ValueError:
            manifest_rel = manifest.as_posix()
        for pkg in result.get("packages", []):
            p = pkg.get("package", {})
            groups = pkg.get("groups", []) or [{"ids": [v["id"]]} for v in pkg.get("vulnerabilities", [])]
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            for g in groups:
                ids = g.get("ids", [])
                v = vulns.get(ids[0], {}) if ids else {}
                fixed = sorted({fv for i in ids for fv in _fixed_versions(vulns.get(i, {}))})
                out.append(_dep_finding(ctx.project, manifest_rel, p.get("ecosystem", ""), p.get("name", ""),
                                        p.get("version", ""), ids + [a for a in v.get("aliases", [])][:3],
                                        v.get("summary", ""), _sev(g.get("max_severity")), fixed, "osv-scanner"))
    return out


def run_pip_audit(ctx: RunContext, module: Module) -> list[Finding]:
    mod_dir = ctx.project / module.path
    req = mod_dir / "requirements.txt"
    if not req.is_file() or not tools.which("pip-audit"):
        return []
    res = tools.run(["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off"],
                    cwd=mod_dir, timeout=180)
    if res.timed_out:
        ctx.warn(f"pip-audit timed out for {module.path}; skipping its dependency scan")
        return []
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        ctx.warn(f"pip-audit failed for {module.path}: {res.stderr[-300:]}")
        return []
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    manifest = (Path(module.path) / "requirements.txt").as_posix()
    out = []
    for dep in deps:
        for v in dep.get("vulns", []):
            out.append(_dep_finding(ctx.project, manifest, "PyPI", dep["name"], dep.get("version", ""),
                                    [v["id"], *v.get("aliases", [])], v.get("description", "")[:160],
                                    "high", v.get("fix_versions", []), "pip-audit"))
    return out


def run_npm_audit(ctx: RunContext, module: Module) -> list[Finding]:
    mod_dir = ctx.project / module.path
    if not (mod_dir / "package-lock.json").is_file():
        ctx.log(f"npm audit skipped for {module.path}: no package-lock.json")
        return []
    if not tools.which("npm"):
        return []
    res = tools.run(["npm", "audit", "--json", "--package-lock-only", "--no-fund"], cwd=mod_dir, timeout=120)
    if res.timed_out:
        ctx.warn(f"npm audit timed out for {module.path}; skipping its dependency scan")
        return []
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        ctx.warn(f"npm audit failed for {module.path}")
        return []
    manifest = (Path(module.path) / "package.json").as_posix()
    out = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        via = [x for x in v.get("via", []) if isinstance(x, dict)]
        if not via:
            continue   # transitive-only entry; the root advisory is reported on its own package
        ids = [str(x.get("url", "")).rsplit("/", 1)[-1] or x.get("title", "") for x in via]
        fix = v.get("fixAvailable")
        fixed = [fix["version"]] if isinstance(fix, dict) and fix.get("name") == name else []
        out.append(_dep_finding(ctx.project, manifest, "npm", name, v.get("range", ""), ids,
                                via[0].get("title", ""), _sev(v.get("severity")), fixed, "npm-audit"))
    return out


def scan_dependencies(ctx: RunContext, info: ProjectInfo) -> list[Finding]:
    osv = run_osv(ctx)
    if osv is not None:
        return osv
    ctx.log("osv-scanner not available; using pip-audit / npm audit (Maven/Gradle dependencies not scanned)")
    out: list[Finding] = []
    for m in info.modules:
        if m.build == "pip":
            out += run_pip_audit(ctx, m)
        elif m.build == "npm":
            out += run_npm_audit(ctx, m)
    return out
