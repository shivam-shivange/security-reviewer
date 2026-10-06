"""Build (once per run) the per-stack sandbox image used by DockerRunner."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from .. import ROOT, tools
from ..context import RunContext
from ..discovery import Module

DOCKER = ROOT / "docker"
DOCKERFILE = {"pip": "python.Dockerfile", "npm": "node.Dockerfile",
              "maven": "maven.Dockerfile", "gradle": "gradle.Dockerfile", "none": "python.Dockerfile"}
LANG_DEFAULT = {"python": "python.Dockerfile", "javascript": "node.Dockerfile", "java": "maven.Dockerfile"}


def ensure_image(ctx: RunContext, sandbox: Path, module: Module | None, language: str) -> str | None:
    dockerfile_name = DOCKERFILE.get(module.build if module else "", LANG_DEFAULT.get(language))
    if not dockerfile_name:
        return None
    build = module.build if module else language
    tag = f"secreview-sandbox-{build}:{ctx.run_id[:8]}"
    # Build context: the module dir (so its manifests/lockfiles are available to the Dockerfile COPYs).
    ctx_dir = sandbox / (module.path if module and module.path != "." else "")
    build_ctx = ctx.out_dir / f"img_{build}"
    build_ctx.mkdir(parents=True, exist_ok=True)
    for manifest in ("requirements.txt", "requirements-dev.txt", "package.json", "package-lock.json",
                     "pom.xml", "build.gradle", "build.gradle.kts"):
        src = ctx_dir / manifest
        if src.is_file():
            shutil.copy(src, build_ctx / manifest)
    shutil.copy(DOCKER / dockerfile_name, build_ctx / "Dockerfile")
    ctx.log(f"building sandbox image {tag} ({dockerfile_name})")
    res = tools.run(["docker", "build", "-t", tag, "-f", str(build_ctx / "Dockerfile"), str(build_ctx)],
                    timeout=int(ctx.config.get("verify.build_timeout_seconds", 1800)))
    if not res.ok:
        ctx.warn(f"docker build failed for {build}: {res.stderr[-400:]}")
        return None
    return tag
