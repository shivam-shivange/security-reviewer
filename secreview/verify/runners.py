"""Sandbox runners: LocalRunner (dev, not isolated) and DockerRunner (isolated)."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .. import ROOT, tools
from ..context import RunContext
from ..discovery import Module
from ..models import Finding, Patch
from .spec import build_spec
from .workspace import apply_patch, copy_project, revert

HARNESS = ROOT / "harness"


@dataclass
class OracleResult:
    result: str                 # vulnerable | blocked | error
    reason: str = ""
    log: str = ""


@dataclass
class RegressionResult:
    status: str                 # passed | failed | no-tests | skipped
    log: str = ""


@dataclass
class Env:
    finding_id: str
    sandbox: Path
    module: Module | None = None
    data: dict = field(default_factory=dict)


class Runner:
    name = "base"

    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        self.root = ctx.out_dir / "sandbox"
        self.info = None

    def setup(self, findings: list[Finding]) -> None:
        ...

    def teardown(self) -> None:
        ...

    def _module_of(self, f: Finding) -> Module | None:
        if self.ctx.verify_info is None:
            return None
        return self.ctx.verify_info.module_for(f.file)

    # overridden by subclasses
    def prepare(self, f: Finding) -> Env: ...
    def run_oracle(self, env: Env, f: Finding, patched: bool) -> OracleResult: ...
    def run_regression(self, env: Env, f: Finding) -> RegressionResult: ...
    def apply(self, env: Env, patch: Patch): return apply_patch(env.sandbox, patch)
    def revert(self, env: Env, backups): revert(backups)
    def cleanup(self, env: Env) -> None: ...


def parse_result(stdout: str) -> OracleResult:
    for line in reversed(stdout.splitlines()):
        if line.startswith("SECREVIEW_RESULT "):
            try:
                data = json.loads(line[len("SECREVIEW_RESULT "):])
                return OracleResult(data.get("result", "error"), data.get("reason", "") or data.get("evidence", ""),
                                    json.dumps(data))
            except json.JSONDecodeError:
                break
    return OracleResult("error", "no result line from harness", stdout[-2000:])


# ----------------------------------------------------------------------------- local
class LocalRunner(Runner):
    """Runs the harness directly on the host. NOT isolated: for development only."""
    name = "local"

    def setup(self, findings) -> None:
        if not self.ctx.allow("run_project_code_unsandboxed",
                              "The local sandbox executes the scanned project on this machine without isolation."):
            raise PermissionError("local sandbox not permitted")
        self.shared = copy_project(self.ctx.project, self.root / "project")
        self._venv_python = self._ensure_python_env(self.shared)

    def _ensure_python_env(self, sandbox: Path) -> str:
        """Create a venv with the project's requirements, so the app imports; fall back to base venv."""
        base = str(ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / "python")
        reqs = [sandbox / m.path / "requirements.txt" for m in (self.ctx.verify_info.modules if self.ctx.verify_info else [])
                if m.build == "pip"]
        reqs = [r for r in reqs if r.is_file()]
        if not reqs or not self.ctx.config.get("verify.install_deps", True):
            return base
        venv = sandbox / ".secreview_venv"
        py = str(venv / ("Scripts" if os.name == "nt" else "bin") / "python")
        if not Path(py).exists():
            if not self.ctx.allow("network_install", "Install the project's Python dependencies into a local venv."):
                return base
            tools.run([base, "-m", "venv", str(venv)], timeout=120)
            tools.run([py, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                       "flask", "fastapi", "starlette", "httpx", "django", "pytest"], timeout=600)
            for r in reqs:
                res = tools.run([py, "-m", "pip", "install", "-q", "-r", str(r)], timeout=1200)
                if not res.ok:
                    self.ctx.warn(f"could not install {r.name}; app may not import ({res.stderr[-200:]})")
        return py if Path(py).exists() else base

    def prepare(self, f: Finding) -> Env:
        return Env(f.id, self.shared, self._module_of(f))

    def _run_harness(self, env: Env, f: Finding) -> OracleResult:
        runtime = {"python": "python", "javascript": "node", "java": "java"}.get(f.language)
        spec = build_spec(env.sandbox, f, overrides=self.ctx.config.get("verify.spec_overrides", {}))
        spec_file = self.ctx.out_dir / f"spec_{f.id}.json"
        spec_file.write_text(json.dumps(spec), encoding="utf-8")
        if f.language == "python":
            cmd = [self._venv_python, str(HARNESS / "python" / "verify_harness.py"), str(spec_file)]
            cwd = env.sandbox
        elif f.language == "javascript":
            node_harness = HARNESS / "node" / "verify_harness.js"
            if not node_harness.exists() or not tools.which("node"):
                return OracleResult("error", "node harness unavailable")
            cmd = ["node", str(node_harness), str(spec_file)]
            cwd = env.sandbox
        else:
            return OracleResult("error", f"no local harness for {f.language}")
        res = tools.run(cmd, cwd=cwd, timeout=int(self.ctx.config.get("verify.timeout_seconds", 600)),
                        env={**tools.tool_env(), "PYTHONPATH": str(env.sandbox)})
        out = parse_result(res.stdout)
        out.log = (res.stdout + "\n" + res.stderr)[-4000:]
        return out

    def run_oracle(self, env: Env, f: Finding, patched: bool) -> OracleResult:
        return self._run_harness(env, f)

    def run_regression(self, env: Env, f: Finding) -> RegressionResult:
        if not self.ctx.config.get("verify.run_regression", True):
            return RegressionResult("skipped")
        mod = env.module
        if mod is None or not mod.test_command:
            return RegressionResult("no-tests")
        cmd = mod.test_command.split()
        if cmd[0] == "python":
            cmd[0] = self._venv_python
        res = tools.run(cmd, cwd=env.sandbox / mod.path, timeout=int(self.ctx.config.get("verify.timeout_seconds", 600)))
        if res.timed_out:
            return RegressionResult("failed", "tests timed out")
        status = "passed" if res.ok else "failed"
        if re.search(r"no tests ran|collected 0 items", res.stdout, re.I):
            status = "no-tests"
        return RegressionResult(status, (res.stdout + res.stderr)[-4000:])

    def teardown(self) -> None:
        if self.ctx.config.get("verify.keep_sandbox", False):
            return
        shutil.rmtree(self.root, ignore_errors=True)


# ----------------------------------------------------------------------------- docker
class DockerRunner(Runner):
    """Isolated verification inside a per-stack Docker image (network disabled by default)."""
    name = "docker"

    def setup(self, findings) -> None:
        if not self.ctx.allow("docker_build", "Build/run Docker sandbox images for verification."):
            raise PermissionError("docker build not permitted")
        self.shared = copy_project(self.ctx.project, self.root / "project")
        self.images: dict[str, str] = {}

    def _image_for(self, f: Finding) -> str | None:
        from .docker_images import ensure_image
        mod = self._module_of(f)
        key = (mod.build if mod else f.language) or f.language
        if key not in self.images:
            img = ensure_image(self.ctx, self.shared, mod, f.language)
            if not img:
                return None
            self.images[key] = img
        return self.images[key]

    def prepare(self, f: Finding) -> Env:
        return Env(f.id, self.shared, self._module_of(f), data={"image": self._image_for(f)})

    def _docker_exec(self, env: Env, inner_cmd: list[str], timeout: int) -> tools.ToolResult:
        image = env.data.get("image")
        if not image:
            return tools.ToolResult([], 1, "", "no image")
        net = "none" if self.ctx.config.get("verify.network", "none") == "none" else "bridge"
        mount = f"{self.shared}:/work"
        harness_mount = f"{HARNESS}:/harness:ro"
        cmd = ["docker", "run", "--rm", f"--network={net}", "--memory=1g", "--cpus=1.5",
               "-v", mount, "-v", harness_mount, "-w", "/work", image, *inner_cmd]
        return tools.run(cmd, timeout=timeout)

    def run_oracle(self, env: Env, f: Finding, patched: bool) -> OracleResult:
        spec = build_spec(Path("/work"), f, overrides=self.ctx.config.get("verify.spec_overrides", {}))
        spec["canary_dir"] = "/tmp"
        spec["canary_file"] = f"/tmp/secreview_canary_{spec['token']}"
        (self.shared / ".secreview_spec.json").write_text(json.dumps(spec), encoding="utf-8")
        timeout = int(self.ctx.config.get("verify.timeout_seconds", 600))
        if f.language == "python":
            inner = ["python", "/harness/python/verify_harness.py", "/work/.secreview_spec.json"]
        elif f.language == "javascript":
            inner = ["node", "/harness/node/verify_harness.js", "/work/.secreview_spec.json"]
        else:
            inner = ["bash", "/harness/java/run_harness.sh", "/work/.secreview_spec.json"]
        res = self._docker_exec(env, inner, timeout)
        out = parse_result(res.stdout)
        out.log = (res.stdout + "\n" + res.stderr)[-4000:]
        return out

    def run_regression(self, env: Env, f: Finding) -> RegressionResult:
        if not self.ctx.config.get("verify.run_regression", True):
            return RegressionResult("skipped")
        mod = env.module
        if mod is None or not mod.test_command:
            return RegressionResult("no-tests")
        workdir = "/work" if mod.path == "." else f"/work/{mod.path}"
        res = self._docker_exec(env, ["bash", "-lc", f"cd {workdir} && {mod.test_command}"],
                                int(self.ctx.config.get("verify.timeout_seconds", 600)))
        status = "passed" if res.ok else "failed"
        if re.search(r"no tests ran|collected 0 items|No tests found", res.stdout + res.stderr, re.I):
            status = "no-tests"
        return RegressionResult(status, (res.stdout + res.stderr)[-4000:])

    def teardown(self) -> None:
        if not self.ctx.config.get("verify.keep_sandbox", False):
            shutil.rmtree(self.root, ignore_errors=True)
