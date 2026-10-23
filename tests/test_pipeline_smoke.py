"""End-to-end smoke test: scan the bundled vulnerable Flask app with no LLM, local sandbox.

Verifies the four stages run and that known classes are detected, grounded and (where the oracle
works on this OS) verified. Requires semgrep; skips if absent.
"""

import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview import tools                              # noqa: E402
from secreview.config import Config                      # noqa: E402
from secreview.models import Status                      # noqa: E402
from secreview.pipeline import run_pipeline              # noqa: E402
from secreview.store import Store                        # noqa: E402


def _force_rmtree(path: Path) -> None:
    """rmtree that also removes read-only files (git marks its object files read-only on Windows)."""
    def clear_readonly(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass   # still open (e.g. the run's SQLite db); the next run's setup removes it
    if path.exists():
        shutil.rmtree(path, onexc=clear_readonly)


@pytest.fixture
def scratch(request):
    """A scratch dir under the repo, not the system temp, and with no leading dot in any path
    component (semgrep skips dot-directories; %TEMP% on Windows triggers a Defender-scan slowdown).
    Each test gets its own subdir to avoid cross-test cleanup races on Windows (locked SQLite files)."""
    base = ROOT / "pytest_scan_tmp" / request.node.name
    _force_rmtree(base)
    base.mkdir(parents=True, exist_ok=True)
    yield base
    _force_rmtree(base)


@pytest.fixture
def flask_app(scratch):
    import subprocess
    dst = scratch / "app"
    shutil.copytree(ROOT / "examples" / "flask-vuln", dst)
    # Make the copy its own git root so this repo's .gitignore does not hide it from semgrep, and so
    # the provenance (git blame) stage has a repo to annotate.
    if tools.which("git"):
        subprocess.run(["git", "init", "-q"], cwd=dst)
        subprocess.run(["git", "add", "-A"], cwd=dst)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"], cwd=dst)
    return dst


@pytest.mark.skipif(not tools.which("semgrep"), reason="semgrep not installed")
def test_scan_detects_and_fixes(flask_app, scratch):
    cfg = Config.load()
    cfg.set("llm.enabled", False)
    cfg.set("verify.sandbox", "local")
    cfg.set("verify.install_deps", False)
    cfg.set("verify.run_regression", False)   # avoid nested pytest (slow on Windows); oracle still proves the fix
    cfg.set("permissions.mode", "auto-approve")
    cfg.set("paths.workspace", str(scratch / "ws"))
    store = Store(scratch / "ws" / "db.sqlite")

    run_id, summary = run_pipeline(cfg, flask_app, store, interactive=False, echo=False)

    findings = store.findings(run_id)
    classes = {f.vuln_class for f in findings}
    assert {"sqli", "xss", "open_redirect", "path_traversal"} <= classes

    # Detection + grounding produced evidence chains for taint findings.
    sqli = [f for f in findings if f.vuln_class == "sqli" and f.evidence and f.evidence.chain]
    assert sqli, "SQLi should have an evidence chain"

    # At least the template-fixable, OS-independent classes get verified on any platform.
    verified = {f.vuln_class for f in findings if f.status == Status.VERIFIED_FIXED.value}
    assert "sqli" in verified, f"expected SQLi verified-fixed, got {verified}"
    assert "vulnerable_dependency" in verified

    # No crashes: every finding ends in a terminal status.
    assert all(f.status != Status.CANDIDATE.value for f in findings)
    assert summary["reportable"] >= 8


@pytest.mark.skipif(not tools.which("semgrep"), reason="semgrep not installed")
def test_ablation_without_ground(flask_app, scratch):
    cfg = Config.load()
    cfg.set("llm.enabled", False)
    cfg.set("verify.enabled", False)   # ablation focuses on detect+ground; no sandbox
    cfg.set("permissions.mode", "auto-approve")
    cfg.set("paths.workspace", str(scratch / "ws"))
    store = Store(scratch / "ws" / "db.sqlite")
    run_id, summary = run_pipeline(cfg, flask_app, store, interactive=False, echo=False,
                                   ground_enabled=False)
    # With grounding off, nothing is discarded as a false positive.
    assert summary["discarded"] == 0
