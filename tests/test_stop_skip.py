"""Live Stop / Skip of a running scan (dashboard buttons), driven through the real pipeline with stub stages."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import secreview.detect.engine as engine                  # noqa: E402
import secreview.pipeline as pipeline                      # noqa: E402
from secreview.config import Config                       # noqa: E402
from secreview.context import RunStopped                   # noqa: E402
from secreview.models import Finding                       # noqa: E402
from secreview.store import Store                          # noqa: E402

DETECTORS = ("semgrep", "bandit", "secrets", "dependencies", "supply_chain", "access_control", "ai_app",
             "general_bugs")


@pytest.fixture
def setup(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")
    cfg = Config.load()
    cfg.set("llm.enabled", False)
    cfg.set("verify.enabled", False)
    cfg.set("permissions.mode", "auto-approve")
    cfg.set("paths.workspace", str(tmp_path / "ws"))
    for d in DETECTORS:
        cfg.set(f"detect.{d}", d == "secrets")      # one cheap detector, replaced by a stub below
    return cfg, project, Store(tmp_path / "ws" / "db.sqlite")


def _finding(i):
    return Finding(rule_id="r", vuln_class="sqli", title="", file="app.py", line=i, tool="semgrep",
                   code=f"q{i}", language="python")


def _stages(store, run_id):
    return {s["name"]: s for s in store.get_run(run_id)["stages"]}


def test_skip_during_ground_writes_report_and_leaves_ground_resumable(setup, monkeypatch):
    cfg, project, store = setup
    monkeypatch.setattr(engine, "scan_secrets", lambda ctx: [_finding(i) for i in range(1, 6)])

    def ground(ctx, findings, gate, enabled=True):
        ctx.store.request_control(ctx.run_id, "skip:ground")    # the user presses Skip mid-stage
        ctx.progress(1, len(findings))
    monkeypatch.setattr(pipeline, "run_ground", ground)

    run_id, summary = pipeline.run_pipeline(cfg, project, store, echo=False)
    stages = _stages(store, run_id)
    assert store.get_run(run_id)["status"] == "done" and stages["report"]["status"] == "done"
    assert stages["ground"]["status"] == "skipped" and "skipped by you" in stages["ground"]["note"]
    assert stages["verify"]["status"] == "skipped" and "skipped ahead" in stages["verify"]["note"]
    assert summary["total_findings"] == 5 and store.control(run_id) == ""


def test_skip_during_detect_keeps_partial_findings(setup, monkeypatch):
    cfg, project, store = setup

    def secrets(ctx):
        ctx.store.request_control(ctx.run_id, "skip:detect")
        return [_finding(1)]
    monkeypatch.setattr(engine, "scan_secrets", secrets)
    run_id, summary = pipeline.run_pipeline(cfg, project, store, echo=False)
    stages = _stages(store, run_id)
    assert stages["detect"]["status"] == "skipped" and summary["total_findings"] == 1
    assert all(stages[s]["status"] == "skipped" for s in ("provenance", "ground", "verify"))
    assert stages["report"]["status"] == "done"


def test_stop_marks_run_and_stage_stopped(setup, monkeypatch):
    cfg, project, store = setup
    monkeypatch.setattr(engine, "scan_secrets", lambda ctx: [_finding(1)])

    def ground(ctx, findings, gate, enabled=True):
        ctx.store.request_control(ctx.run_id, "stop")
        ctx.progress(1, len(findings))
    monkeypatch.setattr(pipeline, "run_ground", ground)
    with pytest.raises(RunStopped):
        pipeline.run_pipeline(cfg, project, store, echo=False)
    run = store.list_runs(1)[0]
    assert run["status"] == "stopped"
    assert _stages(store, run["id"])["ground"]["status"] == "stopped"
    assert store.control(run["id"]) == ""


def test_stale_skip_for_another_stage_is_ignored(setup, monkeypatch):
    cfg, project, store = setup
    monkeypatch.setattr(engine, "scan_secrets", lambda ctx: [_finding(1)])

    def ground(ctx, findings, gate, enabled=True):
        ctx.store.request_control(ctx.run_id, "skip:detect")   # arrived after Detect had finished
        ctx.progress(1, len(findings))
    monkeypatch.setattr(pipeline, "run_ground", ground)
    run_id, _ = pipeline.run_pipeline(cfg, project, store, echo=False)
    assert _stages(store, run_id)["ground"]["status"] == "done"


def test_generate_report_for_a_stopped_run(setup, monkeypatch):
    """A run stopped (or interrupted) before Report gets its report without re-running anything."""
    cfg, project, store = setup
    monkeypatch.setattr(engine, "scan_secrets", lambda ctx: [_finding(i) for i in range(1, 4)])

    def ground(ctx, findings, gate, enabled=True):
        ctx.store.request_control(ctx.run_id, "stop")
        ctx.progress(1, len(findings))
    monkeypatch.setattr(pipeline, "run_ground", ground)
    with pytest.raises(RunStopped):
        pipeline.run_pipeline(cfg, project, store, echo=False)
    run_id = store.list_runs(1)[0]["id"]

    summary = pipeline.continue_run(cfg, store, run_id, "report", echo=False)
    stages = _stages(store, run_id)
    assert store.get_run(run_id)["status"] == "done" and stages["report"]["status"] == "done"
    assert stages["ground"]["status"] == "stopped"          # report-only: earlier stages keep their status
    assert summary["total_findings"] == 3 and Path(summary["reports"]["html"]).is_file()


def test_skip_during_detect_only_verify_is_immediate(setup, monkeypatch):
    """Detect-only Patch & Verify used to have no checkpoint, so Skip waited for the whole stage."""
    import secreview.verify.engine as verify_engine
    cfg, project, store = setup
    monkeypatch.setattr(engine, "scan_secrets", lambda ctx: [_finding(i) for i in range(1, 6)])
    calls = []

    def candidates(ctx, gate, f, **kw):
        calls.append(f.line)
        ctx.store.request_control(ctx.run_id, "skip:verify")   # pressed while the first patch is written
        return []
    monkeypatch.setattr(verify_engine, "candidates", candidates)
    run_id, _ = pipeline.run_pipeline(cfg, project, store, echo=False)
    assert len(calls) == 1                                      # stopped after the first finding
    stages = _stages(store, run_id)
    assert stages["verify"]["status"] == "skipped" and stages["report"]["status"] == "done"
