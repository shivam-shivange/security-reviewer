"""Top-level pipeline: Discover -> Detect -> Ground -> Patch/Verify -> Report."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .config import Config
from .context import RunContext, RunStopped, StageSkipped
from .detect.engine import run_detect
from .discovery import discover
from .ground import run_ground
from .llm.gate import LLMGate
from .models import SEVERITY_ORDER, Endpoint, Finding, Status
from .patch.engine import run_patch_recommendations
from .provenance import annotate
from .report.writer import write_reports
from .store import Store
from .verify import run_verify


def _summary(findings: list[Finding], endpoints: list, elapsed: float, gate: LLMGate) -> dict:
    by_status: dict[str, int] = {}
    by_class: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    reportable = [f for f in findings if f.status != Status.DISCARDED.value]
    return {
        "total_findings": len(findings),
        "reportable": len(reportable),
        "verified_fixed": by_status.get(Status.VERIFIED_FIXED.value, 0),
        "patch_unverified": by_status.get(Status.PATCH_UNVERIFIED.value, 0),
        "needs_review": by_status.get(Status.NEEDS_REVIEW.value, 0),
        "discarded": by_status.get(Status.DISCARDED.value, 0),
        "report_only": by_status.get(Status.REPORT_ONLY.value, 0),
        "by_status": by_status, "by_class": by_class, "by_severity": by_sev,
        "endpoints": len(endpoints), "elapsed_seconds": round(elapsed, 1), "llm": gate.stats,
    }


# A finished run can be continued from these stages (e.g. run Ground after a detect-only scan).
CONTINUABLE = ("ground", "verify", "report")   # "report": write the report now, nothing else runs
TAIL = ("ground", "verify", "report")


def _snapshot_path(ctx: RunContext, stage: str) -> Path:
    return ctx.out_dir / f"findings_before_{stage}.json"


def _snapshot(ctx: RunContext, stage: str, findings: list[Finding]) -> None:
    """Findings exactly as they enter `stage`, so the run can later be continued from there."""
    _snapshot_path(ctx, stage).write_text(json.dumps([f.to_dict() for f in findings], default=str),
                                          encoding="utf-8")


def _restore(ctx: RunContext, stage: str, stored: list[Finding]) -> list[Finding]:
    path = _snapshot_path(ctx, stage)
    if path.is_file():
        return [Finding.from_dict(d) for d in json.loads(path.read_text(encoding="utf-8"))]
    return _reset(stored, stage)   # run made before snapshots existed


def _reset(findings: list[Finding], stage: str) -> list[Finding]:
    """Best-effort undo of the stages from `stage` on, for runs without a snapshot."""
    for f in findings:
        if f.vuln_class == "general_bug":
            continue   # linters attach their fix at Detect; nothing later changes these
        f.patch, f.recommended_patch, f.verification = None, None, []
        f.extra.pop("unverifiable_reason", None)
        if stage == "ground":
            decided_by_detect = (f.tool in ("access-analyzer", "ai-analyzer") and f.status == Status.NEEDS_REVIEW.value) \
                or (f.tool == "bandit" and f.status == Status.DISCARDED.value)
            if not decided_by_detect:
                f.status = Status.CANDIDATE.value
                f.extra.pop("ambiguous", None)
                if f.evidence and f.evidence.method == "none":
                    f.evidence = None
        elif f.status in (Status.VERIFIED_FIXED.value, Status.PATCH_UNVERIFIED.value, Status.REPORT_ONLY.value):
            f.status = Status.GROUNDED.value
    return findings


def _not_run(ctx: RunContext, stage: str) -> None:
    ctx.stage_start(stage)
    ctx.stage_end("skipped", note="not run: you skipped ahead to the report (click to run it now)")


def _run_tail(ctx: RunContext, gate: LLMGate, info, findings: list[Finding], endpoints: list, start: float,
              from_stage: str, ground_enabled: bool) -> dict:
    """Ground -> Patch & Verify -> Report, starting at `from_stage` ("report" = the user skipped ahead).
    Skip pressed during Ground or Verify ends that stage and goes straight to the report."""
    config, store, run_id = ctx.config, ctx.store, ctx.run_id
    jump = from_stage == "report"

    def count(status: Status) -> int:
        return sum(1 for f in findings if f.status == status.value)

    # 3. Ground
    if from_stage == "ground":
        ctx.stage_start("ground", total=len(findings))
        try:
            run_ground(ctx, findings, gate, enabled=ground_enabled)
            if ground_enabled:
                ctx.stage_end("done", note=f"{count(Status.GROUNDED)} grounded, {count(Status.NEEDS_REVIEW)} need "
                                           f"review, {count(Status.DISCARDED)} discarded")
            else:
                ctx.stage_end("skipped", note=f"Ground off (ablation): {count(Status.GROUNDED)} findings passed on "
                                              "without evidence checks")
            _snapshot(ctx, "verify", findings)
        except StageSkipped:
            checked = len(findings) - count(Status.CANDIDATE)
            ctx.stage_end("skipped", note=f"skipped by you after {checked} of {len(findings)} findings; "
                                          "the rest stay unchecked (click to run Ground again)")
            ctx.warn("Ground skipped by you; going straight to the report")
            jump = True
    elif jump:
        _not_run(ctx, "ground")

    # 4. Patch + Verify
    if jump:
        _not_run(ctx, "verify")
    else:
        ctx.stage_start("verify", total=count(Status.GROUNDED))
        try:
            run_verify(ctx, findings, gate)
            run_patch_recommendations(ctx, gate, findings)
            outcome = (f"{count(Status.VERIFIED_FIXED)} verified, {count(Status.PATCH_UNVERIFIED)} patch unverified, "
                       f"{count(Status.REPORT_ONLY)} report only")
            if config.get("verify.enabled", True):
                ctx.stage_end("done", note=outcome)
            else:
                ctx.stage_end("skipped", note=f"Verify off (detection only): patches recommended, none executed; "
                                              f"{outcome}")
        except StageSkipped:
            ctx.stage_end("skipped", note=f"skipped by you; {count(Status.GROUNDED)} grounded findings not processed "
                                          "(click to run Patch & Verify again)")
            ctx.warn("Patch & Verify skipped by you; going straight to the report")

    # 5. Report
    return _report(ctx, gate, info, findings, endpoints, start)


def _report(ctx: RunContext, gate: LLMGate, info, findings: list[Finding], endpoints: list, start: float) -> dict:
    store, run_id = ctx.store, ctx.run_id
    ctx.stage_start("report")
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.status))
    for f in findings:
        store.save_finding(run_id, f)
    summary = _summary(findings, endpoints, time.time() - start, gate)
    paths = write_reports(ctx, findings, endpoints, info, summary)
    summary["reports"] = {k: str(v) for k, v in paths.items()}
    store.update_run(run_id, status="done", finished=time.time(), summary=summary, stage="done", error="")
    store.clear_control(run_id)
    ctx.stage_end("done", note=", ".join(f"{k}={v}" for k, v in paths.items()))
    ctx.log(f"done: {summary['verified_fixed']} verified-fixed, {summary['reportable']} reportable findings")
    return summary


def _stopped(ctx: RunContext) -> None:
    """Stop pressed: record where the run ended. Findings saved so far stay in the store."""
    ctx.store.stage(ctx.run_id, ctx.stage_name, "stopped", note="stopped by you")
    ctx.store.update_run(ctx.run_id, status="stopped", finished=time.time(), error="stopped by user")
    ctx.store.clear_control(ctx.run_id)
    ctx.log(f"run stopped by you during the {ctx.stage_name} stage", "warn")


def run_pipeline(config: Config, project: Path, store: Store, *, interactive: bool = False,
                 echo: bool = True, ground_enabled: bool = True, llm_client=None) -> tuple[str, dict]:
    project = project.resolve()
    run_id = store.create_run(str(project), {"ground_enabled": ground_enabled,
                                             "verify_enabled": bool(config.get("verify.enabled", True)),
                                             "provider": config.get("llm.provider"),
                                             "sandbox": config.get("verify.sandbox")})
    ctx = RunContext(config, store, run_id, project, interactive=interactive, echo=echo)
    gate = LLMGate(ctx, client=llm_client)
    start = time.time()
    try:
        # 1. Discover
        ctx.stage_start("discover")
        info = discover(project, config.get("scan.exclude", []), config.get("scan.max_file_kb", 1024))
        ctx.verify_info = info
        store.update_run(run_id, summary={"languages": info.languages, "modules": len(info.modules)})
        ctx.log(f"languages={info.languages} modules={len(info.modules)} frameworks={info.frameworks}")
        ctx.stage_end("done", note=f"{info.total_files} files, {len(info.modules)} modules")

        # 2. Detect
        ctx.stage_start("detect")
        findings, endpoints = run_detect(ctx, info)
        store.save_endpoints(run_id, endpoints)
        for f in findings:
            store.save_finding(run_id, f)
        if ctx.skipped_by_user == "detect":
            ctx.stage_end("skipped", done=len(findings), total=len(findings),
                          note=f"skipped by you: {len(findings)} findings from the tools that had finished")
        else:
            ctx.stage_end("done", done=len(findings), total=len(findings), note=f"{len(findings)} findings")
        jump = bool(ctx.skipped_by_user)

        # provenance (git blame)
        ctx.stage_start("provenance")
        if jump:
            ctx.stage_end("skipped", note="not run: you skipped ahead to the report")
        elif (project / ".git").exists():
            try:
                n = annotate(project, findings, tick=ctx.progress)
                ctx.stage_end("done", note=f"annotated {n} findings")
            except StageSkipped:
                ctx.stage_end("skipped", note="skipped by you: blame annotation incomplete")
                jump = True
        else:
            ctx.stage_end("skipped", note="not a git repository root: no blame annotation")
        _snapshot(ctx, "ground", findings)

        summary = _run_tail(ctx, gate, info, findings, endpoints, start, "report" if jump else "ground",
                            ground_enabled)
        return run_id, summary
    except (RunStopped, KeyboardInterrupt):   # Stop button, or Ctrl+C in the terminal
        _stopped(ctx)
        raise
    except Exception as exc:
        import traceback
        store.update_run(run_id, status="failed", finished=time.time(), error=str(exc))
        ctx.log(f"pipeline failed: {exc}", "error", trace=traceback.format_exc()[-2000:])
        raise


def continue_run(config: Config, store: Store, run_id: str, from_stage: str, *, interactive: bool = False,
                 echo: bool = True, llm_client=None) -> dict:
    """Run `from_stage` and every stage after it again on a finished run, reusing its Detect results.

    Typical use: a detect-only (ablation) scan, then "run Ground now" from the dashboard. The run keeps
    its id; later stages are re-run so the report reflects the new results.
    """
    if from_stage not in CONTINUABLE:
        raise ValueError(f"can only continue from {', '.join(CONTINUABLE)}, not '{from_stage}'")
    run = store.get_run(run_id)
    if run is None:
        raise ValueError(f"no run {run_id}")
    if run["status"] == "running":
        raise ValueError("this run is still running")
    project = Path(run["target"])
    if not project.is_dir():
        raise ValueError(f"the scanned folder no longer exists: {project}")

    ctx = RunContext(config, store, run_id, project, interactive=interactive, echo=echo)
    gate = LLMGate(ctx, client=llm_client)
    previous = float((run.get("summary") or {}).get("elapsed_seconds") or 0)
    start = time.time() - previous   # report the total time spent on the run
    options = dict(run.get("options") or {})
    options.setdefault("continued", []).append({"from": from_stage, "at": time.strftime("%Y-%m-%d %H:%M:%S")})
    if from_stage == "ground":
        options["ground_enabled"] = True
    if from_stage != "report":
        options["verify_enabled"] = bool(config.get("verify.enabled", True))
    store.update_run(run_id, status="running", stage=from_stage, finished=None, error="", options=options)
    store.clear_control(run_id)
    for name in TAIL[TAIL.index(from_stage):]:
        store.stage(run_id, name, "pending", note="queued: re-running" if from_stage != "report"
                    else "queued: writing the report")
    try:
        ctx.stage_name = from_stage
        ctx.log(f"continuing run from the {from_stage} stage")
        info = discover(project, config.get("scan.exclude", []), config.get("scan.max_file_kb", 1024))
        ctx.verify_info = info
        endpoints = [Endpoint(**d) for d in store.endpoints(run_id)]
        if from_stage == "report":
            # report the findings exactly as they are now; earlier stages keep their status
            return _report(ctx, gate, info, store.findings(run_id), endpoints, start)
        findings = _restore(ctx, from_stage, store.findings(run_id))
        return _run_tail(ctx, gate, info, findings, endpoints, start, from_stage, ground_enabled=True)
    except (RunStopped, KeyboardInterrupt):   # Stop button, or Ctrl+C in the terminal
        _stopped(ctx)
        raise
    except Exception as exc:
        import traceback
        store.update_run(run_id, status="failed", finished=time.time(), error=str(exc))
        ctx.log(f"continue failed: {exc}", "error", trace=traceback.format_exc()[-2000:])
        raise
