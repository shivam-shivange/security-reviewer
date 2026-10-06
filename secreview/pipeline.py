"""Top-level pipeline: Discover -> Detect -> Ground -> Patch/Verify -> Report."""

from __future__ import annotations

import time
from pathlib import Path

from .config import Config
from .context import RunContext
from .detect.engine import run_detect
from .discovery import discover
from .ground import run_ground
from .llm.gate import LLMGate
from .models import SEVERITY_ORDER, Finding, Status
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


def run_pipeline(config: Config, project: Path, store: Store, *, interactive: bool = False,
                 echo: bool = True, ground_enabled: bool = True, llm_client=None) -> tuple[str, dict]:
    project = project.resolve()
    run_id = store.create_run(str(project), {"ground_enabled": ground_enabled,
                                             "provider": config.get("llm.provider"),
                                             "sandbox": config.get("verify.sandbox")})
    ctx = RunContext(config, store, run_id, project, interactive=interactive, echo=echo)
    gate = LLMGate(ctx, client=llm_client)
    start = time.time()
    findings: list[Finding] = []
    endpoints: list = []
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
        ctx.stage_end("done", done=len(findings), total=len(findings), note=f"{len(findings)} findings")

        # provenance (git blame)
        if (project / ".git").exists():
            ctx.stage_start("provenance")
            n = annotate(project, findings)
            ctx.stage_end("done", note=f"annotated {n} findings")

        # 3. Ground
        ctx.stage_start("ground", total=len(findings))
        run_ground(ctx, findings, gate, enabled=ground_enabled)
        grounded = sum(1 for f in findings if f.status == Status.GROUNDED.value)
        ctx.stage_end("done", note=f"{grounded} grounded, "
                      f"{sum(1 for f in findings if f.status == Status.DISCARDED.value)} discarded")

        # 4. Patch + Verify
        ctx.stage_start("verify", total=sum(1 for f in findings if f.status == Status.GROUNDED.value))
        run_verify(ctx, findings, gate)
        run_patch_recommendations(ctx, gate, findings)
        ctx.stage_end("done", note=f"{sum(1 for f in findings if f.status == Status.VERIFIED_FIXED.value)} verified")

        # 5. Report
        ctx.stage_start("report")
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.status))
        for f in findings:
            store.save_finding(run_id, f)
        summary = _summary(findings, endpoints, time.time() - start, gate)
        paths = write_reports(ctx, findings, endpoints, info, summary)
        summary["reports"] = {k: str(v) for k, v in paths.items()}
        store.update_run(run_id, status="done", finished=time.time(), summary=summary, stage="done")
        ctx.stage_end("done", note=", ".join(f"{k}={v}" for k, v in paths.items()))
        ctx.log(f"done: {summary['verified_fixed']} verified-fixed, {summary['reportable']} reportable findings")
        return run_id, summary
    except Exception as exc:
        import traceback
        store.update_run(run_id, status="failed", finished=time.time(), error=str(exc))
        ctx.log(f"pipeline failed: {exc}", "error", trace=traceback.format_exc()[-2000:])
        raise
