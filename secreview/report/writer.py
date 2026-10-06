"""Write JSON, HTML and patch-file reports for a completed run."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path

from .. import ROOT, __version__
from ..context import RunContext
from ..models import Finding, Status
from ..taxonomy import info as class_info

STATUS_LABEL = {
    Status.VERIFIED_FIXED.value: "Verified Fixed",
    Status.PATCH_UNVERIFIED.value: "Grounded, patch unverified",
    Status.NEEDS_REVIEW.value: "Needs review",
    Status.GROUNDED.value: "Grounded",
    Status.DISCARDED.value: "Discarded at grounding",
    Status.REPORT_ONLY.value: "Report only",
    Status.CANDIDATE.value: "Candidate",
}


def _finding_json(f: Finding) -> dict:
    d = f.to_dict()
    d["status_label"] = STATUS_LABEL.get(f.status, f.status)
    d["remediation"] = f.remediation or class_info(f.vuln_class).get("remediation", "")
    return d


def build_report(ctx: RunContext, findings: list[Finding], endpoints: list, info, summary: dict) -> dict:
    reportable = [f for f in findings if f.status != Status.DISCARDED.value]
    return {
        "tool": "secreview", "version": __version__, "run_id": ctx.run_id,
        "project": str(ctx.project), "generated": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "project_info": info.to_dict() if info else {},
        "findings": [_finding_json(f) for f in reportable],
        "discarded": [_finding_json(f) for f in findings if f.status == Status.DISCARDED.value],
        "endpoints": [asdict(e) if is_dataclass(e) else e for e in endpoints],
    }


def write_reports(ctx: RunContext, findings: list[Finding], endpoints, info, summary: dict) -> dict:
    report = build_report(ctx, findings, endpoints, info, summary)
    out = ctx.out_dir
    paths = {}

    json_path = out / "report.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    paths["json"] = json_path

    patches_dir = out / "patches"
    patches_dir.mkdir(exist_ok=True)
    combined = []
    for f in findings:
        p = f.patch or f.recommended_patch
        if p and p.diff:
            (patches_dir / f"{f.vuln_class}_{f.id}.patch").write_text(p.diff, encoding="utf-8")
            if f.patch:
                combined.append(p.diff)
    if combined:
        (out / "verified_fixes.patch").write_text("\n".join(combined), encoding="utf-8")
        paths["patch"] = out / "verified_fixes.patch"

    from .html import render_html
    html_path = out / "report.html"
    html_path.write_text(render_html(report), encoding="utf-8")
    paths["html"] = html_path

    # a short console-friendly summary
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return paths
