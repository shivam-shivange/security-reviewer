"""Continuing a finished run from a stage: the reset used for runs made before snapshots existed."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview.models import Evidence, Finding, Patch, Status   # noqa: E402
from secreview.pipeline import CONTINUABLE, _reset             # noqa: E402


def _f(status, tool="semgrep", vclass="sqli", evidence=None, **extra):
    f = Finding(rule_id="r", vuln_class=vclass, title="", file="a.py", line=1, tool=tool, status=status,
                evidence=evidence, extra=dict(extra))
    f.recommended_patch = Patch(diff="d", source="template:x")
    return f


def test_reset_before_ground_keeps_detect_decisions():
    ablated = _f(Status.REPORT_ONLY.value, evidence=Evidence(method="none", summary="grounding disabled (ablation)"),
                 unverifiable_reason="verify stage disabled")
    heuristic = _f(Status.NEEDS_REVIEW.value, tool="ai-analyzer", vclass="prompt_injection",
                   evidence=Evidence(method="ai-app-analysis", summary="chain"))
    constant_cmd = _f(Status.DISCARDED.value, tool="bandit", vclass="cmdi")
    lint = _f(Status.REPORT_ONLY.value, tool="ruff", vclass="general_bug")
    _reset([ablated, heuristic, constant_cmd, lint], "ground")
    assert ablated.status == Status.CANDIDATE.value and ablated.evidence is None
    assert ablated.recommended_patch is None and "unverifiable_reason" not in ablated.extra
    assert heuristic.status == Status.NEEDS_REVIEW.value and heuristic.evidence.method == "ai-app-analysis"
    assert constant_cmd.status == Status.DISCARDED.value
    assert lint.recommended_patch is not None        # linter fixes are attached at Detect


def test_reset_before_verify_returns_findings_to_grounded():
    done = _f(Status.PATCH_UNVERIFIED.value, evidence=Evidence(method="semgrep-taint", summary="t"))
    review = _f(Status.NEEDS_REVIEW.value, tool="ai-analyzer")
    _reset([done, review], "verify")
    assert done.status == Status.GROUNDED.value and done.evidence.method == "semgrep-taint"
    assert done.recommended_patch is None
    assert review.status == Status.NEEDS_REVIEW.value


def test_continuable_stages():
    assert CONTINUABLE == ("ground", "verify", "report")
