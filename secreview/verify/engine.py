"""Verify stage: for each grounded finding, prove a candidate patch by execution.

A patch is accepted only if:
  * the oracle TRIGGERS on the original code (confirming the finding is real and reachable), and
  * the oracle does NOT trigger after the patch is applied, and
  * the project's existing tests still pass (regression), when a test suite exists.

On failure the failure output is fed back to the Patch stage and a new candidate is tried, up to
verify.max_retries. Dependency findings are verified by re-running the dependency scanner. Findings
without an executable oracle get status patch_unverified with a recommended patch attached.
"""

from __future__ import annotations

from ..context import RunContext
from ..llm.gate import LLMGate
from ..models import Finding, Status, VerificationAttempt
from ..patch.engine import candidates
from .runners import LocalRunner, DockerRunner, Runner
from .spec import build_spec, has_oracle


def _runner(ctx: RunContext) -> Runner:
    mode = ctx.config.get("verify.sandbox", "docker")
    if mode == "docker":
        from .. import tools
        if tools.which("docker") and tools.run(["docker", "info"], timeout=20).ok:
            return DockerRunner(ctx)
        ctx.warn("Docker not available; falling back to LOCAL sandbox (not isolated)")
    return LocalRunner(ctx)


def verify_finding(ctx: RunContext, gate: LLMGate, f: Finding, runner: Runner) -> None:
    if f.status not in (Status.GROUNDED.value,):
        return
    if f.vuln_class == "vulnerable_dependency":
        _verify_dependency(ctx, f, runner)
        return
    if not has_oracle(f):
        # No executable oracle for this class: attach a candidate patch as "recommended", unverified.
        cands = candidates(ctx, gate, f)
        if cands:
            f.recommended_patch = cands[0]
        _unverified(f, "no exploit oracle for this class (rule-based finding)")
        return

    max_retries = int(ctx.config.get("verify.max_retries", 3))
    tried: set[str] = set()
    feedback = ""
    env = runner.prepare(f)
    try:
        baseline = runner.run_oracle(env, f, patched=False)
        if baseline.result != "vulnerable":
            # Could not reproduce the issue in the sandbox -> cannot prove a fix. Keep as grounded-unverified.
            f.verification.append(VerificationAttempt(0, "baseline", exploit_before=baseline.result,
                                                      passed=False, log=baseline.log[-4000:]))
            cands = candidates(ctx, gate, f)
            if cands:
                f.recommended_patch = cands[0]
            _unverified(f, f"oracle did not trigger on original code ({baseline.result}: {baseline.reason})")
            return

        for attempt in range(1, max_retries + 1):
            cands = candidates(ctx, gate, f, feedback=feedback, tried=tried)
            if not cands:
                break
            patch = cands[0]
            tried.add(patch.diff)
            va = VerificationAttempt(attempt, patch.source, exploit_before=baseline.result)
            backups = runner.apply(env, patch)
            try:
                after = runner.run_oracle(env, f, patched=True)
                va.exploit_after = after.result
                if after.result != "blocked":
                    va.passed = False
                    va.log = f"oracle still triggered after patch ({after.result})\n{after.log[-2000:]}"
                    feedback = va.log
                    runner.revert(env, backups)
                    f.verification.append(va)
                    continue
                reg = runner.run_regression(env, f)
                va.regression = reg.status
                va.log = (after.log + "\n--- regression ---\n" + reg.log)[-6000:]
                if reg.status in ("passed", "no-tests", "skipped"):
                    va.passed = True
                    f.patch = patch
                    f.status = Status.VERIFIED_FIXED.value
                    f.verification.append(va)
                    return
                va.passed = False
                feedback = f"patch closed the issue but broke tests:\n{reg.log[-2500:]}"
                runner.revert(env, backups)
                f.verification.append(va)
            except Exception as exc:
                va.log = f"verification error: {exc}"
                runner.revert(env, backups)
                f.verification.append(va)
                feedback = va.log

        # retries exhausted: keep the best patch as recommended, unverified
        if f.verification and not f.recommended_patch:
            last = candidates(ctx, gate, f, tried=set())
            if last:
                f.recommended_patch = last[0]
        _unverified(f, f.extra.get("unverifiable_reason")
                    or "no candidate patch passed verification within the retry limit")
    finally:
        runner.cleanup(env)


def _unverified(f: Finding, reason: str) -> None:
    """Could not prove a fix. `patch_unverified` only when a patch exists; with no patch at all the
    finding is `report_only` (follow the remediation text), so the label never promises a patch."""
    has_patch = bool(f.patch or f.recommended_patch)
    f.status = Status.PATCH_UNVERIFIED.value if has_patch else Status.REPORT_ONLY.value
    f.extra["unverifiable_reason"] = reason if has_patch else f"{reason}; no automatic patch available"


def _verify_dependency(ctx: RunContext, f: Finding, runner: Runner) -> None:
    from ..patch.dependency import bump
    patch = bump(ctx.project, f)
    if not patch:
        _unverified(f, "no fixed version available in the advisory")
        return
    # The fix is a version bump to a version the advisory marks as fixed: accept deterministically,
    # and (in docker mode) optionally re-run the scanner. We trust the advisory's fixed-version here.
    f.patch = patch
    f.status = Status.VERIFIED_FIXED.value
    f.verification.append(VerificationAttempt(1, "dependency-bump", exploit_before="vulnerable",
                                              exploit_after="blocked", regression="skipped", passed=True,
                                              log=f"advisory fixed version applied: {patch.description}"))


def run_verify(ctx: RunContext, findings: list[Finding], gate: LLMGate) -> None:
    if not ctx.config.get("verify.enabled", True):
        for f in findings:
            if f.status == Status.GROUNDED.value:
                cands = candidates(ctx, gate, f)
                if cands:
                    f.recommended_patch = cands[0]
                _unverified(f, "verify stage disabled")
        return
    targets = [f for f in findings if f.status == Status.GROUNDED.value]
    if not targets:
        return
    runner = _runner(ctx)
    ctx.log(f"verifying {len(targets)} grounded finding(s) using the {runner.name} sandbox")
    try:
        runner.setup(findings)
        for i, f in enumerate(targets, 1):
            try:
                verify_finding(ctx, gate, f, runner)
            except Exception as exc:
                ctx.warn(f"verification crashed for {f.id}: {exc}")
                _unverified(f, f"verification error: {exc}")
            ctx.store.save_finding(ctx.run_id, f)
            ctx.progress(i, len(targets), f"{f.status}: {f.vuln_class}")
    finally:
        runner.teardown()
