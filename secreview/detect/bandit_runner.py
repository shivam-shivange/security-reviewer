"""Bandit (Python) as a secondary scanner. Its test ids are mapped onto our classes."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from .. import tools
from ..context import RunContext
from ..models import Evidence, Finding, Status
from ..taxonomy import class_for_cwe
from .common import rel

BANDIT_CLASS = {
    "B608": "sqli", "B610": "sqli", "B611": "sqli",
    "B602": "cmdi", "B604": "cmdi", "B605": "cmdi", "B609": "cmdi",
    "B307": "code_injection", "B102": "code_injection",
    "B301": "deserialization", "B302": "deserialization", "B403": "deserialization", "B506": "deserialization",
    "B501": "tls_validation", "B502": "tls_validation", "B503": "tls_validation", "B504": "tls_validation",
    "B323": "tls_validation",
    "B105": "hardcoded_secret", "B106": "hardcoded_secret", "B107": "hardcoded_secret",
    "B201": "debug_enabled",
    "B303": "weak_crypto", "B304": "weak_crypto", "B305": "weak_crypto", "B324": "weak_crypto",
    "B311": "insecure_random",
    "B310": "ssrf",
    "B313": "xxe", "B314": "xxe", "B315": "xxe", "B316": "xxe", "B317": "xxe", "B318": "xxe",
    "B319": "xxe", "B320": "xxe", "B410": "xxe",
    "B701": "xss", "B702": "xss", "B703": "xss", "B704": "xss",
    "B104": "security_misconfig", "B108": "security_misconfig",
    "B614": "deserialization", "B615": "supply_chain",
}
# Shell / process checks that only matter when the command is built from data.
COMMAND_TESTS = {"B602", "B604", "B605", "B606", "B609"}
PROCESS_CALLS = {"system", "run", "call", "Popen", "check_call", "check_output", "getoutput", "getstatusoutput",
                 "startfile"}
# Low-value checks that only add noise to a security report.
IGNORED = {"B101", "B404", "B603", "B607", "B110", "B112", "B311"}
SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_bandit(ctx: RunContext, targets: list[Path]) -> list[Finding]:
    if not tools.which("bandit"):
        ctx.warn("bandit not installed; skipping")
        return []
    excludes = ",".join(f"*/{e}/*" for e in ctx.config.get("scan.exclude", []) if "*" not in e)
    cmd = ["bandit", "-r", "-f", "json", "-q", "-x", excludes, *[str(t) for t in targets]]
    res = tools.run(cmd, cwd=ctx.project, timeout=1800)
    try:
        data = json.loads(res.stdout or "{}")
    except json.JSONDecodeError:
        ctx.warn(f"bandit produced no JSON: {res.stderr[-300:]}")
        return []
    out = []
    for r in data.get("results", []):
        tid = r.get("test_id", "")
        if tid in IGNORED:
            continue
        cwe = r.get("issue_cwe", {}) or {}
        cwe_id = f"CWE-{cwe['id']}" if cwe.get("id") else ""
        vclass = BANDIT_CLASS.get(tid) or class_for_cwe([cwe_id]) or "general_bug"
        path = rel(ctx.project, r["filename"])
        line = r.get("line_number", 0)
        rng = r.get("line_range") or [line]
        f = Finding(
            rule_id=f"bandit-{tid}-{r.get('test_name', '')}", vuln_class=vclass, title="",
            file=path, line=line, end_line=max(rng), tool="bandit", language="python",
            message=r.get("issue_text", ""), code=_strip_numbers(r.get("code", "")),
            severity=SEV.get(r.get("issue_severity", ""), ""), cwe=[cwe_id] if cwe_id else [],
            extra={"confidence": r.get("issue_confidence", "").lower(), "taint": False},
        )
        if tid in COMMAND_TESTS and _constant_command(ctx.project / path, line):
            # A fixed command string cannot carry attacker input: keep it visible, but as discarded.
            f.status = Status.DISCARDED.value
            f.evidence = Evidence(method="rule-match", summary="Discarded: the command is a constant string "
                                  "literal, so no untrusted input can reach the shell.", confidence=0.9)
        out.append(f)
    return out


def _constant_command(path: Path, line: int) -> bool:
    """True when the process call on `line` takes only string literals (no data can be injected)."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno <= line <= (node.end_lineno or node.lineno) and node.args:
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name not in PROCESS_CALLS and not name.startswith(("spawn", "exec", "popen")):
                continue
            first = node.args[0]
            parts = first.elts if isinstance(first, (ast.List, ast.Tuple)) else [first]
            if parts and all(isinstance(p, ast.Constant) and isinstance(p.value, str) for p in parts):
                return True
    return False


def _strip_numbers(code: str) -> str:
    """Bandit prefixes each code line with its line number."""
    lines = []
    for line in code.splitlines():
        head, _, rest = line.partition(" ")
        lines.append(rest if head.isdigit() else line)
    return "\n".join(lines).strip("\n")
