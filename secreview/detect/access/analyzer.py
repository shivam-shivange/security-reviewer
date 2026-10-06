from __future__ import annotations

from ...context import RunContext
from ...discovery import ProjectInfo, is_test_file
from ...models import Endpoint, Finding
from .express import ExpressParser
from .markers import load_markers
from .python_web import PythonWebParser
from .rules import evaluate
from .spring import SpringParser


def _security_starter(ctx: RunContext, info: ProjectInfo) -> bool:
    for m in info.modules:
        if m.language == "java" and m.manifest:
            try:
                if "spring-boot-starter-security" in (ctx.project / m.manifest).read_text(encoding="utf-8", errors="ignore"):
                    return True
            except OSError:
                pass
    return False


def analyze_access(ctx: RunContext, info: ProjectInfo) -> tuple[list[Endpoint], list[Finding]]:
    markers = load_markers()
    include_tests = ctx.config.get("scan.include_tests", False)

    def files(lang: str) -> list[str]:
        return [f for f in info.files.get(lang, []) if include_tests or not is_test_file(f)]

    all_eps: list[Endpoint] = []
    findings: list[Finding] = []
    parsers = []
    if files("javascript"):
        parsers.append(ExpressParser(ctx.project, files("javascript"), markers))
    if files("python"):
        parsers.append(PythonWebParser(ctx.project, files("python"), markers))
    if files("java"):
        parsers.append(SpringParser(ctx.project, files("java"), markers, _security_starter(ctx, info)))

    for parser in parsers:
        try:
            eps, facts = parser.endpoints()
        except Exception as exc:  # a parser bug must not kill the whole scan
            ctx.warn(f"{type(parser).__name__} failed: {exc}")
            continue
        for ep in eps:
            mod = info.module_for(ep.file)
            ep.module = mod.path if mod else "."
        ctx.log(f"{type(parser).__name__}: {len(eps)} endpoints, "
                f"{len(parser.sensitive_models)} models with sensitive fields")
        findings += evaluate(eps, facts, markers, parser.sensitive_models, parser.global_rate_limit, parser.has_auth)
        all_eps += eps
    for f in findings:
        mod = info.module_for(f.file)
        f.module = mod.path if mod else "."
        f.language = mod.language if mod else ""
    return all_eps, findings
