"""Deterministic fix templates for configuration and manifest findings (Streamlit config, requirements)."""

from __future__ import annotations

import re

from ..detect.supply_chain import DIST_TO_MODULE
from .base import FixContext, fixer

MODULE_TO_DIST = {module.lower(): dist for dist, module in DIST_TO_MODULE.items()}


@fixer("config", ["error_leakage"], "Streamlit: show only generic error messages in the browser")
def streamlit_hide_error_details(ctx: FixContext) -> str | None:
    if not ctx.file.endswith("config.toml") or ctx.finding.extra.get("config_key") != "showErrorDetails":
        return None
    line = re.compile(r"(?m)^(\s*)showErrorDetails\s*=.*$")
    if line.search(ctx.text):
        return line.sub(r'\1showErrorDetails = "none"', ctx.text, count=1)
    section = re.compile(r"(?m)^\[client\]\s*$")
    if section.search(ctx.text):
        return section.sub('[client]\nshowErrorDetails = "none"', ctx.text, count=1)
    return ctx.text.rstrip("\n") + '\n\n[client]\nshowErrorDetails = "none"\n'


@fixer("config", ["supply_chain"], "requirements: declare the package the code actually imports")
def requirements_declared_package(ctx: FixContext) -> str | None:
    declared, imported = ctx.finding.extra.get("declared"), ctx.finding.extra.get("imported")
    if not declared or not imported:
        return None
    dist = MODULE_TO_DIST.get(imported.lower(), imported.replace("_", "-"))
    lines = ctx.text.splitlines(True)
    n = ctx.line - 1
    if not 0 <= n < len(lines) or not lines[n].lstrip().lower().startswith(declared.lower()):
        return None
    lines[n] = re.sub(rf"^(\s*){re.escape(declared)}", rf"\g<1>{dist}", lines[n], count=1, flags=re.I)
    ctx.notes.append(f"replaced `{declared}` with `{dist}`; pin it to the version you test with")
    return "".join(lines)
