"""Deterministic access-control / leakage rules evaluated over the endpoint inventory."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict

from ...models import Endpoint, Finding, Status
from .markers import HandlerFacts, Markers

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def _resource_key(path: str) -> str:
    """/api/users/:id, /api/users/{id}, /api/users/<int:id> -> /api/users/{}"""
    p = re.sub(r"(:\w+|\{[^}]+\}|<[^>]+>)", "{}", path.rstrip("/") or "/")
    return p.lower()


def _finding(ep: Endpoint, vclass: str, rule: str, message: str, severity: str = "") -> Finding:
    return Finding(rule_id=rule, vuln_class=vclass, title="", file=ep.file, line=ep.line,
                   end_line=ep.end_line or ep.line, tool="access-analyzer", language="",
                   module=ep.module, message=message, code=f"{ep.method} {ep.path}  ->  {ep.handler}",
                   severity=severity, status=Status.NEEDS_REVIEW.value, endpoint=asdict(ep),
                   extra={"confidence": "medium", "taint": False, "heuristic": True})


def evaluate(endpoints: list[Endpoint], facts: dict[int, HandlerFacts], m: Markers,
             sensitive_models: dict[str, list[str]], global_rate_limit: bool,
             project_has_auth: bool) -> list[Finding]:
    out: list[Finding] = []

    for idx, ep in enumerate(endpoints):
        f = facts.get(idx, HandlerFacts())
        path = ep.path or "/"
        public = bool(m.public.search(path))
        sensitive = bool(m.sensitive.search(path))
        privileged = bool(m.privileged.search(path))

        # 1. unauthenticated sensitive / state-changing endpoint
        if not ep.auth and not public and (ep.method in STATE_CHANGING or sensitive or ep.method == "ANY"):
            sev = "critical" if privileged or ep.method == "DELETE" else "high" if (sensitive or ep.method in STATE_CHANGING) else "medium"
            why = "no authentication middleware/decorator/security rule protects this route"
            if not project_has_auth:
                why += " (no authentication mechanism was found anywhere in this module)"
            out.append(_finding(ep, "open_endpoint", "access-open-endpoint",
                                f"{ep.method} {path} is reachable without authentication: {why}.", sev))

        # 2. privileged path without any role check
        if privileged and not ep.roles and not f.role_check and not public:
            out.append(_finding(ep, "missing_role_check", "access-missing-role-check",
                                f"{ep.method} {path} looks privileged but no role/permission check was found "
                                f"(authenticated={ep.auth}).", "high"))

        # 3. IDOR / BOLA
        if f.uses_path_id and f.id_lookup and not f.owner_check and not ep.roles and not f.role_check:
            out.append(_finding(ep, "idor", "access-idor",
                                f"{ep.method} {path} loads an object by a client-supplied id without checking "
                                f"that it belongs to the current user.", "high"))

        # 4. login / credential endpoints without rate limiting
        if ep.method in ("POST", "ANY") and m.login.search(path) and not ep.rate_limited and not global_rate_limit:
            out.append(_finding(ep, "rate_limiting", "access-no-rate-limit",
                                f"{ep.method} {path} handles credentials but has no rate limiting / lockout.",
                                "medium"))

        # 5. sensitive model returned without field filtering
        if f.returns_models and not f.filters_fields:
            leaked = {mdl: sensitive_models[mdl] for mdl in f.returns_models if mdl in sensitive_models}
            if leaked:
                desc = "; ".join(f"{k} ({', '.join(v)})" for k, v in leaked.items())
                out.append(_finding(ep, "sensitive_data_exposure", "access-data-exposure",
                                    f"{ep.method} {path} returns model objects with sensitive fields: {desc}.",
                                    "high"))

    # 6. inconsistent protection on the same resource
    groups: dict[str, list[int]] = defaultdict(list)
    for idx, ep in enumerate(endpoints):
        groups[_resource_key(ep.path)].append(idx)
    for key, idxs in groups.items():
        eps = [endpoints[i] for i in idxs]
        protected = [e for e in eps if e.auth]
        role_protected = [e for e in eps if e.roles]
        for e in eps:
            if protected and not e.auth and e.method in STATE_CHANGING:
                ref = protected[0]
                out.append(_finding(e, "inconsistent_authz", "access-inconsistent-auth",
                                    f"{e.method} {e.path} has no authentication while {ref.method} {ref.path} on the "
                                    f"same resource requires it.", "high"))
            elif role_protected and e.auth and not e.roles and e.method in STATE_CHANGING \
                    and not facts.get(endpoints.index(e), HandlerFacts()).role_check:
                ref = role_protected[0]
                out.append(_finding(e, "inconsistent_authz", "access-inconsistent-role",
                                    f"{e.method} {e.path} only requires login while {ref.method} {ref.path} requires "
                                    f"role(s) {', '.join(ref.roles)}.", "high"))
    return out
