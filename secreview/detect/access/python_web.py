"""Flask / FastAPI / Django endpoint inventory using Python's `ast`."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ...models import Endpoint
from .markers import HandlerFacts, Markers

FLASK_VERBS = {"get", "post", "put", "patch", "delete"}

PARAM_RE = re.compile(r'''request\.(?:args|form|values|json|GET|POST|data)(?:\.get\(\s*|\[\s*)['"](\w+)['"]''')


def _body_params(body: str) -> list:
    return sorted(set(PARAM_RE.findall(body or "")))


def _const(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _src(node, text: str) -> str:
    return ast.get_source_segment(text, node) or ""


class PythonWebParser:
    def __init__(self, project: Path, files: list[str], markers: Markers):
        self.project = project
        self.files = [f for f in files if f.endswith(".py")]
        self.m = markers
        self.sensitive_models: dict[str, list[str]] = {}
        self.global_rate_limit = False
        self.has_auth = False
        self.trees: dict[str, tuple[ast.AST, str]] = {}
        for rel in self.files:
            try:
                text = (project / rel).read_text(encoding="utf-8", errors="replace")
                self.trees[rel] = (ast.parse(text), text)
            except (SyntaxError, OSError, ValueError):
                continue

    # ------------------------------------------------------------------ helpers
    def _models(self) -> None:
        """SQLAlchemy / Django / Pydantic models with sensitive columns."""
        for rel, (tree, text) in self.trees.items():
            for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
                bases = " ".join(_src(b, text) for b in cls.bases)
                if not re.search(r"(db\.Model|Base|models\.Model|Document|SQLModel|BaseModel|AbstractUser)", bases):
                    continue
                fields = []
                for stmt in cls.body:
                    targets = []
                    if isinstance(stmt, ast.Assign):
                        targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                    elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        targets = [stmt.target.id]
                    fields += [t for t in targets if self.m.sensitive_fields.fullmatch(t)]
                if "AbstractUser" in bases or "AbstractBaseUser" in bases:
                    fields.append("password")
                has_filter = any(isinstance(s, ast.FunctionDef) and s.name in ("to_dict", "serialize", "to_json")
                                 and not re.search(self.m.sensitive_fields.pattern, _src(s, text), re.I)
                                 for s in cls.body)
                if fields and not has_filter:
                    self.sensitive_models[cls.name] = sorted(set(fields))

    def _decorator_names(self, fn, text: str) -> list[str]:
        return [_src(d, text) for d in fn.decorator_list]

    def _facts(self, fn, text: str, path: str) -> HandlerFacts:
        body = _src(fn, text)
        f = HandlerFacts(body_text=body[:4000])
        params = [a.arg for a in fn.args.args]
        f.uses_path_id = bool(re.search(r"<(\w+:)?\w*id\w*>|\{\w*id\w*\}", path)) or any(
            re.search(r"(^|_)id$", p) for p in params)
        f.id_lookup = bool(re.search(r"\.(get_or_404|get|filter_by|filter|first_or_404|find_one|get_object_or_404)\(|"
                                     r"get_object_or_404\(|\.query\.get\(|session\.get\(", body))
        f.owner_check = bool(self.m.owner_check.search(body))
        f.role_check = bool(re.search(r"(is_admin|is_staff|is_superuser|\.role\b|has_perm|has_role|permission)", body))
        f.filters_fields = bool(re.search(r"(schema\.dump|Serializer\(|\.to_dict\(|response_model|exclude|only=|"
                                          r"\{\s*['\"]\w+['\"]\s*:\s*\w+\.\w+)", body))
        models = set()
        for m in re.finditer(r"(\w+)\.(?:query\.(?:get|filter_by|all|first)|objects\.(?:get|filter|all))", body):
            if re.search(r"(jsonify|return|JsonResponse)\s*\(?[^\n]*(__dict__|vars\(|model_to_dict|\bto_dict\(\)\s*$)", body):
                models.add(m.group(1))
        f.returns_models = sorted(models)
        return f

    def _auth_from(self, decorators: list[str], params_src: str, extra: list[str]) -> tuple[bool, list[str], bool]:
        texts = decorators + extra + ([params_src] if params_src else [])
        auth = any(self.m.auth.search(t) or self.m.role.search(t) for t in texts)
        roles = []
        for t in decorators + extra:
            if self.m.role.search(t) and not self.m.auth.search(t.split("(")[0]):
                roles += re.findall(r"""['"]([\w:-]+)['"]""", t) or [t[:40]]
        if re.search(r"Depends\((\w*(admin|role|permission)\w*)", params_src or "", re.I):
            roles.append(re.search(r"Depends\((\w+)", params_src).group(1))
        rate = any(self.m.rate_limit.search(t) for t in texts)
        return auth, sorted(set(roles)), rate

    # ------------------------------------------------------------------ flask + fastapi
    def _blueprints(self) -> dict[str, dict]:
        """Blueprint/APIRouter variable -> {prefix, deps, before_auth}."""
        info: dict[str, dict] = {}
        for rel, (tree, text) in self.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    fn = _src(node.value.func, text)
                    for t in node.targets:
                        if isinstance(t, ast.Name) and re.search(r"(Blueprint|APIRouter|FastAPI|Flask)$", fn):
                            prefix = _const(_kw(node.value, "url_prefix")) or _const(_kw(node.value, "prefix")) or ""
                            deps = _src(_kw(node.value, "dependencies"), text) if _kw(node.value, "dependencies") else ""
                            info[t.id] = {"prefix": prefix, "deps": deps, "before_auth": False, "kind": fn}
                # app.register_blueprint(bp, url_prefix=...) / app.include_router(r, prefix=..., dependencies=...)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                        node.func.attr in ("register_blueprint", "include_router") and node.args:
                    target = node.args[0]
                    name = target.id if isinstance(target, ast.Name) else (
                        target.attr if isinstance(target, ast.Attribute) else None)
                    if name:
                        entry = info.setdefault(name, {"prefix": "", "deps": "", "before_auth": False, "kind": ""})
                        p = _const(_kw(node, "url_prefix")) or _const(_kw(node, "prefix"))
                        if p:
                            entry["prefix"] = p.rstrip("/") + entry["prefix"]
                        if _kw(node, "dependencies") is not None:
                            entry["deps"] += _src(_kw(node, "dependencies"), text)
                # @bp.before_request that enforces auth
                if isinstance(node, ast.FunctionDef):
                    for d in node.decorator_list:
                        ds = _src(d, text)
                        m = re.match(r"(\w+)\.before_(app_)?request$", ds)
                        if m and re.search(r"(abort\(\s*40[13]|current_user|session\.get|verify_jwt|"
                                           r"login_required|is_authenticated|token)", _src(node, text)):
                            info.setdefault(m.group(1), {"prefix": "", "deps": "", "before_auth": False,
                                                         "kind": ""})["before_auth"] = True
                # Flask-Limiter with default_limits / app-wide limiter
                if isinstance(node, ast.Call) and re.search(r"Limiter$", _src(node.func, text)):
                    if _kw(node, "default_limits") is not None or _kw(node, "application_limits") is not None:
                        self.global_rate_limit = True
        return info

    def flask_fastapi(self, eps: list[Endpoint], facts: dict[int, HandlerFacts]) -> None:
        bps = self._blueprints()
        for rel, (tree, text) in self.trees.items():
            for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                decos = self._decorator_names(fn, text)
                for d in fn.decorator_list:
                    if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                            and isinstance(d.func.value, ast.Name)):
                        continue
                    owner, verb = d.func.value.id, d.func.attr
                    if verb not in FLASK_VERBS | {"route", "api_route", "websocket"} or not d.args:
                        continue
                    path = _const(d.args[0])
                    if path is None:
                        continue
                    if verb in ("route", "api_route"):
                        mnode = _kw(d, "methods")
                        methods = [(_const(e) or "GET").upper() for e in mnode.elts] if isinstance(mnode, (ast.List, ast.Tuple)) else ["GET"]
                    else:
                        methods = [verb.upper()]
                    bp = bps.get(owner, {"prefix": "", "deps": "", "before_auth": False, "kind": ""})
                    params_src = ", ".join(_src(a, text) for a in fn.args.args) + " " + " ".join(
                        _src(dflt, text) for dflt in fn.args.defaults)
                    route_deps = _src(_kw(d, "dependencies"), text) if _kw(d, "dependencies") is not None else ""
                    extra = [x for x in (bp["deps"], route_deps) if x]
                    auth, roles, rate = self._auth_from([x for x in decos if x != _src(d, text)], params_src, extra)
                    notes = []
                    if bp.get("before_auth"):
                        auth = True
                        notes.append(f"{owner}.before_request enforces authentication")
                    body = _src(fn, text)
                    if not auth and re.search(r"if\s+not\s+(current_user\.is_authenticated|session\.get\(|g\.user)", body):
                        auth = True
                        notes.append("authentication checked inside the handler")
                    if auth:
                        self.has_auth = True
                    full = (bp["prefix"].rstrip("/") + "/" + path.lstrip("/")) if bp["prefix"] else path
                    for method in methods:
                        idx = len(eps)
                        framework = "fastapi" if "APIRouter" in bp.get("kind", "") or "FastAPI" in bp.get("kind", "") \
                            or verb in FLASK_VERBS and "Depends" in params_src else "flask"
                        eps.append(Endpoint(framework=framework, method=method, path=full, file=rel,
                                            line=fn.lineno, end_line=fn.end_lineno or fn.lineno, handler=fn.name,
                                            handler_file=rel, handler_line=fn.lineno,
                                            handler_end_line=fn.end_lineno or fn.lineno, auth=auth, roles=roles,
                                            auth_evidence=", ".join(x for x in decos + extra if self.m.auth.search(x) or self.m.role.search(x))[:120],
                                            params=_body_params(body) or [a.arg for a in fn.args.args if a.arg not in ("self","cls")], rate_limited=rate,
                                            middlewares=decos, notes=notes))
                        facts[idx] = self._facts(fn, text, full)

    # ------------------------------------------------------------------ django
    def django(self, eps: list[Endpoint], facts: dict[int, HandlerFacts]) -> None:
        default_auth = False
        for rel, (tree, text) in self.trees.items():
            if "settings" in Path(rel).name and re.search(
                    r"DEFAULT_PERMISSION_CLASSES[^\]]*IsAuthenticated", text, re.S):
                default_auth = True
        views: dict[str, tuple[str, ast.AST, str]] = {}
        for rel, (tree, text) in self.trees.items():
            for n in tree.body:
                if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                    views[n.name] = (rel, n, text)
        for rel, (tree, text) in self.trees.items():
            if not rel.endswith("urls.py"):
                continue
            for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
                fname = _src(call.func, text)
                if fname not in ("path", "re_path", "url") or len(call.args) < 2:
                    continue
                route = _const(call.args[0]) or ""
                target = call.args[1]
                tsrc = _src(target, text)
                vname = re.sub(r"\.as_view\(.*", "", tsrc).split(".")[-1]
                if vname not in views:
                    continue
                vrel, vnode, vtext = views[vname]
                decos = [_src(d, vtext) for d in getattr(vnode, "decorator_list", [])]
                extra = []
                methods = ["ANY"]
                if isinstance(vnode, ast.ClassDef):
                    extra += [_src(b, vtext) for b in vnode.bases]
                    for s in vnode.body:
                        if isinstance(s, ast.Assign) and any(isinstance(t, ast.Name) and t.id in (
                                "permission_classes", "authentication_classes") for t in s.targets):
                            extra.append(_src(s, vtext))
                    verbs = [s.name.upper() for s in vnode.body if isinstance(s, ast.FunctionDef)
                             and s.name in ("get", "post", "put", "patch", "delete")]
                    methods = verbs or ["ANY"]
                    if re.search(r"(ModelViewSet|ViewSet)", " ".join(extra)):
                        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
                auth, roles, rate = self._auth_from(decos, "", extra)
                if re.search(r"AllowAny", " ".join(extra)):
                    auth = False
                elif default_auth and not auth:
                    auth = True
                if re.search(r"IsAdminUser|is_staff|PermissionRequiredMixin|permission_required", " ".join(decos + extra)):
                    roles = roles or ["admin"]
                if auth:
                    self.has_auth = True
                full = "/" + route.lstrip("^").rstrip("$").lstrip("/")
                for method in methods:
                    idx = len(eps)
                    eps.append(Endpoint(framework="django", method=method, path=full, file=rel,
                                        line=call.lineno, end_line=call.lineno, handler=vname,
                                        handler_file=vrel, handler_line=vnode.lineno,
                                        handler_end_line=vnode.end_lineno or vnode.lineno, auth=auth, roles=roles,
                                        auth_evidence=", ".join(decos + extra)[:120], rate_limited=rate,
                                        middlewares=decos))
                    facts[idx] = self._facts(vnode, vtext, full) if isinstance(vnode, ast.FunctionDef) else \
                        HandlerFacts(body_text=_src(vnode, vtext)[:4000])

    def endpoints(self) -> tuple[list[Endpoint], dict[int, HandlerFacts]]:
        self._models()
        eps: list[Endpoint] = []
        facts: dict[int, HandlerFacts] = {}
        self.flask_fastapi(eps, facts)
        self.django(eps, facts)
        return eps, facts
