"""Express (Node/MERN) endpoint inventory using tree-sitter.

Handles: express() apps, express.Router(), app.use(prefix, ...middleware, router) mounts across files
(require/import), router.use(middleware) ordering, app.route('/x').get().post() chains, controller
functions defined in other files, and Mongoose/Sequelize models with sensitive fields.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ... import ts
from ...models import Endpoint
from .markers import HandlerFacts, Markers

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "all", "options", "head"}
JS_EXT = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
FUNC_TYPES = ("arrow_function", "function_expression", "function", "function_declaration", "method_definition")


@dataclass
class Event:
    kind: str                 # use | route
    obj: str
    pos: int
    path: str | None = None
    method: str = ""
    mw: list = field(default_factory=list)       # middleware nodes
    handler: object = None
    mount: str | None = None                     # identifier of a mounted router
    line: int = 0


@dataclass
class JSFile:
    path: Path
    rel: str
    root: object
    requires: dict[str, Path] = field(default_factory=dict)     # var -> module file
    destructured: dict[str, tuple[Path, str]] = field(default_factory=dict)  # var -> (file, export name)
    apps: set[str] = field(default_factory=set)
    routers: set[str] = field(default_factory=set)
    exported: str | None = None
    events: list[Event] = field(default_factory=list)
    functions: dict[str, object] = field(default_factory=dict)  # name -> function node


def _resolve(base: Path, spec: str) -> Path | None:
    if not spec.startswith("."):
        return None
    cand = (base.parent / spec).resolve()
    for p in [cand, *[cand.with_name(cand.name + e) for e in JS_EXT], *[cand / f"index{e}" for e in JS_EXT]]:
        if p.is_file():
            return p
    return None


def _call_parts(node):
    """For `a.b(args)` return (object_text, property, args_nodes)."""
    fn = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    if fn is None or args is None or fn.type != "member_expression":
        return None
    obj = fn.child_by_field_name("object")
    prop = fn.child_by_field_name("property")
    return obj, ts.text(prop), [c for c in args.named_children if c.type != "comment"]


class ExpressParser:
    def __init__(self, project: Path, files: list[str], markers: Markers):
        self.project = project
        self.m = markers
        self.files: dict[Path, JSFile] = {}
        for rel in files:
            if not rel.endswith(JS_EXT):
                continue
            p = (project / rel).resolve()
            try:
                root, _ = ts.parse_file(p)
            except Exception:
                continue
            if root is not None:
                self.files[p] = JSFile(p, rel, root)
        self.sensitive_models: dict[str, list[str]] = {}
        self.global_rate_limit = False
        self.has_auth = False

    # ------------------------------------------------------------------ collection
    def collect(self) -> None:
        for jf in self.files.values():
            self._collect_file(jf)

    def _collect_file(self, jf: JSFile) -> None:
        src_text = ts.text(jf.root)
        schemas: dict[str, list[str]] = {}
        schema_filtered: set[str] = set()
        for n in ts.walk(jf.root):
            t = n.type
            if t == "variable_declarator":
                name_node, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                if value is None:
                    continue
                vtext = ts.text(value)
                if name_node is not None and name_node.type == "identifier":
                    name = ts.text(name_node)
                    if re.match(r"^(await\s+)?express\s*\(\s*\)", vtext):
                        jf.apps.add(name)
                    elif re.match(r"^(express\.)?Router\s*\(|^new\s+(express\.)?Router\s*\(", vtext):
                        jf.routers.add(name)
                    m = re.match(r"""^require\(\s*['"]([^'"]+)['"]\s*\)""", vtext)
                    if m and (r := _resolve(jf.path, m.group(1))):
                        jf.requires[name] = r
                    if value.type in FUNC_TYPES:
                        jf.functions[name] = value
                    if re.search(r"new\s+(mongoose\.)?Schema\s*\(", vtext):
                        schemas[name] = self._schema_fields(vtext)
                elif name_node is not None and name_node.type == "object_pattern":
                    m = re.match(r"""^require\(\s*['"]([^'"]+)['"]\s*\)""", vtext)
                    if m and (r := _resolve(jf.path, m.group(1))):
                        for prop in name_node.named_children:
                            key = ts.text(prop).split(":")[0].strip()
                            alias = ts.text(prop).split(":")[-1].strip()
                            jf.destructured[alias] = (r, key)
            elif t == "import_statement":
                srcn = n.child_by_field_name("source")
                spec = ts.string_value(srcn) or ""
                r = _resolve(jf.path, spec)
                if r:
                    for c in ts.walk(n):
                        if c.type == "import_clause":
                            for cc in c.named_children:
                                if cc.type == "identifier":
                                    jf.requires[ts.text(cc)] = r
                        elif c.type == "import_specifier":
                            name = ts.text(c.child_by_field_name("name"))
                            alias = c.child_by_field_name("alias")
                            jf.destructured[ts.text(alias) if alias else name] = (r, name)
            elif t == "function_declaration":
                nm = n.child_by_field_name("name")
                if nm is not None:
                    jf.functions[ts.text(nm)] = n
            elif t == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                ltext = ts.text(left)
                if ltext in ("module.exports", "exports") and right is not None:
                    if right.type == "identifier":
                        jf.exported = ts.text(right)
                    elif right.type == "object":
                        for prop in right.named_children:
                            if prop.type == "pair":
                                key = ts.text(prop.child_by_field_name("key"))
                                val = prop.child_by_field_name("value")
                                if val is not None and val.type in FUNC_TYPES:
                                    jf.functions[key] = val
                                elif val is not None and val.type == "identifier":
                                    jf.functions.setdefault(key, val)
                            elif prop.type == "shorthand_property_identifier":
                                jf.functions.setdefault(ts.text(prop), prop)
                m = re.match(r"^(module\.)?exports\.(\w+)$", ltext)
                if m and right is not None:
                    jf.functions[m.group(2)] = right
                if re.search(r"\.methods\.toJSON|\.set\(\s*['\"]toJSON", ltext):
                    schema_filtered.add(ltext.split(".")[0])
            elif t == "export_statement":
                txt = ts.text(n)
                m = re.match(r"export\s+default\s+(\w+)\s*;?$", txt)
                if m:
                    jf.exported = m.group(1)
            elif t == "call_expression":
                self._collect_call(jf, n)

        # schema-level toJSON transforms / set('toJSON') hide fields
        for name in list(schemas):
            if re.search(rf"{re.escape(name)}\.(set\(\s*['\"]toJSON|methods\.toJSON|options\.toJSON)", src_text):
                schema_filtered.add(name)
        for m in re.finditer(r"""(?:mongoose\.)?model\(\s*['"](\w+)['"]\s*,\s*(\w+)""", src_text):
            model, schema = m.group(1), m.group(2)
            if schema in schemas and schemas[schema] and schema not in schema_filtered:
                self.sensitive_models[model] = schemas[schema]
        for m in re.finditer(r"""\.define\(\s*['"](\w+)['"]\s*,\s*\{(.*?)\}\s*[,)]""", src_text, re.S):
            fields = self._schema_fields("{" + m.group(2) + "}")
            if fields and "defaultScope" not in src_text:
                self.sensitive_models[m.group(1)] = fields

    def _schema_fields(self, schema_text: str) -> list[str]:
        fields = []
        for m in re.finditer(r"(\w+)\s*:\s*(\{[^{}]*\}|[\w.\[\]]+)", schema_text):
            name, spec = m.group(1), m.group(2)
            if self.m.sensitive_fields.fullmatch(name) and "select: false" not in spec.replace("select:false", "select: false"):
                fields.append(name)
        return sorted(set(fields))

    def _collect_call(self, jf: JSFile, node) -> None:
        parts = _call_parts(node)
        if not parts:
            return
        obj, prop, args = parts
        prop_l = prop.lower()
        # app.route('/x').get(...).post(...)
        route_path = None
        base_obj = obj
        while base_obj is not None and base_obj.type == "call_expression":
            inner = _call_parts(base_obj)
            if not inner:
                break
            iobj, iprop, iargs = inner
            if iprop == "route" and iargs:
                route_path = ts.string_value(iargs[0])
                base_obj = iobj
                break
            base_obj = iobj
        if base_obj is None or base_obj.type != "identifier":
            return
        objname = ts.text(base_obj)
        pos = node.start_byte
        if prop_l in HTTP_METHODS and (route_path is not None or (args and ts.string_value(args[0]) is not None)):
            if route_path is None:
                path, rest = ts.string_value(args[0]), args[1:]
            else:
                path, rest = route_path, args
            if not rest:
                return
            jf.events.append(Event("route", objname, pos, path=path, method=prop.upper(),
                                   mw=rest[:-1], handler=rest[-1], line=ts.line(node)))
        elif prop_l == "use" and args:
            path = ts.string_value(args[0])
            rest = args[1:] if path is not None else args
            mount = None
            mws = []
            for a in rest:
                if a.type == "identifier" and (ts.text(a) in jf.routers or ts.text(a) in jf.requires):
                    mount = ts.text(a)
                elif a.type == "call_expression" and re.match(r"^require\(", ts.text(a)):
                    spec = re.search(r"""['"]([^'"]+)['"]""", ts.text(a))
                    r = _resolve(jf.path, spec.group(1)) if spec else None
                    if r:
                        alias = f"__req_{pos}"
                        jf.requires[alias] = r
                        mount = alias
                else:
                    mws.append(a)
            for a in mws:
                if self.m.rate_limit.search(ts.text(a)):
                    self.global_rate_limit = True
            jf.events.append(Event("use", objname, pos, path=path, mw=mws, mount=mount, line=ts.line(node)))

    # ------------------------------------------------------------------ resolution
    def _router_target(self, jf: JSFile, ident: str) -> tuple[JSFile, str] | None:
        if ident in jf.routers or ident in jf.apps:
            return jf, ident
        if ident in jf.requires:
            target = self.files.get(jf.requires[ident])
            if target and target.exported:
                return target, target.exported
            if target and target.routers:
                return target, next(iter(target.routers))
        return None

    def _resolve_function(self, jf: JSFile, node):
        """Find the function node behind a handler reference (identifier or ctrl.fn)."""
        if node is None:
            return None, jf
        if node.type in FUNC_TYPES:
            return node, jf
        t = ts.text(node)
        if node.type == "identifier":
            if t in jf.functions and jf.functions[t].type in FUNC_TYPES:
                return jf.functions[t], jf
            if t in jf.destructured:
                f, name = jf.destructured[t]
                other = self.files.get(f)
                if other and name in other.functions:
                    return self._resolve_function(other, other.functions[name])
        if node.type == "member_expression":
            obj = ts.text(node.child_by_field_name("object"))
            prop = ts.text(node.child_by_field_name("property"))
            if obj in jf.requires:
                other = self.files.get(jf.requires[obj])
                if other and prop in other.functions:
                    return self._resolve_function(other, other.functions[prop])
        if node.type == "call_expression":   # asyncHandler(fn) / catchAsync(async (req,res)=>...)
            args = node.child_by_field_name("arguments")
            if args is not None and args.named_children:
                return self._resolve_function(jf, args.named_children[-1])
        return None, jf

    def endpoints(self) -> tuple[list[Endpoint], dict[int, HandlerFacts]]:
        self.collect()
        eps: list[Endpoint] = []
        facts: dict[int, HandlerFacts] = {}
        visited_routers: set[tuple[Path, str]] = set()

        def emit(jf: JSFile, obj: str, prefix: str, inherited: list[str], depth: int) -> None:
            if depth > 12 or (jf.path, obj, prefix) in seen:
                return
            seen.add((jf.path, obj, prefix))
            visited_routers.add((jf.path, obj))
            scoped: list[tuple[str | None, list[str]]] = []   # (path prefix or None, middleware texts)
            for ev in sorted((e for e in jf.events if e.obj == obj), key=lambda e: e.pos):
                if ev.kind == "use":
                    mw_texts = [ts.text(x) for x in ev.mw]
                    if ev.mount:
                        tgt = self._router_target(jf, ev.mount)
                        if tgt:
                            active = inherited + [t for p, ms in scoped if p is None or (ev.path or "").startswith(p) for t in ms]
                            emit(tgt[0], tgt[1], _join(prefix, ev.path or ""), active + mw_texts, depth + 1)
                    elif mw_texts:
                        scoped.append((ev.path, mw_texts))
                else:
                    full = _join(prefix, ev.path or "")
                    active = inherited + [t for p, ms in scoped
                                          if p is None or (ev.path or "").startswith(p) for t in ms]
                    eps.append(self._endpoint(jf, ev, full, active, facts, len(eps)))

        seen: set = set()
        for jf in self.files.values():
            for app in jf.apps:
                emit(jf, app, "", [], 0)
        # routers that are never mounted (or mounted from unparsed code): list them standalone
        for jf in self.files.values():
            for r in list(jf.routers) + ([jf.exported] if jf.exported and jf.exported not in jf.apps else []):
                if r and (jf.path, r) not in visited_routers and any(e.obj == r for e in jf.events):
                    emit(jf, r, "", [], 0)
        return eps, facts

    def _endpoint(self, jf: JSFile, ev: Event, full_path: str, inherited: list[str],
                  facts: dict[int, HandlerFacts], idx: int) -> Endpoint:
        route_mw = [ts.text(x) for x in ev.mw]
        mws = inherited + route_mw
        fn, fn_file = self._resolve_function(jf, ev.handler)
        body = ts.text(fn) if fn is not None else ts.text(ev.handler)
        auth = any(self.m.auth.search(x) or self.m.role.search(x) for x in mws)
        notes = []
        if not auth and re.search(r"if\s*\(\s*!\s*req\.(user|session\.user|isAuthenticated\(\))", body):
            auth = True
            notes.append("authentication checked inside the handler")
        roles = []
        for x in mws:
            if self.m.role.search(x) and not self.m.auth.fullmatch(x.strip()):
                lits = re.findall(r"""['"]([\w:-]+)['"]""", x)
                roles += lits or [x[:40]]
        if auth:
            self.has_auth = True
        f = HandlerFacts(body_text=body[:4000])
        f.uses_path_id = bool(re.search(r"req\.params\.\w+|\{\s*[\w\s,]*\}\s*=\s*req\.params|req\.params\[", body))
        f.id_lookup = bool(re.search(r"\.(findById\w*|findOne\w*|findByPk|deleteOne|updateOne|findOneAndUpdate|"
                                     r"findOneAndDelete|destroy|update)\s*\(", body))
        f.owner_check = bool(self.m.owner_check.search(body))
        f.role_check = bool(re.search(r"req\.user\.(role|roles|isAdmin|is_admin|permissions)", body))
        f.filters_fields = bool(re.search(r"\.select\(\s*['\"`][^'\"`]*-|\.select\(\s*\{|\bdelete\s+\w+\.(password|hash)|"
                                          r"\.password\s*=\s*undefined|\bomit\(|\bpick\(|toJSON|attributes\s*:\s*\{\s*exclude|"
                                          r"\.select\(\s*['\"`][\w\s]+['\"`]", body))
        models = set()
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*await\s+(\w+)\.(find\w*|findAll|findByPk)\(", body):
            if re.search(rf"res\.(?:status\(\d+\)\.)?(?:json|send)\(\s*(?:\{{[^}}]*\b)?{m.group(1)}\b", body):
                models.add(m.group(2))
        for m in re.finditer(r"res\.(?:status\(\d+\)\.)?(?:json|send)\(\s*await\s+(\w+)\.(find\w*|findAll)\(", body):
            models.add(m.group(1))
        f.returns_models = sorted(models)
        params = sorted(set(re.findall(r"req\.(?:query|body|params)\.(\w+)", body)))
        ep = Endpoint(framework="express", method="ANY" if ev.method == "ALL" else ev.method,
                      path=full_path or "/", file=jf.rel, line=ev.line,
                      end_line=ts.end_line(fn) if fn is not None and fn_file is jf else ev.line,
                      handler=(ts.text(ev.handler)[:60] if ev.handler is not None and ev.handler.type not in FUNC_TYPES
                               else "inline handler"),
                      auth=auth, roles=sorted(set(roles)), auth_evidence=", ".join(x[:40] for x in mws if self.m.auth.search(x) or self.m.role.search(x)),
                      params=params, rate_limited=any(self.m.rate_limit.search(x) for x in mws),
                      middlewares=[x[:60] for x in mws], notes=notes)
        if fn is not None:
            ep.handler_file, ep.handler_line, ep.handler_end_line = fn_file.rel, ts.line(fn), ts.end_line(fn)
            if fn_file is not jf:
                ep.notes.append(f"handler defined in {fn_file.rel}:{ts.line(fn)}")
        facts[idx] = f
        return ep


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path or path == "/":
        return prefix
    return prefix.rstrip("/") + "/" + path.lstrip("/")
