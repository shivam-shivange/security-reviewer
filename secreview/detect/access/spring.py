"""Spring MVC / Spring Boot endpoint inventory using tree-sitter (Java).

Combines controller annotations (@RequestMapping/@GetMapping..., @PreAuthorize/@Secured/@RolesAllowed)
with Spring Security filter-chain rules (requestMatchers(...).permitAll()/authenticated()/hasRole()).
"""

from __future__ import annotations

import re
from pathlib import Path

from ... import ts
from ...models import Endpoint
from .markers import HandlerFacts, Markers

MAPPINGS = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE",
            "PatchMapping": "PATCH", "RequestMapping": "ANY"}


def _annotations(modifiers) -> list:
    if modifiers is None:
        return []
    return [c for c in modifiers.children if c.type in ("annotation", "marker_annotation")]


def _ann_name(a) -> str:
    return ts.text(a.child_by_field_name("name"))


def _ann_paths(a) -> list[str]:
    args = a.child_by_field_name("arguments")
    if args is None:
        return [""]
    paths = []
    for n in ts.walk(args):
        if n.type == "element_value_pair":
            key = ts.text(n.child_by_field_name("key"))
            if key not in ("value", "path"):
                continue
            paths += [ts.text(s)[1:-1] for s in ts.walk(n.child_by_field_name("value")) if s.type == "string_literal"]
    if not paths:
        direct = [c for c in args.named_children if c.type in ("string_literal", "element_value_array_initializer")]
        for d in direct:
            paths += [ts.text(s)[1:-1] for s in ts.walk(d) if s.type == "string_literal"]
    return paths or [""]


def _ann_methods(a) -> list[str]:
    return re.findall(r"RequestMethod\.(\w+)", ts.text(a)) or ["ANY"]


def _ant_to_regex(pattern: str) -> re.Pattern:
    rx = re.escape(pattern).replace(r"/\*\*", "(/.*)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    rx = re.sub(r"\\\{[^}]+\\\}", "[^/]+", rx)
    return re.compile("^" + rx + "$")


class SpringParser:
    def __init__(self, project: Path, files: list[str], markers: Markers, security_starter: bool):
        self.project = project
        self.files = [f for f in files if f.endswith(".java")]
        self.m = markers
        self.security_starter = security_starter
        self.sensitive_models: dict[str, list[str]] = {}
        self.global_rate_limit = False
        self.has_auth = False
        self.rules: list[tuple[list[re.Pattern], str, list[str], str]] = []   # patterns, kind, roles, method
        self.has_security_config = False

    def _parse_all(self):
        out = []
        for rel in self.files:
            try:
                root, _ = ts.parse_file(self.project / rel)
            except Exception:
                continue
            if root is not None:
                out.append((rel, root))
        return out

    def _security_rules(self, rel: str, root) -> None:
        src = ts.text(root)
        if not re.search(r"SecurityFilterChain|WebSecurityConfigurerAdapter|authorizeHttpRequests|authorizeRequests", src):
            return
        self.has_security_config = True
        self.has_auth = True
        chain = re.compile(
            r"\.(?:requestMatchers|antMatchers|mvcMatchers|regexMatchers)\(\s*(?:HttpMethod\.(\w+)\s*,\s*)?([^)]*)\)\s*"
            r"\.(permitAll|authenticated|denyAll|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|fullyAuthenticated|"
            r"access)\(([^)]*)\)", re.S)
        for m in chain.finditer(src):
            method, pats, kind, args = m.group(1) or "", m.group(2), m.group(3), m.group(4)
            patterns = [_ant_to_regex(p) for p in re.findall(r'"([^"]+)"', pats)]
            roles = re.findall(r'"([^"]+)"', args)
            if patterns:
                self.rules.append((patterns, kind, roles, method.upper()))
        anyreq = re.search(r"\.anyRequest\(\)\s*\.(permitAll|authenticated|denyAll|hasRole|hasAnyRole|"
                           r"hasAuthority|fullyAuthenticated)\(([^)]*)\)", src)
        if anyreq:
            self.rules.append(([re.compile(".*")], anyreq.group(1), re.findall(r'"([^"]+)"', anyreq.group(2)), ""))
        if re.search(r"(Bucket4j|RateLimiter|@RateLimiter|bucket4j)", src):
            self.global_rate_limit = True

    def _entities(self, rel: str, root) -> None:
        for cls in [n for n in ts.walk(root) if n.type == "class_declaration"]:
            mods = next((c for c in cls.children if c.type == "modifiers"), None)
            anns = [_ann_name(a) for a in _annotations(mods)]
            if not {"Entity", "Document", "Table"} & set(anns):
                continue
            body = cls.child_by_field_name("body")
            fields = []
            for fd in [c for c in body.named_children if c.type == "field_declaration"]:
                fmods = next((c for c in fd.children if c.type == "modifiers"), None)
                fanns = " ".join(ts.text(a) for a in _annotations(fmods))
                name_nodes = [d.child_by_field_name("name") for d in fd.named_children if d.type == "variable_declarator"]
                for nn in name_nodes:
                    name = ts.text(nn)
                    if self.m.sensitive_fields.fullmatch(name) and not re.search(
                            r"JsonIgnore|WRITE_ONLY|Transient", fanns):
                        fields.append(name)
            if fields:
                self.sensitive_models[ts.text(cls.child_by_field_name("name"))] = fields

    def _rule_for(self, path: str, method: str):
        for patterns, kind, roles, rmethod in self.rules:
            if rmethod and method not in (rmethod, "ANY"):
                continue
            if any(p.match(path) for p in patterns):
                return kind, roles
        return None

    def endpoints(self) -> tuple[list[Endpoint], dict[int, HandlerFacts]]:
        parsed = self._parse_all()
        for rel, root in parsed:
            self._security_rules(rel, root)
            self._entities(rel, root)
        eps: list[Endpoint] = []
        facts: dict[int, HandlerFacts] = {}
        for rel, root in parsed:
            for cls in [n for n in ts.walk(root) if n.type == "class_declaration"]:
                mods = next((c for c in cls.children if c.type == "modifiers"), None)
                canns = _annotations(mods)
                cnames = [_ann_name(a) for a in canns]
                if not {"RestController", "Controller"} & set(cnames):
                    continue
                prefixes = [""]
                class_auth_anns = []
                for a in canns:
                    if _ann_name(a) == "RequestMapping":
                        prefixes = _ann_paths(a)
                    if _ann_name(a) in ("PreAuthorize", "Secured", "RolesAllowed"):
                        class_auth_anns.append(ts.text(a))
                body = cls.child_by_field_name("body")
                for meth in [c for c in body.named_children if c.type == "method_declaration"]:
                    mmods = next((c for c in meth.children if c.type == "modifiers"), None)
                    manns = _annotations(mmods)
                    mapping = next((a for a in manns if _ann_name(a) in MAPPINGS), None)
                    if mapping is None:
                        continue
                    verbs = [MAPPINGS[_ann_name(mapping)]] if _ann_name(mapping) != "RequestMapping" else _ann_methods(mapping)
                    auth_anns = class_auth_anns + [ts.text(a) for a in manns
                                                   if _ann_name(a) in ("PreAuthorize", "Secured", "RolesAllowed")]
                    params_text = ts.text(meth.child_by_field_name("parameters"))
                    method_text = ts.text(meth)
                    for prefix in prefixes:
                        for sub in _ann_paths(mapping):
                            full = "/" + "/".join(x.strip("/") for x in (prefix, sub) if x.strip("/"))
                            for verb in verbs:
                                eps.append(self._endpoint(rel, meth, full, verb, auth_anns, params_text,
                                                          method_text, facts, len(eps)))
        return eps, facts

    def _endpoint(self, rel, meth, path, verb, auth_anns, params_text, method_text, facts, idx) -> Endpoint:
        roles: list[str] = []
        auth = False
        notes = []
        for a in auth_anns:
            if re.search(r"permitAll", a):
                continue
            auth = True
            roles += re.findall(r"""(?:hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\(\s*['"]([^'"]+)['"]""", a)
            roles += re.findall(r'"(ROLE_\w+|\w+)"', a) if re.match(r"@(Secured|RolesAllowed)", a) else []
            if not roles and re.search(r"isAuthenticated|authenticated", a):
                pass
        rule = self._rule_for(path, verb)
        if rule:
            kind, rroles = rule
            if kind in ("authenticated", "fullyAuthenticated", "denyAll"):
                auth = True
                notes.append(f"security rule: {kind}")
            elif kind in ("hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority", "access"):
                auth = True
                roles += rroles
                notes.append(f"security rule: {kind}({', '.join(rroles)})")
            elif kind == "permitAll" and not auth_anns:
                auth = False
                notes.append("security rule: permitAll")
        elif self.security_starter and not self.has_security_config:
            auth = True
            notes.append("spring-boot-starter-security default: all requests authenticated")
        if re.search(r"@AuthenticationPrincipal|\bPrincipal\b|\bAuthentication\b", params_text):
            auth = True
        if auth:
            self.has_auth = True
        f = HandlerFacts(body_text=method_text[:4000])
        f.uses_path_id = bool(re.search(r"@PathVariable[^,)]*\b\w*[iI]d\b", params_text)) or "{id}" in path
        f.id_lookup = bool(re.search(r"\.(findById|getById|getOne|getReferenceById|findOne|deleteById|existsById)\(", method_text))
        f.owner_check = bool(self.m.owner_check.search(method_text)) or "#" in " ".join(auth_anns)
        f.role_check = bool(re.search(r"(hasRole|isUserInRole|getAuthorities)", method_text))
        rtype = ts.text(meth.child_by_field_name("type"))
        f.returns_models = sorted({m for m in self.sensitive_models if re.search(rf"\b{m}\b", rtype)})
        f.filters_fields = bool(re.search(r"(Dto|DTO|Response|View)\b", rtype))
        facts[idx] = f
        return Endpoint(framework="spring", method=verb, path=path, file=rel, line=ts.line(meth),
                        end_line=ts.end_line(meth), handler=ts.text(meth.child_by_field_name("name")),
                        handler_file=rel, handler_line=ts.line(meth), handler_end_line=ts.end_line(meth),
                        auth=auth, roles=sorted(set(roles)), auth_evidence="; ".join(auth_anns + notes)[:160],
                        params=re.findall(r"@(?:PathVariable|RequestParam|RequestBody)[^,)]*?\s(\w+)\s*(?:,|$)", params_text),
                        rate_limited=bool(re.search(r"RateLimiter|Bucket", method_text)), notes=notes)
