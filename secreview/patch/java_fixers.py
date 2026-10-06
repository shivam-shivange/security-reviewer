"""Deterministic Java fix templates (tree-sitter based)."""

from __future__ import annotations

import re

from .. import ts
from .base import FixContext, fixer, flatten_concat_js_java, java_add_helper, java_package, placeholders_from_parts
from .js_fixers import Src


def invocations(s: Src, line: int, names: tuple[str, ...]) -> list:
    out = [n for n in ts.walk(s.root) if n.type == "method_invocation" and ts.line(n) <= line <= ts.end_line(n)
           and ts.text(n.child_by_field_name("name")) in names]
    return sorted(out, key=lambda n: n.end_byte - n.start_byte)


def creations(s: Src, line: int, types: tuple[str, ...]) -> list:
    out = [n for n in ts.walk(s.root) if n.type == "object_creation_expression" and ts.line(n) <= line <= ts.end_line(n)
           and ts.text(n.child_by_field_name("type")).split(".")[-1] in types]
    return sorted(out, key=lambda n: n.end_byte - n.start_byte)


def jargs(n) -> list:
    a = n.child_by_field_name("arguments")
    return list(a.named_children) if a is not None else []


def enclosing_method(s: Src, node):
    p = node.parent
    while p is not None and p.type not in ("method_declaration", "constructor_declaration"):
        p = p.parent
    return p


def local_string_init(s: Src, method, name: str, before_byte: int):
    """`String name = <expr>;` declared in the method before `before_byte`."""
    best = None
    for n in ts.walk(method):
        if n.type == "variable_declarator" and ts.text(n.child_by_field_name("name")) == name and n.start_byte < before_byte:
            best = n
    return best.child_by_field_name("value") if best is not None else None


def java_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


# ------------------------------------------------------------------ SQL injection
@fixer("java", ["sqli"], "Bind parameters (PreparedStatement / JdbcTemplate args / JPA setParameter)")
def java_sqli(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = invocations(s, ctx.line, ("query", "queryForObject", "queryForList", "queryForMap", "update",
                                      "executeQuery", "executeUpdate", "execute", "createQuery", "createNativeQuery",
                                      "prepareStatement"))
    if not calls:
        return None
    call = calls[0]
    name = ts.text(call.child_by_field_name("name"))
    args = jargs(call)
    if not args:
        return None
    qnode = args[0]
    decl_value = None
    if qnode.type == "identifier":
        method = enclosing_method(s, call)
        decl_value = local_string_init(s, method, ts.text(qnode), call.start_byte) if method is not None else None
        if decl_value is None:
            return None
        parts = flatten_concat_js_java(decl_value, "java")
    else:
        parts = flatten_concat_js_java(qnode, "java")
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    jpa = name in ("createQuery", "createNativeQuery")
    sql, params = placeholders_from_parts(list(parts), (lambda i: f":p{i}") if name == "createQuery" else (lambda i: "?"))
    target = decl_value if decl_value is not None else qnode

    if jpa:
        s.replace(target, java_str(sql))
        keys = [f'"p{i}"' if name == "createQuery" else str(i) for i in range(1, len(params) + 1)]
        chain = "".join(f".setParameter({k}, {p})" for k, p in zip(keys, params))
        s.insert(call.end_byte, chain)
    elif name in ("query", "queryForObject", "queryForList", "queryForMap", "update"):
        s.replace(target, java_str(sql))
        s.insert(call.child_by_field_name("arguments").end_byte - 1, ", " + ", ".join(params))
    else:
        # java.sql.Statement: switch to PreparedStatement
        obj = call.child_by_field_name("object")
        if obj is None or obj.type != "identifier":
            return None
        stmt_var = ts.text(obj)
        method = enclosing_method(s, call)
        decl = next((n for n in ts.walk(method) if n.type == "local_variable_declaration"
                     and re.search(rf"\b{re.escape(stmt_var)}\s*=\s*(\w+)\.createStatement\(\s*\)", ts.text(n))), None)
        if decl is None:
            return None
        conn = re.search(rf"\b{re.escape(stmt_var)}\s*=\s*(\w+)\.createStatement", ts.text(decl)).group(1)
        indent = re.match(r"\s*", ctx.text.encode("utf-8")[:decl.start_byte].decode("utf-8").splitlines()[-1]).group(0)
        if decl_value is not None:
            return None   # query built in a separate String variable: too ambiguous to rewrite safely
        setters = "".join(f"\n{indent}{stmt_var}.setString({i}, String.valueOf({p}));" for i, p in enumerate(params, 1))
        s.replace(decl, f"java.sql.PreparedStatement {stmt_var} = {conn}.prepareStatement({java_str(sql)});{setters}")
        s.replace(call.child_by_field_name("arguments"), "()")
    ctx.notes.append(f"query parameterised ({len(params)} bound value(s))")
    return s.result()


# ------------------------------------------------------------------ command injection
@fixer("java", ["cmdi"], "Runtime.exec(String) -> ProcessBuilder with separate arguments (no shell parsing)")
def java_cmdi(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = invocations(s, ctx.line, ("exec",))
    if not calls or not jargs(calls[0]):
        return None
    call = calls[0]
    parts = flatten_concat_js_java(jargs(call)[0], "java")
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    lits = "".join(v for k, v in parts if k == "lit")
    if re.search(r"\b(sh|bash|cmd(\.exe)?)\s+(-c|/c)\b", lits):
        return None
    tokens: list[list[tuple[str, str]]] = [[]]
    for kind, val in parts:
        if kind == "expr":
            tokens[-1].append((kind, val))
            continue
        for ch in re.split(r"(\s+)", val):
            if not ch:
                continue
            if ch.isspace():
                if tokens[-1]:
                    tokens.append([])
            else:
                tokens[-1].append(("lit", ch.strip("'\"")))
    toks = [" + ".join(java_str(v) if k == "lit" else f"String.valueOf({v})" for k, v in t) for t in tokens if t]
    s.replace(call, f"new ProcessBuilder({', '.join(toks)}).start()")
    ctx.notes.append("command run through ProcessBuilder with separate arguments")
    return s.result()


# ------------------------------------------------------------------ path traversal
@fixer("java", ["path_traversal"], "Canonicalise the path and refuse anything outside the base directory")
def java_path(ctx: FixContext) -> str | None:
    s = Src(ctx)
    news = creations(s, ctx.line, ("File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
                                   "FileSystemResource"))
    gets = invocations(s, ctx.line, ("get", "of", "resolve"))
    if news and len(jargs(news[0])) == 2 and ts.text(news[0].child_by_field_name("type")).endswith("File"):
        a, b = jargs(news[0])
        s.replace(news[0], f"secreviewSafeFile(String.valueOf({ts.text(a)}), {ts.text(b)})")
    elif news and len(jargs(news[0])) == 1 and jargs(news[0])[0].type == "binary_expression":
        arg = jargs(news[0])[0]
        left, right = arg.child_by_field_name("left"), arg.child_by_field_name("right")
        s.replace(arg, f"secreviewSafeFile(String.valueOf({ts.text(left)}), {ts.text(right)})")
    elif gets and ts.text(gets[0].child_by_field_name("object")) in ("Paths", "Path") and len(jargs(gets[0])) >= 2:
        a = jargs(gets[0])
        rest = " + \"/\" + ".join(ts.text(x) for x in a[1:])
        s.replace(gets[0], f"secreviewSafeFile(String.valueOf({ts.text(a[0])}), {rest}).toPath()")
    elif gets and ts.text(gets[0].child_by_field_name("name")) == "resolve" and jargs(gets[0]):
        obj = gets[0].child_by_field_name("object")
        s.replace(gets[0], f"secreviewSafeFile(String.valueOf({ts.text(obj)}), {ts.text(jargs(gets[0])[0])}).toPath()")
    else:
        return None
    out = s.result()
    return java_add_helper(out, "safe_file") if out else None


# ------------------------------------------------------------------ SSRF / redirect / XSS
@fixer("java", ["ssrf"], "Validate outbound URLs (scheme + no internal addresses)")
def java_ssrf(ctx: FixContext) -> str | None:
    s = Src(ctx)
    target = None
    news = creations(s, ctx.line, ("URL", "URI", "HttpGet", "HttpPost"))
    if news and jargs(news[0]):
        target = jargs(news[0])[0]
    else:
        calls = invocations(s, ctx.line, ("getForObject", "getForEntity", "postForObject", "postForEntity", "exchange",
                                          "create", "uri", "connect"))
        if calls and jargs(calls[0]):
            target = jargs(calls[0])[0]
    if target is None or "secreviewSafeUrl" in ts.text(target):
        return None
    s.replace(target, f"secreviewSafeUrl(String.valueOf({ts.text(target)}))")
    out = s.result()
    return java_add_helper(out, "safe_url") if out else None


@fixer("java", ["open_redirect"], "Only allow relative same-site redirects")
def java_redirect(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = invocations(s, ctx.line, ("sendRedirect",))
    if calls and jargs(calls[0]):
        arg = jargs(calls[0])[0]
        s.replace(arg, f"secreviewSafeRedirect({ts.text(arg)})")
    else:
        bins = [n for n in ts.walk(s.root) if n.type == "binary_expression" and ts.line(n) == ctx.line
                and ts.text(n.child_by_field_name("left")).startswith('"redirect:')]
        if not bins:
            return None
        right = bins[0].child_by_field_name("right")
        s.replace(right, f"secreviewSafeRedirect({ts.text(right)})")
    out = s.result()
    return java_add_helper(out, "safe_redirect") if out else None


@fixer("java", ["xss"], "HTML-escape values written into responses")
def java_xss(ctx: FixContext) -> str | None:
    s = Src(ctx)
    expr = None
    rets = [n for n in ts.walk(s.root) if n.type == "return_statement" and ts.line(n) <= ctx.line <= ts.end_line(n)]
    calls = invocations(s, ctx.line, ("print", "println", "write", "append"))
    if calls and jargs(calls[0]):
        expr = jargs(calls[0])[0]
    elif rets and rets[0].named_children:
        expr = rets[0].named_children[0]
    if expr is None:
        return None
    parts = flatten_concat_js_java(expr, "java")
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    s.replace(expr, " + ".join(java_str(v) if k == "lit" else f"secreviewEscapeHtml({v})" for k, v in parts))
    out = s.result()
    return java_add_helper(out, "escape_html") if out else None


# ------------------------------------------------------------------ XML / deserialization / randomness
XXE_FEATURES = {
    "DocumentBuilderFactory": '{v}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    "SAXParserFactory": '{v}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    "XMLInputFactory": '{v}.setProperty(javax.xml.stream.XMLInputFactory.SUPPORT_DTD, false);',
    "TransformerFactory": '{v}.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");',
}


@fixer("java", ["xxe"], "Disable DOCTYPE / external entities on the XML parser factory")
def java_xxe(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    m = re.search(r"(\w+)\s*=\s*(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.newInstance\(\)\s*;", line)
    if not m:
        return None
    indent = re.match(r"\s*", line).group(0)
    lines = ctx.text.splitlines(True)
    lines.insert(ctx.line, indent + XXE_FEATURES[m.group(2)].format(v=m.group(1)) + "\n")
    return "".join(lines)


@fixer("java", ["deserialization"], "Restrict ObjectInputStream to application and java.base classes")
def java_deser(ctx: FixContext) -> str | None:
    s = Src(ctx)
    decls = [n for n in ts.walk(s.root) if n.type == "local_variable_declaration" and "ObjectInputStream" in ts.text(n)
             and ts.line(n) <= ctx.line]
    if not decls:
        return None
    decl = max(decls, key=lambda n: n.start_byte)
    var = ts.text(decl.child_by_field_name("declarator").child_by_field_name("name"))
    pkg = java_package(ctx.text)
    pattern = (pkg + ".**;" if pkg else "") + "java.base/*;!*"
    s.insert(decl.end_byte, f'\n        {var}.setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter("{pattern}"));')
    ctx.notes.append(f"allow-list filter '{pattern}' - extend it if the application deserialises other types")
    return s.result()


@fixer("java", ["insecure_random"], "Use SecureRandom for security-sensitive values")
def java_random(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    new = re.sub(r"new\s+(java\.util\.)?Random\(\s*\)", "new java.security.SecureRandom()", line)
    new = new.replace("Math.random()", "new java.security.SecureRandom().nextDouble()")
    if new == line:
        return None
    lines = ctx.text.splitlines(True)
    lines[ctx.line - 1] = new + ("\n" if lines[ctx.line - 1].endswith("\n") else "")
    return "".join(lines)


@fixer("java", ["weak_credential_storage"], "Replace weak/no-op password encoders with BCryptPasswordEncoder")
def java_password_encoder(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    new = re.sub(r"NoOpPasswordEncoder\.getInstance\(\)|new\s+(Md5PasswordEncoder|ShaPasswordEncoder|StandardPasswordEncoder|"
                 r"MessageDigestPasswordEncoder|LdapShaPasswordEncoder)\([^)]*\)",
                 "new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder()", line)
    if new == line:
        return None
    lines = ctx.text.splitlines(True)
    lines[ctx.line - 1] = new + ("\n" if lines[ctx.line - 1].endswith("\n") else "")
    ctx.notes.append("existing stored hashes must be migrated (re-hash on next login)")
    return "".join(lines)
