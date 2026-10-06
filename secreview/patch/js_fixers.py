"""Deterministic JavaScript / TypeScript / React fix templates (tree-sitter based)."""

from __future__ import annotations

import re
from pathlib import Path

from .. import ts
from .base import (FixContext, fixer, flatten_concat_js_java, js_add_helper, js_insert_after_imports, js_is_esm,
                   placeholders_from_parts)

SHELL_META = re.compile(r"[|&;<>()$`*?\[\]{}~]")


class Src:
    """Byte-level editor over a tree-sitter tree (edits applied back-to-front)."""

    def __init__(self, ctx: FixContext):
        self.ctx = ctx
        self.raw = ctx.text.encode("utf-8")
        lang_default = {"java": "java", "javascript": "javascript"}.get(ctx.finding.language, "javascript")
        grammar = ts.SUFFIX_GRAMMAR.get(Path(ctx.file).suffix.lower(), lang_default)
        self.root = ts.parse_source(grammar, self.raw)
        self.edits: list[tuple[int, int, str]] = []

    def calls_at(self, line: int, pred) -> list:
        out = [n for n in ts.walk(self.root) if n.type in ("call_expression", "new_expression")
               and ts.line(n) <= line <= ts.end_line(n) and pred(n)]
        return sorted(out, key=lambda n: n.end_byte - n.start_byte)

    def nodes_at(self, line: int, types: tuple, pred=lambda n: True) -> list:
        out = [n for n in ts.walk(self.root) if n.type in types and ts.line(n) <= line <= ts.end_line(n) and pred(n)]
        return sorted(out, key=lambda n: n.end_byte - n.start_byte)

    def replace(self, node, new: str) -> None:
        self.edits.append((node.start_byte, node.end_byte, new))

    def insert(self, byte: int, new: str) -> None:
        self.edits.append((byte, byte, new))

    def result(self) -> str | None:
        if not self.edits:
            return None
        raw = self.raw
        for start, end, new in sorted(self.edits, key=lambda e: e[0], reverse=True):
            raw = raw[:start] + new.encode("utf-8") + raw[end:]
        return raw.decode("utf-8")


def callee(n) -> str:
    fn = n.child_by_field_name("function") or n.child_by_field_name("constructor")
    return ts.text(fn)


def args_of(n) -> list:
    a = n.child_by_field_name("arguments")
    return [c for c in a.named_children if c.type != "comment"] if a is not None else []


def _tail(name: str) -> str:
    return name.split(".")[-1]


# ------------------------------------------------------------------ SQL injection
@fixer("javascript", ["sqli"], "Use driver placeholders (? or $n) and pass values separately")
def js_sqli(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: _tail(callee(n)) in ("query", "execute") and args_of(n))
    if not calls:
        return None
    call = calls[0]
    args = args_of(call)
    if len(args) > 1 and args[1].type == "array":
        return None
    parts = flatten_concat_js_java(args[0], "javascript")
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    pg = bool(re.search(r"require\(['\"]pg['\"]\)|from ['\"]pg['\"]|\bnew Pool\(|\bnew Client\(", ctx.text))
    sql, params = placeholders_from_parts(list(parts), (lambda i: f"${i}") if pg else (lambda i: "?"))
    s.replace(args[0], repr_js(sql))
    s.insert(args[0].end_byte, ", [" + ", ".join(params) + "]")
    ctx.notes.append(f"query parameterised ({'$n' if pg else '?'} placeholders)")
    return s.result()


def repr_js(value: str) -> str:
    if "\n" in value:
        return "`" + value.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${") + "`"
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ------------------------------------------------------------------ NoSQL injection
@fixer("javascript", ["nosqli"], "Wrap request-supplied values in {$eq: ...} so they cannot carry query operators")
def js_nosqli_eq(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: args_of(n) and args_of(n)[0].type == "object")
    if not calls:
        return None
    obj = args_of(calls[0])[0]
    changed = False
    for pair in [c for c in obj.named_children if c.type in ("pair", "shorthand_property_identifier")]:
        if pair.type == "shorthand_property_identifier":
            name = ts.text(pair)
            s.replace(pair, f"{name}: {{ $eq: {name} }}")
            changed = True
            continue
        key = ts.text(pair.child_by_field_name("key"))
        val = pair.child_by_field_name("value")
        if key.startswith("$") or val is None or val.type in ("string", "number", "true", "false", "null", "object",
                                                               "regex", "template_string"):
            continue
        s.replace(val, f"{{ $eq: {ts.text(val)} }}")
        changed = True
    if not changed:
        return None
    ctx.notes.append("query values wrapped in $eq (operator objects from the request no longer change the query)")
    return s.result()


# ------------------------------------------------------------------ command injection
@fixer("javascript", ["cmdi"], "Use execFile with an argument array (no shell); quote values when a shell is required")
def js_cmdi(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: _tail(callee(n)) in ("exec", "execSync") and args_of(n))
    if not calls:
        return None
    call = calls[0]
    args = args_of(call)
    parts = flatten_concat_js_java(args[0], "javascript")
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    lits = "".join(v for k, v in parts if k == "lit")
    if SHELL_META.search(lits):
        quoted = "`" + "".join(v.replace("`", "\\`").replace("'", "").replace('"', "") if k == "lit"
                               else "${secreviewShellQuote(" + v + ")}" for k, v in parts) + "`"
        s.replace(args[0], quoted)
        ctx.notes.append("shell kept (pipeline/redirection present); values quoted")
        out = s.result()
        return js_add_helper(out, "shell_quote") if out else None
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
    tokens = [t for t in tokens if t]
    if not tokens or tokens[0][0][0] != "lit" or len(tokens[0]) != 1:
        return None
    def tok(t):
        if len(t) == 1:
            return repr_js(t[0][1]) if t[0][0] == "lit" else f"String({t[0][1]})"
        return "`" + "".join(v if k == "lit" else "${" + v + "}" for k, v in t) + "`"
    prog = tok(tokens[0])
    argv = "[" + ", ".join(tok(t) for t in tokens[1:]) + "]"
    sync = _tail(callee(call)) == "execSync"
    fn_node = call.child_by_field_name("function")
    new_fn = "execFileSync" if sync else "execFile"
    if fn_node.type == "member_expression":
        s.replace(fn_node.child_by_field_name("property"), new_fn)
    else:
        s.replace(fn_node, f"require('child_process').{new_fn}" if not js_is_esm(ctx.text) else new_fn)
    s.replace(args[0], f"{prog}, {argv}")
    out = s.result()
    if out and fn_node.type != "member_expression" and js_is_esm(ctx.text) and new_fn not in ctx.text:
        out = js_insert_after_imports(out, f"import {{ {new_fn} }} from 'child_process';")
    ctx.notes.append(f"{_tail(callee(call))} replaced by {new_fn} with an argument array (no shell)")
    return out


# ------------------------------------------------------------------ code injection
@fixer("javascript", ["code_injection"], "Parse data with JSON.parse instead of evaluating it")
def js_eval_json(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: callee(n) == "eval" and args_of(n))
    if not calls:
        return None
    s.replace(calls[0].child_by_field_name("function"), "JSON.parse")
    return s.result()


# ------------------------------------------------------------------ path traversal
@fixer("javascript", ["path_traversal"], "Resolve the path and refuse anything outside the base directory")
def js_path_confine(ctx: FixContext) -> str | None:
    s = Src(ctx)
    sinks = s.calls_at(ctx.line, lambda n: re.search(
        r"(fs(\.promises)?|fsPromises)\.\w+$|\.(sendFile|download)$", callee(n)) is not None and args_of(n))
    if not sinks:
        return None
    arg = args_of(sinks[0])[0]
    base = rest = None
    if arg.type == "call_expression" and re.search(r"path\.(join|resolve)$", callee(arg)):
        a = args_of(arg)
        if len(a) >= 2:
            base, rest = ts.text(a[0]), [ts.text(x) for x in a[1:]]
    elif arg.type == "binary_expression":
        base, rest = ts.text(arg.child_by_field_name("left")), [ts.text(arg.child_by_field_name("right"))]
    elif arg.type == "template_string":
        parts = flatten_concat_js_java(arg, "javascript")
        if parts and parts[0][0] == "expr" and len(parts) >= 2:
            base = parts[0][1]
            rest = ["`" + "".join(v if k == "lit" else "${" + v + "}" for k, v in parts[1:]).lstrip("/") + "`"]
    if base is None:
        return None
    s.replace(arg, f"secreviewSafePath({base}, {', '.join(rest)})")
    out = s.result()
    ctx.notes.append(f"path confined to {base}")
    return js_add_helper(out, "safe_path") if out else None


# ------------------------------------------------------------------ SSRF / redirect / XSS
@fixer("javascript", ["ssrf"], "Validate the URL (http/https, no internal hosts) before the request")
def js_ssrf(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: re.search(r"^(axios(\.\w+)?|fetch|got(\.\w+)?|https?\.(get|request)|request|needle\.get)$",
                                                     callee(n)) is not None and args_of(n))
    if not calls:
        return None
    arg = args_of(calls[0])[0]
    if "secreviewSafeUrl" in ts.text(arg):
        return None
    s.replace(arg, f"secreviewSafeUrl({ts.text(arg)})")
    out = s.result()
    return js_add_helper(out, "safe_url") if out else None


@fixer("javascript", ["open_redirect"], "Only allow relative same-site redirects")
def js_redirect(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: _tail(callee(n)) in ("redirect", "location") and args_of(n))
    if not calls:
        return None
    arg = args_of(calls[0])[-1]
    s.replace(arg, f"secreviewSafeRedirect({ts.text(arg)})")
    out = s.result()
    return js_add_helper(out, "safe_redirect") if out else None


@fixer("javascript", ["xss"], "HTML-escape interpolated values (server) / sanitise HTML with DOMPurify (React)")
def js_xss(ctx: FixContext) -> str | None:
    s = Src(ctx)
    # React: dangerouslySetInnerHTML={{__html: x}}
    attrs = s.nodes_at(ctx.line, ("jsx_attribute",), lambda n: "dangerouslySetInnerHTML" in ts.text(n))
    if attrs:
        pairs = [p for p in ts.walk(attrs[0]) if p.type == "pair" and ts.text(p.child_by_field_name("key")) == "__html"]
        if not pairs:
            return None
        val = pairs[0].child_by_field_name("value")
        s.replace(val, f"DOMPurify.sanitize({ts.text(val)})")
        out = s.result()
        if out and "DOMPurify" not in ctx.text:
            out = js_insert_after_imports(out, 'import DOMPurify from "dompurify";')
        ctx.notes.append("requires the 'dompurify' package (npm install dompurify)")
        return out
    calls = s.calls_at(ctx.line, lambda n: _tail(callee(n)) in ("send", "write", "end") and args_of(n))
    if not calls:
        return None
    arg = args_of(calls[0])[0]
    parts = flatten_concat_js_java(arg, "javascript")
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    if len(parts) == 1:
        new = f"secreviewEscapeHtml({parts[0][1]})"
    else:
        new = "`" + "".join(v.replace("`", "\\`") if k == "lit" else "${secreviewEscapeHtml(" + v + ")}"
                            for k, v in parts) + "`"
    s.replace(arg, new)
    out = s.result()
    return js_add_helper(out, "escape_html") if out else None


# ------------------------------------------------------------------ prototype pollution
@fixer("javascript", ["prototype_pollution"], "Reject __proto__/constructor/prototype keys")
def js_proto(ctx: FixContext) -> str | None:
    s = Src(ctx)
    # merge(target, src) -> merge(target, secreviewStripProto(src))
    merges = s.calls_at(ctx.line, lambda n: re.search(r"(merge|mergeWith|defaultsDeep|extend|deepMerge|deepExtend)$",
                                                      callee(n)) is not None and len(args_of(n)) >= 2)
    if merges:
        src = args_of(merges[0])[-1]
        s.replace(src, f"secreviewStripProto({ts.text(src)})")
        out = s.result()
        return js_add_helper(out, "strip_proto") if out else None
    # unsafe recursive merge: guard inside the for-in loop
    loops = s.nodes_at(ctx.line, ("for_in_statement",))
    if loops:
        loop = loops[0]
        key = ts.text(loop.child_by_field_name("left")).split()[-1]
        body = loop.child_by_field_name("body")
        if body is not None and body.type == "statement_block":
            s.insert(body.start_byte + 1, f"\n    if ({key} === '__proto__' || {key} === 'constructor' || "
                                          f"{key} === 'prototype') continue;")
            return s.result()
    # obj[a][b] = v
    assigns = s.nodes_at(ctx.line, ("assignment_expression",),
                         lambda n: n.child_by_field_name("left").type == "subscript_expression")
    if assigns:
        left = assigns[0].child_by_field_name("left")
        for sub in [n for n in ts.walk(left) if n.type == "subscript_expression"]:
            idx = sub.child_by_field_name("index")
            if idx is not None and idx.type not in ("string", "number"):
                s.replace(idx, f"secreviewSafeKey({ts.text(idx)})")
        out = s.result()
        return js_add_helper(out, "safe_key") if out else None
    return None


# ------------------------------------------------------------------ config / crypto / leakage
def _line_sub(ctx: FixContext, subs: list[tuple[str, str]]) -> str | None:
    lines = ctx.text.splitlines(True)
    old = lines[ctx.line - 1]
    new = old
    for pat, rep in subs:
        new = re.sub(pat, rep, new)
    if new == old:
        return None
    lines[ctx.line - 1] = new
    return "".join(lines)


@fixer("javascript", ["tls_validation"], "Re-enable TLS certificate validation")
def js_tls(ctx: FixContext) -> str | None:
    return _line_sub(ctx, [(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true"),
                           (r"(NODE_TLS_REJECT_UNAUTHORIZED['\"]?\]?\s*=\s*)['\"]?0['\"]?", r"\g<1>'1'")])


@fixer("javascript", ["insecure_random"], "Generate tokens with crypto.randomBytes")
def js_random(ctx: FixContext) -> str | None:
    return _line_sub(ctx, [(r"Math\.random\(\)\.toString\(\s*\d+\s*\)(\.(substr|substring|slice)\([^)]*\))?",
                            "require('crypto').randomBytes(16).toString('hex')")])


@fixer("javascript", ["error_leakage"], "Send a generic error message instead of the error object / stack")
def js_error(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: _tail(callee(n)) in ("send", "json") and args_of(n))
    if not calls:
        return None
    call = calls[0]
    arg = args_of(call)[0]
    generic = "{ error: 'Internal server error' }" if _tail(callee(call)) == "json" else "'Internal server error'"
    if arg.type == "object":
        for pair in [p for p in arg.named_children if p.type == "pair"]:
            v = pair.child_by_field_name("value")
            if re.search(r"(stack|err|error|e)\b", ts.text(v)):
                s.replace(v, "'Internal server error'")
    else:
        s.replace(arg, generic)
    return s.result()


@fixer("javascript", ["jwt_misuse"], "Verify JWT signatures instead of only decoding them; pin algorithms")
def js_jwt(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: callee(n) == "jwt.decode" and args_of(n))
    if calls:
        m = re.search(r"jwt\.(?:sign|verify)\([^,]+,\s*([^,)]+)", ctx.text)
        secret = m.group(1).strip() if m else "process.env.JWT_SECRET"
        s.replace(calls[0], f"jwt.verify({ts.text(args_of(calls[0])[0])}, {secret}, {{ algorithms: ['HS256'] }})")
        return s.result()
    return _line_sub(ctx, [(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"][^\]]*\]", "algorithms: ['HS256']"),
                           (r"algorithm\s*:\s*['\"]none['\"]", "algorithm: 'HS256'")])


@fixer("javascript", ["unrestricted_upload"], "Add a file-type filter and size limit to multer")
def js_multer(ctx: FixContext) -> str | None:
    s = Src(ctx)
    calls = s.calls_at(ctx.line, lambda n: callee(n) == "multer" and args_of(n) and args_of(n)[0].type == "object")
    if not calls:
        return None
    obj = args_of(calls[0])[0]
    inner = ts.text(obj)[1:-1].strip().rstrip(",")
    extra = ("limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => "
             "cb(null, /^(image\\/(png|jpe?g|gif)|application\\/pdf|text\\/plain)$/.test(file.mimetype))")
    s.replace(obj, "{ " + (inner + ", " if inner else "") + extra + " }")
    return s.result()


@fixer("javascript", ["hardcoded_secret"], "Read the secret from process.env")
def js_secret_env(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*(['\"`])[^'\"`]+\2", line) or \
        re.search(r"(\w+)\s*:\s*(['\"`])[^'\"`]+\2", line)
    if not m:
        return None
    name = re.sub(r"(?<!^)(?=[A-Z])", "_", m.group(1)).upper()
    new = line[:m.start(2)] + f"process.env.{name}" + line[m.end():]
    lines = ctx.text.splitlines(True)
    lines[ctx.line - 1] = new + ("\n" if lines[ctx.line - 1].endswith("\n") else "")
    ctx.notes.append(f"secret moved to environment variable {name}; rotate the committed value")
    return "".join(lines)
