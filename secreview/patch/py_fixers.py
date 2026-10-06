"""Deterministic Python fix templates (AST-based, minimal edits)."""

from __future__ import annotations

import ast
import re

from .base import (FixContext, fixer, indent_of, py_add_helper, py_add_import, py_node_at, py_offset,
                   py_replace_node)

SHELL_META = re.compile(r"[|&;<>()$`*?\[\]{}~]")


def _src(ctx: FixContext, node) -> str:
    return ast.get_source_segment(ctx.text, node) or ""


def _parts(ctx: FixContext, node) -> list[tuple[str, str]] | None:
    """Flatten f-strings, '+' concatenation, % formatting and .format() into lit/expr parts."""
    if isinstance(node, ast.JoinedStr):
        out = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                out.append(("lit", str(v.value)))
            elif isinstance(v, ast.FormattedValue):
                out.append(("expr", _src(ctx, v.value)))
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _parts(ctx, node.left), _parts(ctx, node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("lit", node.value)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
        args = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        pieces = re.split(r"(%[sdifr])", node.left.value)
        out, i = [], 0
        for p in pieces:
            if re.fullmatch(r"%[sdifr]", p):
                if i >= len(args):
                    return None
                out.append(("expr", _src(ctx, args[i])))
                i += 1
            elif p:
                out.append(("lit", p))
        return out
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
        fmt = node.func.value.value
        kw = {k.arg: _src(ctx, k.value) for k in node.keywords if k.arg}
        out, auto = [], 0
        for lit, field, _spec, _conv in __import__("string").Formatter().parse(fmt):
            if lit:
                out.append(("lit", lit))
            if field is None:
                continue
            if field == "":
                if auto >= len(node.args):
                    return None
                out.append(("expr", _src(ctx, node.args[auto])))
                auto += 1
            elif field.isdigit():
                out.append(("expr", _src(ctx, node.args[int(field)])))
            elif field in kw:
                out.append(("expr", kw[field]))
            else:
                return None
        return out
    if isinstance(node, ast.Name):
        return [("expr", node.id)]
    return None


def _func_of(tree, line: int):
    fns = py_node_at(tree, line, (ast.FunctionDef, ast.AsyncFunctionDef))
    return fns[0] if fns else tree


def _last_assignment(fn, name: str, before_line: int):
    best = None
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and n.lineno < before_line and any(
                isinstance(t, ast.Name) and t.id == name for t in n.targets):
            if best is None or n.lineno > best.lineno:
                best = n
    return best


# ------------------------------------------------------------------ SQL injection
def _placeholder_style(text: str) -> str:
    if re.search(r"^\s*(import sqlite3|from sqlite3)", text, re.M):
        return "qmark"
    if re.search(r"(psycopg|pymysql|mysql\.connector|MySQLdb|from django\.db import connection)", text):
        return "format"
    return "qmark"


@fixer("python", ["sqli"], "Parameterised query: move interpolated values into the driver's params argument")
def py_sqli_parameterize(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: isinstance(c.func, ast.Attribute)
                       and c.func.attr in ("execute", "executemany") and c.args)
    if not calls:
        return None
    call = calls[0]
    if len(call.args) > 1 or call.keywords:
        return None   # already passes parameters
    q = call.args[0]
    assign = None
    if isinstance(q, ast.Name):
        assign = _last_assignment(_func_of(tree, ctx.line), q.id, call.lineno)
        if assign is None:
            return None
        q = assign.value
    parts = _parts(ctx, q)
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    mark = "?" if _placeholder_style(ctx.text) == "qmark" else "%s"
    from .base import placeholders_from_parts
    sql, params = placeholders_from_parts(list(parts), lambda i: mark)
    if mark == "%s":
        sql = sql.replace("%", "%%").replace("%%s", "%s") if "%" in sql.replace("%s", "") else sql
    params_src = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    text = ctx.text
    if assign is not None:
        # rewrite the call first (it is below the assignment), then the assignment
        new_call = f"{_src(ctx, call.func)}({call.args[0].id}, {params_src})"
        text = py_replace_node(text, call, new_call)
        text = py_replace_node(text, assign.value, repr(sql))
    else:
        text = py_replace_node(text, call, f"{_src(ctx, call.func)}({sql!r}, {params_src})")
    ctx.notes.append(f"query parameterised with {mark} placeholders ({len(params)} value(s))")
    return text


@fixer("python", ["nosqli"], "Force query values to strings so request objects cannot inject MongoDB operators")
def py_nosqli_cast(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: isinstance(c.func, ast.Attribute) and c.args
                       and isinstance(c.args[0], ast.Dict))
    if not calls:
        return None
    d = calls[0].args[0]
    text, changed = ctx.text, False
    for v in sorted(d.values, key=lambda n: (n.lineno, n.col_offset), reverse=True):
        if isinstance(v, (ast.Constant, ast.Dict)):
            continue
        text = py_replace_node(text, v, f"str({_src(ctx, v)})")
        changed = True
    return text if changed else None


# ------------------------------------------------------------------ command injection
def _argv_tokens(parts: list[tuple[str, str]]) -> list[str] | None:
    tokens: list[list[tuple[str, str]]] = [[]]
    for kind, val in parts:
        if kind == "expr":
            tokens[-1].append(("expr", val))
            continue
        chunks = re.split(r"(\s+)", val)
        for ch in chunks:
            if not ch:
                continue
            if ch.isspace():
                if tokens[-1]:
                    tokens.append([])
            else:
                tokens[-1].append(("lit", ch.strip("'\"")))
    out = []
    for tok in tokens:
        if not tok:
            continue
        if len(tok) == 1:
            kind, val = tok[0]
            out.append(repr(val) if kind == "lit" else f"str({val})")
        else:
            out.append("f" + repr("".join(v if k == "lit" else "{" + v + "}" for k, v in tok)))
    return out or None


@fixer("python", ["cmdi"], "Run the command without a shell (argument list), or shlex.quote values when a shell is required")
def py_cmdi(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: _src(ctx, c.func) in (
        "os.system", "os.popen", "subprocess.getoutput") or (
        _src(ctx, c.func).startswith("subprocess.") and any(
            k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in c.keywords)))
    if not calls:
        return None
    call = calls[0]
    fn = _src(ctx, call.func)
    parts = _parts(ctx, call.args[0]) if call.args else None
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    lits = "".join(v for k, v in parts if k == "lit")
    if SHELL_META.search(lits):
        # A real shell pipeline is needed: keep the shell, quote every interpolated value.
        quoted = "f" + repr("".join(v.replace("'", "").replace('"', "") if k == "lit"
                                    else "{shlex.quote(str(" + v + "))}" for k, v in parts))
        ctx.notes.append("shell kept (pipeline/redirection present); values quoted with shlex.quote")
        return py_add_import(py_replace_node(ctx.text, call.args[0], quoted), "import shlex")
    argv = _argv_tokens(parts)
    if not argv:
        return None
    arglist = "[" + ", ".join(argv) + "]"
    target = call
    if fn == "os.system":
        new_call = f"subprocess.run({arglist}, check=False).returncode"
    elif fn == "os.popen":
        new_call = f"subprocess.run({arglist}, capture_output=True, text=True).stdout"
        parent = next((n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                       and n.func.attr == "read" and n.func.value is call), None)
        if parent is not None:
            target = parent
    elif fn == "subprocess.getoutput":
        new_call = f"subprocess.run({arglist}, capture_output=True, text=True).stdout.rstrip('\n')"
    else:
        kws = [f"{k.arg}={_src(ctx, k.value)}" for k in call.keywords if k.arg != "shell"]
        rest = [_src(ctx, a) for a in call.args[1:]]
        new_call = f"{fn}({', '.join([arglist, *rest, *kws])})"
    ctx.notes.append("command executed without a shell (argument list)")
    return py_add_import(py_replace_node(ctx.text, target, new_call), "import subprocess")


def _src2(text: str, node) -> str:
    return ast.get_source_segment(text, node) or ""


# ------------------------------------------------------------------ code injection
@fixer("python", ["code_injection"], "Replace eval() with ast.literal_eval() (literals only)")
def py_eval_literal(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: isinstance(c.func, ast.Name) and c.func.id == "eval")
    if not calls:
        return None
    text = py_replace_node(ctx.text, calls[0].func, "ast.literal_eval")
    return py_add_import(text, "import ast")


# ------------------------------------------------------------------ path traversal
PATH_SINKS = ("open", "io.open", "codecs.open", "send_file", "flask.send_file", "os.remove", "os.unlink",
              "Path", "pathlib.Path", "shutil.rmtree", "shutil.copy")


def _base_and_rest(ctx: FixContext, node) -> tuple[str, list[str]] | None:
    if isinstance(node, ast.Call) and _src(ctx, node.func) in ("os.path.join", "path.join", "join") and len(node.args) >= 2:
        return _src(ctx, node.args[0]), [_src(ctx, a) for a in node.args[1:]]
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        return _src(ctx, node.left), [_src(ctx, node.right)]
    if isinstance(node, ast.JoinedStr):
        parts = _parts(ctx, node)
        if parts and parts[0][0] == "expr" and len(parts) >= 3:
            return parts[0][1], ["".join(v if k == "lit" else "{" + v + "}" for k, v in parts[1:]).lstrip("/\\")]
    return None


@fixer("python", ["path_traversal"], "Resolve the path and refuse anything outside the intended base directory")
def py_path_confine(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: _src(ctx, c.func) in PATH_SINKS and c.args)
    if not calls:
        return None
    call = calls[0]
    arg = call.args[0]
    fn = _func_of(tree, ctx.line)
    found = _base_and_rest(ctx, arg)
    if found is None and isinstance(arg, ast.Name):
        assign = _last_assignment(fn, arg.id, call.lineno)
        if assign is not None:
            found = _base_and_rest(ctx, assign.value)
    if found is None:
        return None
    base, rest = found
    rest_expr = rest[0] if len(rest) == 1 else f"os.path.join({', '.join(rest)})"
    compound = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.With, ast.If, ast.For, ast.While, ast.Try)
    stmts = [n for n in ast.walk(tree) if isinstance(n, ast.stmt) and n.lineno <= call.lineno <= n.end_lineno
             and (n.lineno == call.lineno or not isinstance(n, compound))]
    if not stmts:
        return None
    stmt = max(stmts, key=lambda n: n.lineno)
    indent = indent_of(ctx.line_text(stmt.lineno))
    guard = (f"{indent}_secreview_base = os.path.realpath({base})\n"
             f"{indent}_secreview_path = os.path.realpath(os.path.join(_secreview_base, {rest_expr}))\n"
             f"{indent}if os.path.commonpath([_secreview_base, _secreview_path]) != _secreview_base:\n"
             f"{indent}    raise PermissionError('path traversal blocked')\n")
    text = py_replace_node(ctx.text, arg, "_secreview_path")
    insert_at = py_offset(text, stmt.lineno, 0)
    text = text[:insert_at] + guard + text[insert_at:]
    ctx.notes.append(f"path confined to base directory {base}")
    return py_add_import(text, "import os")


# ------------------------------------------------------------------ SSRF / redirect
URL_SINKS = re.compile(r"^(requests\.\w+|httpx\.\w+|urllib\.request\.urlopen|urlopen|urllib\.request\.Request|\w+\.get)$")


@fixer("python", ["ssrf"], "Validate the URL (scheme + no internal addresses) before the outbound request")
def py_ssrf_guard(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: URL_SINKS.match(_src(ctx, c.func)) and c.args)
    if not calls:
        return None
    call = calls[0]
    idx = 1 if _src(ctx, call.func) == "requests.request" and len(call.args) > 1 else 0
    arg = call.args[idx]
    if "_secreview_safe_url" in _src(ctx, arg):
        return None
    text = py_replace_node(ctx.text, arg, f"_secreview_safe_url({_src(ctx, arg)})")
    return py_add_helper(text, "safe_url")


@fixer("python", ["open_redirect"], "Only allow relative same-site redirect targets")
def py_redirect_guard(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: _src(ctx, c.func).split(".")[-1] in (
        "redirect", "HttpResponseRedirect") and c.args)
    if not calls:
        return None
    arg = calls[0].args[0]
    text = py_replace_node(ctx.text, arg, f"_secreview_safe_redirect({_src(ctx, arg)})")
    return py_add_helper(text, "safe_redirect")


# ------------------------------------------------------------------ XSS
@fixer("python", ["xss"], "HTML-escape interpolated values before they reach the response")
def py_xss_escape(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    text = ctx.text
    # Markup(x) / mark_safe(x) -> escape(x)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: _src(ctx, c.func) in ("Markup", "markupsafe.Markup", "mark_safe"))
    if calls:
        return py_add_import(py_replace_node(text, calls[0].func, "html.escape"), "import html")
    # find the expression at the sink: return value / first argument
    target = None
    rets = py_node_at(tree, ctx.line, (ast.Return,), lambda r: r.value is not None)
    sinks = py_node_at(tree, ctx.line, (ast.Call,), lambda c: _src(ctx, c.func).split(".")[-1] in (
        "render_template_string", "make_response", "HttpResponse") and c.args)
    if sinks:
        target = sinks[0].args[0]
    elif rets:
        target = rets[0].value
        if isinstance(target, ast.Tuple) and target.elts:
            target = target.elts[0]
    if target is None:
        return None
    if isinstance(target, ast.JoinedStr):
        pieces = []
        for v in target.values:
            if isinstance(v, ast.Constant):
                pieces.append(str(v.value).replace("{", "{{").replace("}", "}}"))
            else:
                pieces.append("{html.escape(str(" + _src(ctx, v.value) + "))}")
        new = "f" + repr("".join(pieces))
    elif isinstance(target, ast.BinOp) and isinstance(target.op, ast.Add):
        parts = _parts(ctx, target)
        if not parts:
            return None
        new = " + ".join(repr(v) if k == "lit" else f"html.escape(str({v}))" for k, v in parts)
    elif isinstance(target, (ast.Name, ast.Subscript, ast.Attribute, ast.Call)):
        new = f"html.escape(str({_src(ctx, target)}))"
    else:
        return None
    return py_add_import(py_replace_node(text, target, new), "import html")


# ------------------------------------------------------------------ XXE / deserialization / crypto
@fixer("python", ["xxe"], "Parse XML with entity resolution and network access disabled")
def py_xxe_parser(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: _src(ctx, c.func).endswith(("etree.fromstring", "etree.parse", "etree.XML")))
    if not calls or any(k.arg == "parser" for k in calls[0].keywords):
        return None
    call = calls[0]
    args = [_src(ctx, a) for a in call.args] + [f"{k.arg}={_src(ctx, k.value)}" for k in call.keywords]
    mod = _src(ctx, call.func).rsplit(".", 1)[0]
    args.append(f"parser={mod}.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)")
    return py_replace_node(ctx.text, call, f"{_src(ctx, call.func)}({', '.join(args)})")


@fixer("python", ["deserialization"], "yaml.load -> yaml.safe_load")
def py_yaml_safe(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: _src(ctx, c.func) == "yaml.load")
    if not calls:
        return None
    call = calls[0]
    return py_replace_node(ctx.text, call, f"yaml.safe_load({_src(ctx, call.args[0])})") if call.args else None


@fixer("python", ["insecure_random"], "Use the `secrets` CSPRNG for security tokens")
def py_secrets_random(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    new = re.sub(r"\brandom\.choice\(", "secrets.choice(", line)
    new = re.sub(r"\brandom\.getrandbits\(", "secrets.randbits(", new)
    new = re.sub(r"\brandom\.randint\(\s*0\s*,\s*([^)]+)\)", r"secrets.randbelow(\1 + 1)", new)
    new = re.sub(r"\brandom\.random\(\)", "(secrets.randbits(53) / (1 << 53))", new)
    if new == line:
        return None
    lines = ctx.text.splitlines(True)
    nl = "\n" if lines[ctx.line - 1].endswith("\n") else ""
    lines[ctx.line - 1] = new + nl
    return py_add_import("".join(lines), "import secrets")


@fixer("python", ["tls_validation"], "Re-enable certificate verification")
def py_tls_verify(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    new = re.sub(r"verify\s*=\s*False", "verify=True", line)
    new = new.replace("ssl._create_unverified_context(", "ssl.create_default_context(")
    new = re.sub(r"\.verify_mode\s*=\s*ssl\.CERT_NONE", ".verify_mode = ssl.CERT_REQUIRED", new)
    new = re.sub(r"\.check_hostname\s*=\s*False", ".check_hostname = True", new)
    if new == line:
        return None
    lines = ctx.text.splitlines(True)
    lines[ctx.line - 1] = new + ("\n" if lines[ctx.line - 1].endswith("\n") else "")
    return "".join(lines)


@fixer("python", ["debug_enabled"], "Disable debug mode")
def py_debug_off(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    new = re.sub(r"debug\s*=\s*True", "debug=False", line)
    new = re.sub(r"^(\s*)DEBUG\s*=\s*True", r"\1DEBUG = False", new)
    if new == line:
        return None
    lines = ctx.text.splitlines(True)
    lines[ctx.line - 1] = new + ("\n" if lines[ctx.line - 1].endswith("\n") else "")
    return "".join(lines)


@fixer("python", ["jwt_misuse"], "Verify JWT signatures and never allow the 'none' algorithm")
def py_jwt_verify(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    new = re.sub(r",\s*verify\s*=\s*False", "", line)
    new = re.sub(r"[\"']verify_signature[\"']\s*:\s*False", '"verify_signature": True', new)
    new = re.sub(r"algorithms\s*=\s*\[[^\]]*[\"']none[\"'][^\]]*\]", 'algorithms=["HS256"]', new)
    if new == line:
        return None
    lines = ctx.text.splitlines(True)
    lines[ctx.line - 1] = new + ("\n" if lines[ctx.line - 1].endswith("\n") else "")
    return "".join(lines)


@fixer("python", ["hardcoded_secret"], "Read the secret from an environment variable")
def py_secret_env(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    m = re.match(r"^(\s*)([\w.\[\]'\"]+)\s*=\s*(['\"])(.+?)\3\s*$", line)
    if not m:
        return None
    target = m.group(2)
    env = re.sub(r"[^A-Z0-9]+", "_", re.sub(r".*[.\[]", "", target).upper()).strip("_") or "APP_SECRET"
    lines = ctx.text.splitlines(True)
    lines[ctx.line - 1] = f'{m.group(1)}{target} = os.environ["{env}"]\n'
    ctx.notes.append(f"secret moved to environment variable {env}; rotate the committed value")
    return py_add_import("".join(lines), "import os")


@fixer("python", ["error_leakage"], "Return a generic error message and log the details server-side")
def py_error_generic(ctx: FixContext) -> str | None:
    line = ctx.line_text(ctx.line)
    new = re.sub(r"str\(\s*(\w+)\s*\)", "'Internal server error'", line)
    new = new.replace("traceback.format_exc()", "'Internal server error'")
    if new == line:
        return None
    lines = ctx.text.splitlines(True)
    indent = indent_of(line)
    lines[ctx.line - 1] = f"{indent}logging.exception('request failed')\n" + new + (
        "\n" if lines[ctx.line - 1].endswith("\n") else "")
    return py_add_import("".join(lines), "import logging")


@fixer("python", ["unrestricted_upload"], "Allow only known-safe file extensions before saving an upload")
def py_upload_allowlist(ctx: FixContext) -> str | None:
    tree = ast.parse(ctx.text)
    calls = py_node_at(tree, ctx.line, (ast.Call,), lambda c: isinstance(c.func, ast.Attribute) and c.func.attr == "save")
    fn = _func_of(tree, ctx.line)
    saves = calls or [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                      and n.func.attr == "save"]
    if not saves:
        return None
    call = saves[0]
    obj = _src(ctx, call.func.value)
    stmt_line = call.lineno
    indent = indent_of(ctx.line_text(stmt_line))
    guard = (f"{indent}if os.path.splitext({obj}.filename or '')[1].lower() not in "
             f"{{'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.txt', '.csv'}}:\n"
             f"{indent}    raise ValueError('file type not allowed')\n")
    insert_at = py_offset(ctx.text, stmt_line, 0)
    return py_add_import(ctx.text[:insert_at] + guard + ctx.text[insert_at:], "import os")
