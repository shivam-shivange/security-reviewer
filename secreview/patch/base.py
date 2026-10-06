"""Shared machinery for deterministic fix templates."""

from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import ts
from ..models import Finding, Patch

SNIPPETS = Path(__file__).parent / "snippets"


@dataclass
class FixContext:
    project: Path
    finding: Finding
    file: str                    # relative path of the file being fixed
    text: str                    # current content
    notes: list[str] = field(default_factory=list)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines(True)

    @property
    def line(self) -> int:
        return self.finding.line

    def line_text(self, n: int) -> str:
        lines = self.text.splitlines()
        return lines[n - 1] if 0 < n <= len(lines) else ""


Fixer = Callable[[FixContext], "str | None"]


@dataclass
class FixerSpec:
    name: str
    language: str
    classes: tuple[str, ...]
    fn: Fixer
    description: str


REGISTRY: list[FixerSpec] = []


def fixer(language: str, classes: list[str], description: str):
    def deco(fn: Fixer) -> Fixer:
        REGISTRY.append(FixerSpec(fn.__name__, language, tuple(classes), fn, description))
        return fn
    return deco


def fixers_for(language: str, vuln_class: str) -> list[FixerSpec]:
    return [s for s in REGISTRY if s.language == language and vuln_class in s.classes]


# ------------------------------------------------------------------ text utilities
def unified(path: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def make_patch(file: str, old: str, new: str, source: str, description: str, llm: bool = False) -> Patch | None:
    if new is None or new == old:
        return None
    return Patch(diff=unified(file, old, new), source=source, description=description,
                 files={file: new}, llm_used=llm)


def indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def snippet(language: str, name: str) -> str:
    fname = {"python": "python_helpers.py", "javascript": "js_helpers.js", "java": "java_helpers.java"}[language]
    text = (SNIPPETS / fname).read_text(encoding="utf-8")
    marker = "# --- secreview:" if language == "python" else "// --- secreview:"
    start = text.index(marker + name)
    start = text.index("\n", start) + 1
    end = text.index(marker, start)
    return text[start:end].rstrip() + "\n"


def syntax_ok(language: str, path: str, text: str) -> bool:
    if language == "python":
        try:
            ast.parse(text)
            return True
        except SyntaxError:
            return False
    grammar = ts.SUFFIX_GRAMMAR.get(Path(path).suffix.lower())
    if not grammar:
        return True
    try:
        return not ts.parse_source(grammar, text.encode("utf-8")).has_error
    except Exception:
        return True


# ------------------------------------------------------------------ python insertion helpers
def py_offset(text: str, lineno: int, col: int) -> int:
    """ast positions use UTF-8 byte columns; convert (line, col) to a str index."""
    lines = text.splitlines(True)
    base = sum(len(l) for l in lines[: lineno - 1])
    line_bytes = lines[lineno - 1].encode("utf-8")
    return base + len(line_bytes[:col].decode("utf-8", errors="ignore"))


def py_replace_node(text: str, node: ast.AST, new_src: str) -> str:
    start = py_offset(text, node.lineno, node.col_offset)
    end = py_offset(text, node.end_lineno, node.end_col_offset)
    return text[:start] + new_src + text[end:]


def py_add_import(text: str, statement: str) -> str:
    """Add `import x` / `from x import y` after the last top-level import, if not present."""
    if re.search(rf"^{re.escape(statement)}\s*$", text, re.M):
        return text
    tree = ast.parse(text)
    last = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last = node.end_lineno
        elif isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) and last == 0:
            last = node.end_lineno          # module docstring
        else:
            if last:
                break
    lines = text.splitlines(True)
    lines.insert(last, statement + "\n")
    return "".join(lines)


def py_add_helper(text: str, name: str) -> str:
    """Insert a predefined helper function after the imports (once)."""
    body = snippet("python", name)
    fn_name = re.search(r"def (\w+)", body).group(1)
    if f"def {fn_name}(" in text:
        return text
    tree = ast.parse(text)
    last = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)) or (
                isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and last == 0):
            last = node.end_lineno
        elif last:
            break
    lines = text.splitlines(True)
    lines.insert(last, "\n\n" + body + "\n")
    return "".join(lines)


def py_node_at(tree: ast.AST, line: int, types: tuple, pred=None) -> list:
    out = []
    for n in ast.walk(tree):
        if isinstance(n, types) and getattr(n, "lineno", -1) <= line <= getattr(n, "end_lineno", -1):
            if pred is None or pred(n):
                out.append(n)
    out.sort(key=lambda n: (n.end_lineno - n.lineno, n.end_col_offset - n.col_offset))
    return out


# ------------------------------------------------------------------ js insertion helpers
def js_is_esm(text: str) -> bool:
    return bool(re.search(r"^\s*import\s.+\sfrom\s+['\"]|^\s*export\s", text, re.M)) and "require(" not in text


def js_insert_after_imports(text: str, block: str) -> str:
    lines = text.splitlines(True)
    last = 0
    for i, ln in enumerate(lines[:200]):
        s = ln.strip()
        if s.startswith(("import ", "'use strict'", '"use strict"')) or re.match(
                r"^(const|let|var)\s+[\w{}\s,]+=\s*require\(", s):
            last = i + 1
    lines.insert(last, "\n" + block + "\n")
    return "".join(lines)


def js_add_helper(text: str, name: str) -> str:
    esm = js_is_esm(text)
    key = "safe_path_esm" if name == "safe_path" and esm else name
    body = snippet("javascript", key)
    fn = re.search(r"function (\w+)", body).group(1)
    if f"function {fn}(" in text:
        return text
    if key == "safe_path_esm" and "__secreviewPath" not in text:
        body = 'import __secreviewPath from "path";\n' + body
    return js_insert_after_imports(text, body.rstrip())


# ------------------------------------------------------------------ java insertion helpers
def java_add_helper(text: str, name: str) -> str:
    body = snippet("java", name)
    fn = re.search(r"static [\w.<>\[\]]+ (\w+)\(", body).group(1)
    if f" {fn}(" in text:
        return text
    root = ts.parse_source("java", text.encode("utf-8"))
    classes = [n for n in root.named_children if n.type in ("class_declaration", "enum_declaration", "record_declaration")]
    if not classes:
        return text
    body_node = classes[0].child_by_field_name("body")
    end = body_node.end_byte - 1          # position of the closing brace
    raw = text.encode("utf-8")
    return (raw[:end] + b"\n" + body.encode("utf-8") + raw[end:]).decode("utf-8")


def java_package(text: str) -> str:
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.M)
    return m.group(1) if m else ""


# ------------------------------------------------------------------ concatenation flattening
def flatten_concat_js_java(node, grammar: str) -> list[tuple[str, str]] | None:
    """Flatten `"a" + x + "b"` / template literals into [("lit", text) | ("expr", code)]."""
    parts: list[tuple[str, str]] = []

    def rec(n) -> bool:
        if n.type == "binary_expression" and ts.text(n.child_by_field_name("operator")) == "+":
            return rec(n.child_by_field_name("left")) and rec(n.child_by_field_name("right"))
        if n.type == "parenthesized_expression" and n.named_children:
            return rec(n.named_children[0])
        lit = ts.string_value(n)
        if lit is not None:
            parts.append(("lit", lit))
            return True
        if n.type == "template_string":
            for c in n.children:
                if c.type == "string_fragment":
                    parts.append(("lit", ts.text(c)))
                elif c.type == "template_substitution":
                    inner = [x for x in c.named_children]
                    parts.append(("expr", ts.text(inner[0]) if inner else ""))
                elif c.type == "escape_sequence":
                    parts.append(("lit", ts.text(c)))
            return True
        parts.append(("expr", ts.text(n)))
        return True

    return parts if rec(node) else None


def placeholders_from_parts(parts: list[tuple[str, str]], placeholder: Callable[[int], str]) -> tuple[str, list[str]]:
    """Build a parameterised SQL string: strip quotes that surrounded interpolated values."""
    sql, params = "", []
    for i, (kind, val) in enumerate(parts):
        if kind == "lit":
            sql += val
            continue
        nxt = parts[i + 1][1] if i + 1 < len(parts) and parts[i + 1][0] == "lit" else None
        if sql.endswith(("'", '"')) and nxt is not None and nxt.startswith(sql[-1]):
            sql = sql[:-1]
            parts[i + 1] = ("lit", nxt[1:])
        params.append(val)
        sql += placeholder(len(params))
    return sql, params
