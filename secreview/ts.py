"""Small tree-sitter helpers (parsing JS/TS/Java for slicing, endpoint inventory and templates)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterator

try:
    from tree_sitter_language_pack import get_parser
except ImportError:  # pragma: no cover - optional dependency
    get_parser = None

SUFFIX_GRAMMAR = {".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
                  ".ts": "typescript", ".tsx": "tsx", ".java": "java", ".py": "python"}


@lru_cache(maxsize=8)
def parser(grammar: str):
    if get_parser is None:
        raise RuntimeError("tree-sitter-language-pack is not installed")
    return get_parser(grammar)


def parse_file(path: Path):
    grammar = SUFFIX_GRAMMAR.get(path.suffix.lower())
    if not grammar:
        return None, b""
    src = path.read_bytes()
    return parser(grammar).parse(src).root_node, src


def parse_source(grammar: str, src: bytes):
    return parser(grammar).parse(src).root_node


def text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None and node.text is not None else ""


def walk(node) -> Iterator:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def line(node) -> int:
    return node.start_point[0] + 1


def end_line(node) -> int:
    return node.end_point[0] + 1


def string_value(node) -> str | None:
    """Literal value of a JS/Java string or template literal without substitutions."""
    if node is None:
        return None
    if node.type in ("string", "string_literal"):
        return text(node)[1:-1]
    if node.type == "template_string" and not any(c.type == "template_substitution" for c in node.children):
        return text(node)[1:-1]
    return None


ENCLOSING = {
    "javascript": ("function_declaration", "function_expression", "function", "arrow_function",
                   "method_definition", "generator_function_declaration"),
    "typescript": ("function_declaration", "function_expression", "function", "arrow_function",
                   "method_definition"),
    "tsx": ("function_declaration", "function_expression", "function", "arrow_function", "method_definition"),
    "java": ("method_declaration", "constructor_declaration", "lambda_expression"),
    "python": ("function_definition",),
}


def enclosing_function(path: Path, line_no: int, outermost_handler: bool = False) -> tuple[int, int] | None:
    """(start_line, end_line) of the function containing `line_no` (1-based)."""
    root, _ = parse_file(path)
    if root is None:
        return None
    grammar = SUFFIX_GRAMMAR[path.suffix.lower()]
    kinds = ENCLOSING.get(grammar, ())
    best = None
    for n in walk(root):
        if n.type in kinds and line(n) <= line_no <= end_line(n):
            size = end_line(n) - line(n)
            if best is None or (size > best[2] if outermost_handler else size < best[2]):
                best = (line(n), end_line(n), size)
    return (best[0], best[1]) if best else None
