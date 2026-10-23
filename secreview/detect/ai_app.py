"""AI / LLM application analyzer (Python, `ast`; deterministic, no LLM).

In LLM apps the user input, the prompt and the rendering of the answer usually live in different files
(UI -> agent -> UI), which Semgrep's per-function taint cannot follow. This analyzer links them across
the project:

  * prompt_injection     - an LLM prompt built by interpolating runtime values in a project that takes
                           user input; also flags LLM output fed into a later prompt (agent chaining)
  * llm_output_handling  - LLM output (tracked through state/dict keys) rendered as markdown/HTML in the UI
  * rag_poisoning        - web-fetched content that reaches the knowledge base (vector store or data file
                           loaded at runtime), linked through shared data files
  * llm_resource_abuse   - a Streamlit / Gradio page that triggers LLM calls with no authentication or
                           rate limit, unbounded text inputs, server listening on all interfaces
  * error_leakage / security_misconfig / cors_misconfig - .streamlit/config.toml and exception display

It also adds Streamlit / Gradio pages to the endpoint inventory (API surface). The AI classes are
heuristic (`heuristic: true` in the taxonomy) => status needs_review.
"""

from __future__ import annotations

import ast
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import tomllib

from ..context import RunContext
from ..discovery import ProjectInfo, is_test_file
from ..models import Endpoint, Evidence, EvidenceStep, Finding, Status

LLM_CLASS = re.compile(r"^(Chat[A-Z]\w*|(Async)?(OpenAI|AzureOpenAI|Anthropic|AnthropicVertex|Groq|Mistral|Cohere)|"
                       r"Ollama(LLM)?|GenerativeModel|HuggingFaceEndpoint|LlamaCpp|Bedrock\w*|VertexAI)$")
INVOKE = {"invoke", "ainvoke", "stream", "astream", "batch", "predict", "generate_content", "chat", "complete"}
CLIENT_CALL = re.compile(r"(\.chat\.completions\.create|\.completions\.create|\.messages\.create|"
                         r"\.responses\.create|\.generate_content|^ollama\.(chat|generate))$")
VECTOR_LIB = re.compile(r"^(qdrant_client|chromadb|pinecone|weaviate|pymilvus|lancedb|faiss|llama_index|"
                        r"langchain\w*)")
VECTOR_WRITE = {"upsert", "upload_points", "upload_collection", "add_documents", "add_texts", "from_documents",
                "from_texts", "index_documents"}
FETCH = re.compile(r"^(requests|httpx|urllib3|aiohttp)\.(get|post|request|Session)$|(^|\.)(urlopen|fetch_url|"
                   r"WebBaseLoader|AsyncHtmlLoader|SitemapLoader|RecursiveUrlLoader|AsyncChromiumLoader)$")
DATA_FILE = re.compile(r"[\w.-]+\.(json|jsonl|csv|tsv|txt|parquet|pkl|md|xml|html)$")
UI_INPUT = {"text_input", "text_area", "chat_input", "number_input", "file_uploader", "Textbox", "TextArea",
            "Chatbot", "File", "ChatInterface"}
FREE_TEXT = {"text_input", "text_area", "chat_input", "Textbox", "TextArea"}
MD_SINKS = {"markdown", "write", "info", "warning", "error", "success", "caption", "toast", "subheader", "header"}
DANGER_SINKS = {"eval", "exec", "system", "popen", "execute", "render_template_string", "Markup"}
CAST_FUNCS = {"len", "int", "float", "round", "bool", "sum", "min", "max", "abs"}
AUTH = re.compile(r"st\.login\(|st\.user\b|st\.experimental_user|streamlit_authenticator|stauth\.|check_password|"
                  r"\.launch\([^)]*auth\s*=|login_required|Depends\(\s*\w*(auth|user)", re.I)
RATE = re.compile(r"rate_?limit|RateLimit|Limiter\(|slowapi|flask_limiter|@throttle|throttle_classes|"
                  r"max_requests_per|requests_per_(minute|hour|day)", re.I)


# ------------------------------------------------------------------ ast helpers
def dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(dotted(node.func) + "()")
    else:
        parts.append("?")
    return ".".join(reversed(parts))


def walk_scope(scope: ast.AST):
    """Nodes of one function (or module top level), not descending into nested functions."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def scopes(tree: ast.AST):
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def names_in(expr: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)}


def keys_read(expr: ast.AST) -> set[str]:
    """Constant dict keys read in expr: x["k"], x.get("k")."""
    out = set()
    for n in ast.walk(expr):
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
            out.add(n.slice.value)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("get", "setdefault") \
                and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
            out.add(n.args[0].value)
    return out


def target_names(target: ast.AST) -> set[str]:
    """Names bound by an assignment target. `x[k] = v` / `x.a = v` bind nothing: tainting the whole
    container would mark every other key of it as tainted too."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {n for e in target.elts for n in target_names(e)}
    if isinstance(target, ast.Starred):
        return target_names(target.value)
    return set()


@dataclass
class Bind:
    line: int
    target: ast.AST
    value: ast.AST
    aug: bool = False          # x += ... keeps earlier taint


def bindings(scope: ast.AST) -> list[Bind]:
    """Assignments, augmented assignments, for-loop and with targets of one scope, in line order."""
    out = []
    for n in walk_scope(scope):
        if isinstance(n, ast.Assign):
            out += [Bind(n.lineno, t, n.value) for t in n.targets]
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
            out.append(Bind(n.lineno, n.target, n.value, aug=isinstance(n, ast.AugAssign)))
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            out.append(Bind(n.lineno, n.target, n.iter))
        elif isinstance(n, ast.comprehension):
            out.append(Bind(getattr(n.iter, "lineno", 0), n.target, n.iter))
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            out += [Bind(n.lineno, i.optional_vars, i.context_expr) for i in n.items if i.optional_vars]
        elif isinstance(n, ast.NamedExpr):
            out.append(Bind(n.lineno, n.target, n.value))
    return sorted(out, key=lambda b: b.line)


def propagate(binds: list[Bind], seed: set[str], is_source) -> set[str]:
    """Forward taint over names: a name is tainted when its value uses a tainted name or a source."""
    tainted = set(seed)
    for _ in range(3):   # loops: a later binding can feed an earlier line
        before = len(tainted)
        for b in binds:
            if names_in(b.value) & tainted or is_source(b.value):
                tainted |= target_names(b.target)
        if len(tainted) == before:
            break
    return tainted


def taint_at(binds: list[Bind], is_source, clean=lambda e: False):
    """Flow-sensitive taint: returns tainted(line) -> names tainted just before `line`. Rebinding a name
    to a clean value untaints it (so a reused loop variable does not stay tainted)."""
    events: dict[str, list[tuple[int, bool]]] = {}
    current: set[str] = set()
    for b in binds:
        hot = not clean(b.value) and bool(names_in(b.value) & current or is_source(b.value))
        for name in target_names(b.target):
            state = hot or (b.aug and name in current)
            events.setdefault(name, []).append((b.line, state))
            if state:
                current.add(name)
            else:
                current.discard(name)

    def tainted(line: int) -> set[str]:
        out = set()
        for name, evs in events.items():
            last = [t for ln, t in evs if ln < line] or [t for ln, t in evs if ln == line]
            if last and last[-1]:
                out.add(name)
        return out
    return tainted


@dataclass
class Src:
    rel: str
    text: str
    tree: ast.Module
    lines: list[str] = field(default_factory=list)

    def code(self, line: int) -> str:
        return self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""

    def seg(self, node: ast.AST) -> str:
        return (ast.get_source_segment(self.text, node) or "").strip().replace("\n", " ")[:160]


@dataclass
class LLMCall:
    src: Src
    scope: ast.AST
    node: ast.Call


# ------------------------------------------------------------------ analyzer
class AIAppAnalyzer:
    def __init__(self, project: Path, files: list[str]):
        self.project = project
        self.srcs: dict[str, Src] = {}
        for rel in files:
            try:
                text = (project / rel).read_text(encoding="utf-8", errors="replace")
                self.srcs[rel] = Src(rel, text, ast.parse(text), text.splitlines())
            except (OSError, SyntaxError, ValueError):
                continue
        self.all_text = "\n".join(s.text for s in self.srcs.values())
        self.findings: list[Finding] = []
        self.endpoints: list[Endpoint] = []
        self.llm_calls: list[LLMCall] = []
        self.llm_keys: dict[str, tuple[str, int]] = {}   # state/dict key -> where LLM output is stored
        self.clean_keys: set[str] = set()                 # system keys added onto an LLM result dict
        self._subkeys: list[tuple[str, str, bool]] = []   # (outer key, inner key, value is LLM output)
        self.inputs: list[tuple[str, int, str]] = []     # user-input sites (file, line, code)
        self.ui_files: dict[str, str] = {}               # rel -> "streamlit" | "gradio"

    # -- discovery --------------------------------------------------------
    def _imports(self, src: Src) -> set[str]:
        out = set()
        for n in ast.walk(src.tree):
            if isinstance(n, ast.Import):
                out |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module:
                out.add(n.module)
        return out

    def _llm_names(self, src: Src) -> set[str]:
        names = set()
        for n in ast.walk(src.tree):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) \
                    and LLM_CLASS.match(dotted(n.value.func).split(".")[-1]):
                names |= {dotted(t) for t in n.targets}
        return names

    def _is_llm_call(self, call: ast.Call, llm_names: set[str]) -> bool:
        name = dotted(call.func)
        if CLIENT_CALL.search(name):
            return True
        return isinstance(call.func, ast.Attribute) and call.func.attr in INVOKE and dotted(call.func.value) in llm_names

    def _collect_llm(self) -> None:
        for src in self.srcs.values():
            llm_names = self._llm_names(src)
            for scope in scopes(src.tree):
                calls = [n for n in walk_scope(scope) if isinstance(n, ast.Call) and self._is_llm_call(n, llm_names)]
                if not calls:
                    continue
                self.llm_calls += [LLMCall(src, scope, c) for c in calls]
                call_ids = {id(c) for c in calls}

                def is_llm(expr: ast.AST, ids: set[int] = call_ids) -> bool:
                    return any(id(x) in ids for x in ast.walk(expr))
                tainted = propagate(bindings(scope), set(), is_llm)
                # where does LLM output get stored for other code to read? x["k"] = ..., {"k": ...}
                for b in bindings(scope):
                    if not isinstance(b.target, ast.Subscript):
                        continue
                    hot = bool(names_in(b.value) & tainted or is_llm(b.value))
                    key = _const_key(b.target)
                    outer = _const_key(b.target.value) if isinstance(b.target.value, ast.Subscript) else None
                    if outer and key:
                        self._subkeys.append((outer, key, hot))   # state["response"]["evidence"] = ...
                    elif hot and key:
                        self.llm_keys.setdefault(key, (src.rel, b.line))
                for n in walk_scope(scope):
                    if isinstance(n, ast.Dict):
                        for k, v in zip(n.keys, n.values):
                            if isinstance(k, ast.Constant) and isinstance(k.value, str) \
                                    and (names_in(v) & tainted or is_llm(v)):
                                self.llm_keys.setdefault(k.value, (src.rel, n.lineno))

    def _finish_keys(self) -> None:
        self.clean_keys = {inner for outer, inner, hot in self._subkeys if outer in self.llm_keys and not hot}

    def _ui_kind(self, src: Src) -> str:
        imports = self._imports(src)
        if any(i == "streamlit" or i.startswith("streamlit.") for i in imports):
            return "streamlit"
        if any(i == "gradio" or i.startswith("gradio.") for i in imports):
            return "gradio"
        return ""

    def _ui_names(self, src: Src, scope: ast.AST) -> set[str]:
        """Names bound to Streamlit / Gradio objects (columns, containers, tabs...)."""
        def is_ui(expr: ast.AST) -> bool:
            return any(isinstance(c, ast.Call) and dotted(c.func).split(".")[0] in ("st", "gr", "streamlit", "gradio")
                       for c in ast.walk(expr))
        return propagate(bindings(scope), set(), is_ui) | {"st", "gr", "streamlit", "gradio"}

    def _widgets(self, src: Src) -> list[tuple[int, str, str, bool]]:
        """(line, widget, label, length_limited) for every input widget of a UI file."""
        out = []
        for scope in scopes(src.tree):
            ui = self._ui_names(src, scope)
            for n in walk_scope(scope):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in UI_INPUT \
                        and dotted(n.func.value).split(".")[0] in ui:
                    label = src.seg(n.args[0]) if n.args else ""
                    for k in n.keywords:
                        if k.arg in ("label", "key") and not label:
                            label = src.seg(k.value)
                    limited = any(k.arg in ("max_chars", "max_length", "max_lines") for k in n.keywords)
                    out.append((n.lineno, n.func.attr, label.strip("'\""), limited))
        return sorted(set(out))

    # -- checks -----------------------------------------------------------
    def _prompt_leaves(self, src: Src, scope: ast.AST, expr: ast.AST, binds: dict[str, list[ast.AST]],
                       depth: int = 0, seen: set | None = None) -> list[ast.AST]:
        """Runtime values interpolated into a prompt (f-strings, +, %, .format, .join, message objects)."""
        seen = seen if seen is not None else set()
        if depth > 6 or id(expr) in seen:
            return []
        seen.add(id(expr))

        def rec(e):
            return self._prompt_leaves(src, scope, e, binds, depth + 1, seen)

        def value(e) -> list[ast.AST]:
            """An interpolated value: follow names that are themselves built strings, else it is a leaf."""
            if isinstance(e, ast.Constant):
                return []
            if isinstance(e, ast.Name):
                if e.id.isupper():
                    return []   # module constant
                built = [v for v in binds.get(e.id, []) if isinstance(v, (ast.JoinedStr, ast.BinOp, ast.Call))
                         and _builds_string(v)]
                return [x for v in built for x in rec(v)] or [e] if built else [e]
            if isinstance(e, ast.Call) and getattr(e.func, "id", "") in CAST_FUNCS:
                return []
            if isinstance(e, ast.Call) and _builds_string(e):
                return rec(e)
            return [e]

        if isinstance(expr, ast.JoinedStr):
            return [x for v in expr.values if isinstance(v, ast.FormattedValue) for x in value(v.value)]
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            out = []
            for side in (expr.left, expr.right):
                out += rec(side) if isinstance(side, (ast.JoinedStr, ast.BinOp, ast.Constant, ast.Call)) else value(side)
            return out
        if isinstance(expr, ast.Call):
            attr = expr.func.attr if isinstance(expr.func, ast.Attribute) else getattr(expr.func, "id", "")
            if attr in ("format", "format_map"):
                return [x for a in [*expr.args, *(k.value for k in expr.keywords)] for x in value(a)] + rec(expr.func.value)
            if attr == "join":
                return [x for a in expr.args for x in (rec(a) if isinstance(a, (ast.GeneratorExp, ast.ListComp))
                                                       else value(a))]
            if attr in CAST_FUNCS:
                return []
            # message objects / dicts / helper calls: look at their arguments
            return [x for a in [*expr.args, *(k.value for k in expr.keywords)] for x in rec(a)]
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return [x for e in expr.elts for x in rec(e)]
        if isinstance(expr, ast.Dict):
            return [x for v in expr.values for x in (rec(v) if isinstance(v, (ast.JoinedStr, ast.BinOp, ast.Call,
                                                                              ast.List, ast.Dict, ast.Name, ast.Constant))
                                                     else value(v))]
        if isinstance(expr, (ast.GeneratorExp, ast.ListComp)):
            return rec(expr.elt)
        if isinstance(expr, ast.IfExp):
            return rec(expr.body) + rec(expr.orelse)
        if isinstance(expr, ast.Name):
            if expr.id.isupper():
                return []
            vals = binds.get(expr.id, [])
            return [x for v in vals for x in rec(v)] if vals else []
        if isinstance(expr, ast.Constant):
            return []
        return value(expr)

    def _origin_keys(self, leaf: ast.AST, binds: dict[str, list[ast.AST]], depth: int = 0) -> set[str]:
        keys = keys_read(leaf)
        if depth < 3:
            for name in names_in(leaf):
                for v in binds.get(name, []):
                    keys |= self._origin_keys(v, binds, depth + 1)
        return keys

    def check_prompts(self) -> None:
        entry = self.inputs[:3]
        for call in self.llm_calls:
            src, scope = call.src, call.scope
            binds: dict[str, list[ast.AST]] = {}
            for b in bindings(scope):
                for name in target_names(b.target):
                    binds.setdefault(name, []).append(b.value)
            leaves = [x for a in [*call.node.args, *(k.value for k in call.node.keywords)]
                      for x in self._prompt_leaves(src, scope, a, binds)]
            uniq: dict[int, ast.AST] = {}
            for leaf in leaves:
                uniq.setdefault(hash((getattr(leaf, "lineno", 0), src.seg(leaf))), leaf)
            if not uniq:
                continue
            steps = [EvidenceStep(f, ln, code, "user input (UI)") for f, ln, code in entry]
            chained = []
            for leaf in list(uniq.values())[:8]:
                origin = [k for k in self._origin_keys(leaf, binds) if k in self.llm_keys
                          and self.llm_keys[k] != (src.rel, call.node.lineno)]
                note = "interpolated into the prompt"
                if origin:
                    file, line = self.llm_keys[origin[0]]
                    note += f" - output of another LLM call ({file}:{line}, key '{origin[0]}')"
                    chained.append(origin[0])
                steps.append(EvidenceStep(src.rel, getattr(leaf, "lineno", call.node.lineno), src.seg(leaf), note))
            steps.append(EvidenceStep(src.rel, call.node.lineno, src.code(call.node.lineno), "prompt sent to the LLM"))
            names = ", ".join(sorted({src.seg(x) for x in uniq.values()})[:6])
            msg = (f"LLM prompt is built by interpolating {len(uniq)} runtime value(s) ({names}) with no validation "
                   "or delimiting, so text in them can override the instructions.")
            if self.inputs:
                msg += f" The project takes user input ({len(self.inputs)} input site(s), e.g. {entry[0][0]}:{entry[0][1]})."
            if chained:
                msg += (f" It also feeds the output of an earlier LLM call (key '{chained[0]}') into this prompt, so an "
                        "injection in the first call carries into the second.")
            severity = "high" if self.inputs else ("medium" if chained else "low")
            self._add("ai-prompt-injection", "prompt_injection", src, call.node.lineno, msg, severity,
                      steps, confidence=0.6 if self.inputs else 0.4)

    def check_output_rendering(self) -> None:
        if not self.llm_keys:
            return
        keys = set(self.llm_keys)

        def clean(e: ast.AST) -> bool:
            return bool(keys_read(e) & self.clean_keys)
        for rel in self.ui_files:
            src = self.srcs[rel]
            for scope in scopes(src.tree):
                tainted_at = taint_at(bindings(scope), lambda e: bool(keys_read(e) & keys), clean)
                ui = self._ui_names(src, scope)
                md, danger = [], []
                for n in walk_scope(scope):
                    if not isinstance(n, ast.Call):
                        continue
                    args = [*n.args, *(k.value for k in n.keywords if k.arg not in ("icon", "key", "help"))]
                    tainted = tainted_at(n.lineno)
                    if not any(not clean(a) and (names_in(a) & tainted or keys_read(a) & keys) for a in args):
                        continue
                    name = dotted(n.func)
                    attr = name.split(".")[-1]
                    unsafe = any(k.arg == "unsafe_allow_html" and isinstance(k.value, ast.Constant) and k.value.value
                                 for k in n.keywords)
                    if attr in DANGER_SINKS or attr == "html" or unsafe or (attr in ("run", "Popen", "call") and any(
                            k.arg == "shell" for k in n.keywords)):
                        danger.append(n)
                    elif attr in MD_SINKS and name.split(".")[0] in ui:
                        md.append(n)
                md.sort(key=lambda c: c.lineno)
                origin = sorted(keys & self._scope_keys(scope))
                where = f"LLM output stored under key '{origin[0]}' ({self.llm_keys[origin[0]][0]}:" \
                        f"{self.llm_keys[origin[0]][1]})" if origin else "LLM output"
                for n in danger:
                    steps = self._origin_steps(origin) + [EvidenceStep(rel, n.lineno, src.code(n.lineno), "dangerous sink")]
                    self._add("ai-llm-output-dangerous-sink", "llm_output_handling", src, n.lineno,
                              f"{where} reaches {dotted(n.func)}(...) - raw HTML, code or command built from model output.",
                              "high", steps)
                if md:
                    steps = self._origin_steps(origin) + [EvidenceStep(rel, n.lineno, src.code(n.lineno), "rendered as markdown")
                                                          for n in md[:8]]
                    self._add("ai-llm-output-markdown", "llm_output_handling", src, md[0].lineno,
                              f"{where} is rendered as markdown in {len(md)} place(s) without validation. Injected "
                              "output can show phishing links or load remote images that leak data; render it as "
                              "plain text or validate it against a schema first.", "medium", steps)

    def _scope_keys(self, scope: ast.AST) -> set[str]:
        return {k for n in walk_scope(scope) for k in keys_read(n)} if not isinstance(scope, ast.Module) else \
            {k for n in ast.walk(scope) for k in keys_read(n)}

    def _origin_steps(self, keys: list[str]) -> list[EvidenceStep]:
        out = []
        for k in keys[:2]:
            file, line = self.llm_keys[k]
            out.append(EvidenceStep(file, line, self.srcs[file].code(line), f"LLM output stored as '{k}'"))
        return out

    def check_rag(self) -> None:
        if not self.llm_calls:
            return
        data_files: dict[str, dict[str, int]] = {}   # file -> data file name -> line naming it
        fetch: dict[str, ast.Call] = {}
        writes: dict[str, ast.Call] = {}
        for rel, src in self.srcs.items():
            data_files[rel] = {}
            for n in ast.walk(src.tree):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and DATA_FILE.search(n.value):
                    data_files[rel].setdefault(Path(n.value).name, n.lineno)
            vector = any(VECTOR_LIB.match(i) for i in self._imports(src))
            for n in ast.walk(src.tree):
                if not isinstance(n, ast.Call):
                    continue
                name = dotted(n.func)
                if FETCH.search(name) and rel not in fetch:
                    fetch[rel] = n
                if vector and name.split(".")[-1] in VECTOR_WRITE and rel not in writes:
                    writes[rel] = n
        importers = self._importers()
        for rel, call in fetch.items():
            # files linked to the fetcher through shared data files (scraped.json -> merge -> merged.json -> ingest)
            path, seen, queue = {rel: []}, {rel}, deque([rel])
            while queue:
                cur = queue.popleft()
                for other, files in data_files.items():
                    shared = data_files[cur].keys() & files.keys()
                    if other not in seen and shared:
                        seen.add(other)
                        path[other] = path[cur] + [(other, sorted(shared)[0])]
                        queue.append(other)
            sinks = [(f, "written to a vector store", writes[f]) for f in seen if f in writes]
            sinks += [(f, "loaded at runtime by imported code", None) for f in seen
                      if f != rel and f not in writes and importers.get(f)]
            if not sinks:
                continue
            src = self.srcs[rel]
            steps = [EvidenceStep(rel, call.lineno, src.code(call.lineno), "content fetched from the web")]
            for f, data in path[sinks[0][0]]:
                line = data_files[f][data]
                steps.append(EvidenceStep(f, line, self.srcs[f].code(line), f"reads/writes shared data file '{data}'"))
            for f, how, node in sinks[:3]:
                line = node.lineno if node is not None else 1
                steps.append(EvidenceStep(f, line, self.srcs[f].code(line), how))
            msg = ("Web-fetched content flows into the knowledge base that is placed into LLM prompts ("
                   + "; ".join(f"{f}: {how}" for f, how, _ in sinks[:3]) + "). Whoever controls the fetched pages can "
                   "plant instructions (indirect prompt injection) or false facts that the app presents as evidence.")
            shared_keys = self._shared_write_keys(writes)
            if shared_keys:
                msg += (f" The serving code reads the same credential ({', '.join(shared_keys)}) as the ingest script, "
                        "so a leak of the app's key also allows writing to the store; give the app a read-only key.")
            self._add("ai-rag-poisoning", "rag_poisoning", src, call.lineno, msg, "medium", steps)

    def _importers(self) -> dict[str, list[str]]:
        mod_to_file = {rel[:-3].replace("/", ".").removesuffix(".__init__"): rel for rel in self.srcs}
        out: dict[str, list[str]] = {}
        for rel, src in self.srcs.items():
            for imp in self._imports(src):
                target = mod_to_file.get(imp)
                if target and target != rel:
                    out.setdefault(target, []).append(rel)
        return out

    def _shared_write_keys(self, writes: dict[str, ast.Call]) -> list[str]:
        env = re.compile(r"""(?:getenv|environ\.get|environ\[)\(?\s*["'](\w*(?:KEY|TOKEN|SECRET)\w*)["']""")
        write_keys = {k for f in writes for k in env.findall(self.srcs[f].text)}
        other = {k for rel, s in self.srcs.items() if rel not in writes and not is_test_file(rel)
                 for k in env.findall(s.text)}
        return sorted(write_keys & other)

    def check_ui(self) -> None:
        has_auth = bool(AUTH.search(self.all_text))
        has_rate = bool(RATE.search(self.all_text))
        for rel, kind in self.ui_files.items():
            src = self.srcs[rel]
            widgets = self._widgets(src)
            cfg = self._streamlit_config(rel) if kind == "streamlit" else None
            notes = []
            unbounded = [w for w in widgets if w[1] in FREE_TEXT and not w[3]]
            if unbounded:
                notes.append(f"{len(unbounded)} text input(s) without a length limit")
            stem = Path(rel).stem
            self.endpoints.append(Endpoint(
                framework=kind, method="UI", path=f"/{stem}" if "pages" in Path(rel).parts else "/",
                file=rel, line=widgets[0][0] if widgets else 1, end_line=len(src.lines), handler=f"{kind} page {rel}",
                handler_file=rel, handler_line=1, handler_end_line=len(src.lines), auth=has_auth,
                params=[w[2] or w[1] for w in widgets][:20], rate_limited=has_rate, notes=notes))
            if kind == "streamlit":
                self._check_streamlit_config(rel, cfg)
                self._check_exception_display(src)
            else:
                self._check_gradio_launch(src)
            if not self.llm_calls or (has_auth and has_rate):
                continue
            missing = [x for x, ok in (("authentication", has_auth), ("rate limiting", has_rate)) if not ok]
            msg = (f"This {kind} page triggers {len(self.llm_calls)} LLM call site(s) with no "
                   f"{' or '.join(missing)} found in the project: anyone who can reach it can run paid LLM calls "
                   "(denial of wallet).")
            if unbounded:
                msg += " Text inputs without max_chars: " + ", ".join(f"'{w[2] or w[1]}' (line {w[0]})" for w in unbounded[:5]) + "."
            if kind == "streamlit" and cfg is not None and cfg[1].get("server", {}).get("address") in (None, "0.0.0.0", ""):
                msg += " server.address is not set to localhost, so Streamlit listens on all network interfaces."
            line = (unbounded or widgets or [(1,)])[0][0]
            steps = [EvidenceStep(rel, w[0], src.code(w[0]), f"input widget {w[1]}"
                                  + ("" if w[3] else " (no length limit)")) for w in widgets[:6]]
            steps += [EvidenceStep(c.src.rel, c.node.lineno, c.src.code(c.node.lineno), "LLM call") for c in self.llm_calls[:3]]
            self._add("ai-llm-unbounded-consumption", "llm_resource_abuse", src, line, msg, "medium", steps)

    def _streamlit_config(self, rel: str) -> tuple[str, dict] | None:
        """The .streamlit/config.toml Streamlit would use for this script (its dir or a parent)."""
        d = (self.project / rel).parent
        while True:
            cfg = d / ".streamlit" / "config.toml"
            if cfg.is_file():
                try:
                    return cfg.relative_to(self.project).as_posix(), tomllib.loads(cfg.read_text(encoding="utf-8"))
                except (OSError, tomllib.TOMLDecodeError, ValueError):
                    return None
            if d == self.project or self.project not in d.parents:
                return ("", {})
            d = d.parent

    def _check_streamlit_config(self, rel: str, cfg: tuple[str, dict] | None) -> None:
        if cfg is None:
            return
        path, data = cfg
        text_lines = (self.project / path).read_text(encoding="utf-8").splitlines() if path else []

        def line_of(key: str) -> int:
            return next((i for i, l in enumerate(text_lines, 1) if re.match(rf"\s*{key}\s*=", l)), 1)

        def add(rule, vclass, key, msg, severity):
            file = path or rel
            line = line_of(key) if path else 1
            code = text_lines[line - 1] if path and text_lines else ""
            self.findings.append(Finding(rule_id=rule, vuln_class=vclass, title="", file=file, line=line,
                                         tool="ai-analyzer", language="config", message=msg, code=code,
                                         severity=severity, extra={"confidence": "high", "taint": False,
                                                                   "config_key": key}))
        show = data.get("client", {}).get("showErrorDetails", None)
        if show in (True, "full", "stacktrace"):
            add("streamlit-show-error-details", "error_leakage", "showErrorDetails",
                f"client.showErrorDetails = {show!r}: exception messages and tracebacks are shown in the browser.",
                "medium")
        elif show is None:
            add("streamlit-show-error-details", "error_leakage", "showErrorDetails",
                "client.showErrorDetails is not set; Streamlit's default (\"full\") shows exception messages and "
                "tracebacks in the browser. Set it to \"none\" for deployment.", "low")
        server = data.get("server", {})
        if server.get("enableXsrfProtection") is False:
            add("streamlit-xsrf-disabled", "security_misconfig", "enableXsrfProtection",
                "server.enableXsrfProtection = false disables CSRF protection for uploads and widget calls.", "medium")
        if server.get("enableCORS") is False:
            add("streamlit-cors-disabled", "cors_misconfig", "enableCORS",
                "server.enableCORS = false accepts cross-origin requests to the Streamlit server.", "low")

    def _check_exception_display(self, src: Src) -> None:
        for h in ast.walk(src.tree):
            if not isinstance(h, ast.ExceptHandler) or not h.name:
                continue
            for n in ast.walk(h):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                        and n.func.attr in MD_SINKS | {"exception", "json"} and dotted(n.func).startswith("st.") \
                        and any(h.name in names_in(a) for a in n.args):
                    self.findings.append(Finding(
                        rule_id="streamlit-exception-shown", vuln_class="error_leakage", title="", file=src.rel,
                        line=n.lineno, tool="ai-analyzer", language="python", code=src.code(n.lineno),
                        message=f"The raw exception `{h.name}` is shown to the user; client/API errors can include "
                                "internal URLs, hostnames or request details. Show a generic message and log the detail.",
                        severity="low", extra={"confidence": "high", "taint": False}))
                    break

    def _check_gradio_launch(self, src: Src) -> None:
        for n in ast.walk(src.tree):
            if isinstance(n, ast.Call) and dotted(n.func).endswith(".launch") and any(
                    k.arg == "share" and isinstance(k.value, ast.Constant) and k.value.value for k in n.keywords):
                self.findings.append(Finding(
                    rule_id="gradio-public-share", vuln_class="security_misconfig", title="", file=src.rel,
                    line=n.lineno, tool="ai-analyzer", language="python", code=src.code(n.lineno),
                    message="launch(share=True) publishes the app on a public gradio.live URL.",
                    severity="medium", extra={"confidence": "high", "taint": False}))

    # -- output -----------------------------------------------------------
    def _add(self, rule: str, vclass: str, src: Src, line: int, message: str, severity: str,
             steps: list[EvidenceStep], confidence: float = 0.6) -> None:
        self.findings.append(Finding(
            rule_id=rule, vuln_class=vclass, title="", file=src.rel, line=line, tool="ai-analyzer",
            language="python", message=message, code=src.code(line), severity=severity,
            status=Status.NEEDS_REVIEW.value,
            evidence=Evidence(method="ai-app-analysis", chain=steps, summary=message, confidence=confidence),
            extra={"confidence": "medium", "taint": False, "heuristic": True}))

    def run(self) -> tuple[list[Endpoint], list[Finding]]:
        for rel, src in self.srcs.items():
            kind = self._ui_kind(src)
            if kind:
                self.ui_files[rel] = kind
                self.inputs += [(rel, w[0], src.code(w[0])) for w in self._widgets(src)]
            for n in ast.walk(src.tree):
                if isinstance(n, ast.Call) and dotted(n.func) in ("input", "request.get_json") or \
                        isinstance(n, ast.Attribute) and dotted(n) in ("request.args", "request.form", "request.json"):
                    self.inputs.append((rel, n.lineno, src.code(n.lineno)))
                    break
        self._collect_llm()
        self._finish_keys()
        self.check_prompts()
        self.check_output_rendering()
        self.check_rag()
        self.check_ui()
        return self.endpoints, self.findings


def _const_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
        return node.slice.value
    return None


def _builds_string(node: ast.AST) -> bool:
    if isinstance(node, (ast.JoinedStr, ast.Constant)):
        return isinstance(node, ast.JoinedStr) or isinstance(node.value, str)
    if isinstance(node, ast.BinOp):
        return _builds_string(node.left) or _builds_string(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in ("format", "format_map", "join")
    return False


def analyze_ai_app(ctx: RunContext, info: ProjectInfo) -> tuple[list[Endpoint], list[Finding]]:
    include_tests = ctx.config.get("scan.include_tests", False)
    files = [f for f in info.files.get("python", []) if include_tests or not is_test_file(f)]
    if not files:
        return [], []
    eps, findings = AIAppAnalyzer(ctx.project, files).run()
    for ep in eps:
        mod = info.module_for(ep.file)
        ep.module = mod.path if mod else "."
    ctx.log(f"ai-app: {len(eps)} UI pages, {len(findings)} findings")
    return eps, findings
