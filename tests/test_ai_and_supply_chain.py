"""AI-app analyzer, supply-chain checks, git-aware secret grading and status handling.

Runs the detectors directly on examples/llm-streamlit-vuln (no semgrep, no LLM, no network).
"""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview import tools                                         # noqa: E402
from secreview.config import Config                                 # noqa: E402
from secreview.detect.ai_app import AIAppAnalyzer                   # noqa: E402
from secreview.detect.bandit_runner import _constant_command        # noqa: E402
from secreview.detect.secrets import scan_secrets                   # noqa: E402
from secreview.detect.supply_chain import scan_supply_chain         # noqa: E402
from secreview.discovery import discover                            # noqa: E402
from secreview.models import Finding, Patch, Status                 # noqa: E402
from secreview.patch.base import FixContext                         # noqa: E402
from secreview.patch.config_fixers import requirements_declared_package, streamlit_hide_error_details  # noqa: E402
from secreview.taxonomy import catalog, class_for_cwe, is_heuristic  # noqa: E402
from secreview.verify.engine import _unverified                     # noqa: E402

APP = ROOT / "examples" / "llm-streamlit-vuln"


def _force_rmtree(path: Path) -> None:
    """rmtree that also removes read-only files (git marks its object files read-only on Windows)."""
    def clear_readonly(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass   # still open (e.g. the run's SQLite db); the next run's setup removes it
    if path.exists():
        shutil.rmtree(path, onexc=clear_readonly)


class StubCtx:
    """The parts of RunContext the detectors use."""
    def __init__(self, project: Path):
        self.project = project.resolve()
        self.config = Config.load()
        self.warnings: list[str] = []

    def log(self, message, level="info", **data):
        pass

    def warn(self, message, **data):
        self.warnings.append(message)


@pytest.fixture(scope="module")
def ai():
    info = discover(APP, [])
    eps, findings = AIAppAnalyzer(APP, info.files["python"]).run()
    return eps, findings


def _by_class(findings, vclass):
    return [f for f in findings if f.vuln_class == vclass]


def test_new_classes_in_taxonomy():
    cat = catalog()
    for name in ("supply_chain", "prompt_injection", "rag_poisoning", "llm_output_handling", "llm_resource_abuse"):
        assert name in cat
    assert is_heuristic("prompt_injection") and not is_heuristic("supply_chain")
    assert class_for_cwe(["CWE-494"]) == "supply_chain"
    assert class_for_cwe(["CWE-1427"]) == "prompt_injection"


def test_prompt_injection_cross_file_and_chained(ai):
    _, findings = ai
    pi = _by_class(findings, "prompt_injection")
    assert {f.line for f in pi} == {13, 20}            # both llm.invoke calls in agent.py
    assert all(f.status == Status.NEEDS_REVIEW.value and f.severity == "high" for f in pi)
    first = next(f for f in pi if f.line == 13)
    assert any(s.file == "app.py" and "user input" in s.note for s in first.evidence.chain)
    chained = next(f for f in pi if f.line == 20)
    assert "output of an earlier LLM call (key 'answer')" in chained.message


def test_llm_output_rendered_as_markdown(ai):
    _, findings = ai
    out = _by_class(findings, "llm_output_handling")
    assert len(out) == 1 and out[0].file == "app.py"
    sinks = [s.line for s in out[0].evidence.chain if s.note == "rendered as markdown"]
    assert sinks == [14, 15]                             # answer + summary, not the error message


def test_rag_poisoning_linked_through_data_file(ai):
    _, findings = ai
    rag = _by_class(findings, "rag_poisoning")
    assert len(rag) == 1 and rag[0].file == "scrape.py"
    assert any(s.file == "ingest.py" and "vector store" in s.note for s in rag[0].evidence.chain)
    assert "QDRANT_API_KEY" in rag[0].message           # serving code reuses the ingest credential


def test_streamlit_surface_abuse_and_config(ai):
    eps, findings = ai
    assert len(eps) == 1 and eps[0].framework == "streamlit" and not eps[0].auth
    abuse = _by_class(findings, "llm_resource_abuse")
    assert len(abuse) == 1 and "'Your question'" in abuse[0].message
    leaks = {f.rule_id: f for f in _by_class(findings, "error_leakage")}
    assert leaks["streamlit-show-error-details"].file == ".streamlit/config.toml"
    assert leaks["streamlit-exception-shown"].line == 12


def test_reused_loop_variable_is_not_tainted(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n"
        "def run(state):\n    r = llm.invoke(state['q'])\n    state['out'] = r.content\n    return state\n")
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\nfrom agent import run\nres = run({'q': st.text_input('q', max_chars=50)})\n"
        "for i, line in enumerate(res['out'].splitlines()):\n    pass\n"
        "for i, item in enumerate(res['log']):\n    st.markdown(f'{i} {item}')\n")
    _, findings = AIAppAnalyzer(tmp_path, ["agent.py", "ui.py"]).run()
    assert not _by_class(findings, "llm_output_handling")


def test_supply_chain_mismatch_and_unpinned():
    ctx = StubCtx(APP)
    findings = scan_supply_chain(ctx, discover(APP, []))
    rules = {f.rule_id: f for f in findings}
    mismatch = rules["supply-declared-package-mismatch"]
    assert mismatch.extra["declared"] == "dataset" and mismatch.extra["imported"] == "datasets"
    assert mismatch.severity == "high" and mismatch.line == 5
    unpinned = rules["supply-unpinned-requirements"]
    assert unpinned.extra["unpinned"] == ["streamlit", "langchain-openai", "qdrant-client",
                                          "sentence-transformers", "dataset"]
    assert ctx.warnings


def test_constant_shell_command_is_recognised(tmp_path):
    src = tmp_path / "r.py"
    src.write_text("import os, subprocess\nos.system('ls -l')\nos.system(cmd)\nsubprocess.call(['a', x], shell=True)\n")
    assert _constant_command(src, 2)
    assert not _constant_command(src, 3)
    assert not _constant_command(src, 4)


@pytest.mark.skipif(not tools.which("git"), reason="git not installed")
def test_secret_graded_by_git_state(request):
    repo = ROOT / "pytest_scan_tmp" / request.node.name
    _force_rmtree(repo)
    repo.mkdir(parents=True)
    try:
        (repo / ".gitignore").write_text(".env\n")
        (repo / ".env").write_text("API_KEY=Zq8v3LmP0xT7rK2wN9yB\n")
        (repo / "prod.env").write_text("API_KEY=Hj4kS8dF2gL6pQ0zX5cV\n")
        (repo / "new.env").write_text("API_KEY=Wn7bR3tY9uI1oP5aE8sD\n")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "add", ".gitignore", "prod.env"], cwd=repo, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"], cwd=repo, check=True)
        found = {f.file: f for f in scan_secrets(StubCtx(repo)) if f.vuln_class == "hardcoded_secret"}
        assert found["prod.env"].severity == "critical" and found["prod.env"].extra["git"] == "committed"
        assert found[".env"].severity == "info" and found[".env"].extra["git"] == "ignored"
        assert found["new.env"].extra["git"] == "untracked" and "NOT git-ignored" in found["new.env"].message
    finally:
        _force_rmtree(repo)


def test_unverified_status_depends_on_patch():
    f = Finding(rule_id="r", vuln_class="hardcoded_secret", title="", file="a", line=1)
    _unverified(f, "no oracle")
    assert f.status == Status.REPORT_ONLY.value and "no automatic patch" in f.extra["unverifiable_reason"]
    g = Finding(rule_id="r", vuln_class="xss", title="", file="a", line=1)
    g.recommended_patch = Patch(diff="d", source="template:x")
    _unverified(g, "no oracle")
    assert g.status == Status.PATCH_UNVERIFIED.value


def test_config_fixers():
    cfg = Finding(rule_id="streamlit-show-error-details", vuln_class="error_leakage", title="",
                  file=".streamlit/config.toml", line=5, extra={"config_key": "showErrorDetails"})
    text = (APP / ".streamlit" / "config.toml").read_text()
    new = streamlit_hide_error_details(FixContext(APP, cfg, cfg.file, text))
    assert 'showErrorDetails = "none"' in new and "showErrorDetails = true" not in new
    req = Finding(rule_id="supply-declared-package-mismatch", vuln_class="supply_chain", title="",
                  file="requirements.txt", line=5, extra={"declared": "dataset", "imported": "datasets"})
    text = (APP / "requirements.txt").read_text()
    new = requirements_declared_package(FixContext(APP, req, req.file, text))
    assert new.splitlines()[4] == "datasets" and "\ndataset\n" not in new
