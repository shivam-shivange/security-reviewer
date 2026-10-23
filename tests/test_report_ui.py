"""HTML report and dashboard: hostile scanned code must stay text, and labels must not overclaim."""

import re
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview.report.html import _patch_label, render_html   # noqa: E402

HOSTILE = '+name = "><img src=x onerror=alert(document.domain)>"'


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def _report(finding: dict) -> str:
    summary = {"reportable": 1, "verified_fixed": 0, "patch_unverified": 1, "needs_review": 0, "discarded": 0,
               "by_status": {"patch_unverified": 1}, "endpoints": 0, "elapsed_seconds": 1,
               "llm": {"provider": "fallback:x", "calls": 2, "cache_hits": 0, "served_by": {"gemini:m": 2}}}
    return render_html({"run_id": "r", "project": "p", "generated": "now", "summary": summary,
                        "findings": [finding], "endpoints": []})


def _finding(**kw) -> dict:
    f = {"title": "SQL Injection", "severity": "high", "status": "patch_unverified", "vuln_class": "sqli",
         "category": "injection", "file": "app.py", "line": 3, "message": HOSTILE, "code": HOSTILE,
         "attack": "SQLi", "attack_tier": "B", "cwe": ["CWE-89"],
         "recommended_patch": {"diff": f"--- a/app.py\n+++ b/app.py\n{HOSTILE}", "source": "llm", "description": HOSTILE},
         "evidence": {"method": "semgrep-taint", "chain": [{"file": "app.py", "line": 3, "code": HOSTILE, "note": "sink"}]}}
    f.update(kw)
    return f


def test_report_keeps_hostile_code_as_text():
    parser = Tags()
    parser.feed(_report(_finding()))
    assert not [t for t in parser.tags if t[0] == "img"]
    assert not [t for t in parser.tags if any(k.startswith("on") for k in t[1])]


def test_report_labels_do_not_overclaim():
    html = _report(_finding())
    assert "Docker" not in html and "Proven with Exploit" not in html
    assert "Tier B: enabling weakness" in html
    assert "answered by gemini:m ×2" in html
    assert _patch_label({"recommended_patch": {"diff": "d"}}) == "Recommended patch (not executed)"
    bump = {"patch": {"diff": "d"}, "verification": [{"passed": True, "patch_source": "dependency-bump"}]}
    assert _patch_label(bump) == "Verified fix (advisory's fixed version)"
    oracle = {"patch": {"diff": "d"}, "verification": [{"passed": True, "patch_source": "template:x"}]}
    assert _patch_label(oracle) == "Verified fix (exploit blocked, tests pass)"


def test_dashboard_never_puts_raw_diff_into_an_attribute():
    page = (ROOT / "secreview" / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    # JSON.stringify(...) inside a quoted onclick closes the attribute and turns the diff into markup
    assert not re.search(r'on\w+="[^"]*\$\{JSON\.stringify', page)
    assert 'data-diff="${esc(patch.diff)}"' in page
    assert "copyText('${" not in page    # a quote in a file name would break out of the JS string


def test_dashboard_colours_only_the_priority_word():
    page = (ROOT / "secreview" / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    # colour rules are scoped to the tag, so they cannot paint a whole card
    assert not re.search(r"(?m)^\s*\.priority-p[0-4]\s*\{", page)
    assert not re.search(r"\.finding-card\.priority-p", page)
    assert '<div class="finding-card">' in page
