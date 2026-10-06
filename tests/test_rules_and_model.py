"""Fast unit tests that need no external tools or LLM."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview.models import Finding, Status          # noqa: E402
from secreview.taxonomy import catalog, class_for_cwe, enrich  # noqa: E402


def test_taxonomy_loads_and_every_class_has_fields():
    cat = catalog()
    assert "sqli" in cat and "nosqli" in cat and "prototype_pollution" in cat
    for name, meta in cat.items():
        assert meta.get("title"), name
        assert "category" in meta, name
        assert "attack_tier" in meta, name


def test_cwe_mapping():
    assert class_for_cwe(["CWE-89"]) == "sqli"
    assert class_for_cwe(["CWE-1321"]) == "prototype_pollution"
    assert class_for_cwe(["CWE-99999"]) is None


def test_finding_fingerprint_stable():
    a = Finding(rule_id="r", vuln_class="sqli", title="", file="a.py", line=5, code="x = 1")
    b = Finding(rule_id="r", vuln_class="sqli", title="", file="a.py", line=5, code="x = 1")
    assert a.id == b.id
    c = Finding(rule_id="r", vuln_class="sqli", title="", file="a.py", line=6, code="y = 2")
    assert c.id != a.id


def test_enrich_fills_class_fields():
    f = Finding(rule_id="r", vuln_class="sqli", title="", file="a.py", line=1)
    enrich(f)
    assert f.cwe == ["CWE-89"]
    assert f.severity == "critical"
    assert f.attack and f.verifiable is True


def test_finding_roundtrip():
    f = Finding(rule_id="r", vuln_class="xss", title="X", file="a.py", line=1)
    enrich(f)
    d = f.to_dict()
    f2 = Finding.from_dict(d)
    assert f2.id == f.id and f2.vuln_class == "xss"


def test_semgrep_rules_valid():
    """All rule packs parse under semgrep --validate (skipped if semgrep absent)."""
    exe = ROOT / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / "semgrep"
    if not exe.exists():
        pytest.skip("semgrep not installed")
    r = subprocess.run([str(exe), "--validate", "--metrics=off", "--config", str(ROOT / "rules" / "semgrep")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
