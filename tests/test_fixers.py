"""Unit tests for deterministic fix templates: each must remove the pattern and stay valid syntax."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview.models import Finding                       # noqa: E402
from secreview.patch import java_fixers, js_fixers, py_fixers  # noqa: E402,F401
from secreview.patch.base import FixContext, fixers_for, syntax_ok  # noqa: E402


def _apply(language, vuln_class, code, line, tmp_path):
    f = Finding(rule_id="t", vuln_class=vuln_class, title="", file="x", line=line, language=language)
    for spec in fixers_for(language, vuln_class):
        fc = FixContext(project=tmp_path, finding=f, file="x", text=code)
        try:
            out = spec.fn(fc)
        except Exception:
            continue
        if out and out != code and syntax_ok(language, f"x.{_ext(language)}", out):
            return out, spec.name
    return None, None


def _ext(lang):
    return {"python": "py", "javascript": "js", "java": "java"}[lang]


def test_py_sqli_parameterized(tmp_path):
    code = ('def f(cur, name):\n'
            '    query = "SELECT * FROM u WHERE n = \'" + name + "\'"\n'
            '    cur.execute(query)\n')
    out, name = _apply("python", "sqli", code, 3, tmp_path)
    assert out and "execute(query, (" in out and "+ name" not in out.split("execute")[0].splitlines()[-1]


def test_py_cmdi_no_shell(tmp_path):
    code = 'import os\ndef f(host):\n    os.system("ping -c 1 " + host)\n'
    out, name = _apply("python", "cmdi", code, 3, tmp_path)
    assert out and "subprocess" in out and "os.system" not in out


def test_py_yaml_safe_load(tmp_path):
    code = 'import yaml\ndef f(data):\n    return yaml.load(data)\n'
    out, _ = _apply("python", "deserialization", code, 3, tmp_path)
    assert out and "safe_load" in out


def test_py_tls_verify(tmp_path):
    code = 'import requests\ndef f(u):\n    return requests.get(u, verify=False)\n'
    out, _ = _apply("python", "tls_validation", code, 3, tmp_path)
    assert out and "verify=True" in out


def test_js_sqli(tmp_path):
    code = 'function f(db, name) {\n  return db.query("SELECT * FROM u WHERE n = \'" + name + "\'");\n}\n'
    out, _ = _apply("javascript", "sqli", code, 2, tmp_path)
    assert out and ("?" in out or "$1" in out) and "[" in out


def test_js_nosqli_eq(tmp_path):
    code = 'async function f(User, req) {\n  return await User.findOne({ name: req.body.name });\n}\n'
    out, _ = _apply("javascript", "nosqli", code, 2, tmp_path)
    assert out and "$eq" in out


def test_js_cmdi_execfile(tmp_path):
    code = 'const cp = require("child_process");\nfunction f(name){ cp.exec("ls " + name); }\n'
    out, _ = _apply("javascript", "cmdi", code, 2, tmp_path)
    assert out and "execFile" in out


def test_js_proto_merge(tmp_path):
    code = 'const _ = require("lodash");\nfunction f(req){ _.merge({}, req.body); }\n'
    out, _ = _apply("javascript", "prototype_pollution", code, 2, tmp_path)
    assert out and ("secreviewStripProto" in out or "__proto__" in out)


def test_java_sqli(tmp_path):
    code = ('class A {\n  void f(java.sql.Connection c, String name) throws Exception {\n'
            '    var st = c.createStatement();\n'
            '    st.executeQuery("SELECT * FROM u WHERE n = \'" + name + "\'");\n  }\n}\n')
    out, _ = _apply("java", "sqli", code, 4, tmp_path)
    assert out and "prepareStatement" in out and "setString" in out


def test_java_cmdi(tmp_path):
    code = ('class A {\n  void f(String h) throws Exception {\n'
            '    Runtime.getRuntime().exec("ping -c 1 " + h);\n  }\n}\n')
    out, _ = _apply("java", "cmdi", code, 3, tmp_path)
    assert out and "ProcessBuilder" in out
