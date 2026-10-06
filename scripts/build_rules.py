"""Expand YAML anchors in Semgrep rule sources (Semgrep's parser rejects anchors/aliases).

Rule authors write `rules/semgrep_src/<lang>/*.yaml` using anchors for shared sources/sinks;
this script writes the expanded files to `rules/semgrep/<lang>/` and validates them.

    python scripts/build_rules.py            # build + validate all languages
"""

from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "rules" / "semgrep_src"
OUT = ROOT / "rules" / "semgrep"


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def build() -> list[Path]:
    written = []
    for src in sorted(SRC.rglob("*.yaml")):
        text = src.read_text(encoding="utf-8")
        header = "".join(line for line in text.splitlines(True)[:5] if line.startswith("#"))
        data = copy.deepcopy(yaml.safe_load(text))
        out = OUT / src.relative_to(SRC)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("# GENERATED from rules/semgrep_src by scripts/build_rules.py - edit the source.\n"
                       + header + yaml.dump(data, Dumper=NoAliasDumper, sort_keys=False, width=120,
                                            allow_unicode=True), encoding="utf-8")
        written.append(out)
    return written


def validate() -> int:
    exe = ROOT / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / "semgrep"
    p = subprocess.run([str(exe), "--validate", "--metrics=off", "--config", str(OUT)],
                       capture_output=True, text=True)
    print((p.stdout + p.stderr).strip().splitlines()[0] if (p.stdout + p.stderr).strip() else "no output")
    if p.returncode:
        print(p.stdout, p.stderr)
    return p.returncode


if __name__ == "__main__":
    for path in build():
        print("built", path.relative_to(ROOT))
    sys.exit(validate())
