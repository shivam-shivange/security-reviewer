"""Quote plain YAML scalars that contain ': ' in Semgrep rule sources (pattern/message lines).

    python scripts/quote_rule_scalars.py rules/semgrep_src
"""
import re
import sys
from pathlib import Path

LINE = re.compile(r"^(\s*(?:- )?(?:pattern|pattern-not|pattern-inside|pattern-not-inside|message|fix|regex|replacement|comparison): )(.*)$")

for path in Path(sys.argv[1] if len(sys.argv) > 1 else "rules/semgrep_src").rglob("*.yaml"):
    out, changed = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        m = LINE.match(line)
        if m:
            value = m.group(2)
            if value and value[0] not in "'\"|>" and (": " in value or value.rstrip().endswith(":") or " #" in value):
                line = m.group(1) + "'" + value.replace("'", "''") + "'"
                changed = True
        out.append(line)
    if changed:
        path.write_text("\n".join(out) + "\n", encoding="utf-8")
        print("quoted", path)
