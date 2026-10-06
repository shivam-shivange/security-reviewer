"""Python verification harness used only inside the sandbox by the Verify stage.

Purpose: decide whether ONE finding is still present, by sending the oracle's test inputs to the
app through its in-process test client and checking the oracle condition. It is the pass/fail oracle
that lets the Verify stage prove a fix: the same probe must trigger on the original code and NOT
trigger after the patch. It drives the user's own application; it does not attack anything external.

    python verify_harness.py spec.json
    -> prints one line:  SECREVIEW_RESULT {"result": "vulnerable|blocked|error", ...}
    exit 0 = triggered (vulnerable), 1 = not triggered (blocked), 2 = inconclusive/error
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from probe import load_oracle, result_line  # noqa: E402
from clients import build_client  # noqa: E402


def main() -> int:
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    os.chdir(spec.get("project_dir", "."))
    sys.path.insert(0, spec.get("project_dir", "."))
    try:
        oracle = load_oracle(spec["vuln_class"], spec)
    except KeyError as exc:
        print(result_line("error", reason=f"no oracle for {exc}"))
        return 2
    try:
        client = build_client(spec)
    except Exception as exc:  # app failed to import / construct
        print(result_line("error", reason=f"could not load app: {exc}", trace=traceback.format_exc()[-1500:]))
        return 2
    try:
        verdict = client.run(oracle)
    except Exception as exc:
        print(result_line("error", reason=f"probe failed: {exc}", trace=traceback.format_exc()[-1500:]))
        return 2
    print(result_line(verdict.result, **verdict.detail))
    return {"vulnerable": 0, "blocked": 1}.get(verdict.result, 2)


if __name__ == "__main__":
    sys.exit(main())
