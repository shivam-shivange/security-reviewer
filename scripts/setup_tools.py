"""Install the scanner's external tools INTO this repository (no system-wide installs).

    python scripts/setup_tools.py            # install everything that is missing
    python scripts/setup_tools.py --check    # only report what is present

Layout created:
    .venv/                      Python tools (semgrep, bandit, pip-audit, ruff) - created separately
    tools/node/node_modules/    eslint + plugins (JS/React general-bug tier)
    tools/bin/osv-scanner       dependency scanner for Maven/Gradle/npm/PyPI
    tools/pmd/                  PMD (Java general-bug tier)

Java (JDK) and PMD download links are printed if a JDK is not found; this script does not download a
JRE automatically. Node tools need `npm` on PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
IS_WIN = os.name == "nt"
OSV_VERSION = "1.9.1"

NODE_PACKAGES = [
    "eslint@^9", "@eslint/js@^9", "globals@^15", "typescript-eslint@^8",
    "eslint-plugin-react-hooks@^5",
]


def run(cmd, **kw):
    print("  $", " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, **kw)


def have(name: str) -> bool:
    from importlib import import_module
    sys.path.insert(0, str(ROOT))
    tools = import_module("secreview.tools")
    return bool(tools.which(name))


def setup_node(check: bool) -> None:
    node_dir = TOOLS / "node"
    if have("eslint"):
        print("✓ eslint present")
        return
    if check:
        print("✗ eslint missing (run without --check to install)")
        return
    if not shutil.which("npm"):
        print("✗ npm not on PATH; install Node.js to get the JavaScript general-bug tier")
        return
    node_dir.mkdir(parents=True, exist_ok=True)
    (node_dir / "package.json").write_text(json.dumps({"name": "secreview-tools", "private": True}), encoding="utf-8")
    shutil.copy(ROOT / "config" / "eslint.config.mjs", node_dir / "eslint.config.mjs")
    run(["npm" + (".cmd" if IS_WIN else ""), "install", "--no-fund", "--no-audit", *NODE_PACKAGES], cwd=node_dir)
    print("✓ eslint installed into tools/node")


def setup_osv(check: bool) -> None:
    if have("osv-scanner"):
        print("✓ osv-scanner present")
        return
    if check:
        print("✗ osv-scanner missing")
        return
    arch = "amd64" if platform.machine().lower() in ("amd64", "x86_64") else "arm64"
    osname = "windows" if IS_WIN else ("darwin" if sys.platform == "darwin" else "linux")
    ext = ".exe" if IS_WIN else ""
    url = (f"https://github.com/google/osv-scanner/releases/download/v{OSV_VERSION}/"
           f"osv-scanner_{osname}_{arch}{ext}")
    (TOOLS / "bin").mkdir(parents=True, exist_ok=True)
    dest = TOOLS / "bin" / f"osv-scanner{ext}"
    try:
        print(f"  downloading {url}")
        urllib.request.urlretrieve(url, dest)
        if not IS_WIN:
            dest.chmod(0o755)
        print("✓ osv-scanner installed into tools/bin")
    except Exception as exc:
        print(f"✗ could not download osv-scanner: {exc}\n  get it from https://github.com/google/osv-scanner/releases")


def setup_pmd(check: bool) -> None:
    if have("pmd"):
        print("✓ pmd present")
        return
    if check:
        print("✗ pmd missing (optional: Java general-bug tier)")
        return
    version = "7.7.0"
    url = f"https://github.com/pmd/pmd/releases/download/pmd_releases%2F{version}/pmd-dist-{version}-bin.zip"
    try:
        tmp = TOOLS / "pmd.zip"
        TOOLS.mkdir(parents=True, exist_ok=True)
        print(f"  downloading {url}")
        urllib.request.urlretrieve(url, tmp)
        with zipfile.ZipFile(tmp) as z:
            z.extractall(TOOLS)
        extracted = TOOLS / f"pmd-bin-{version}"
        target = TOOLS / "pmd"
        if target.exists():
            shutil.rmtree(target)
        extracted.rename(target)
        tmp.unlink()
        if not IS_WIN:
            (target / "bin" / "pmd").chmod(0o755)
        print("✓ pmd installed into tools/pmd")
    except Exception as exc:
        print(f"✗ could not install PMD: {exc}\n  get it from https://github.com/pmd/pmd/releases")


def check_jdk() -> None:
    if have("java"):
        print("✓ java present (needed for PMD and Java test runs)")
    else:
        print("✗ java not found. Install a JDK 17+ (e.g. https://adoptium.net) to run PMD and "
              "Java/Maven/Gradle verification. Place it on PATH or in tools/jdk/.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report only, do not install")
    ap.add_argument("--skip", nargs="*", default=[], help="skip: node osv pmd")
    args = ap.parse_args()
    print(f"secreview tool setup (repository: {ROOT})\n")
    print("Python tools (.venv) are installed separately; see scripts/setup_tools.ps1/.sh.\n")
    if "node" not in args.skip:
        setup_node(args.check)
    if "osv" not in args.skip:
        setup_osv(args.check)
    if "pmd" not in args.skip:
        setup_pmd(args.check)
    check_jdk()
    print("\nDone. Run `secreview tools` to see the final status.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
