#!/usr/bin/env bash
# Set up the secreview Python environment and external tools inside this repository (Linux/macOS).
#   bash scripts/setup_tools.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Creating Python virtual environment (.venv) ..."
python3 -m venv "$ROOT/.venv"
PY="$ROOT/.venv/bin/python"
"$PY" -m pip install -q --upgrade pip
echo "Installing Python tools and runtime deps ..."
"$PY" -m pip install -q semgrep bandit pip-audit ruff pytest \
    requests pyyaml jinja2 fastapi "uvicorn[standard]" tree-sitter tree-sitter-language-pack \
    flask django httpx
echo "Installing Node / OSV / PMD tools ..."
"$PY" "$ROOT/scripts/setup_tools.py"
echo ""
echo "Done. Try:  .venv/bin/python -m secreview.cli tools"
