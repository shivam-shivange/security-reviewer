# Set up the secreview Python environment and external tools inside this repository (Windows).
#   powershell -ExecutionPolicy Bypass -File scripts\setup_tools.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "Creating Python virtual environment (.venv) ..."
python -m venv "$root\.venv"
$py = "$root\.venv\Scripts\python.exe"
& $py -m pip install -q --upgrade pip
Write-Host "Installing Python tools and runtime deps ..."
& $py -m pip install -q semgrep bandit pip-audit ruff pytest `
    requests pyyaml jinja2 fastapi "uvicorn[standard]" tree-sitter tree-sitter-language-pack `
    flask django httpx
Write-Host "Installing Node / OSV / PMD tools ..."
& $py "$root\scripts\setup_tools.py"
Write-Host "`nDone. Try:  .venv\Scripts\python -m secreview.cli tools"
