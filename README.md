# Self-Verifying AI Security Reviewer (`secreview`)

A whole-project security scanner for **Python, Java (Maven + Gradle) and JavaScript/MERN** that
finds vulnerabilities, maps each to the attack it enables, and **proves its fixes by running them**.
It uses a four-stage pipeline and keeps LLM use to a minimum — deterministic rules, fix templates
and exploit oracles do the work; the LLM is only a fallback.

```
Detect  ──►  Ground  ──►  Patch  ──►  Verify  ──►  Report
(scanners)  (evidence)  (templates)  (sandbox)   (JSON/HTML/dashboard)
   no LLM    LLM only     LLM only    executes     —
            if ambiguous  if no       the fix
                          template
```

A fix is only reported as **Verified Fixed** when an exploit oracle triggers on the original code,
stops triggering after the patch, and the project's existing tests still pass — all inside a sandbox.

## What it detects

Injection (SQLi, NoSQLi, XSS, command, code, path traversal, SSRF, open redirect, XXE,
insecure deserialization, prototype pollution); configuration & crypto (disabled TLS validation,
missing rate limiting, weak/plaintext credential storage, hardcoded secrets, weak crypto, insecure
randomness, JWT misuse, unrestricted upload, CORS, debug mode); access control & API leakage (open
endpoints, missing/inconsistent role checks, IDOR/BOLA, mass assignment, client-controlled authz,
sensitive-data exposure, error/secret leakage); vulnerable dependencies; and a lower-confidence
general-bug tier (Ruff / ESLint / PMD). See [rules/taxonomy.yaml](rules/taxonomy.yaml).

## Install

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts\setup_tools.ps1
```
```bash
# Linux / macOS
bash scripts/setup_tools.sh
```
This creates `.venv/` (Python tools) and installs Node/OSV/PMD into `tools/` — all inside this repo,
nothing system-wide. Docker Desktop is needed for the isolated Verify sandbox (see below).

## Use

```bash
# scan a project (deterministic only, no LLM)
.venv/Scripts/python -m secreview.cli scan path/to/project --no-llm

# with a local LLM (Ollama) or a cloud provider
.venv/Scripts/python -m secreview.cli scan path/to/project --provider local
.venv/Scripts/python -m secreview.cli scan path/to/project --provider openrouter   # needs OPENROUTER_API_KEY
.venv/Scripts/python -m secreview.cli scan path/to/project --provider gemini        # needs GEMINI_API_KEY

secreview tools            # show which external tools are available
secreview llm --test       # check the configured LLM backend
secreview runs             # list past runs
secreview report --open    # open the latest HTML report
secreview dashboard        # live web dashboard
```

Key flags: `--sandbox docker|local` (local is **not** isolated — dev only), `--no-ground`
(ablation), `--yes` (auto-approve permission prompts), `--open` (open the report).

## LLM backends (all optional)

Configured in [config/default.toml](config/default.toml) or via env vars; pick with `--provider`.

| Provider | Setting | Key |
|----------|---------|-----|
| `local` (Ollama, default) | `SECREVIEW_LOCAL_MODEL`, `OLLAMA_HOST` | none |
| `openrouter` | `SECREVIEW_OPENROUTER_MODEL` | `OPENROUTER_API_KEY` |
| `gemini` | `SECREVIEW_GEMINI_MODEL` | `GEMINI_API_KEY` |

The tool runs fully without any LLM (`--no-llm`); responses are cached so repeat scans are free.

## Verify sandbox

- **docker** (default, isolated): builds a per-stack image from [docker/](docker) and runs the
  exploit oracle + tests with networking disabled.
- **local** (dev only, **not isolated**): runs the harness directly on the host. Requires approval.

## Layout

| Path | What |
|------|------|
| `secreview/` | the package (detect / ground / patch / verify / report / dashboard) |
| `rules/` | Semgrep rule packs, taxonomy, secret & auth knowledge bases |
| `secreview/patch/*_fixers.py` | deterministic fix templates per language |
| `harness/` | exploit oracles + per-language verification harnesses |
| `docker/` | sandbox Dockerfiles |
| `examples/` | deliberately vulnerable sample apps |
| `docs/datasets.md` | datasets for the evaluation phase |
| `context.md` | running project record |

## Scope & honesty

This tool finds the **code flaw that makes an attack possible**, not the attack itself. Runtime,
network and human-layer attacks (phishing, DDoS, ransomware, etc.) are out of scope, as are
access-control findings' exploit-verification (reported as *needs review*). See `context.md` and the
project synopsis for the full scope and feasibility tiers.
