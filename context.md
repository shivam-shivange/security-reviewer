# Project Context — Self-Verifying AI Security Reviewer

Running reference file. Update it whenever a decision is made, scope changes, or a milestone lands.
Last updated: 2026-10-23

## 1. What this project is
B.Tech final-year project (PCCOE Pune, CSE AI&ML, group GA16 — Shivam Shivange, Vinayak Pawara,
Aryan Enadle, Yashwardhan Patil; guide Dr. Santwana Gudhade).

A **whole-project scanner** that finds security vulnerabilities (and, at lower confidence, general
bugs) in a codebase, maps each one to the information-security attack it enables, and proves its
fixes by running them. Pipeline: **Detect → Ground → Patch → Verify**.

Source documents (in this folder):
- `Self-Verifying_AI_Security_Reviewer_Synopsis (3).docx` — short synopsis
- `Project Deep Analysis (4).docx` — full analysis: tiers, tools, 10 target classes, output format

Guiding principle (from the docs): the tool finds the **code flaw that makes an attack possible**,
not the attack itself. Runtime/network/human attacks (phishing, DDoS, ransomware, etc.) are out of scope.

## 2. Decisions made
| Date | Decision |
|---|---|
| 2026-10-06 | LLM backend has 3 switchable options: **local (Ollama)**, **OpenRouter API**, **Google Gemini API**. Which one is used in practice is decided later. Docs updated to say so. |
| 2026-10-06 | Target languages: **Python**, **Java**, **JavaScript (MERN: MongoDB, Express, React, Node)**. |
| 2026-10-06 | **Minimise LLM use.** Prefer deterministic rules, predefined fix templates, predefined exploit-test templates and predefined scripts; call the LLM only when nothing predefined fits. |
| 2026-10-06 | Keep a library of **predefined, reusable scripts** (scanner runners, Dockerfiles, test runners, fix templates, PoC templates) instead of generating them each time. |
| 2026-10-06 | Scope and requirements must be confirmed with the user **before** implementation starts. |
| 2026-10-06 | Extra classes added beyond the docs' ten: **NoSQL injection, prototype pollution, insecure deserialization**, plus code injection, XXE, open redirect, weak crypto/randomness, JWT misuse, CORS misconfig, debug mode, and an **access-control & API-leakage** family: open (unauthenticated) endpoints, missing/inconsistent role checks (RBAC), IDOR/BOLA, mass assignment, client-controlled roles, sensitive-data leakage in responses, stack-trace leakage, secrets in logs/frontend/repo. NOTE: the docs list access control as a non-goal; these are implemented as rule/heuristic findings labelled *Needs review* (not exploit-verified). The docs should be updated to match later. |
| 2026-10-06 | **General bugs**: reported, with a *Recommended patch* section. Deterministic fixes (Ruff/ESLint autofix) are shown; the LLM-based recommended patch is **implemented but disabled by default** (`general_bugs.llm_patch = false`). |
| 2026-10-06 | The tool **never modifies the scanned project**. It outputs patch files + reports; `--apply` is optional. |
| 2026-10-06 | **Web dashboard** (in addition to CLI): runs, live stage/progress, event log, findings, finding detail, API-surface (endpoint) inventory, pending **permission requests** (approve/deny), tool status, LLM settings. |
| 2026-10-06 | Tier 2 rules (TLS, rate limiting, credential storage, file upload) are built **now**, alongside Tier 1. |
| 2026-10-06 | Java: **both Maven and Gradle**. |
| 2026-10-06 | Target scale: industry-grade average to large projects → module-by-module scanning, incremental caches, excludes. |
| 2026-10-06 | Testing/evaluation is **later**; now implementation only. Dataset shortlist to be researched and reported. |
| 2026-10-06 | Git remote: `https://github.com/shivam-shivange/security-reviewer.git` (**public**). Work under the **shivam-shivange** account (local git identity `shivam-shivange <shivamshivange@gmail.com>`; `gh` active account switched to shivam-shivange). The .docx files (contain names/PRNs) are kept out of git until the user confirms. |
| 2026-10-06 | All tools are installed **inside this folder**: `.venv/` (Python tools), `tools/` (Node tools, OSV-Scanner, JDK, PMD, SpotBugs). |
| 2026-10-06 | API keys come later (env vars `OPENROUTER_API_KEY`, `GEMINI_API_KEY`). LLM is optional everywhere; the tool must work with the LLM disabled. |

## 3. Scope and architecture (confirmed 2026-10-06)

### Stages and where the LLM is (and isn't) used
| Stage | Deterministic path (default) | LLM (optional fallback) |
|---|---|---|
| Discover | Language/framework/module detection, file walk with excludes, endpoint inventory | — |
| Detect | Semgrep (custom rule packs per language), Bandit, secret scanner, dependency scanners, linters, access-control/leakage analyzer | — |
| Ground | Semgrep taint trace = evidence; rule matches = evidence; advisories for deps | ambiguous findings only (`ground.llm = auto`) |
| Patch | Semgrep `fix:` rules → fixer templates (per class × language) → dependency version bumps | when no template applies (`patch.llm_fallback`) |
| Verify | Predefined Docker sandboxes + exploit harnesses (oracle per class) + regression suite | PoC generation (`poc.llm_fallback`, off by default) |
| Report | JSON, HTML, patch files, dashboard | — |

### Finding statuses
`verified_fixed` · `patch_unverified` (patch exists; verification not possible or failed) · `discarded` (grounding rejected it) · `needs_review` (heuristic finding) · `report_only` (general bugs / advisories without a fix)

### Predefined assets (reused, not generated)
- `rules/semgrep/<lang>/*.yaml` — detection rules (with `fix:` where expressible)
- `rules/secrets.yaml`, `rules/sanitizers.yaml`, `rules/auth_markers.yaml` — knowledge bases
- `secreview/patch/templates/` — fixer templates per language
- `harness/` — exploit harnesses (Python/Flask/FastAPI/Django, Node/Express, Java/Spring MockMvc) + `oracles.yaml` (payloads + success checks per class)
- `docker/` — toolbox + sandbox Dockerfiles (python, maven, gradle, node, mongo)
- `scripts/` — setup, test-runner and helper scripts

Earlier design points (kept):
- **Detect** (no LLM): Semgrep (all 3 languages, custom rule packs), Bandit (Python), dependency
  scanning (pip-audit / npm audit / OSV-Scanner for Maven & npm), linters for the general-bug tier
  (Ruff, ESLint, SpotBugs/PMD). Tools run from a predefined Docker "toolbox" image so Windows support issues don't matter.
- **Ground** (deterministic first): use the taint trace from Semgrep as evidence; known sanitizers
  discard the finding automatically; the LLM is consulted only for findings the rules can't settle.
- **Patch** (templates first): predefined fix templates per class × language (parameterised queries,
  escaping, `shell=False`/arg lists, path canonicalisation + base-dir check, URL allowlist, etc.);
  the LLM is used only when no template applies.
- **Verify**: predefined Dockerfiles per stack (Python / Maven / Gradle / Node + Mongo); exploit test
  must FAIL on the original code and PASS on the patched code, and the existing test suite must still
  pass; failures are retried up to a fixed limit.
- **Provenance**: git blame per finding (annotation only, no causal claim).
- **Report**: JSON + HTML; status = Verified Fixed / Grounded but Unverified / Discarded at Grounding.
- **Attack mapping**: each finding is tagged with the attack it enables (Tier A/B from the docs).
- **LLM response cache** so that repeat scans don't call the LLM again.

## 4. Environment (dev machine, checked 2026-10-06)
- Windows 11, Python 3.13.7, Node 22.18, Git 2.54, Docker 28.3 (Desktop daemon was **not running**).
- 7.3 GB RAM, integrated AMD Radeon GPU (no dedicated VRAM) → can't run a 7B–14B coding model well;
  cloud LLM options will be needed for good Ground/Patch quality on this machine.
- Ollama 0.35 installed with small models only: gemma3:4b, qwen3.5:4b, qwen2.5-coder:1.5b,
  deepseek-r1:1.5b, nomic-embed-text.
- Not yet installed: semgrep, bandit, pip-audit, osv-scanner, pytest (all installable / dockerisable).

## 5. Open questions for the user
(see the 2026-10-06 conversation; move answers to section 2 when resolved)

## 5b. Implementation status (2026-10-06)
**Working end-to-end** (Detect → Ground → Patch → Verify → Report), tested on `examples/flask-vuln`:
SQLi, XSS and open-redirect are **verified-fixed by execution** with deterministic templates, plus
dependency bumps. cmdi/path-traversal verify on Linux/Docker (Windows local-mode shell/path
semantics differ).

Built:
- Core: `config.py`, `models.py`, `taxonomy.py`, `store.py` (SQLite), `context.py`, `discovery.py`,
  `tools.py`, `provenance.py` (git blame), `slicer.py`, `ts.py` (tree-sitter).
- LLM: `llm/` — 3 backends (Ollama/OpenRouter/Gemini), response cache, availability gate + cloud
  permission. Tool runs fully without an LLM.
- Detect (no LLM): Semgrep packs (105 rules, `rules/semgrep_src` → built by `scripts/build_rules.py`),
  Bandit, secret+config scanner, dependency scan (OSV/pip-audit/npm), linters (Ruff/ESLint/PMD),
  access-control analyzer (Express/Flask/FastAPI/Django/Spring endpoint inventory + RBAC/IDOR/leakage).
- Ground: taint-trace/rule/advisory evidence first; LLM only for ambiguous findings; LLM chains are
  machine-checked against source.
- Patch: 42 deterministic fix templates (`patch/py_fixers`, `js_fixers`, `java_fixers`) + semgrep-fix
  + dependency bump; LLM fallback with self-consistency.
- Verify: Docker sandbox (`docker/` images) + Local sandbox (dev); exploit oracles
  (`harness/oracles.yaml`) + Python & Node harnesses; retry loop feeds failures back to Patch.
- Report: JSON + self-contained HTML (`report/html.py`) + patch files.
- CLI: `secreview scan|tools|llm|runs|report|dashboard`.
- Tests: `tests/` (rules valid, taxonomy, 42 fixers on snippets, pipeline smoke + ablation).
- Setup: `scripts/setup_tools.{py,ps1,sh}` install tools into `.venv/` and `tools/`.

**Dashboard DONE (2026-10-07):** live web UI at `secreview dashboard` — runs list, stage progress,
event log, findings (evidence/diff/verification), API-surface table, permission approve/deny.

**TODO:** Java verification harness, Node harness wired into the Docker image, more sample apps
(Express+MongoDB / Spring) for the evaluation phase, evaluation runner for `docs/datasets.md`.
Git: still local only (not pushed; user chose "keep local"). Only `examples/flask-vuln` exists as a
built-in smoke-test fixture (user informed).

### Known issues / gaps (noted 2026-10-07)
- **Patch is not a visible pipeline stage.** The pipeline surfaces Discover → Detect → Ground →
  Verify → Report (see `pipeline.py`), but **Patch** has no stage of its own: patch candidates are
  generated *inside* the Verify stage (`verify/engine.py` calls `patch/engine.candidates()` per
  finding). So the dashboard/progress never shows a "Patch" step. User flagged this 2026-10-07;
  **deferred**. Fix later by either (a) adding an explicit Patch stage that pre-generates candidate
  patches for all grounded findings before Verify and reports progress, or (b) renaming the stage to
  "Patch & Verify" so the UI reflects what happens. The Patch *code* is complete and working
  (42 templates + semgrep-fix + dependency bump + LLM fallback); only its visibility as a stage is
  missing.
- Dashboard concurrency: runs one scan at a time; orphaned "running" runs are swept to failed on
  restart (fixed 2026-10-07). npm audit / pip-audit now time-bounded (fixed 2026-10-07).

### Gap analysis vs. Automotive-Fault-Diagnosis-Agent (run 20261022-113222-5d1f8e, reviewed 2026-10-23)
Target = Streamlit + LangGraph + Groq LLM + Qdrant RAG app. Tool reported 11 findings (2 secrets in a
git-ignored `.env`, 1 cmdi FP on a constant `os.system`, 8 lint nits). Manual review found the real
issues the tool **missed**: prompt injection (user free-text, unvalidated DTCs and freeze-frame values
go straight into the LLM prompt; LLM output is chained into a second LLM), indirect prompt injection /
RAG poisoning (`data/scraper.py` web content → knowledge base → prompt), LLM output rendered as
markdown (`st.markdown`/`st.info`), unbounded consumption (no limit on DTC count or freeze-frame length,
no auth or rate limiting, 2 paid LLM calls per submit), `showErrorDetails = true` + raw exception
shown in the UI, unpinned `requirements.txt` with the wrong package (`dataset` instead of `datasets`),
unpinned HF dataset/model downloads (Bandit B615 found but filed as `general_bug`), one Qdrant key
used for both writing (ingest) and reading (app).
Tool-side gaps: no LLM/AI rule pack, no Streamlit/Gradio source model (endpoints = 0), secrets in
git-ignored/uncommitted files rated high, supply-chain issues downgraded to general_bug, dependency scan
silent on unpinned manifests, misleading `patch_unverified` status for findings with no patch.
**DONE 2026-10-23 (all non-LLM improvements, user-approved):** `detect/ai_app.py` (cross-file AI-app
analyzer: prompt injection + agent chaining, LLM output -> markdown/HTML, RAG poisoning via shared data
files + shared write key, unbounded LLM consumption, Streamlit/Gradio endpoints, `.streamlit/config.toml`,
exception display), `rules/semgrep_src/python/llm.yaml` (same-function LLM taint + HF/torch.hub supply
chain), `detect/supply_chain.py` (unpinned requirements, declared-vs-imported mismatch, npm wildcards /
lockfile), git-aware secret grading + dot-dir config scan, Bandit constant-command FP -> discarded, B615 ->
supply_chain, `report_only` instead of `patch_unverified` when no patch exists, `patch/config_fixers.py`.
New classes: supply_chain, prompt_injection, rag_poisoning, llm_output_handling, llm_resource_abuse
(`heuristic: true` => needs_review). Fixture `examples/llm-streamlit-vuln` + `tests/test_ai_and_supply_chain.py`.
Result on the Automotive project: 15 security findings (was 3, 1 FP); all 7 manual gaps now detected.
Not done: JavaScript/Java LLM-app rules (Python only so far).

## 7. Gotchas learned (save time later)
- **Git object files are read-only on Windows** -> `shutil.rmtree(ignore_errors=True)` silently leaves
  git-initialised test dirs behind and the next run fails with FileExistsError. Tests use `_force_rmtree`.
- Streamlit defaults: `client.showErrorDetails` = "full" and `server.address` unset (all interfaces), so a
  Streamlit app with no config leaks tracebacks and listens on the LAN.
- The tool's LLM prompts are small (~0.8k tokens avg, 1.2k max: a +/-25-line slice + ~1.1k-char system
  prompt); output ~0.2k (ground) / ~0.4k (patch). Use these numbers for cost estimates.
- **Semgrep skips dot-directories and respects the enclosing git repo's `.gitignore`.** Scanning a
  copy placed under a `.`-prefixed or git-ignored folder returns 0 findings. Tests copy the sample
  into a non-ignored dir and `git init` it.
- **Semgrep on Windows hangs when the scan target is under `%TEMP%`** (`AppData\Local\Temp`), likely
  Defender. Keep scan targets on the project drive; `scan.semgrep_timeout_seconds` bounds it.
- Semgrep rejects YAML anchors → authored in `rules/semgrep_src/`, expanded by
  `scripts/build_rules.py`; `scripts/quote_rule_scalars.py` quotes scalars containing `: `.
- The base `.venv` needs `flask`/`django` for local-mode harness to import common apps.
- Windows local sandbox can't run bash-shell cmdi payloads or `/tmp` canary paths → cmdi &
  path-traversal verify on Docker/Linux, not Windows local mode (expected).

## 8. Change log
- 2026-10-24: **Secrets kept out of LLM prompts** (`secreview/redact.py`).
  - **Masking:** every prompt is masked in `LLMClient.complete`. It covers known key formats (from
    `rules/secrets.yaml`), private keys, credentialed URIs, quoted secret literals and `.env`-style lines.
  - **Exclusion:** secret findings and secret files (`.env*`, `*.pem`, `secrets.*`...) are never sent
    (`llm_allowed`). Deterministic fixes still apply to them.
  - **Why:** before this, LLM patch requests read raw slices, so `.env` values could reach the cloud. In
    both affected scans (AI-Interviewer-Bot, and this repo scanned at 02:07) the `.env` findings were not
    reached before the run was stopped; the cached answers confirm no key appeared.
  - **Empty LLM replies** now count as provider failures, so the fallback cools that provider down.
- 2026-10-24: **Stop / Skip act immediately.** LLM calls run in a thread polled every 0.5 s and are abandoned
  on Stop / Skip; retry pauses are interruptible. Detect-only Patch & Verify gained per-finding checkpoints
  (it had none, so Skip waited for the whole stage). Sandbox subprocesses (Verify with oracles) are still
  checked only between findings.
- 2026-10-24: **Live Stop / Skip** (user request). A running scan shows "⏭ Skip <stage> → Report" and
  "⏹ Stop" in the dashboard.
  - **How it works:** the request is stored on the run (`runs.control`), so CLI scans can be stopped from the
    dashboard too. Every `ctx.progress()` is a checkpoint; an LLM call in flight finishes first, and a
    pending permission prompt notices immediately. `RunStopped` / `StageSkipped` derive from BaseException
    so per-tool `except Exception` guards cannot swallow them.
  - **Skip:** ends the stage (marked skipped with how far it got) and jumps to the report. Detect keeps the
    findings of the tools that had finished.
  - **Stop:** marks the run and stage `stopped`. Ctrl+C in the CLI does the same. Stopped runs can be resumed
    from Ground / Verify.
  - **API:** `POST /api/runs/{id}/stop|skip`. A run with no live process (silent for 10 min) is marked stopped
    at once.
  - **Timeouts:** `llm.timeout_seconds` is now 90 (cloud); local Qwen has its own 300 s (`llm.local.timeout_seconds`).
- 2026-10-24: **Continue a finished run from a skipped stage** (user request). In the dashboard, a skipped
  or failed Ground / Patch & Verify card is clickable: it asks to confirm (LLM, sandbox, optional Verify),
  then runs that stage and the later ones on the same run, reusing Detect's findings (no rescan).
  - CLI: `secreview continue <run-id> --from ground|verify`.
  - The pipeline saves `findings_before_{ground,verify}.json` per run; older runs fall back to `_reset`.
  - API: `POST /api/runs/{id}/continue`. The scan lock is now set before the worker thread starts.
  - The writer clears stale patch files when it rewrites a report.
- 2026-10-24: Ablation (`--no-ground`) fixed: it used to wipe Detect's own decisions (heuristic evidence
  chains -> "none", the constant-command discard revived). Now it skips only Ground's checks.
- 2026-10-24: Dashboard/report fixes on top of the user's UI redesign:
  - **Stages:** stages switched off are recorded as `skipped` (Ground in ablation, Verify in detection-only,
    Provenance outside a git root) and drawn as skipped, not "DONE".
  - **Filters:** active filters are shown with clear buttons; category counts follow the other filters;
    search keeps focus while typing.
  - **XSS:** fixed in the Copy Diff button (diff was put into an onclick attribute).
  - **Wording:** no "Docker"/"proven by exploit" claims unless true; Tier A/B worded correctly.
  - **Report:** status and category filter rows now combine; the header shows `served_by`.
  - Tests in `tests/test_report_ui.py`; 38 tests pass.
- 2026-10-24: **LLM fallback chain decided and built**: `llm.provider = "fallback"` (default; also in `.env`),
  order OpenRouter → Gemini → local Qwen (`llm.fallback_order`), 300 s cooldown for a failed provider,
  invalid JSON falls through without cooldown, declined cloud consent leaves only local. `llm/fallback.py`,
  `tests/test_llm_fallback.py`; live-tested all three paths. 35 tests pass.
- 2026-10-23: **LLM models chosen by bake-off** (see `docs/llm_models.md`): OpenRouter
  `poolside/laguna-s-2.1:free` (4/4, main), Gemini `gemini-3.5-flash-lite` (4/4, fastest), Ollama
  `qwen3.5:4b` (2/4, ~2–2.5 min/call on CPU; small local models are unreliable). Set in
  `config/default.toml` and `.env`; `llm.timeout_seconds` raised 180 → 300 for local models.
- 2026-10-23: `plan.md` created: phase status (~55% overall) and milestone timeline M1–M7 to the
  final defence (assumed late April 2027; dates to be matched to the college calendar).
- 2026-10-23: main pushed (pre-today code); `new_updates` branch pushed with today's work.
- 2026-10-23: AI/LLM + supply-chain + git-aware-secrets detection added (see 5b gap analysis). 28 tests pass.
- 2026-10-06: **Initial implementation committed** (commit 5979150, 104 files, local only — NOT
  pushed to the public remote yet, pending user confirmation; .docx kept out of git — contain PII).
  End-to-end pipeline working; 17 tests pass.
- 2026-10-06: Added the dual/triple LLM option (local Ollama / OpenRouter / Gemini) to both .docx
  files (abstract, software & hardware requirements, table 7.2, new "LLM backend selection" paragraph,
  best-practices bullet). Originals backed up outside the repo.
- 2026-10-06: context.md created. No code written yet.
