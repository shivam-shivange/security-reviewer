# Project Context — Self-Verifying AI Security Reviewer

Running reference file. Update it whenever a decision is made, scope changes, or a milestone lands.
Last updated: 2026-10-06

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

**TODO:** web dashboard (CLI stub present), Java verification harness, Node harness wired into Docker
image, more sample apps (Express/Spring), evaluation runner for `docs/datasets.md`.

## 6. Change log
- 2026-10-06: Added the dual/triple LLM option (local Ollama / OpenRouter / Gemini) to both .docx
  files (abstract, software & hardware requirements, table 7.2, new "LLM backend selection" paragraph,
  best-practices bullet). Originals backed up outside the repo.
- 2026-10-06: context.md created. No code written yet.
