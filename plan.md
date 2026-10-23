# Project Plan: Self-Verifying AI Security Reviewer

Group GA16 (PCCOE Pune, CSE AI&ML). Guide: Dr. Santwana Gudhade.
Written 2026-10-23. Check it against `context.md` (the running log of decisions) whenever plans change.

> **Assumed dates.** The synopsis and analysis documents have no calendar. This plan assumes a
> Semester VII progress review in **late November 2026**, a winter exam/break until early January, and
> a final demo and report in **late April 2027**. Change the milestone dates below to match the
> college's academic calendar. The order of the work stays the same either way.

---

## 1. What we are building, and why

**What:** a tool that scans a whole codebase (Python, Java, JavaScript/MERN). It finds the code flaws that
make real attacks possible, and it reports a fix as *verified* only after it has proven the fix by
running it.

The pipeline is **Discover → Detect → Ground → Patch → Verify → Report**:

| Stage | What it does | Why it exists |
|---|---|---|
| Detect | Semgrep, Bandit, secret/config scanner, dependency scanners, access-control and AI-app analyzers, linters | Cheap and deterministic, so we can run it on every scan |
| Ground | Keeps a finding only if it has evidence: a taint trace, a rule match, an advisory, or a source-checked LLM chain | Static scanners raise many false positives, and this stage cuts them |
| Patch | Fix templates first; the LLM is used only when no template fits | Fixes are predictable and cheap, and need no LLM by default |
| Verify | Docker sandbox: the exploit must work before the patch, stop working after it, and the project's tests must still pass | The guarantee other tools don't give: a fix is shown to work, not just suggested |
| Report | JSON, HTML, patch files and a live dashboard | Every claim comes with its evidence and logs, so a reviewer can check it |

**Guiding principle:** we find the *code flaw* that enables an attack, not the attack itself. Attacks
that happen only at runtime, on the network or through people (phishing, DDoS, ransomware…) are out of scope.

---

## 2. Current progress (as of 2026-10-23)

**Overall: about 55% of the full project.** Building the tool is mostly done. Proving it works
(Docker verification, real LLM runs, evaluation) has barely started, and that is what the
final grade rests on.

| # | Phase | Status | Done | Evidence / what's left |
|---|---|---|---|---|
| 0 | Planning & scope | ✅ Done | 100% | Synopsis, deep-analysis doc, scope decisions in `context.md` §2 |
| 1 | Core pipeline (Tier 1) | 🟡 Nearly | 90% | All stages work end to end on `examples/flask-vuln` (SQLi, XSS and open redirect verified by running them). **Left:** Docker sandbox never run (daemon off, no images built); Patch is not shown as its own stage |
| 2 | Detection breadth (Tier 2) | 🟡 Mostly | 80% | 40 vulnerability classes, 111 Semgrep rules, access-control analyzer, cross-file AI/LLM analyzer, supply-chain checks, git-aware secrets, general-bug tier, dashboard. **Left:** cross-file taint outside AI apps (Joern/CodeQL); LLM-app rules for JS/Java |
| 3 | Patch library | ✅ Done | 95% | 44 fix templates (Python 17, JS 15, Java 10, config 2), Semgrep autofix, dependency bumps, LLM fallback with multiple candidates |
| 4 | Verification breadth | 🟠 Partial | 35% | Python harness works; exploit checks (oracles) exist for 10 classes. **Left:** Node harness in the Docker image, Java (Spring MockMvc) harness, Maven/Gradle images, cmdi and path traversal checked on Linux |
| 5 | LLM integration | 🟠 Built, untested | 40% | 3 backends (Ollama/OpenRouter/Gemini), cache, permission gate. **Left:** no real LLM call has ever run; no backend chosen; default model names are out of date |
| 6 | Evaluation | 🔴 Not started | 5% | Dataset shortlist in `docs/datasets.md`; `--no-ground` ablation switch exists. **Left:** everything else (see §4, M4–M5) |
| 7 | Documentation & defence | 🔴 Early | 15% | README, `context.md`. **Left:** update the .docx scope (it says access control is out of scope, but it is now built), results chapter, presentation, demo |

Code is on GitHub: `main` holds the working code from before 2026-10-23; `new_updates` adds the
AI/LLM, supply-chain and secrets work (28 tests pass). Merge it once reviewed.

---

## 3. Gaps between the documents and what we can currently prove

These must be fixed or reworded before the final report. An examiner will look for exactly these.

| Claim in the synopsis | Reality today | Action |
|---|---|---|
| "Each of the ten classes has an executable test" | TLS validation, rate limiting, weak credential storage and file upload have **no exploit oracle**. They are reported as rule findings with a patch, but nothing proves the patch | Either build oracles for them (M3) or reword the scope as 6 exploit-verified classes + 4 config classes verified by rule re-check |
| Verify runs in Docker | Never run: Docker Desktop is off and no images exist | M1: start Docker, build images, run the smoke test in Docker |
| Ground uses an LLM to discard false positives | The deterministic path does all the grounding; the LLM path has never run | M1: choose a backend and smoke-test it; M5: measure it |
| Hardware: 16 GB RAM + 12–24 GB GPU | Dev laptop: 7.3 GB RAM, integrated GPU only; can run only 1.5–4B local models | State that the cloud backend is used for experiments; keep local mode as an option |
| Access control is out of scope | Built as *needs-review* heuristic findings | Update the .docx scope section |
| 30–80 real CVEs evaluated | None curated yet | M4 |

---

## 4. Timeline and milestones

Every milestone has a **definition of done (DoD)**. A milestone is complete only when its DoD is met.
The owner column is for the group to fill in.

### M1: Make verification and the LLM real · Oct 26 – Nov 8, 2026
- **What:** start Docker Desktop and build the `docker/` images. Run `tests/test_pipeline_smoke.py` with
  `verify.sandbox=docker`, and confirm cmdi and path traversal verify on Linux. Show Patch in the
  dashboard (rename the stage to "Patch & Verify" or split it out). Choose the LLM backend for
  experiments, update the default model names in `config/default.toml`, and run one real scan with the
  LLM. Review `new_updates` and merge it into `main`.
- **Why:** these are the project's two core claims, verification by running code and grounding with an
  LLM, and neither has been shown working yet.
- **How:** free OpenRouter models or a $10 credit (≈ $0.001–0.01 per scan) for the LLM. Local Ollama
  3–4B models stay as a privacy option.
- **DoD:** the smoke test passes in Docker; a run's report shows `llm_used: true` on at least one
  finding; `main` contains the merged work.
- **Owner:** _TBD_

### M2: Semester VII progress review · Nov 9 – Nov 22, 2026
- **What:** a demo on three targets (`examples/flask-vuln`, `examples/llm-streamlit-vuln` and the
  Automotive Fault Diagnosis project), with before/after numbers. Update the .docx files using §3 above.
  Prepare progress slides. Run a quick scan of VAmPI (Flask) and NodeGoat (Express) as public sanity checks.
- **Why:** this review is graded, and the demo shows that the pipeline works on real code, not just
  on our own sample.
- **DoD:** slides, an updated synopsis, and a recorded demo run with its HTML report.
- **Owner:** _TBD_

### Exams and winter break (low intensity) · Nov 23, 2026 – Jan 3, 2027
- Download and filter datasets (Vul4J subset, BenchmarkPython, SecBench.js), and write the
  evaluation-runner skeleton (`scripts/evaluate.py`). No new features.

### M3: Verification breadth · Jan 4 – Jan 31, 2027
- **What:** Node/Express harness inside the Docker image (with a Mongo service for NoSQLi); Java
  Spring MockMvc harness and Maven/Gradle images; decide on oracles for the four config classes (§3);
  optionally, LLM-app rules for JavaScript.
- **Why:** the scope promises all three languages, and today only Python fixes can be proven.
- **DoD:** at least one verified-fixed finding per language in a Docker run; the decision on the
  four config classes is recorded in `context.md`.
- **Owner:** _TBD_

### M4: Evaluation set and runner · Feb 1 – Feb 28, 2027
- **What:** curate **30–80 CVEs** that have a reproducible proof-of-concept and a test suite (Vul4J
  for Java, a PatchEval subset for Python/JS, SecBench.js for npm). Prepare labelled true/false
  cases (OWASP BenchmarkPython/Java) for precision and recall, and small hand-labelled cases for the
  classes no dataset covers (rate limiting, mass assignment, TLS, upload, LLM apps).
- **Why:** the expected outcome in the synopsis is a measured result on real CVEs; without it the
  project is just a demo.
- **How:** `scripts/evaluate.py` runs the scanner on each case and writes one row per finding
  (class, status, ground decision, verified?, time, LLM calls/tokens) to CSV.
- **Constraints:** PatchEval needs about 500 GB in full, so use a subset. Datasets under GPL are used
  for evaluation only, never copied into this repo.
- **DoD:** a frozen case list (`docs/eval_set.md`) and the runner producing CSV for all cases.
- **Owner:** _TBD_

### M5: Experiments · Mar 1 – Mar 21, 2027
Run the five measurements from the evaluation plan in the analysis document:
1. **Ground precision/recall** compared with raw Detect output (deterministic only, then with the LLM).
2. **Patch verification success rate**: on the first attempt, and after the retry loop.
3. **Time and compute per finding** on ordinary hardware (this laptop, local LLM vs cloud).
4. **Ablation**: Detect→Patch→Verify (`--no-ground`) against the full pipeline.
5. **LLM backend comparison**: local Ollama vs Gemini vs OpenRouter (quality, cost, speed).
- **DoD:** tables and charts in `docs/results.md`, with the raw CSV committed for reproducibility.
- **Owner:** _TBD_

### M6: Feature freeze and write-up · Mar 22 – Apr 11, 2027
- **What:** fix bugs only; write the report chapters (implementation, results, limitations, Tier 3
  out of scope); keep the README and docs consistent.
- **Why:** an honest, consistent report is part of the deliverable. The documents must state what is
  not claimed as clearly as what is.
- **DoD:** a full report draft reviewed by the guide.
- **Owner:** _TBD_

### M7: Final defence · Apr 12 – Apr 30, 2027
- **What:** final presentation, demo video, final report submission; tag `v1.0` on `main`.
- **DoD:** submitted, with `v1.0` reproducible from a clean clone using `scripts/setup_tools`.
- **Owner:** _TBD_

**Buffer:** about 1 week each is hidden in the winter break, M5 and M6. If a milestone slips by
more than a week, cut scope in this order: JS LLM-app rules → config-class oracles → the Java harness.
Do **not** cut the evaluation (M4–M5).

---

## 5. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Laptop has 7.3 GB RAM and no GPU | Local 7B+ models won't run; Docker builds are slow | Cloud LLM for experiments; build Docker images once and reuse; use a lab machine if one is available |
| Free LLM tiers change or shrink (Gemini free limits are unpublished; OpenRouter free models rotate) | Experiments stall | $10 OpenRouter credit (raises the cap to 1,000 requests a day), and the response cache means repeat runs cost nothing |
| Gemini's free tier uses prompts to improve Google products | Source code is shared | Use only public datasets on the free tier; private code goes to local Ollama or paid tiers |
| Too few CVEs with a reproducible proof-of-concept | Evaluation set below 30 | Start curating in the winter break; mix library-level sets (Vul4J, SecBench.js) with app-level ones |
| Windows-specific sandbox problems | Verify results differ by OS | Run experiments in Docker/Linux only |
| Scope creep (new classes, new languages) | Evaluation squeezed | Feature freeze on Mar 22; new ideas go to "future work" |

---

## 6. Out of scope (state plainly in every report and presentation)

Predicting which commit introduced a bug (SZZ-style; best published accuracy ≈ 40%), zero-day
discovery, attacks visible only at runtime, on the network or through people, real-time single-pass
analysis of multi-million-line codebases, and any promise of zero false positives or negatives. Our
only guarantee is narrow: **a finding marked "verified fixed" was run against a concrete exploit and
shown to be closed, with the project's tests still passing.**
