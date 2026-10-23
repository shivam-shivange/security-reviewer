# LLM models: choice and test results

Tested 2026-10-23. Re-test before the evaluation phase (M5 in `plan.md`): free model lists and
free-tier limits change every few weeks.

## Chosen models

| Provider | Model | Score | Speed per call | Why |
|---|---|---|---|---|
| **OpenRouter** (free) | `poolside/laguna-s-2.1:free` | **4/4** | ~10 s | The only model to pass every task. Built for coding agents, 262k context |
| **Gemini** (free tier) | `gemini-3.5-flash-lite` | **4/4**¹ | ~2 s | Fastest by far, and correct on every task. Flash-Lite gets far more free daily requests than Flash |
| **Ollama** (local) | `qwen3.5:4b` | 2/4 | 2–2.5 min | The only installed model whose verdicts were both correct on its own (gemma3:4b was faster but wrong). Too slow and incomplete for experiments; use it only when code must stay on the machine. `llm.timeout_seconds` raised to 300 for it |

¹ The bake-off script first marked its patch as failed because of a bug in the checker (§4). Re-run with
the fixed check, the patch is correct (diff in §3.2).
gemma3:4b's "passes" on the safe cases came from the tool's source check catching a wrong answer, not
from the model (see §3.3).

**Project setup (decided 2026-10-24): fallback chain OpenRouter → Gemini → local Qwen.**
`llm.provider = "fallback"` tries the providers in this order: the most accurate first, the fastest
second, and the private, slow local model last. It moves on when a provider is unavailable,
rate-limited, out of quota or returns invalid JSON, and skips a failed provider for 5 minutes
(`llm.fallback_cooldown_seconds`). The run summary shows which provider answered (`llm.served_by`).

Live check, 2026-10-24: normal run → OpenRouter answered. OpenRouter model broken on purpose → Gemini
answered. OpenRouter and Gemini both broken → local qwen3.5:4b answered. Unit tests:
`tests/test_llm_fallback.py`.

The models are set in `config/default.toml` and `.env` (`SECREVIEW_*_MODEL`). To use one provider only,
pass `--provider local|openrouter|gemini` or set `SECREVIEW_LLM_PROVIDER`.

## 1. How the models were tested

Each model got four tasks, sent through the tool's real code paths (`ground.llm_ground` and
`patch.llm_patch.llm_candidates`) with the real prompts in `prompts/`. Caching was off.

| Task | Code | Expected result |
|---|---|---|
| TP sqli | `examples/flask-vuln/app.py:33`, request arg concatenated into SQL | `grounded`: verdict true positive, **and** its evidence chain passes the tool's check against the source lines |
| FP sqli | Input passed through `int()` before the `%d` query | `discarded` (false positive) |
| FP cmdi | Host checked against an `ALLOWED_HOSTS` allowlist before `subprocess.getoutput` | `discarded` (false positive) |
| Patch sqli | Same finding as TP sqli | A patch that applies, compiles and turns the query into a parameterised `execute(query, (name,))` |

Each prompt is about 0.8–1.2k tokens in and 0.2–0.4k out, the same size as a real scan.
**Limitation:** this is four tasks, one run each. It ranks models for a first choice; it is not a statistical result.
The evaluation phase measures quality properly on the CVE set.

## 2. Candidates and why they were chosen

- **Gemini:** this key can use 3.8 Flash, 3.5 Flash-Lite and 3.1 Flash-Lite. These are the newest Flash
  and two Flash-Lite generations; Pro models are not on the free tier.
- **OpenRouter:** the free models with a live endpoint. Laguna S 2.1 and North Mini Code are coding
  models; Gemma 4 31B supports JSON mode. Nemotron 3 Super was down (0% uptime); xing4.0 was degraded.
  The previous default, `qwen/qwen-2.5-coder-32b-instruct`, is a paid model and this key is free tier with no credit.
- **Ollama:** the installed models that can do the task: qwen2.5-coder:1.5b, gemma3:4b and qwen3.5:4b.
  The previous default, `qwen2.5-coder:7b`, is not installed and would barely fit in 7.3 GB RAM.

## 3. Results

Time is per call, in seconds. A failed call includes the tool's own retries.

### 3.1 OpenRouter (free models)

| Model | TP sqli | FP sqli (int) | FP cmdi (allowlist) | Patch | Score | Total |
|---|---|---|---|---|---|---|
| **poolside/laguna-s-2.1:free** | ✅ 12.8 | ✅ 11.2 | ✅ 10.7 | ✅ 5.0 | **4/4** | 40 s |
| cohere/north-mini-code:free | ✅ 16.3 | ✅ 9.0 | ⚠️ "uncertain" → needs review, 47.8 | ✅ 4.1 | 3/4 | 77 s |
| google/gemma-4-31b-it:free | ❌ HTTP 429 | ❌ 429 | ❌ 429 | ❌ 429 | 0/4 | 74 s |

North Mini Code's miss is a safe failure: it sent the finding to human review instead of a wrong verdict.
Gemma 4 was rate-limited by its upstream provider (Google AI Studio) on every call.

### 3.2 Gemini (free tier)

| Model | TP sqli | FP sqli (int) | FP cmdi (allowlist) | Patch | Score | Total |
|---|---|---|---|---|---|---|
| **gemini-3.5-flash-lite** | ✅ 2.5 | ✅ 2.0 | ✅ 1.4 | ✅ 1.4 | **4/4** | 7 s |
| gemini-3.1-flash-lite | ✅ 12.0 | ❌ HTTP 503, 83.2 | ✅ 8.4 | patch produced, not re-checked³ | 2–3/4 | 147 s |
| gemini-3.8-flash | ❌ 503 | ❌ 503 | ❌ 429 quota | ❌ | 0/4 | 92 s |

³ Only the Flash-Lite 3.5 patch was re-run after the checker fix.

Gemini 3.8 Flash returned 503 "high demand", then 429 "quota exceeded", so its free quota is too small for scans.
The Gemini 3.5 Flash-Lite patch (from a re-run):

```diff
-    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
-    cur.execute(query)
+    query = "SELECT id, name FROM users WHERE name = ?"
+    cur.execute(query, (name,))
```

### 3.3 Ollama (local, this laptop: 7.3 GB RAM, integrated GPU, CPU only)

| Model | TP sqli | FP sqli (int) | FP cmdi (allowlist) | Patch | Score | Total |
|---|---|---|---|---|---|---|
| gemma3:4b | ✅ 69.2 | ⚠️ said "true positive"; chain failed the source check → discarded, 30.7 | ❌ wrongly grounded, 24.9 | ❌ no usable patch, 15.9 | 1/4 real (2/4 counted) | 141 s |
| qwen2.5-coder:1.5b | ❌ Ollama aborted: "token repeat limit", 47.8 | ❌ wrongly grounded, 195.7 | ⚠️ said "true positive"; chain failed the check → discarded, 13.4 | ❌ no patch, 10.1 | 0/4 real (1/4 counted) | 267 s |
| **qwen3.5:4b** | ✅ 148.0 | ✅ 120.0 | ❌ timed out at 180 s (×3 retries), 560.3 | ❌ no patch, 66.6 | **2/4** | 895 s |

qwen3.5:4b is a "thinking" model. It reasons before it answers, which makes it about 4× slower than
gemma3:4b on this CPU, but both of its verdicts were genuinely correct. The tool's timeout was
180 s per call during this test; it is now 300 s.

The ⚠️ cases count as passes in the script, but the model was wrong. The tool's source check rejected
its invented evidence chain, and the finding was discarded for that reason. This shows the source check
catches small-model mistakes, but these models can't be trusted to judge findings themselves.

## 4. Fault in the test script (found and fixed)

The first patch check failed any file that still contained `+ name +`. The sample app also has an unrelated
`/greet` route with that text, so correct patches were marked as failed. The fixed check looks only at the SQL
line. The OpenRouter results were scored with the fixed check; Gemini 3.5 Flash-Lite's patch was re-verified by hand.

## 5. Limits, cost and privacy

| | OpenRouter free | Gemini free | Ollama local |
|---|---|---|---|
| Daily limit | 50 requests/day (1,000 after a one-off $10 credit purchase); 20 requests/min | Not published by Google; reports say about 500/day for Flash-Lite and about 20/day for Flash | None |
| One scan (about 14–28 calls) | 2–3 scans/day on free | about 18–35 scans/day | 5–30 min per scan on this laptop |
| Paid fallback | gpt-oss-120b about $0.001 per scan | Flash-Lite about $0.01 per scan | Free |
| Privacy | Depends on the host; turn off "allow training" in OpenRouter settings | **Free tier: Google may use prompts to improve its products** | Code stays on the machine |

Rule for the project: scan only **public** code (datasets, our examples) on free cloud tiers. Private code
goes to Ollama or a paid tier.

Quota used by this test: about 20 OpenRouter requests (of 50/day) and about 15 Gemini requests.

## 6. CLI check with the chosen models

`secreview llm --provider <p> --test`, 2026-10-23:

| Provider | Result |
|---|---|
| Gemini (`gemini-3.5-flash-lite`) | ✅ reachable, returned `{"ok": true}` |
| OpenRouter (`poolside/laguna-s-2.1:free`) | ✅ reachable, returned `{"ok": true}` |
| Ollama (`qwen3.5:4b`) | ✅ reachable, returned `{"ok": true}` |
