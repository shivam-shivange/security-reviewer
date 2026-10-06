# Test datasets for the evaluation phase

Researched 2026-10-06 by web search. Items marked "unverified" could not be confirmed online.
Nothing has been downloaded yet; testing starts after implementation.

**Needs:**
1. Labelled true/false-positive data, to measure Ground precision and recall.
2. Real CVEs with executable exploit or PoV tests plus fixes, to measure Patch + Verify.
3. Deliberately vulnerable full applications, for end-to-end demos.

## Shortlist

| Need | Python | Java (Maven / Gradle) | JavaScript / MERN |
|---|---|---|---|
| 1. TP/FP labels | [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython): 1,230 cases, 462 true / 768 false, 14 categories. [RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark): 66 real Python repos plus false-positive traps. | [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) v1.2: ~2,740 cases. [CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java): 120 CVEs; CWE-22, 78, 79, 94. | RealVuln JS/TS (74 repos). [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark): 218 CVEs, vulnerable and patched commits. |
| 2. CVE + PoV | [PatchEval](https://github.com/bytedance/PatchEval): 230 Dockerised CVEs with PoC and unit tests (Go/JS/Py). | [Vul4J](https://github.com/tuhh-softsec/vul4j): 79 CVEs with JUnit PoV tests, Docker, Maven+Gradle. | PatchEval (JS part). [SecBench.js](https://github.com/cristianstaicu/SecBench.js): 600 npm vulns with exploits; prototype pollution 192, path traversal 169, cmdi 101, code injection 40. |
| 3. Vulnerable apps | [VAmPI](https://github.com/erev0s/VAmPI) (Flask): has a vulnerable on/off switch; covers BOLA, mass assignment, rate limiting. [pygoat](https://github.com/adeyosemanputra/pygoat) (Django). | [WebGoat](https://github.com/WebGoat/WebGoat) (Spring, Maven). [java-sec-code](https://github.com/JoyChou93/java-sec-code): deserialization, SSRF, XXE, SpEL, upload. | [NodeGoat](https://github.com/OWASP/NodeGoat) (Express + MongoDB). [dvws-node](https://github.com/snoopysecurity/dvws-node): NoSQLi, XXE, SSRF, IDOR, JWT. [vulnerable-rest-api](https://github.com/bnematzadeh/vulnerable-rest-api) (React + Express + MongoDB). |

**Other candidates:**
- **General bugs:** Defects4J (Java), BugsInPy (Python), BugsJS (Node). These are real bugs with triggering tests.
- **Cross-language:** SastBench (arXiv 2601.02941), whose false positives come from Semgrep. Its repo URL is unverified.
- **Multi-stack showcase:** [crAPI](https://github.com/OWASP/crAPI), covering the OWASP API Top 10.
- **Background:**
  - Juliet Java 1.3: synthetic test cases.
  - CVEfixes / CrossVul / MoreFixes: fix commits only, no exploits.
  - OWASP Juice Shop: frontend is **Angular, not React**, and it uses MarsDB, not real MongoDB.

## Caveats
- **PatchEval is heavy:** each Docker image is about 2 GB and the full set needs about 500 GB of disk. Use a subset.
- **Vul4J and SecBench.js are library-level:** their PoV tests call functions directly, not HTTP routes. This suits the function-level exploit harness.
- **Licenses:**
  - GPL: BenchmarkJava (GPL-2.0), BenchmarkPython and Vul4J (GPL-3.0).
  - Unverified: SecBench.js.
  - Use these for evaluation only; don't copy their code into this repo.
- **Missing labelled data:** nothing covers rate limiting, mass assignment, disabled TLS validation or file upload well. We need our own small labelled cases, built from VAmPI/crAPI or written ourselves.
- **Gradle coverage** comes only from parts of Vul4J and CWE-Bench-Java.
