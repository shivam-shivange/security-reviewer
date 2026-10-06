"""Oracle loading and response evaluation for the verification harness.

An oracle turns a vulnerability class into a benign/control input plus one or more test inputs and a
condition that distinguishes "the weakness is present" from "the weakness is closed". All values are
tokenised with a random run token and class-specific canaries, so a match reflects genuine differing
behaviour rather than the literal input echoing back.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ORACLES = yaml.safe_load((Path(__file__).resolve().parents[1] / "oracles.yaml").read_text(encoding="utf-8"))


@dataclass
class Oracle:
    vuln_class: str
    check: str
    benign: str = ""
    marker: str = ""
    payloads: list = field(default_factory=list)
    json_payloads: list = field(default_factory=list)
    query_payloads: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class Verdict:
    result: str                       # vulnerable | blocked | error
    detail: dict = field(default_factory=dict)


def _fill(value, subs: dict):
    if isinstance(value, str):
        for k, v in subs.items():
            value = value.replace("{" + k + "}", str(v))
        return value
    if isinstance(value, list):
        return [_fill(v, subs) for v in value]
    if isinstance(value, dict):
        return {_fill(k, subs): _fill(v, subs) for k, v in value.items()}
    return value


def load_oracle(vuln_class: str, spec: dict) -> Oracle:
    raw = dict(ORACLES[vuln_class])
    token = spec.get("token", "tok")
    canary_file = spec.get("canary_file", "/tmp/secreview_canary")
    subs = {
        "TOKEN": token,
        "CANARY_FILE": canary_file,
        "CANARY_FILE_NOSLASH": canary_file.lstrip("/"),
        "CANARY_DIR": spec.get("canary_dir", "/tmp"),
        "CANARY_URL": spec.get("canary_url", "http://127.0.0.1:0"),
        "CANARY_PORT": spec.get("canary_port", 0),
    }
    lang_key = f"payloads_{spec.get('runtime', 'python')}"
    payloads = raw.get(lang_key, raw.get("payloads", []))
    return Oracle(
        vuln_class=vuln_class, check=raw["check"], benign=_fill(raw.get("benign", ""), subs),
        marker=_fill(raw.get("marker", raw.get("property", "")), subs), payloads=_fill(payloads, subs),
        json_payloads=_fill(raw.get("json_payloads", []), subs),
        query_payloads=_fill(raw.get("query_payloads", []), subs),
        extra=_fill({k: v for k, v in raw.items() if k not in
                     ("check", "benign", "marker", "payloads", "json_payloads", "query_payloads")}, subs),
    )


def result_line(result: str, **detail) -> str:
    return "SECREVIEW_RESULT " + json.dumps({"result": result, **detail})


# ---- response condition evaluators -------------------------------------------------------------
def evaluate(oracle: Oracle, benign_resp, test_resps: list[tuple], canary) -> Verdict:
    """benign_resp / test_resps are (status, body) tuples. `canary` exposes file/ssrf/proto state."""
    check = oracle.check
    if check == "reflect":
        for payload, (status, body) in test_resps:
            if oracle.marker in (body or "") and 200 <= status < 400:
                return Verdict("vulnerable", {"evidence": "marker reflected unescaped", "payload": payload[:120]})
        return Verdict("blocked", {"reason": "marker never reflected unescaped"})
    if check == "differential":
        if benign_resp is None:
            return Verdict("error", {"reason": "benign request failed"})
        bstatus, bbody = benign_resp
        if not (200 <= bstatus < 400):
            return Verdict("error", {"reason": f"benign request returned {bstatus}"})
        for payload, (status, body) in test_resps:
            if 200 <= status < 400 and _differs(bbody, body):
                return Verdict("vulnerable", {"evidence": "auth/filter bypassed: response differs from control",
                                              "payload": str(payload)[:120]})
        return Verdict("blocked", {"reason": "no test input changed the control response"})
    if check in ("marker", "marker_or_file"):
        for payload, (status, body) in test_resps:
            if oracle.marker and oracle.marker in (body or ""):
                return Verdict("vulnerable", {"evidence": "command output appeared in response", "payload": payload[:120]})
        if check == "marker_or_file" and canary.file_created():
            return Verdict("vulnerable", {"evidence": "canary file created by injected command"})
        return Verdict("blocked", {"reason": "command never executed"})
    if check == "file_canary":
        if canary.file_created():
            return Verdict("vulnerable", {"evidence": "canary file created (code executed)"})
        return Verdict("blocked", {"reason": "code not executed"})
    if check == "read_canary":
        for payload, (status, body) in test_resps:
            if canary.secret and canary.secret in (body or ""):
                return Verdict("vulnerable", {"evidence": "canary file contents disclosed", "payload": str(payload)[:120]})
        return Verdict("blocked", {"reason": "canary file not disclosed"})
    if check == "ssrf_canary":
        if canary.ssrf_hit():
            return Verdict("vulnerable", {"evidence": "server made a request to the canary URL"})
        return Verdict("blocked", {"reason": "no outbound request to canary"})
    if check == "redirect":
        host = oracle.extra.get("attacker_host", "")
        for payload, (status, body, location) in [(p, r if len(r) == 3 else (*r, "")) for p, r in test_resps]:
            if 300 <= status < 400 and host in (location or ""):
                return Verdict("vulnerable", {"evidence": f"redirects to {location}", "payload": payload[:120]})
        return Verdict("blocked", {"reason": "no external redirect"})
    if check == "proto":
        if canary.proto_polluted(oracle.marker):
            return Verdict("vulnerable", {"evidence": "Object.prototype was polluted"})
        return Verdict("blocked", {"reason": "prototype not polluted"})
    return Verdict("error", {"reason": f"unknown check {check}"})


def _differs(a: str, b: str) -> bool:
    a, b = a or "", b or ""
    if a == b:
        return False
    # Ignore trivial differences (whitespace / length within 5%).
    na, nb = re.sub(r"\s+", "", a), re.sub(r"\s+", "", b)
    if na == nb:
        return False
    longer = max(len(na), len(nb)) or 1
    return abs(len(na) - len(nb)) / longer > 0.05 or (len(nb) > len(na) * 1.2)
