"""Core data model shared by every stage, the store, the reports and the dashboard."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    CANDIDATE = "candidate"              # detected, not grounded yet
    GROUNDED = "grounded"                # evidence confirmed, waiting for patch/verify
    VERIFIED_FIXED = "verified_fixed"    # patch proven by exploit + regression run
    PATCH_UNVERIFIED = "patch_unverified"  # patch exists, could not be verified (or retries exhausted)
    DISCARDED = "discarded"              # grounding rejected it (likely false positive)
    NEEDS_REVIEW = "needs_review"        # heuristic finding (e.g. access control) - human check
    REPORT_ONLY = "report_only"          # general bugs / advisories


class Category(str, Enum):
    INJECTION = "injection"
    CONFIGURATION = "configuration"
    CRYPTO = "crypto"
    ACCESS_CONTROL = "access_control"
    DATA_LEAKAGE = "data_leakage"
    DEPENDENCY = "dependency"
    GENERAL_BUG = "general_bug"


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class EvidenceStep:
    file: str
    line: int
    code: str
    note: str = ""          # e.g. "source: request.args", "assigned to q", "sink: cursor.execute"


@dataclass
class Evidence:
    method: str                          # semgrep-taint | rule-match | advisory | endpoint-analysis | llm | none
    chain: list[EvidenceStep] = field(default_factory=list)
    summary: str = ""
    confidence: float = 0.0
    llm_used: bool = False


@dataclass
class Provenance:
    commit: str = ""
    author: str = ""
    date: str = ""
    summary: str = ""


@dataclass
class Patch:
    diff: str
    source: str                          # semgrep-fix | template:<name> | dependency-bump | ruff | eslint | llm
    description: str = ""
    files: dict[str, str] = field(default_factory=dict)   # relative path -> full new content
    llm_used: bool = False


@dataclass
class VerificationAttempt:
    attempt: int
    patch_source: str
    exploit_before: str = ""             # vulnerable | blocked | error | skipped
    exploit_after: str = ""
    regression: str = ""                 # passed | failed | skipped | no-tests
    passed: bool = False
    log: str = ""


@dataclass
class Endpoint:
    """One HTTP route found by the endpoint inventory (API surface)."""
    framework: str
    method: str
    path: str
    file: str
    line: int
    end_line: int = 0                    # last line of the inline handler (maps findings to routes)
    handler: str = ""
    handler_file: str = ""               # where the handler function lives (may be a controller file)
    handler_line: int = 0
    handler_end_line: int = 0
    auth: bool = False
    roles: list[str] = field(default_factory=list)
    auth_evidence: str = ""
    params: list[str] = field(default_factory=list)
    module: str = ""
    rate_limited: bool = False
    middlewares: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    vuln_class: str                      # key into rules/taxonomy.yaml
    title: str
    file: str                            # path relative to the scanned project root
    line: int
    end_line: int = 0
    column: int = 0
    tool: str = ""
    language: str = ""
    module: str = ""
    message: str = ""
    code: str = ""                       # matched source
    severity: str = ""                   # filled from taxonomy when a detector leaves it empty
    category: str = Category.INJECTION.value
    cwe: list[str] = field(default_factory=list)
    attack: str = ""                     # the attack this flaw enables
    attack_tier: str = ""                # A | B (see Deep Analysis 8.2)
    verifiable: bool = False             # an exploit oracle exists for this class
    status: str = Status.CANDIDATE.value
    evidence: Evidence | None = None
    provenance: Provenance | None = None
    patch: Patch | None = None
    recommended_patch: Patch | None = None
    verification: list[VerificationAttempt] = field(default_factory=list)
    endpoint: dict | None = None         # route the sink is reachable from, if known
    taint_trace: list[dict] = field(default_factory=list)   # raw semgrep dataflow trace
    fix_hint: str = ""                   # semgrep `fix:` text or advisory fix version
    remediation: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.end_line:
            self.end_line = self.line
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        """Stable across scans as long as the flagged code itself does not change."""
        norm = " ".join(self.code.split())
        raw = f"{self.vuln_class}|{self.file}|{norm or self.line}|{self.rule_id}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        if d.get("evidence"):
            ev = dict(d["evidence"])
            ev["chain"] = [EvidenceStep(**s) for s in ev.get("chain", [])]
            d["evidence"] = Evidence(**ev)
        if d.get("provenance"):
            d["provenance"] = Provenance(**d["provenance"])
        for key in ("patch", "recommended_patch"):
            if d.get(key):
                d[key] = Patch(**d[key])
        d["verification"] = [VerificationAttempt(**v) for v in d.get("verification", [])]
        return cls(**d)
