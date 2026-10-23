"""Vulnerability class catalog (rules/taxonomy.yaml) and helpers to enrich findings."""

from __future__ import annotations

from functools import lru_cache

import yaml

from . import ROOT
from .models import Finding

TAXONOMY_FILE = ROOT / "rules" / "taxonomy.yaml"

# Map CWE ids reported by external tools (Bandit, Semgrep registry, PMD...) onto our classes.
CWE_TO_CLASS = {
    "CWE-89": "sqli", "CWE-943": "nosqli", "CWE-79": "xss", "CWE-78": "cmdi", "CWE-77": "cmdi",
    "CWE-94": "code_injection", "CWE-95": "code_injection", "CWE-22": "path_traversal",
    "CWE-23": "path_traversal", "CWE-918": "ssrf", "CWE-601": "open_redirect", "CWE-611": "xxe",
    "CWE-502": "deserialization", "CWE-1321": "prototype_pollution", "CWE-295": "tls_validation",
    "CWE-319": "cleartext_transport", "CWE-307": "rate_limiting", "CWE-770": "rate_limiting",
    "CWE-256": "weak_credential_storage", "CWE-916": "weak_credential_storage",
    "CWE-328": "weak_credential_storage", "CWE-798": "hardcoded_secret", "CWE-259": "hardcoded_secret",
    "CWE-321": "hardcoded_secret", "CWE-327": "weak_crypto", "CWE-326": "weak_crypto",
    "CWE-330": "insecure_random", "CWE-338": "insecure_random", "CWE-347": "jwt_misuse",
    "CWE-434": "unrestricted_upload", "CWE-942": "cors_misconfig", "CWE-489": "debug_enabled",
    "CWE-215": "debug_enabled", "CWE-306": "open_endpoint",
    "CWE-862": "missing_role_check", "CWE-285": "missing_role_check", "CWE-863": "inconsistent_authz",
    "CWE-639": "idor", "CWE-915": "mass_assignment", "CWE-807": "client_controlled_authz",
    "CWE-200": "sensitive_data_exposure", "CWE-359": "sensitive_data_exposure",
    "CWE-209": "error_leakage", "CWE-532": "sensitive_logging", "CWE-1104": "vulnerable_dependency",
    "CWE-494": "supply_chain", "CWE-829": "supply_chain", "CWE-1357": "supply_chain",
    "CWE-1427": "prompt_injection", "CWE-1426": "llm_output_handling",
}


@lru_cache(maxsize=1)
def catalog() -> dict[str, dict]:
    return yaml.safe_load(TAXONOMY_FILE.read_text(encoding="utf-8"))


def info(vuln_class: str) -> dict:
    return catalog().get(vuln_class) or catalog()["general_bug"]


def class_for_cwe(cwes: list[str]) -> str | None:
    for cwe in cwes:
        key = cwe.split(":")[0].strip().upper()
        if key in CWE_TO_CLASS:
            return CWE_TO_CLASS[key]
    return None


def is_heuristic(vuln_class: str) -> bool:
    """Classes found by cross-file heuristics: never auto-confirmed, always need a human check."""
    return bool(info(vuln_class).get("heuristic", False))


def enrich(f: Finding) -> Finding:
    """Fill class-level fields (CWE, attack, category...) that a detector left empty."""
    meta = info(f.vuln_class)
    f.title = f.title or meta["title"]
    f.cwe = f.cwe or list(meta.get("cwe", []))
    f.category = meta.get("category", f.category)
    f.attack = f.attack or meta.get("attack", "")
    f.attack_tier = f.attack_tier or meta.get("attack_tier", "")
    f.verifiable = bool(meta.get("verifiable", False))
    f.remediation = f.remediation or meta.get("remediation", "")
    f.severity = f.severity or meta.get("severity", "medium")
    return f
