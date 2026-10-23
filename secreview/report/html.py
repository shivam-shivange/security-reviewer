"""Self-contained HTML report (no external assets)."""

from __future__ import annotations

import html
import json

SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#06b6d4", "info": "#64748b"}
PRIORITY_MAP = {"critical": ("P0", "P0 Critical"), "high": ("P1", "P1 High"), "medium": ("P2", "P2 Medium"),
                "low": ("P3", "P3 Low"), "info": ("P4", "P4 Info")}

STATUS_COLOR = {"verified_fixed": "#10b981", "patch_unverified": "#f59e0b",
                "needs_review": "#8b5cf6", "report_only": "#94a3b8", "discarded": "#64748b"}


def esc(s) -> str:
    return html.escape(str(s or ""))


def get_category_info(f: dict) -> tuple[str, str, str]:
    """Returns (category_id, display_label, icon)."""
    c = (f.get("category") or "").lower()
    vc = (f.get("vuln_class") or "").lower()
    tool = (f.get("tool") or "").lower()

    if c == "general_bug" or vc == "general_bug" or tool in ("ruff", "eslint", "pmd", "spotbugs"):
        return ("simple_errors", "Simple Errors & Code Quality", "📝")
    if c == "data_leakage" or "leak" in vc or "sensitive_data" in vc or "error_leakage" in vc or "logging" in vc or "client_side_secret" in vc:
        return ("api_leaks", "API & Data Leaks", "💧")
    if c == "crypto" or "secret" in vc or "credential" in vc or "crypto" in vc or "random" in vc or "jwt" in vc:
        return ("secrets_crypto", "Secrets & Cryptography", "🔑")
    if c == "access_control" or "role" in vc or "auth" in vc or "idor" in vc or "mass_assignment" in vc or "endpoint" in vc:
        return ("access_control", "Access Control & Auth", "🚪")
    if c == "dependency" or "dependency" in vc or "supply_chain" in vc:
        return ("supply_chain", "Supply Chain & Dependencies", "📦")
    if c == "configuration" or "tls" in vc or "cors" in vc or "rate_limit" in vc or "debug" in vc or "upload" in vc or "cleartext" in vc or "resource_abuse" in vc:
        return ("security_config", "Security Configurations", "⚙️")
    if c == "injection" or f.get("attack") or f.get("attack_tier") or any(k in vc for k in ("sqli", "xss", "cmdi", "traversal", "ssrf", "prompt")):
        return ("is_attacks", "Related to IS Attacks", "💥")
    return ("simple_errors", "Simple Errors & Code Quality", "📝")


def _chain(f: dict) -> str:
    ev = f.get("evidence") or {}
    chain = ev.get("chain") or []
    if not chain:
        return f"<p class='muted'>{esc(ev.get('summary', 'no evidence chain'))}</p>"
    rows = "".join(
        f"<tr><td class='ln'>{esc(s.get('line'))}</td><td><code>{esc(s.get('code'))}</code></td>"
        f"<td class='muted'>{esc(s.get('note'))}</td></tr>" for s in chain)
    return (f"<p class='muted'>Method: {esc(ev.get('method'))} · confidence {esc(round(ev.get('confidence', 0), 2))}"
            f"{' · LLM' if ev.get('llm_used') else ''}</p>"
            f"<table class='chain'><thead><tr><th>Line</th><th>Code</th><th>Role in Taint Flow</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>")


def _diff(diff: str) -> str:
    rows = []
    for line in (diff or "").splitlines():
        cls = "add" if line.startswith("+") and not line.startswith("+++") else \
              "del" if line.startswith("-") and not line.startswith("---") else \
              "hunk" if line.startswith("@@") else "ctx"
        rows.append(f"<div class='d {cls}'>{esc(line)}</div>")
    return f"<div class='diff'>{''.join(rows)}</div>"


def _verification(f: dict) -> str:
    attempts = f.get("verification") or []
    if not attempts:
        return ""
    rows = "".join(
        f"<tr><td>#{a.get('attempt')}</td><td><code>{esc(a.get('patch_source'))}</code></td>"
        f"<td>{esc(a.get('exploit_before'))}</td><td>{esc(a.get('exploit_after'))}</td>"
        f"<td>{esc(a.get('regression'))}</td><td>{'✅ PASSED' if a.get('passed') else '❌ FAILED'}</td></tr>"
        for a in attempts)
    return ("<h4>Sandbox Verification Log</h4><table class='chain'><thead><tr><th>Attempt</th><th>Patch source</th>"
            "<th>Probe before</th><th>Probe after</th><th>Regression Tests</th><th>Result</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>")


def _patch_label(f: dict) -> str:
    """Say how a patch was proven: by running the exploit, by the advisory's fixed version, or not at all."""
    if not f.get("patch"):
        return "Recommended patch (not executed)"
    passed = next((a for a in f.get("verification") or [] if a.get("passed")), {})
    return ("Verified fix (advisory's fixed version)" if passed.get("patch_source") == "dependency-bump"
            else "Verified fix (exploit blocked, tests pass)")


def _finding_card(f: dict) -> str:
    sev = (f.get("severity") or "info").lower()
    p_code, p_label = PRIORITY_MAP.get(sev, ("P4", "P4 Info"))
    cat_id, cat_label, cat_icon = get_category_info(f)
    status = f.get("status_label", f.get("status", "candidate"))
    raw_status = f.get("status", "")
    patch = f.get("patch") or f.get("recommended_patch")
    prov = f.get("provenance") or {}
    ep = f.get("endpoint") or {}
    attack = f.get("attack", "")
    remediation = f.get("remediation", "")

    parts = [
        f"<div class='card priority-{p_code.lower()}' data-status='{esc(raw_status)}' data-sev='{esc(sev)}' data-class='{esc(f.get('vuln_class'))}' data-cat='{esc(cat_id)}' data-pri='{esc(p_code)}'>",
        "<div class='chead'>",
        f"<span class='sev-badge pri-{p_code.lower()}'>{esc(p_code)} {esc(sev.upper())}</span>",
        f"<span class='cat-badge cat-{cat_id}'>{cat_icon} {esc(cat_label)}</span>",
        f"<span class='status-badge st-{esc(raw_status)}'>{esc(status.replace('_', ' '))}</span>",
        f"<span class='title'>{esc(f.get('title'))}</span>",
        f"<span class='cwe'>{esc(', '.join(f.get('cwe', [])))}</span>",
        "</div>",
        f"<div class='loc'><code>{esc(f.get('file'))}:{esc(f.get('line'))}</code>"
        + (f" &nbsp;·&nbsp; <span class='route'>{esc(ep.get('method'))} {esc(ep.get('path'))}</span>" if ep else "")
        + f" &nbsp;·&nbsp; <span class='muted'>{esc(f.get('tool'))}/{esc(f.get('rule_id'))}</span></div>",
        f"<p class='msg'>{esc(f.get('message'))}</p>",
        f"<div class='attack-box'>⚠️ <b>Enables Attack:</b> {esc(attack)}"
        + (f" &nbsp;(Tier {esc(f.get('attack_tier'))}: "
           f"{'direct attack' if f.get('attack_tier') == 'A' else 'enabling weakness'})" if f.get('attack_tier') else "")
        + "</div>" if attack else "",
        "<details open><summary>Evidence Chain</summary>" + _chain(f) + "</details>",
    ]
    if prov.get("commit"):
        parts.append(f"<p class='muted prov'>Git blame: last changed in <code>{esc(prov.get('commit')[:8])}</code> by "
                     f"<b>{esc(prov.get('author'))}</b> on {esc(prov.get('date'))} — {esc(prov.get('summary'))}</p>")
    if patch and patch.get("diff"):
        label = _patch_label(f) + " — " + esc(patch.get("source", ""))
        parts.append(f"<details open><summary>{label}</summary>"
                     f"<p class='muted'>{esc(patch.get('description'))}</p>{_diff(patch.get('diff'))}</details>")
    parts.append(_verification(f))
    if remediation:
        parts.append(f"<div class='remediation-box'><b>Remediation:</b> {esc(remediation)}</div>")
    parts.append("</div>")
    return "".join(parts)


def render_html(report: dict) -> str:
    s = report["summary"]
    findings = report["findings"]

    # Priority sorting (P0 -> P4)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (sev_order.get((x.get("severity") or "info").lower(), 9), x.get("status", "")))

    chips = "".join(
        f"<button class='chip' data-filter='status:{k}'>{esc(v)} ({s['by_status'].get(k, 0)})</button>"
        for k, v in [("verified_fixed", "Verified Fixed"), ("patch_unverified", "Patch Unverified"),
                     ("needs_review", "Needs Review"), ("report_only", "General Bugs")]
        if s.get("by_status", {}).get(k))

    cards = "".join(_finding_card(f) for f in findings) or "<p>No findings.</p>"
    eps = report.get("endpoints") or []
    ep_rows = "".join(
        f"<tr><td><b>{esc(e.get('method'))}</b></td><td><code>{esc(e.get('path'))}</code></td>"
        f"<td>{'🔒 Auth required' if e.get('auth') else '🔓 Public'}</td><td>{esc(', '.join(e.get('roles', [])))}</td>"
        f"<td>{'✓ Protected' if e.get('rate_limited') else 'None'}</td>"
        f"<td class='muted'><code>{esc(e.get('file'))}:{esc(e.get('line'))}</code></td></tr>" for e in eps)
    llm = s.get("llm", {})
    served = "; answered by " + ", ".join(f"{esc(k)} ×{esc(v)}" for k, v in llm["served_by"].items()) \
        if llm.get("served_by") else ""

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secreview report — {esc(report.get('run_id'))}</title>
<style>
:root{{--bg:#090d16;--card:#111827;--line:rgba(255,255,255,0.08);--line-strong:rgba(255,255,255,0.18);--text:#f1f5f9;--muted:#94a3b8;--accent:#3b82f6;--ok:#10b981;--warn:#f59e0b;--bad:#ef4444;--purple:#8b5cf6;--cyan:#06b6d4}}
*{{box-sizing:border-box}} body{{margin:0;font:13.5px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}}
header{{background:#060910;border-bottom:1px solid var(--line);padding:18px 28px;display:flex;align-items:center;justify-content:space-between}}
header h1{{margin:0;font-size:18px;display:flex;align-items:center;gap:8px}}
header .meta{{color:var(--muted);font-size:12px;margin-top:4px}}
.wrap{{max-width:1120px;margin:0 auto;padding:24px 20px}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px}}
.tile .n{{font-size:24px;font-weight:800}} .tile .l{{color:var(--muted);font-size:11.5px;margin-top:4px;font-weight:600}}
.chips{{margin:14px 0 20px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
.chip{{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:20px;padding:5px 14px;cursor:pointer;font-size:12px;transition:all .15s ease}}
.chip:hover{{border-color:var(--line-strong)}}
.chip.active{{background:var(--accent);color:#fff;border-color:var(--accent);font-weight:600}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 20px;margin-bottom:14px;transition:all .15s ease}}
.card.priority-p0{{border-left:4px solid var(--bad)}}
.card.priority-p1{{border-left:4px solid #f97316}}
.card.priority-p2{{border-left:4px solid var(--warn)}}
.card.priority-p3{{border-left:4px solid var(--cyan)}}
.card.priority-p4{{border-left:4px solid var(--muted)}}
.chead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.sev-badge{{color:#fff;border-radius:4px;padding:2px 8px;font-size:11px;text-transform:uppercase;font-weight:800}}
.pri-p0{{background:#b91c1c}}.pri-p1{{background:#c2410c}}.pri-p2{{background:#b45309}}.pri-p3{{background:#0369a1}}.pri-p4{{background:#475569}}
.cat-badge{{font-size:11px;font-weight:700;padding:2px 10px;border-radius:12px;display:inline-flex;align-items:center;gap:4px}}
.cat-is_attacks{{background:rgba(239,68,68,0.16);color:#f87171;border:1px solid rgba(239,68,68,0.35)}}
.cat-api_leaks{{background:rgba(56,189,248,0.16);color:#38bdf8;border:1px solid rgba(56,189,248,0.35)}}
.cat-secrets_crypto{{background:rgba(251,191,36,0.16);color:#fbbf24;border:1px solid rgba(251,191,36,0.35)}}
.cat-access_control{{background:rgba(192,132,252,0.16);color:#c084fc;border:1px solid rgba(192,132,252,0.35)}}
.cat-supply_chain{{background:rgba(251,146,60,0.16);color:#fb923c;border:1px solid rgba(251,146,60,0.35)}}
.cat-security_config{{background:rgba(167,139,250,0.16);color:#a78bfa;border:1px solid rgba(167,139,250,0.35)}}
.cat-simple_errors{{background:rgba(148,163,184,0.16);color:#94a3b8;border:1px solid rgba(148,163,184,0.35)}}
.status-badge{{font-size:11px;font-weight:700;border-radius:10px;padding:2px 8px;text-transform:uppercase}}
.st-verified_fixed{{background:rgba(16,185,129,0.18);color:var(--ok)}}
.st-patch_unverified{{background:rgba(245,158,11,0.16);color:var(--warn)}}
.st-needs_review{{background:rgba(139,92,246,0.18);color:var(--purple)}}
.st-report_only{{background:rgba(255,255,255,0.08);color:var(--muted)}}
.st-discarded{{background:rgba(255,255,255,0.04);color:var(--muted)}}
.title{{font-weight:700;font-size:14.5px;margin-right:auto}} .cwe{{color:var(--muted);font-size:12px;font-family:ui-monospace,monospace}}
.loc{{margin:8px 0;font-size:12.5px;color:var(--muted)}} .route{{color:var(--accent);font-weight:600}} .msg{{margin:6px 0;font-size:13px;line-height:1.5}}
.attack-box{{background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:6px;padding:8px 12px;font-size:12px;margin:8px 0}}
.attack-box b{{color:#f87171}}
.remediation-box{{background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);border-radius:6px;padding:8px 12px;font-size:12px;color:#a7f3d0;margin-top:10px}}
.remediation-box b{{color:var(--ok)}}
code{{background:rgba(255,255,255,0.06);border-radius:4px;padding:2px 6px;font-family:ui-monospace,monospace;font-size:12px}}
.muted{{color:var(--muted);font-size:12px}} details{{margin:10px 0;border:1px solid var(--line);border-radius:6px;padding:8px 12px;background:#060a12}}
summary{{cursor:pointer;font-weight:600;font-size:12.5px;color:var(--muted)}} details[open] summary{{margin-bottom:8px}}
table.chain{{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}}
table.chain th,table.chain td{{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}}
table.chain th{{color:var(--muted);background:rgba(255,255,255,0.02)}}
.ln{{color:var(--muted);width:48px;font-family:ui-monospace,monospace}}
.diff{{font-family:ui-monospace,monospace;font-size:12px;border:1px solid var(--line);border-radius:6px;overflow:auto;max-height:360px;background:#010409}}
.d{{padding:1px 10px;white-space:pre}} .d.add{{background:rgba(16,185,129,0.15);color:#34d399}} .d.del{{background:rgba(239,68,68,0.15);color:#f87171}} .d.hunk{{background:rgba(59,130,246,0.15);color:#60a5fa}}
h2{{margin-top:34px;border-bottom:1px solid var(--line);padding-bottom:8px;font-size:16px}}
table.eps{{border-collapse:collapse;width:100%;font-size:12px;background:var(--card);border-radius:8px;overflow:hidden}}
table.eps th,table.eps td{{border:1px solid var(--line);padding:8px 12px;text-align:left}}
table.eps th{{background:rgba(255,255,255,0.03);color:var(--muted)}}
</style></head><body>
<header>
  <div>
    <h1>🛡️ secreview Security Review Report</h1>
    <div class="meta">{esc(report.get('project'))} · run {esc(report.get('run_id'))} · {esc(report.get('generated'))}
    · LLM: {esc(llm.get('provider') or 'disabled')} (calls {esc(llm.get('calls', 0))}, cache {esc(llm.get('cache_hits', 0))}{served})
    · Total runtime: {esc(s.get('elapsed_seconds'))}s</div>
  </div>
</header>
<div class="wrap">
<div class="tiles">
<div class="tile"><div class="n">{s['reportable']}</div><div class="l">Reportable Findings</div></div>
<div class="tile"><div class="n" style="color:var(--ok)">{s['verified_fixed']}</div><div class="l">Verified Fixed</div></div>
<div class="tile"><div class="n" style="color:var(--warn)">{s['patch_unverified']}</div><div class="l">Patch Unverified</div></div>
<div class="tile"><div class="n" style="color:var(--purple)">{s['needs_review']}</div><div class="l">Needs Review</div></div>
<div class="tile"><div class="n" style="color:var(--muted)">{s['discarded']}</div><div class="l">Discarded (FP)</div></div>
<div class="tile"><div class="n">{s.get('endpoints', 0)}</div><div class="l">API Endpoints</div></div>
</div>

<div class="chips" data-row="status">
  <span style="font-size:12px;color:var(--muted);font-weight:600">Filter Status:</span>
  <button class="chip active" data-filter="all">All Issues ({len(findings)})</button>
  {chips}
</div>

<div class="chips" data-row="cat" style="margin-top:-6px">
  <span style="font-size:12px;color:var(--muted);font-weight:600">Filter Category:</span>
  <button class="chip active" data-filter="all">All Categories</button>
  <button class="chip" data-filter="cat:is_attacks">💥 IS Attacks</button>
  <button class="chip" data-filter="cat:api_leaks">💧 API & Data Leaks</button>
  <button class="chip" data-filter="cat:secrets_crypto">🔑 Secrets & Crypto</button>
  <button class="chip" data-filter="cat:access_control">🚪 Access Control</button>
  <button class="chip" data-filter="cat:supply_chain">📦 Supply Chain</button>
  <button class="chip" data-filter="cat:security_config">⚙️ Security Config</button>
  <button class="chip" data-filter="cat:simple_errors">📝 Simple Errors</button>
</div>

<div id="findings">{cards}</div>
{"<h2>API Surface (" + str(len(eps)) + " endpoints detected)</h2><table class='eps'><thead><tr><th>Method</th><th>Route</th><th>Authentication</th><th>Roles</th><th>Rate Limiting</th><th>Code Definition</th></tr></thead><tbody>" + ep_rows + "</tbody></table>" if eps else ""}
</div>
<script>
// One active chip per row; the status row and the category row apply together.
const active = {{status: 'all', cat: 'all'}};
document.querySelectorAll('.chip').forEach(c => c.onclick = () => {{
  c.parentElement.querySelectorAll('.chip').forEach(x => x.classList.remove('active'));
  c.classList.add('active');
  const row = c.parentElement.dataset.row;
  active[row] = c.dataset.filter === 'all' ? 'all' : c.dataset.filter.split(':')[1];
  document.querySelectorAll('.card').forEach(card => {{
    const ok = (active.status === 'all' || card.dataset.status === active.status)
            && (active.cat === 'all' || card.dataset.cat === active.cat);
    card.style.display = ok ? '' : 'none';
  }});
}});
</script></body></html>"""
