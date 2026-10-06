"""Self-contained HTML report (no external assets)."""

from __future__ import annotations

import html
import json

SEV_COLOR = {"critical": "#b3123b", "high": "#d9480f", "medium": "#b8860b", "low": "#2b6cb0", "info": "#555"}
STATUS_COLOR = {"Verified Fixed": "#1a7f37", "Grounded, patch unverified": "#9a6700",
                "Needs review": "#8250df", "Report only": "#57606a", "Discarded at grounding": "#999"}


def esc(s) -> str:
    return html.escape(str(s or ""))


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
            f"<table class='chain'><thead><tr><th>Line</th><th>Code</th><th>Role</th></tr></thead>"
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
        f"<tr><td>{a.get('attempt')}</td><td>{esc(a.get('patch_source'))}</td>"
        f"<td>{esc(a.get('exploit_before'))}</td><td>{esc(a.get('exploit_after'))}</td>"
        f"<td>{esc(a.get('regression'))}</td><td>{'✅' if a.get('passed') else '❌'}</td></tr>"
        for a in attempts)
    return ("<h4>Verification log</h4><table class='chain'><thead><tr><th>#</th><th>Patch source</th>"
            "<th>Probe before</th><th>Probe after</th><th>Tests</th><th>Pass</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>")


def _finding_card(f: dict) -> str:
    sev = f.get("severity", "info")
    status = f.get("status_label", f.get("status"))
    patch = f.get("patch") or f.get("recommended_patch")
    prov = f.get("provenance") or {}
    ep = f.get("endpoint") or {}
    attack = f.get("attack", "")
    parts = [
        f"<div class='card' data-status='{esc(f.get('status'))}' data-sev='{esc(sev)}' data-class='{esc(f.get('vuln_class'))}'>",
        "<div class='chead'>",
        f"<span class='sev' style='background:{SEV_COLOR.get(sev, '#555')}'>{esc(sev)}</span>",
        f"<span class='status' style='color:{STATUS_COLOR.get(status, '#333')}'>{esc(status)}</span>",
        f"<span class='title'>{esc(f.get('title'))}</span>",
        f"<span class='cwe'>{esc(', '.join(f.get('cwe', [])))}</span>",
        "</div>",
        f"<div class='loc'><code>{esc(f.get('file'))}:{esc(f.get('line'))}</code>"
        + (f" &nbsp;·&nbsp; <span class='route'>{esc(ep.get('method'))} {esc(ep.get('path'))}</span>" if ep else "")
        + f" &nbsp;·&nbsp; <span class='muted'>{esc(f.get('tool'))}/{esc(f.get('rule_id'))}</span></div>",
        f"<p class='msg'>{esc(f.get('message'))}</p>",
        f"<p class='attack'><b>Enables:</b> {esc(attack)} &nbsp; <b>Module:</b> {esc(f.get('module'))}</p>" if attack else "",
        "<details open><summary>Evidence</summary>" + _chain(f) + "</details>",
    ]
    if prov.get("commit"):
        parts.append(f"<p class='muted prov'>Last changed in {esc(prov.get('commit'))} by "
                     f"{esc(prov.get('author'))} on {esc(prov.get('date'))} — {esc(prov.get('summary'))}</p>")
    if patch and patch.get("diff"):
        label = "Patch (verified)" if f.get("patch") else "Recommended patch (unverified)"
        parts.append(f"<details><summary>{label} — {esc(patch.get('source'))}</summary>"
                     f"<p class='muted'>{esc(patch.get('description'))}</p>{_diff(patch.get('diff'))}</details>")
    parts.append(_verification(f))
    parts.append(f"<p class='muted'>Remediation: {esc(f.get('remediation'))}</p>")
    parts.append("</div>")
    return "".join(parts)


def render_html(report: dict) -> str:
    s = report["summary"]
    findings = report["findings"]
    chips = "".join(
        f"<button class='chip' data-filter='status:{k}'>{esc(v)} ({s['by_status'].get(k, 0)})</button>"
        for k, v in [("verified_fixed", "Verified"), ("patch_unverified", "Unverified"),
                     ("needs_review", "Needs review"), ("report_only", "General bugs")]
        if s["by_status"].get(k))
    cards = "".join(_finding_card(f) for f in findings) or "<p>No findings.</p>"
    eps = report.get("endpoints") or []
    ep_rows = "".join(
        f"<tr><td>{esc(e.get('method'))}</td><td><code>{esc(e.get('path'))}</code></td>"
        f"<td>{'🔒' if e.get('auth') else '🔓'}</td><td>{esc(', '.join(e.get('roles', [])))}</td>"
        f"<td>{'✓' if e.get('rate_limited') else ''}</td>"
        f"<td class='muted'>{esc(e.get('file'))}:{esc(e.get('line'))}</td></tr>" for e in eps)
    llm = s.get("llm", {})
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secreview report — {esc(report.get('run_id'))}</title>
<style>
:root{{--bg:#f6f8fa;--card:#fff;--line:#d0d7de;--text:#1f2328;--muted:#656d76}}
*{{box-sizing:border-box}} body{{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}}
header{{background:#0d1117;color:#fff;padding:18px 24px}} header h1{{margin:0;font-size:18px}}
header .meta{{color:#9aa4b2;font-size:12px;margin-top:4px}}
.wrap{{max-width:1080px;margin:0 auto;padding:20px}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:120px}}
.tile .n{{font-size:24px;font-weight:700}} .tile .l{{color:var(--muted);font-size:12px}}
.chips{{margin:8px 0 16px}} .chip{{border:1px solid var(--line);background:#fff;border-radius:16px;padding:4px 12px;margin-right:6px;cursor:pointer;font-size:12px}}
.chip.active{{background:#0969da;color:#fff;border-color:#0969da}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin-bottom:12px}}
.chead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.sev{{color:#fff;border-radius:4px;padding:2px 8px;font-size:11px;text-transform:uppercase;font-weight:700}}
.status{{font-weight:600;font-size:12px}} .title{{font-weight:600}} .cwe{{color:var(--muted);font-size:12px;margin-left:auto}}
.loc{{margin:8px 0;font-size:13px}} .route{{color:#0969da}} .msg{{margin:6px 0}}
.attack{{font-size:12px;color:#444;margin:4px 0}}
code{{background:#eff1f3;border-radius:4px;padding:1px 4px;font-family:ui-monospace,Consolas,monospace;font-size:12px}}
.muted{{color:var(--muted);font-size:12px}} details{{margin:8px 0}} summary{{cursor:pointer;font-weight:600;font-size:13px}}
table.chain{{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}}
table.chain th,table.chain td{{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}}
.ln{{color:var(--muted);width:48px}}
.diff{{font-family:ui-monospace,Consolas,monospace;font-size:12px;border:1px solid var(--line);border-radius:6px;overflow:auto}}
.d{{padding:0 8px;white-space:pre}} .d.add{{background:#e6ffec}} .d.del{{background:#ffebe9}} .d.hunk{{background:#ddf4ff;color:#0550ae}}
h2{{margin-top:28px;border-bottom:1px solid var(--line);padding-bottom:6px}}
table.eps{{border-collapse:collapse;width:100%;font-size:12px}} table.eps th,table.eps td{{border:1px solid var(--line);padding:4px 8px;text-align:left}}
</style></head><body>
<header><h1>Self-Verifying AI Security Reviewer</h1>
<div class="meta">{esc(report.get('project'))} · run {esc(report.get('run_id'))} · {esc(report.get('generated'))}
· LLM: {esc(llm.get('provider') or 'disabled')} (calls {esc(llm.get('calls', 0))}, cache {esc(llm.get('cache_hits', 0))})
· {esc(s.get('elapsed_seconds'))}s</div></header>
<div class="wrap">
<div class="tiles">
<div class="tile"><div class="n">{s['reportable']}</div><div class="l">reportable findings</div></div>
<div class="tile"><div class="n" style="color:#1a7f37">{s['verified_fixed']}</div><div class="l">verified fixed</div></div>
<div class="tile"><div class="n" style="color:#9a6700">{s['patch_unverified']}</div><div class="l">patch unverified</div></div>
<div class="tile"><div class="n" style="color:#8250df">{s['needs_review']}</div><div class="l">needs review</div></div>
<div class="tile"><div class="n" style="color:#999">{s['discarded']}</div><div class="l">discarded (FP)</div></div>
<div class="tile"><div class="n">{s.get('endpoints', 0)}</div><div class="l">endpoints</div></div>
</div>
<div class="chips"><button class="chip active" data-filter="all">All ({len(findings)})</button>{chips}</div>
<div id="findings">{cards}</div>
{"<h2>API surface (" + str(len(eps)) + " endpoints)</h2><table class='eps'><thead><tr><th>Method</th><th>Path</th><th>Auth</th><th>Roles</th><th>Rate&nbsp;limit</th><th>Location</th></tr></thead><tbody>" + ep_rows + "</tbody></table>" if eps else ""}
</div>
<script>
const chips=document.querySelectorAll('.chip');
chips.forEach(c=>c.onclick=()=>{{chips.forEach(x=>x.classList.remove('active'));c.classList.add('active');
const f=c.dataset.filter;document.querySelectorAll('.card').forEach(card=>{{
if(f==='all'){{card.style.display='';return}} const [k,v]=f.split(':');
card.style.display=card.dataset[k==='status'?'status':k]===v?'':'none';}});}});
</script></body></html>"""
