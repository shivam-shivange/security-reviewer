"""Command-line interface for secreview."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, tools
from .config import Config
from .context import RunStopped
from .store import Store


def _load_config(args) -> Config:
    cfg = Config.load(user_file=getattr(args, "config", None), project=getattr(args, "project", None))
    for dotted in getattr(args, "set", None) or []:
        key, _, value = dotted.partition("=")
        cfg.set(key.strip(), _coerce(value.strip()))
    if getattr(args, "provider", None):
        cfg.set("llm.provider", args.provider)
    if getattr(args, "no_llm", False):
        cfg.set("llm.enabled", False)
    if getattr(args, "sandbox", None):
        cfg.set("verify.sandbox", args.sandbox)
    if getattr(args, "yes", False):
        cfg.set("permissions.mode", "auto-approve")
    return cfg


def _coerce(v: str):
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(v)
    except ValueError:
        return v


def _store(cfg: Config) -> Store:
    return Store(cfg.workspace / "secreview.sqlite")


def cmd_scan(args) -> int:
    from .pipeline import run_pipeline
    cfg = _load_config(args)
    project = Path(args.project).resolve()
    if not project.is_dir():
        print(f"error: {project} is not a directory", file=sys.stderr)
        return 2
    store = _store(cfg)
    try:
        run_id, summary = run_pipeline(cfg, project, store, interactive=not args.yes,
                                       echo=not args.quiet, ground_enabled=not args.no_ground)
    except (RunStopped, KeyboardInterrupt):
        print("\nscan stopped; findings saved so far are in the dashboard (`secreview continue` can resume "
              "the Ground / Verify stages)", file=sys.stderr)
        return 130
    print("\n" + "=" * 60)
    print(f"Run {run_id}")
    print(f"  reportable findings : {summary['reportable']}")
    print(f"  verified fixed      : {summary['verified_fixed']}")
    print(f"  patch unverified    : {summary['patch_unverified']}")
    print(f"  needs review        : {summary['needs_review']}")
    print(f"  discarded (FP)      : {summary['discarded']}")
    print(f"  report-only bugs    : {summary['report_only']}")
    print(f"  report              : {summary['reports'].get('html')}")
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    if args.open:
        import webbrowser
        webbrowser.open(Path(summary["reports"]["html"]).as_uri())
    return 0


def cmd_continue(args) -> int:
    from .pipeline import continue_run
    cfg = _load_config(args)
    store = _store(cfg)
    try:
        summary = continue_run(cfg, store, args.run_id, args.from_stage, interactive=not args.yes,
                               echo=not args.quiet)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (RunStopped, KeyboardInterrupt):
        print("\nstopped", file=sys.stderr)
        return 130
    print("\n" + "=" * 60)
    print(f"Run {args.run_id} continued from {args.from_stage}")
    print(f"  reportable findings : {summary['reportable']}")
    print(f"  verified fixed      : {summary['verified_fixed']}")
    print(f"  needs review        : {summary['needs_review']}")
    print(f"  discarded (FP)      : {summary['discarded']}")
    print(f"  report              : {summary['reports'].get('html')}")
    return 0


def cmd_tools(args) -> int:
    st = tools.status()
    print(f"secreview {__version__} — tool status\n")
    for name, d in st.items():
        mark = "✓" if d["available"] else "✗"
        extra = ""
        if name == "docker" and d["available"]:
            extra = " (daemon running)" if d.get("daemon") else " (daemon NOT running)"
        print(f"  {mark} {name:14} {d['path'] or '— not found'}{extra}")
        print(f"       {d['purpose']}")
    return 0


def cmd_llm(args) -> int:
    from .llm import get_llm
    from .llm.base import LLMUnavailable
    cfg = _load_config(args)
    try:
        client = get_llm(cfg)
        status = client.check()
        print(f"✓ LLM reachable: {status}")
        if args.test:
            out = client.complete("You are a test.", 'Reply with JSON {"ok": true}.')
            print("  response:", out[:200])
        return 0
    except LLMUnavailable as exc:
        print(f"✗ LLM unavailable: {exc}", file=sys.stderr)
        return 1


def cmd_runs(args) -> int:
    cfg = _load_config(args)
    store = _store(cfg)
    for r in store.list_runs(args.limit):
        s = r.get("summary", {})
        print(f"{r['id']}  {r['status']:8}  {r['target']}")
        if s:
            print(f"    reportable={s.get('reportable', '?')} verified={s.get('verified_fixed', '?')} "
                  f"needs_review={s.get('needs_review', '?')}")
    return 0


def cmd_report(args) -> int:
    cfg = _load_config(args)
    store = _store(cfg)
    run = store.get_run(args.run_id) if args.run_id else (store.list_runs(1) or [None])[0]
    if not run:
        print("no such run", file=sys.stderr)
        return 1
    html = (cfg.workspace / "runs" / run["id"] / "report.html")
    print(html)
    if args.open and html.exists():
        import webbrowser
        webbrowser.open(html.as_uri())
    return 0


def cmd_dashboard(args) -> int:
    from .dashboard.app import serve
    cfg = _load_config(args)
    serve(cfg, host=args.host or cfg.get("dashboard.host"), port=args.port or cfg.get("dashboard.port"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secreview", description="Self-Verifying AI Security Reviewer")
    p.add_argument("--version", action="version", version=f"secreview {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--config", help="path to a TOML config file")
        sp.add_argument("--set", action="append", metavar="key=value", help="override a config key")

    sp = sub.add_parser("scan", help="scan a project")
    sp.add_argument("project", help="path to the project to scan")
    sp.add_argument("--provider", choices=["local", "openrouter", "gemini", "fallback"], help="LLM backend")
    sp.add_argument("--no-llm", action="store_true", help="run deterministic-only (no LLM)")
    sp.add_argument("--no-ground", action="store_true", help="ablation: skip the Ground stage")
    sp.add_argument("--sandbox", choices=["docker", "local"], help="verification sandbox")
    sp.add_argument("--yes", "-y", action="store_true", help="auto-approve all permission prompts")
    sp.add_argument("--quiet", "-q", action="store_true", help="less console output")
    sp.add_argument("--json", action="store_true", help="print the run summary as JSON")
    sp.add_argument("--open", action="store_true", help="open the HTML report when done")
    common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("continue", help="run a skipped stage of a finished run (e.g. Ground after a detect-only scan)")
    sp.add_argument("run_id", help="run id (see `secreview runs`)")
    sp.add_argument("--from", dest="from_stage", choices=["ground", "verify", "report"], default="ground",
                    help="stage to run; every stage after it runs again too. `report` only writes the report "
                         "from the findings as they are (default: ground)")
    sp.add_argument("--provider", choices=["local", "openrouter", "gemini", "fallback"], help="LLM backend")
    sp.add_argument("--no-llm", action="store_true", help="deterministic only (no LLM)")
    sp.add_argument("--sandbox", choices=["docker", "local"], help="verification sandbox")
    sp.add_argument("--yes", "-y", action="store_true", help="auto-approve all permission prompts")
    sp.add_argument("--quiet", "-q", action="store_true", help="less console output")
    common(sp)
    sp.set_defaults(func=cmd_continue)

    sp = sub.add_parser("tools", help="show external tool availability")
    sp.set_defaults(func=cmd_tools)

    sp = sub.add_parser("llm", help="check the configured LLM backend")
    sp.add_argument("--provider", choices=["local", "openrouter", "gemini", "fallback"])
    sp.add_argument("--test", action="store_true", help="send a tiny test prompt")
    common(sp)
    sp.set_defaults(func=cmd_llm)

    sp = sub.add_parser("runs", help="list past runs")
    sp.add_argument("--limit", type=int, default=20)
    common(sp)
    sp.set_defaults(func=cmd_runs)

    sp = sub.add_parser("report", help="locate / open a run's HTML report")
    sp.add_argument("run_id", nargs="?")
    sp.add_argument("--open", action="store_true")
    common(sp)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("dashboard", help="serve the web dashboard")
    sp.add_argument("--host")
    sp.add_argument("--port", type=int)
    common(sp)
    sp.set_defaults(func=cmd_dashboard)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
