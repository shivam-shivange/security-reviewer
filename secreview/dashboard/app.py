"""Web dashboard: live view of runs, stages, findings, API surface and permission prompts.

Backed by the same SQLite store the pipeline writes to, so a scan started from the CLI (or from the
dashboard's own background thread) shows up live. Start with:  secreview dashboard
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from ..config import Config
from ..context import RunStopped
from ..store import Store

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn
except ImportError:  # pragma: no cover
    FastAPI = None


def create_app(cfg: Config):
    if FastAPI is None:
        raise SystemExit("FastAPI/uvicorn not installed; run scripts/setup_tools")
    app = FastAPI(title="secreview dashboard")
    store = Store(cfg.workspace / "secreview.sqlite")
    jobs: dict[str, threading.Thread] = {}
    scan_state = {"active": False}   # this machine runs one scan at a time

    # Mark runs orphaned by a previous dashboard process (still "running") as failed on startup.
    for r in store.list_runs(200):
        if r["status"] == "running":
            store.update_run(r["id"], status="failed", error="interrupted (dashboard restarted)")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/runs")
    def runs():
        return store.list_runs(100)

    @app.get("/api/presets")
    def presets():
        from .. import ROOT
        items = []
        p_flask = (ROOT / "examples" / "flask-vuln").resolve()
        if p_flask.exists():
            items.append({
                "id": "flask-vuln",
                "name": "Flask Vulnerable Web App",
                "path": str(p_flask),
                "badge": "Web Exploits",
                "desc": "SQLi, XSS, Open Redirect, Path Traversal, and vulnerable dependencies."
            })
        p_ai = (ROOT / "examples" / "llm-streamlit-vuln").resolve()
        if p_ai.exists():
            items.append({
                "id": "llm-streamlit-vuln",
                "name": "Streamlit AI & LLM App",
                "path": str(p_ai),
                "badge": "AI / OWASP LLM",
                "desc": "Prompt Injection, RAG Poisoning, Improper LLM Output Handling, and Unbounded LLM Consumption."
            })
        return items

    @app.get("/api/tools")
    def tool_status():
        from .. import tools
        return tools.status()

    @app.get("/api/runs/{run_id}")
    def run(run_id: str):
        r = store.get_run(run_id)
        if not r:
            raise HTTPException(404)
        return r

    @app.get("/api/runs/{run_id}/events")
    def events(run_id: str, after: int = 0):
        return store.events(run_id, after_id=after, limit=1000)

    @app.get("/api/runs/{run_id}/findings")
    def findings(run_id: str):
        return [f.to_dict() for f in store.findings(run_id)]

    @app.get("/api/runs/{run_id}/endpoints")
    def endpoints(run_id: str):
        return store.endpoints(run_id)

    @app.get("/api/runs/{run_id}/report", response_class=HTMLResponse)
    def report_html(run_id: str):
        path = cfg.workspace / "runs" / run_id / "report.html"
        if not path.is_file():
            raise HTTPException(404, "report not generated yet")
        return path.read_text(encoding="utf-8")

    @app.get("/api/runs/{run_id}/permissions")
    def permissions(run_id: str):
        return store.permissions(run_id)

    @app.post("/api/permissions/{pid}/{decision}")
    def decide(pid: str, decision: str, remember: bool = False):
        if decision not in ("approve", "deny"):
            raise HTTPException(400)
        store.decide_permission(pid, decision == "approve", remember=remember)
        return {"ok": True}

    @app.post("/api/scan")
    def scan(body: dict):
        from ..pipeline import run_pipeline
        raw = (body.get("project") or "").strip().strip('"')
        project = Path(raw).resolve()
        if ".zip" in raw.lower() or ".tar" in raw.lower():
            raise HTTPException(400, "That path points inside an archive. Extract the .zip/.tar first "
                                     "and scan the extracted folder.")
        if not project.exists():
            raise HTTPException(400, f"Path does not exist: {project}")
        if not project.is_dir():
            raise HTTPException(400, f"Not a folder (point at a project directory, not a file): {project}")
        if scan_state["active"]:
            raise HTTPException(409, "A scan is already running. This machine runs one scan at a time — "
                                     "let it finish (or stop it) before starting another.")
        run_cfg = cfg.copy()
        for k, v in (body.get("options") or {}).items():
            run_cfg.set(k, v)

        def worker():
            try:
                run_pipeline(run_cfg, project, store, interactive=False, echo=False,
                             ground_enabled=not body.get("no_ground", False))
            except (Exception, RunStopped):  # already recorded on the run row
                pass
            finally:
                scan_state["active"] = False

        scan_state["active"] = True   # set before the thread starts, so a second click cannot slip in
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        # give the worker a moment to create the run row
        import time
        for _ in range(50):
            latest = store.list_runs(1)
            if latest and latest[0]["target"] == str(project) and latest[0]["status"] == "running":
                jobs[latest[0]["id"]] = t
                return {"run_id": latest[0]["id"]}
            time.sleep(0.05)
        return {"run_id": None, "note": "scan starting"}

    SKIPPABLE = ("detect", "provenance", "ground", "verify")

    def _running(run_id: str) -> dict:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(404, "run not found")
        if run["status"] != "running":
            raise HTTPException(409, f"This run is not running (status: {run['status']}).")
        return run

    def _orphaned(run_id: str) -> bool:
        """Not driven by a live thread here, and silent for 10 minutes: no process will act on a request."""
        job = jobs.get(run_id)
        if job is not None and job.is_alive():
            return False
        last = store.last_event_ts(run_id)
        return last is None or time.time() - last > 600

    @app.post("/api/runs/{run_id}/stop")
    def stop(run_id: str):
        """Stop a running scan at its next checkpoint (an LLM call in flight finishes first)."""
        _running(run_id)
        store.request_control(run_id, "stop")
        if _orphaned(run_id):
            store.update_run(run_id, status="stopped", finished=time.time(), error="stopped by user (no live process)")
            store.clear_control(run_id)
            return {"ok": True, "note": "no live process was running this scan; marked as stopped"}
        return {"ok": True, "note": "stopping at the next checkpoint"}

    @app.post("/api/runs/{run_id}/skip")
    def skip(run_id: str):
        """End the current stage now and go straight to the report."""
        run = _running(run_id)
        stage = run.get("stage") or ""
        if stage not in SKIPPABLE:
            raise HTTPException(409, f"The {stage or 'current'} stage cannot be skipped "
                                     "(Discover is quick and Report is the last step).")
        store.request_control(run_id, f"skip:{stage}")
        return {"ok": True, "stage": stage, "note": f"skipping {stage} at the next checkpoint, then writing the report"}

    @app.post("/api/runs/{run_id}/continue")
    def continue_(run_id: str, body: dict):
        """Run a skipped stage (Ground or Patch & Verify) of a finished run, then the stages after it."""
        from ..pipeline import CONTINUABLE, continue_run
        stage = body.get("from_stage", "")
        if stage not in CONTINUABLE:
            raise HTTPException(400, f"Only these stages can be run on a finished scan: {', '.join(CONTINUABLE)}")
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(404, "run not found")
        if run["status"] == "running":
            raise HTTPException(409, "This run is still running.")
        if not Path(run["target"]).is_dir():
            raise HTTPException(400, f"The scanned folder no longer exists: {run['target']}")
        if scan_state["active"]:
            raise HTTPException(409, "A scan is already running. This machine runs one scan at a time.")
        run_cfg = cfg.copy()
        for k, v in (body.get("options") or {}).items():
            run_cfg.set(k, v)

        def worker():
            try:
                continue_run(run_cfg, store, run_id, stage, interactive=False, echo=False)
            except (Exception, RunStopped):  # already recorded on the run row
                pass
            finally:
                scan_state["active"] = False

        scan_state["active"] = True
        t = threading.Thread(target=worker, daemon=True)
        jobs[run_id] = t
        t.start()
        return {"run_id": run_id, "from_stage": stage}

    return app


def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8765):
    app = create_app(cfg)
    print(f"secreview dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=int(port), log_level="warning")
