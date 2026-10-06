"""Web dashboard: live view of runs, stages, findings, API surface and permission prompts.

Backed by the same SQLite store the pipeline writes to, so a scan started from the CLI (or from the
dashboard's own background thread) shows up live. Start with:  secreview dashboard
"""

from __future__ import annotations

import threading
from pathlib import Path

from ..config import Config
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

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/runs")
    def runs():
        return store.list_runs(100)

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
        project = Path(body["project"]).resolve()
        if not project.is_dir():
            raise HTTPException(400, "not a directory")
        run_cfg = cfg.copy()
        for k, v in (body.get("options") or {}).items():
            run_cfg.set(k, v)
        holder: dict = {}

        def worker():
            try:
                run_pipeline(run_cfg, project, store, interactive=False, echo=False,
                             ground_enabled=not body.get("no_ground", False))
            except Exception as exc:  # already recorded on the run row
                holder["error"] = str(exc)

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

    return app


def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8765):
    app = create_app(cfg)
    print(f"secreview dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=int(port), log_level="warning")
