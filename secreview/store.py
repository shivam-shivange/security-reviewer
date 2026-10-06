"""SQLite store for runs, stage progress, events, findings, endpoints and permission requests.

The pipeline writes here; the dashboard reads here. One database per workspace.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .models import Endpoint, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, target TEXT, status TEXT, stage TEXT, started REAL, finished REAL,
    options TEXT, summary TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS stages (
    run_id TEXT, name TEXT, status TEXT, done INTEGER, total INTEGER, started REAL, finished REAL,
    note TEXT, PRIMARY KEY (run_id, name)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, ts REAL, level TEXT, stage TEXT,
    message TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_run ON events(run_id, id);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT, id TEXT, status TEXT, severity TEXT, vuln_class TEXT, category TEXT,
    file TEXT, line INTEGER, data TEXT, PRIMARY KEY (run_id, id)
);
CREATE TABLE IF NOT EXISTS endpoints (run_id TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY, run_id TEXT, action TEXT, detail TEXT, status TEXT,
    created REAL, decided REAL, remember INTEGER DEFAULT 0
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur

    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    # ---- runs -------------------------------------------------------------------------
    def create_run(self, target: str, options: dict) -> str:
        run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self._exec("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?)",
                   (run_id, target, "running", "", time.time(), None, json.dumps(options), "{}", ""))
        return run_id

    def update_run(self, run_id: str, **fields: Any) -> None:
        for key, value in fields.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            self._exec(f"UPDATE runs SET {key}=? WHERE id=?", (value, run_id))

    def get_run(self, run_id: str) -> dict | None:
        rows = self._all("SELECT * FROM runs WHERE id=?", (run_id,))
        if not rows:
            return None
        run = rows[0]
        run["options"] = json.loads(run["options"] or "{}")
        run["summary"] = json.loads(run["summary"] or "{}")
        run["stages"] = self._all("SELECT * FROM stages WHERE run_id=? ORDER BY started", (run_id,))
        return run

    def list_runs(self, limit: int = 50) -> list[dict]:
        runs = self._all("SELECT * FROM runs ORDER BY started DESC LIMIT ?", (limit,))
        for r in runs:
            r["summary"] = json.loads(r["summary"] or "{}")
            r.pop("options", None)
        return runs

    # ---- stages -----------------------------------------------------------------------
    def stage(self, run_id: str, name: str, status: str, done: int = 0, total: int = 0, note: str = "") -> None:
        now = time.time()
        existing = self._all("SELECT started FROM stages WHERE run_id=? AND name=?", (run_id, name))
        if not existing:
            self._exec("INSERT INTO stages VALUES (?,?,?,?,?,?,?,?)",
                       (run_id, name, status, done, total, now, None, note))
        else:
            finished = now if status in ("done", "failed", "skipped") else None
            self._exec("UPDATE stages SET status=?, done=?, total=?, finished=?, note=? "
                       "WHERE run_id=? AND name=?", (status, done, total, finished, note, run_id, name))
        if status == "running":
            self.update_run(run_id, stage=name)

    # ---- events -----------------------------------------------------------------------
    def add_event(self, run_id: str, level: str, stage: str, message: str, data: dict | None = None) -> None:
        self._exec("INSERT INTO events (run_id, ts, level, stage, message, data) VALUES (?,?,?,?,?,?)",
                   (run_id, time.time(), level, stage, message, json.dumps(data or {})))

    def events(self, run_id: str, after_id: int = 0, limit: int = 500) -> list[dict]:
        rows = self._all("SELECT * FROM events WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
                         (run_id, after_id, limit))
        for r in rows:
            r["data"] = json.loads(r["data"] or "{}")
        return rows

    # ---- findings ---------------------------------------------------------------------
    def save_finding(self, run_id: str, f: Finding) -> None:
        self._exec("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                   (run_id, f.id, f.status, f.severity, f.vuln_class, f.category, f.file, f.line,
                    json.dumps(f.to_dict())))

    def findings(self, run_id: str) -> list[Finding]:
        rows = self._all("SELECT data FROM findings WHERE run_id=?", (run_id,))
        return [Finding.from_dict(json.loads(r["data"])) for r in rows]

    def finding(self, run_id: str, finding_id: str) -> Finding | None:
        rows = self._all("SELECT data FROM findings WHERE run_id=? AND id=?", (run_id, finding_id))
        return Finding.from_dict(json.loads(rows[0]["data"])) if rows else None

    # ---- endpoints --------------------------------------------------------------------
    def save_endpoints(self, run_id: str, endpoints: list[Endpoint]) -> None:
        from dataclasses import asdict
        self._exec("DELETE FROM endpoints WHERE run_id=?", (run_id,))
        for ep in endpoints:
            self._exec("INSERT INTO endpoints VALUES (?,?)", (run_id, json.dumps(asdict(ep))))

    def endpoints(self, run_id: str) -> list[dict]:
        return [json.loads(r["data"]) for r in self._all("SELECT data FROM endpoints WHERE run_id=?", (run_id,))]

    # ---- permissions ------------------------------------------------------------------
    def request_permission(self, run_id: str, action: str, detail: str) -> str:
        pid = uuid.uuid4().hex[:12]
        self._exec("INSERT INTO permissions VALUES (?,?,?,?,?,?,?,?)",
                   (pid, run_id, action, detail, "pending", time.time(), None, 0))
        return pid

    def decide_permission(self, pid: str, approved: bool, remember: bool = False) -> None:
        self._exec("UPDATE permissions SET status=?, decided=?, remember=? WHERE id=? AND status='pending'",
                   ("approved" if approved else "denied", time.time(), int(remember), pid))

    def permission(self, pid: str) -> dict | None:
        rows = self._all("SELECT * FROM permissions WHERE id=?", (pid,))
        return rows[0] if rows else None

    def permissions(self, run_id: str | None = None, pending_only: bool = False) -> list[dict]:
        sql, args = "SELECT * FROM permissions WHERE 1=1", []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        if pending_only:
            sql += " AND status='pending'"
        return self._all(sql + " ORDER BY created DESC", tuple(args))

    def remembered(self, run_id: str, action: str) -> str | None:
        rows = self._all("SELECT status FROM permissions WHERE run_id=? AND action=? AND remember=1 "
                         "AND status!='pending' ORDER BY decided DESC LIMIT 1", (run_id, action))
        return rows[0]["status"] if rows else None
