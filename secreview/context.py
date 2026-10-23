"""Per-run context: config + store + progress events + permission broker.

Every stage receives a RunContext and reports through it, so the CLI and the dashboard see the
same live picture (current stage, progress, log, pending permissions).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from .config import Config
from .store import Store

class RunStopped(BaseException):   # BaseException: per-tool "except Exception" guards must not swallow it
    """The user pressed Stop: the run ends at this checkpoint, marked "stopped"."""


class StageSkipped(BaseException):
    """The user pressed Skip: the current stage ends here and the run jumps to the Report stage."""


# Actions that need the user's approval when permissions.mode = "ask".
PERMISSION_ACTIONS = {
    "docker_build": "Build or pull Docker images (downloads from the internet)",
    "run_project_code": "Execute the scanned project's code and tests inside the sandbox",
    "run_project_code_unsandboxed": "Execute the scanned project's code WITHOUT isolation (local sandbox)",
    "send_code_to_cloud_llm": "Send code slices to a cloud LLM provider",
    "apply_patch": "Write verified patches into the scanned project",
    "network_install": "Install dependencies from the internet inside the sandbox",
}


class RunContext:
    def __init__(self, config: Config, store: Store, run_id: str, project: Path,
                 interactive: bool = False, echo: bool = True):
        self.config = config
        self.store = store
        self.run_id = run_id
        self.project = project.resolve()
        self.interactive = interactive          # may prompt on the terminal
        self.echo = echo                        # print events to stdout
        self.stage_name = ""
        self.out_dir = config.workspace / "runs" / run_id
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.cancelled = False
        self.skipped_by_user = ""          # stage the user skipped (the run then jumps to the report)
        self.verify_info = None          # ProjectInfo, set by the pipeline for the Verify stage

    # ---- logging & progress -------------------------------------------------------------
    def log(self, message: str, level: str = "info", **data) -> None:
        self.store.add_event(self.run_id, level, self.stage_name, message, data)
        if self.echo:
            tag = f"[{self.stage_name}]" if self.stage_name else ""
            stream = sys.stderr if level in ("warn", "error") else sys.stdout
            print(f"{level.upper():5} {tag} {message}", file=stream, flush=True)

    def warn(self, message: str, **data) -> None:
        self.log(message, "warn", **data)

    def stage_start(self, name: str, total: int = 0, note: str = "") -> None:
        self.stage_name = name
        self.store.stage(self.run_id, name, "running", 0, total, note)
        self.log(f"stage started{': ' + note if note else ''}")

    def progress(self, done: int, total: int, note: str = "") -> None:
        self.store.stage(self.run_id, self.stage_name, "running", done, total, note)
        self.check_control()

    # ---- live control (dashboard Stop / Skip buttons) ---------------------------------
    def check_control(self) -> None:
        """Checkpoint: raise RunStopped / StageSkipped if the user asked for it. Called on every progress
        update; one small read next to the write that progress() already does."""
        action = self.store.control(self.run_id)
        if action == "stop":
            self.cancelled = True
            raise RunStopped("stopped by user")
        if action == f"skip:{self.stage_name}":
            self.store.clear_control(self.run_id)
            raise StageSkipped(self.stage_name)

    def stage_end(self, status: str = "done", done: int = 0, total: int = 0, note: str = "") -> None:
        self.store.stage(self.run_id, self.stage_name, status, done, total, note)
        self.log(f"stage {status}{': ' + note if note else ''}")

    # ---- permissions --------------------------------------------------------------------
    def allow(self, action: str, detail: str = "", timeout: float = 1800) -> bool:
        """Ask for permission to perform `action`. Returns True when approved."""
        mode = self.config.get("permissions.mode", "ask")
        if mode == "auto-approve":
            return True
        if mode == "deny":
            self.warn(f"permission denied by config: {action}")
            return False
        remembered = self.store.remembered(self.run_id, action)
        if remembered:
            return remembered == "approved"

        description = PERMISSION_ACTIONS.get(action, action)
        pid = self.store.request_permission(self.run_id, action, f"{description}. {detail}".strip())
        self.log(f"waiting for permission: {description}", "warn", permission_id=pid, action=action)

        if self.interactive and sys.stdin and sys.stdin.isatty():
            answer = input(f"\nPermission needed: {description}\n  {detail}\n"
                           "  Approve? [y]es / [n]o / [a]lways for this run: ").strip().lower()
            approved = answer in ("y", "yes", "a", "always")
            self.store.decide_permission(pid, approved, remember=answer in ("a", "always"))
        else:
            # Wait for a decision from the dashboard.
            deadline = time.time() + timeout
            while time.time() < deadline and not self.cancelled:
                row = self.store.permission(pid)
                if row and row["status"] != "pending":
                    break
                if self.store.control(self.run_id):   # Stop / Skip pressed while we wait
                    break
                time.sleep(1.0)
            row = self.store.permission(pid)
            if row and row["status"] == "pending":
                self.store.decide_permission(pid, False)
        approved = (self.store.permission(pid) or {}).get("status") == "approved"
        self.log(f"permission {'approved' if approved else 'denied'}: {action}")
        if not approved:
            self.check_control()   # leave now if the wait ended because of Stop / Skip
        return approved
