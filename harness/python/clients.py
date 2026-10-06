"""In-process app clients + canary state for the Python verification harness.

The harness prefers to exercise one route through the framework's own test client (Flask/FastAPI/
Django), so no server or open port is needed inside the sandbox. If the finding is not reachable
through a route, it falls back to calling the flagged function directly with the oracle input.
"""

from __future__ import annotations

import importlib
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from probe import Oracle, Verdict, evaluate


class Canary:
    """Tracks side effects the oracle checks for: file creation/read, SSRF hit, prototype (n/a in py)."""

    def __init__(self, spec: dict):
        self.path = Path(spec.get("canary_file", "/tmp/secreview_canary"))
        self.secret = spec.get("canary_secret", "")
        self._ssrf_hit = False
        self._server = None
        if self.secret and not self.path.exists():
            try:
                self.path.write_text(self.secret, encoding="utf-8")
            except OSError:
                pass
        if self.path.exists() and not self.secret:
            try:
                self.path.unlink()
            except OSError:
                pass

    def start_ssrf_listener(self) -> int:
        canary = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                canary._ssrf_hit = True
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"secreview-canary")

            def log_message(self, *a):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self._server.server_address[1]

    def file_created(self) -> bool:
        return self.path.exists() and not self.secret

    def ssrf_hit(self) -> bool:
        return self._ssrf_hit

    def proto_polluted(self, _prop) -> bool:
        return False

    def reset(self):
        if self.file_created():
            try:
                self.path.unlink()
            except OSError:
                pass


class BaseClient:
    def __init__(self, spec: dict):
        self.spec = spec
        self.canary = Canary(spec)
        self.target = spec.get("endpoint") or {}
        self.params = self._candidate_params()
        self.param = self.params[0]

    def _candidate_params(self) -> list:
        """All plausible parameter names. The harness sends the test value in every one at once, so it
        does not matter which name the handler actually reads."""
        out = list(self.target.get("params") or [])
        if self.spec.get("param"):
            out.insert(0, self.spec["param"])
        for extra in ["q", "id", "name", "username", "user", "search", "query", "url", "file",
                      "path", "host", "target", "data", "input", "cmd", "page"]:
            if extra not in out:
                out.append(extra)
        return out

    def _payload_fields(self, value) -> dict:
        return {p: value for p in self.params}

    def run(self, oracle: Oracle) -> Verdict:
        raise NotImplementedError

    def _prep_canary(self, oracle: Oracle):
        if oracle.check == "ssrf_canary":
            port = self.canary.start_ssrf_listener()
            oracle.payloads = [p.replace(":0/", f":{port}/").replace("127.0.0.1:0", f"127.0.0.1:{port}")
                               for p in oracle.payloads]


def _method_path(spec: dict) -> tuple[str, str]:
    ep = spec.get("endpoint") or {}
    method = (ep.get("method") or "GET").upper()
    if method in ("ANY", "ALL"):
        method = "POST" if spec.get("vuln_class") in ("nosqli", "mass_assignment") else "GET"
    return method, ep.get("path") or "/"


def _subst_path(path: str, value: str) -> tuple[str, bool]:
    """Put the payload into a path parameter if the route has one. Returns (path, used_path_param)."""
    import re
    new, n = re.subn(r"(<[^>]+>|\{[^}]+\}|:\w+)", lambda m: value, path, count=1)
    return new, bool(n)


class FlaskClient(BaseClient):
    def __init__(self, spec):
        super().__init__(spec)
        mod = importlib.import_module(spec["app_module"])
        self.app = getattr(mod, spec.get("app_attr", "app"))
        self.client = self.app.test_client()

    def _request(self, method, path, value, oracle, as_json=False, json_body=None):
        kwargs = {}
        used_path = False
        send_path, used_path = _subst_path(path, value)
        if not used_path:
            if method == "GET":
                kwargs["query_string"] = self._payload_fields(value)
            elif as_json or json_body is not None:
                kwargs["json"] = json_body if json_body is not None else self._payload_fields(value)
            else:
                kwargs["data"] = self._payload_fields(value)
        resp = self.client.open(send_path, method=method, follow_redirects=False, **kwargs)
        body = resp.get_data(as_text=True)
        if oracle.check == "redirect":
            return resp.status_code, body, resp.headers.get("Location", "")
        return resp.status_code, body

    def run(self, oracle: Oracle) -> Verdict:
        self._prep_canary(oracle)
        method, path = _method_path(self.spec)
        benign = self._request(method, path, oracle.benign, oracle) if oracle.benign else None
        test = []
        for payload in oracle.payloads:
            self.canary.reset() if oracle.check in ("file_canary", "marker_or_file") else None
            test.append((payload, self._request(method, path, payload, oracle)))
            if oracle.check in ("file_canary", "ssrf_canary", "read_canary", "marker_or_file") and \
                    (self.canary.file_created() or self.canary.ssrf_hit()):
                break
        for jp in oracle.json_payloads:
            test.append((jp, self._request("POST", path, "", oracle, json_body={self.param: jp})))
        return evaluate(oracle, benign, test, self.canary)


class FastAPIClient(BaseClient):
    def __init__(self, spec):
        super().__init__(spec)
        from starlette.testclient import TestClient
        mod = importlib.import_module(spec["app_module"])
        self.client = TestClient(getattr(mod, spec.get("app_attr", "app")), raise_server_exceptions=False)

    def _request(self, method, path, value, oracle, json_body=None):
        send_path, used_path = _subst_path(path, value)
        kwargs = {"follow_redirects": False}
        if not used_path:
            if method == "GET":
                kwargs["params"] = self._payload_fields(value)
            elif json_body is not None:
                kwargs["json"] = json_body
            else:
                kwargs["json"] = self._payload_fields(value)
        resp = self.client.request(method, send_path, **kwargs)
        if oracle.check == "redirect":
            return resp.status_code, resp.text, resp.headers.get("location", "")
        return resp.status_code, resp.text

    def run(self, oracle: Oracle) -> Verdict:
        self._prep_canary(oracle)
        method, path = _method_path(self.spec)
        benign = self._request(method, path, oracle.benign, oracle) if oracle.benign else None
        test = []
        for payload in oracle.payloads:
            self.canary.reset() if oracle.check in ("file_canary", "marker_or_file") else None
            test.append((payload, self._request(method, path, payload, oracle)))
        for jp in oracle.json_payloads:
            test.append((jp, self._request("POST", path, "", oracle, json_body={self.param: jp})))
        return evaluate(oracle, benign, test, self.canary)


class DjangoClient(BaseClient):
    def __init__(self, spec):
        super().__init__(spec)
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", spec["django_settings"])
        import django
        django.setup()
        from django.test import Client
        self.client = Client()

    def _request(self, method, path, value, oracle, json_body=None):
        send_path, used_path = _subst_path(path, value)
        fn = getattr(self.client, method.lower())
        if used_path:
            resp = fn(send_path)
        elif method == "GET":
            resp = fn(send_path, self._payload_fields(value))
        elif json_body is not None:
            resp = fn(send_path, data=json_body, content_type="application/json")
        else:
            resp = fn(send_path, self._payload_fields(value))
        body = resp.content.decode("utf-8", "replace")
        if oracle.check == "redirect":
            return resp.status_code, body, resp.get("Location", "")
        return resp.status_code, body

    def run(self, oracle: Oracle) -> Verdict:
        self._prep_canary(oracle)
        method, path = _method_path(self.spec)
        benign = self._request(method, path, oracle.benign, oracle) if oracle.benign else None
        test = [(p, self._request(method, path, p, oracle)) for p in oracle.payloads]
        for jp in oracle.json_payloads:
            test.append((jp, self._request("POST", path, "", oracle, json_body={self.param: jp})))
        return evaluate(oracle, benign, test, self.canary)


class FunctionClient(BaseClient):
    """Fallback: import the flagged module and call the target function with the oracle input."""

    def run(self, oracle: Oracle) -> Verdict:
        self._prep_canary(oracle)
        mod = importlib.import_module(self.spec["target_module"])
        fn = getattr(mod, self.spec["target_function"])
        benign = None
        if oracle.benign:
            benign = self._call(fn, oracle.benign)
        test = [(p, self._call(fn, p)) for p in oracle.payloads]
        return evaluate(oracle, benign, test, self.canary)

    def _call(self, fn, value):
        try:
            out = fn(value)
            return 200, str(out) if out is not None else ""
        except Exception as exc:
            return 500, f"{type(exc).__name__}: {exc}"


def build_client(spec: dict) -> BaseClient:
    kind = spec.get("client")
    if not kind:
        fw = (spec.get("endpoint") or {}).get("framework", "")
        kind = {"flask": "flask", "fastapi": "fastapi", "django": "django"}.get(fw, "function")
    return {"flask": FlaskClient, "fastapi": FastAPIClient, "django": DjangoClient,
            "function": FunctionClient}[kind](spec)
