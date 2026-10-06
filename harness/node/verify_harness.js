/*
 * Node verification harness used only inside the sandbox by the Verify stage.
 *
 * Decides whether ONE finding is still present, by driving the app through supertest (Express) or by
 * calling the flagged function directly, then checking the oracle condition. It is the pass/fail
 * oracle that lets the Verify stage prove a fix: the same probe must trigger on the original code and
 * NOT trigger after the patch. It drives the user's own application; it attacks nothing external.
 *
 *   node verify_harness.js spec.json
 *   -> prints:  SECREVIEW_RESULT {"result":"vulnerable|blocked|error", ...}
 *   exit 0 = triggered, 1 = not triggered, 2 = inconclusive/error
 */
"use strict";
const fs = require("fs");
const path = require("path");
const http = require("http");

function emit(result, detail = {}) {
  process.stdout.write("SECREVIEW_RESULT " + JSON.stringify({ result, ...detail }) + "\n");
  process.exit(result === "vulnerable" ? 0 : result === "blocked" ? 1 : 2);
}

function loadOracles(dir) {
  // minimal YAML subset is avoided: oracles are passed in the spec by the runner when possible,
  // else we read the shared JSON cache the Python side writes next to oracles.yaml.
  const jsonPath = path.join(dir, "oracles.json");
  if (fs.existsSync(jsonPath)) return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  return null;
}

function candidateParams(spec) {
  const out = [];
  const ep = spec.endpoint || {};
  if (spec.param) out.push(spec.param);
  for (const p of ep.params || []) if (!out.includes(p)) out.push(p);
  for (const p of ["q", "id", "name", "username", "user", "search", "url", "file", "path",
                   "host", "target", "data", "input", "page"]) if (!out.includes(p)) out.push(p);
  return out;
}

function fields(params, value) {
  const o = {};
  for (const p of params) o[p] = value;
  return o;
}

// Load the Express app exported by the project (module.exports = app) and find its handler.
function loadApp(spec) {
  const entry = spec.app_module || spec.app_entry;
  const candidates = entry ? [entry] : ["app.js", "server.js", "index.js", "src/app.js", "src/server.js",
                                        "src/index.js", "app/app.js"];
  for (const rel of candidates) {
    const full = path.resolve(spec.project_dir || ".", rel);
    if (!fs.existsSync(full)) continue;
    try {
      const mod = require(full);
      const app = mod && (mod.app || mod.default || mod);
      if (typeof app === "function" || (app && app.handle)) return app;
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error("could not load an Express app" + (typeof lastErr !== "undefined" ? ": " + lastErr.message : ""));
}
let lastErr;

function request(app, method, routePath, params, value, body, cb) {
  // substitute a path parameter if present, else send value in every candidate field
  let p = routePath || "/";
  let usedPath = false;
  p = p.replace(/(:\w+|\{[^}]+\}|\*)/, () => { usedPath = true; return encodeURIComponent(value); });
  const isGet = method === "GET" || method === "HEAD";
  let query = "";
  let payload = null;
  if (!usedPath) {
    if (isGet) query = "?" + params.map((k) => `${k}=${encodeURIComponent(value)}`).join("&");
    else payload = JSON.stringify(body || fields(params, value));
  }
  const server = http.createServer(app);
  server.listen(0, "127.0.0.1", () => {
    const port = server.address().port;
    const req = http.request(
      { host: "127.0.0.1", port, path: p + query, method,
        headers: payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {} },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => { server.close(); cb(null, { status: res.statusCode, body: data, location: res.headers.location || "" }); });
      }
    );
    req.on("error", (e) => { server.close(); cb(e); });
    if (payload) req.write(payload);
    req.end();
  });
}

function evaluate(oracle, benign, tests, canary) {
  const check = oracle.check;
  if (check === "reflect") {
    for (const [p, r] of tests) if (r.body && r.body.includes(oracle.marker) && r.status < 400)
      return emit("vulnerable", { evidence: "marker reflected unescaped", payload: String(p).slice(0, 120) });
    return emit("blocked", { reason: "marker never reflected unescaped" });
  }
  if (check === "differential") {
    if (!benign || benign.status >= 400) return emit("error", { reason: "benign request failed" });
    for (const [p, r] of tests) if (r.status < 400 && differs(benign.body, r.body))
      return emit("vulnerable", { evidence: "response differs from control (filter/auth bypass)", payload: String(p).slice(0, 120) });
    return emit("blocked", { reason: "no test input changed the control response" });
  }
  if (check === "redirect") {
    for (const [p, r] of tests) if (r.status >= 300 && r.status < 400 && (r.location || "").includes(oracle.attacker_host))
      return emit("vulnerable", { evidence: "redirects to " + r.location, payload: String(p).slice(0, 120) });
    return emit("blocked", { reason: "no external redirect" });
  }
  if (check === "marker_or_file") {
    for (const [p, r] of tests) if (oracle.marker && r.body && r.body.includes(oracle.marker))
      return emit("vulnerable", { evidence: "command output in response" });
    if (canary.fileCreated()) return emit("vulnerable", { evidence: "canary file created" });
    return emit("blocked", { reason: "command not executed" });
  }
  if (check === "read_canary") {
    for (const [p, r] of tests) if (canary.secret && r.body && r.body.includes(canary.secret))
      return emit("vulnerable", { evidence: "canary file disclosed" });
    return emit("blocked", { reason: "canary not disclosed" });
  }
  if (check === "proto") {
    if (({})[oracle.marker] !== undefined) return emit("vulnerable", { evidence: "Object.prototype polluted" });
    return emit("blocked", { reason: "prototype not polluted" });
  }
  if (check === "file_canary") {
    if (canary.fileCreated()) return emit("vulnerable", { evidence: "canary file created" });
    return emit("blocked", { reason: "code not executed" });
  }
  return emit("error", { reason: "unsupported check " + check });
}

function differs(a, b) {
  a = (a || "").replace(/\s+/g, ""); b = (b || "").replace(/\s+/g, "");
  if (a === b) return false;
  const longer = Math.max(a.length, b.length) || 1;
  return Math.abs(a.length - b.length) / longer > 0.05 || b.length > a.length * 1.2;
}

function main() {
  const spec = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  if (spec.project_dir) { try { process.chdir(spec.project_dir); } catch (e) {} }
  const oracles = loadOracles(path.resolve(__dirname, ".."));
  if (!oracles || !oracles[spec.vuln_class]) return emit("error", { reason: "no oracle for " + spec.vuln_class });
  const raw = oracles[spec.vuln_class];
  const token = spec.token || "tok";
  const fill = (s) => String(s).replace(/\{TOKEN\}/g, token).replace(/\{CANARY_FILE\}/g, spec.canary_file || "/tmp/c")
    .replace(/\{CANARY_FILE_NOSLASH\}/g, (spec.canary_file || "/tmp/c").replace(/^\/+/, ""));
  const oracle = {
    check: raw.check, marker: fill(raw.marker || raw.property || ""),
    attacker_host: raw.attacker_host || "",
    payloads: (raw.payloads_node || raw.payloads || []).map(fill),
    json_payloads: raw.json_payloads || [],
    benign: fill(raw.benign || ""),
  };
  const canary = {
    secret: spec.canary_secret || "",
    fileCreated: () => fs.existsSync(spec.canary_file) && !spec.canary_secret,
  };
  if (canary.secret && !fs.existsSync(spec.canary_file)) { try { fs.writeFileSync(spec.canary_file, canary.secret); } catch (e) {} }

  let app;
  try { app = loadApp(spec); } catch (e) { return emit("error", { reason: e.message }); }
  const ep = spec.endpoint || {};
  let method = (ep.method || "GET").toUpperCase();
  if (method === "ANY" || method === "ALL") method = ["nosqli", "prototype_pollution"].includes(spec.vuln_class) ? "POST" : "GET";
  const params = candidateParams(spec);
  const routePath = ep.path || "/";

  const queue = [];
  if (oracle.benign) queue.push(["__benign__", oracle.benign, null]);
  for (const pl of oracle.payloads) queue.push([pl, pl, null]);
  for (const jp of oracle.json_payloads) {
    const filled = JSON.parse(fill(JSON.stringify(jp)));
    queue.push([JSON.stringify(filled), "", filled]);
  }
  const results = [];
  let benign = null;
  let i = 0;
  const next = () => {
    if (i >= queue.length) return evaluate(oracle, benign, results, canary);
    const [label, value, body] = queue[i++];
    request(app, body ? "POST" : method, routePath, params, value, body, (err, res) => {
      const r = res || { status: 599, body: err ? String(err.message) : "", location: "" };
      if (label === "__benign__") benign = r;
      else results.push([label, r]);
      setImmediate(next);
    });
  };
  next();
}

try { main(); } catch (e) { emit("error", { reason: e.message, trace: (e.stack || "").slice(0, 1200) }); }
