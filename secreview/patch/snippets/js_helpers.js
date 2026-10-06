// Predefined JavaScript helpers inserted by fix templates (only the helpers a fix needs are copied).
// Each helper starts with a "// --- secreview:<name>" marker line.

// --- secreview:escape_html
function secreviewEscapeHtml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// --- secreview:safe_path
function secreviewSafePath(base, ...parts) {
  const nodePath = require("path");
  const root = nodePath.resolve(String(base));
  const target = nodePath.resolve(root, ...parts.map(String));
  if (target !== root && !target.startsWith(root + nodePath.sep)) {
    const err = new Error("Path traversal blocked");
    err.status = 400;
    throw err;
  }
  return target;
}

// --- secreview:safe_path_esm
function secreviewSafePath(base, ...parts) {
  const root = __secreviewPath.resolve(String(base));
  const target = __secreviewPath.resolve(root, ...parts.map(String));
  if (target !== root && !target.startsWith(root + __secreviewPath.sep)) {
    const err = new Error("Path traversal blocked");
    err.status = 400;
    throw err;
  }
  return target;
}

// --- secreview:safe_url
function secreviewSafeUrl(value) {
  const url = new URL(String(value));
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("URL scheme not allowed");
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const allowed = (process.env.SECREVIEW_ALLOWED_HOSTS || "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (allowed.length && !allowed.includes(host)) throw new Error("Host not in allowlist");
  const blocked = /^(localhost|.*\.localhost|.*\.internal|metadata\.google\.internal|0\.0\.0\.0|::1?|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|f[cd][0-9a-f]{2}:.*|fe80:.*)$/;
  if (blocked.test(host)) throw new Error("Internal address blocked");
  return url.toString();
}

// --- secreview:safe_redirect
function secreviewSafeRedirect(target) {
  const t = String(target || "");
  return t.startsWith("/") && !t.startsWith("//") && !t.includes("\\") ? t : "/";
}

// --- secreview:safe_key
function secreviewSafeKey(key) {
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    throw new Error("Prototype pollution attempt blocked");
  }
  return key;
}

// --- secreview:strip_proto
function secreviewStripProto(value) {
  return JSON.parse(JSON.stringify(value), (k, v) =>
    (k === "__proto__" || k === "constructor" || k === "prototype") ? undefined : v);
}

// --- secreview:shell_quote
function secreviewShellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

// --- secreview:end
