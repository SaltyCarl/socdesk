// serve.js — minimal static server for the QA gate. Node only, no deps.
//
// The Content-Type map is load-bearing: Chromium refuses to evaluate an ES
// module served as anything other than a JavaScript MIME type, so a wrong
// `.js` type takes the entire app down with a silent module-load failure.
const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "site");
const PORT = Number(process.env.PORT || 8123);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js":   "text/javascript; charset=utf-8",   // REQUIRED for <script type=module>
  ".mjs":  "text/javascript; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg":  "image/svg+xml",
  ".ico":  "image/x-icon",
  ".png":  "image/png",
  ".jpg":  "image/jpeg",
  ".woff2": "font/woff2",
  ".txt":  "text/plain; charset=utf-8",
  ".map":  "application/json; charset=utf-8",
};

function send(res, code, body, type) {
  res.writeHead(code, {
    "Content-Type": type || "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname); }
  catch { return send(res, 400, "bad request"); }

  if (pathname === "/" || pathname.endsWith("/")) pathname += "index.html";

  // Resolve inside ROOT only — a traversal must 403, never read outside site/.
  const target = path.resolve(ROOT, "." + pathname);
  if (target !== ROOT && !target.startsWith(ROOT + path.sep))
    return send(res, 403, "forbidden");

  fs.readFile(target, (err, buf) => {
    if (err) return send(res, 404, "not found");   // data/brief.json lives here
    send(res, 200, buf, TYPES[path.extname(target).toLowerCase()] || "application/octet-stream");
  });
});

server.listen(PORT, () => console.log(`serving ${ROOT} on http://localhost:${PORT}`));
