// Intentionally vulnerable Express API for testing the SAST scanner.
// DO NOT run in production.

const express = require("express");
const app = express();

// A02:2021 - Cryptographic Failures: hardcoded secrets
const JWT_SECRET = "my-hardcoded-jwt-secret-do-not-use-123";
const DB_URL = "postgres://admin:SuperSecret123@db.internal:5432/prod";

app.get("/search", (req, res) => {
  // A03:2021 - Injection: reflected XSS via innerHTML
  const query = req.query.q;
  res.send(
    "<h1>Results</h1><div id='results'></div>" +
      `<script>document.getElementById('results').textContent = "${query}";</script>`
  );
});

app.get("/redirect", (req, res) => {
  // A01:2021 - Broken Access Control: open redirect
  const ALLOWED_REDIRECT_HOSTS = new Set(["example.com", "www.example.com"]);
  let redirectTarget;
  try {
    redirectTarget = new URL(req.query.url);
  } catch {
    return res.status(400).send("Invalid redirect URL");
  }
  if (!ALLOWED_REDIRECT_HOSTS.has(redirectTarget.hostname)) {
    return res.status(400).send("Redirect target not allowed");
  }
  res.redirect(req.query.url);
});

app.get("/fetch", async (req, res) => {
  // A10:2021 - Server-Side Request Forgery (SSRF)
  const target = req.query.url;
  const SSRF_ALLOWED_HOSTS = new Set(["api.example.com"]);
  let parsedUrl;
  try {
    parsedUrl = new URL(target);
  } catch {
    return res.status(400).type("text/plain").send("Invalid URL");
  }
  if (!SSRF_ALLOWED_HOSTS.has(parsedUrl.hostname) ||
      !/^https?:$/.test(parsedUrl.protocol)) {
    return res.status(400).type("text/plain").send("Blocked host");
  }
  const response = await fetch(target);
  res.type("text/plain").send(await response.text());
});

app.listen(3001, () => console.log("Listening with secret " + JWT_SECRET));
