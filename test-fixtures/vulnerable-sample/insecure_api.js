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
      `<script>document.getElementById('results').innerHTML = "${query}";</script>`
  );
});

app.get("/redirect", (req, res) => {
  // A01:2021 - Broken Access Control: open redirect
  res.redirect(req.query.url);
});

app.get("/fetch", async (req, res) => {
  // A10:2021 - Server-Side Request Forgery (SSRF)
  const target = req.query.url;
  const response = await fetch(target);
  res.send(await response.text());
});

app.listen(3001, () => console.log("Listening with secret " + JWT_SECRET));
