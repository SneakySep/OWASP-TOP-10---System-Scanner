# SAST Scanner — OWASP Top 10 with Semgrep

Drop in a folder, a mix of files, or a .zip archive — it is scanned with
Semgrep's OWASP Top 10 ruleset, and findings are grouped by OWASP category
with remediation guidance.

## Stack

- **Frontend:** Next.js 14 (App Router), Tailwind CSS, Lucide icons
- **Backend:** Python 3.11, FastAPI
- **Engine:** Semgrep CLI (`p/owasp-top-ten`)

## Run with Docker (recommended)

```bash
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000/api/scan
- Health check: http://localhost:8000/api/health

The first scan downloads the Semgrep ruleset and takes a minute or two;
subsequent scans are faster (rules are cached in the `semgrep_cache` volume).

## Local development

Backend:

```bash
cd backend
pip install fastapi "uvicorn[standard]" python-multipart semgrep
uvicorn main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## What you can upload

- A **whole folder** — drag & drop it or use "Browse folder"
- **Any mix of individual files** — drag & drop or "Browse files"
- A **.zip archive** — uploaded as-is

Folders and loose files are zipped in the browser (relative paths preserved)
and sent as a single archive, so the backend always receives a plain `.zip`.
Junk folders (`node_modules`, `.git`, `__pycache__`, `.venv`, `venv`, `.next`,
`dist`, `build`, `.idea`, `.vscode`) are skipped automatically. Limits:
5,000 files and 100 MB per upload (matching the backend).

## API

`POST /api/scan` — multipart form field `file` containing a `.zip`, plus an
optional `ruleset` field (`p/owasp-top-ten`, the default, or
`p/security-audit`; anything else is rejected with 400). Folder/file
selections are zipped client-side first, so the archive contract is unchanged.
Returns enriched JSON:

```json
{
  "scan_id": "...",
  "total_findings": 12,
  "severity_counts": { "Critical": 1, "High": 4, "Medium": 5, "Low": 2 },
  "groups": [
    {
      "category": "A03:2021-Injection",
      "title": "A03: Injection",
      "findings": [
        {
          "rule_id": "python.sqlalchemy.sqli",
          "file": "app/db.py",
          "start_line": 42,
          "code_snippet": "...",
          "severity": "Critical",
          "owasp_category": "A03:2021-Injection",
          "remediation": { "title": "...", "summary": "...", "steps": ["..."],
                            "references": [{ "title": "...", "url": "https://..." }] }
        }
      ]
    }
  ]
}
```

`GET /api/remediation` returns the same OWASP knowledge base as a browsable
catalog: `{ "count": 10, "categories": [{ "category": "...", "title": "...",
"summary": "...", "steps": ["..."], "references": [{ "title", "url" }] }] }`.

## Suggested fixes and `/api/fix`

Findings may carry a `suggested_fix` object with a patched snippet, an
explanation and a confidence level:

```json
{
  "suggested_fix": {
    "patched_code": "query = \"SELECT * FROM users WHERE id = ?\"",
    "explanation": "Replaced string concatenation in the SQL statement ...",
    "confidence": "high"
  }
}
```

- `confidence: "high"` — mechanical, safe transform (SQL parameterization,
  `textContent`, Flask `host`/`debug` flags).
- `confidence: "medium"` — needs a human decision (allow-list placeholders,
  PBKDF2 migration, `shlex.split` semantics).

`POST /api/fix` takes the same multipart `.zip` and optional `ruleset` as
`/api/scan` and streams back `fixed-source.zip` with every applicable suggested fix applied. Original
uploads are never modified; the dashboard only ever edits a downloaded copy.
The archive contains a `_FIX_REPORT.json`:

```json
{
  "applied": [
    { "rule_id": "...", "file": "app.py", "start_line": 42,
      "explanation": "...", "confidence": "high" }
  ],
  "unfixed": [
    { "rule_id": "...", "file": "app.py", "start_line": 7,
      "reason": "No automatic fix available." }
  ],
  "total_findings": 12
}
```

The frontend's "Download fixed code" button posts the scanned archive to this
endpoint, saves the zip, reads the report and shows "Applied X of Y".

## Auto-fix suggestions (how they work)

The autofix engine (`backend/autofix.py`) is a set of conservative,
rule-aware fixers. Each fixer only fires when the flagged code matches the
exact pattern the rule targets; otherwise the finding falls back to plain
remediation guidance.

| Rule family | Fix |
| --- | --- |
| `tainted-sql-string` | Parameterize the query (`?` placeholder + `execute(query, (var,))`) |
| `subprocess-*` with `shell=True` | `shlex.split(...)` + `shell=False`, adds `import shlex` |
| `insecure-hash-algorithms-md5` / `md5-used-as-password` | Passwords → `hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)` with `salt = os.urandom(16)`; other digests → SHA-256 |
| Flask `host="0.0.0.0"` / `debug=True` | `host="127.0.0.1"` / `debug=False` |
| XSS `innerHTML` writes | `textContent` (renders attacker input as plain text) |
| Express open redirect | URL parse + `ALLOWED_REDIRECT_HOSTS` allow-list, 400 otherwise |
| SSRF `fetch` with echoed body | Host/protocol allow-list gate + `res.type("text/plain")` |

Notes and limits:

- Suggestions are **review-first**: review the green "Suggested fix" block and
  the downloaded diff before committing anything.
- Allow-lists ship with placeholder hosts (`example.com`, `api.example.com`) —
  replace them with your real domains before merging.
- The PBKDF2 fix generates a random salt per call; you must wire salt storage
  (e.g. `salt.hex() + "$" + digest.hex()`) into your database schema and
  password-verification path.
- `?` placeholders target SQLite/MySQL-style drivers; use `%s` for psycopg.
- Try it on `test-fixtures/vulnerable-sample/` — all 7 findings carry
  suggested fixes. `test-fixtures/fixed-sample/` shows the expected result
  (re-scanning it reports no findings).

## Security notes

- Uploads are validated (extension, size, ZIP magic bytes) before extraction.
- Each scan extracts into a unique `/tmp/scans/scan-<uuid>` directory.
- A `finally` block deletes the entire temp directory on success or failure.
- Backend container runs as a non-root user (`appuser`).
