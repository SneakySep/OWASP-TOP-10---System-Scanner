"""
FastAPI backend for the SAST application.

Accepts a .zip source-code upload, extracts it into a unique temporary
directory, runs `semgrep scan --config p/owasp-top-ten --json`, enriches the
findings with custom OWASP remediation notes plus rule-aware auto-fix
suggestions, merges overlapping findings that point at the same code
location, and returns the result. `POST /api/fix` re-scans the same kind of
upload and streams back a `fixed-source.zip` with the applicable suggested
fixes applied. The temporary directory is destroyed in a `finally` block on
every code path.
"""

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import store
from autofix import apply_edits, compute_suggested_fix
from remediation import REMEDIATION_NOTES, get_remediation
from reports import to_sarif, to_unified_diff

app = FastAPI(title="SAST Scanner API", version="1.0.0")

# The Next.js frontend runs in its own container; allow its origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://frontend:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
    # Fix and patch responses report counts in headers; a cross-origin browser
    # can only read headers that are explicitly exposed.
    expose_headers=["X-Fixes-Applied", "X-Fixes-Unfixed", "Content-Disposition"],
)

SCAN_DIR = Path(os.environ.get("SCAN_DIR", "/tmp/scans"))
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB, compressed
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB once extracted
# Keep in sync with MAX_FILES in frontend/lib/collectFiles.ts.
MAX_ARCHIVE_FILES = 5_000
# Reject entries that inflate more than 200x (zip-bomb guard).
MAX_COMPRESSION_RATIO = 200
ALLOWED_EXTENSIONS = {".zip"}
ALLOWED_SCAN_FORMATS = {"json", "sarif"}
ALLOWED_FIX_FORMATS = {"zip", "patch"}

# Semgrep configs a client may ask for. Must stay in sync with
# frontend/lib/api.ts — never pass an arbitrary string to `--config`.
ALLOWED_RULESETS = {
    "p/owasp-top-ten": "OWASP Top 10",
    "p/security-audit": "Semgrep security-audit",
}
DEFAULT_RULESET = "p/owasp-top-ten"

# Semgrep severity -> dashboard severity bucket.
SEVERITY_MAP = {
    "ERROR": "Critical",
    "WARNING": "High",
    "INFO": "Medium",
}

# Rough keyword mapping from a rule id/message to an OWASP Top 10 category.
CATEGORY_RULES: list[tuple[str, re.Pattern]] = [
    ("A03:2021-Injection", re.compile(r"inject|sql|command|sqli|xss|script|eval|deserial|format.string|template", re.I)),
    ("A01:2021-Broken Access Control", re.compile(r"access.control|idor|authorization|permission|path.traversal|open.redirect", re.I)),
    ("A02:2021-Cryptographic Failures", re.compile(r"crypto|hash|md5|sha1|password|secret|tls|ssl|random", re.I)),
    ("A07:2021-Identification and Authentication Failures", re.compile(r"auth|session|jwt|token|login|cookie", re.I)),
    ("A05:2021-Security Misconfiguration", re.compile(r"config|debug|cors|header|flask|django.setting|exposure", re.I)),
    ("A08:2021-Software and Data Integrity Failures", re.compile(r"deserial|pickle|yaml.load|integrity|sign", re.I)),
    ("A09:2021-Security Logging and Monitoring Failures", re.compile(r"log|monitor|audit", re.I)),
    ("A10:2021-Server-Side Request Forgery (SSRF)", re.compile(r"ssrf|request|url.fetch|urllib", re.I)),
    ("A04:2021-Insecure Design", re.compile(r"design|race|rate.limit", re.I)),
    ("A06:2021-Vulnerable and Outdated Components", re.compile(r"outdated|cve|dependency", re.I)),
]


def classify_owasp(rule_id: str, message: str) -> str:
    """Best-effort mapping of a Semgrep finding to an OWASP Top 10 category."""
    haystack = f"{rule_id} {message}"
    for category, pattern in CATEGORY_RULES:
        if pattern.search(haystack):
            return category
    return "A05:2021-Security Misconfiguration"


def validate_zip(filename: str, data: bytes) -> None:
    """Reject anything that is not a .zip and anything oversized."""
    if not filename or Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .zip uploads are accepted.")
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 100 MB limit.")
    # ZIP magic bytes: PK\x03\x04
    if data[:4] != b"PK\x03\x04":
        raise HTTPException(status_code=400, detail="File is not a valid zip archive.")


def normalize_rel_path(path: str) -> str:
    """Normalize a Semgrep-reported path to one inside the extracted tree.

    Strips the absolute container prefix up to ``/source/`` and a leading
    ``./``. Only the ``./`` *sequence* is removed: ``lstrip("./")`` would also
    eat the leading dot of ``.env`` or ``.github/workflows/ci.yml``.
    """
    normalized = path.replace("\\", "/")
    marker = "/source/"
    if marker in normalized:
        normalized = normalized.split(marker, 1)[1]
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/")


def extract_zip(zip_path: Path, extract_dir: Path) -> None:
    """Extract ``zip_path`` after rejecting bombs and unsafe member paths.

    ``zipfile`` already sanitizes absolute paths and ``..`` components, but it
    does not bound decompressed size, so a small upload can expand to many
    gigabytes. Every member is checked before a single byte is written.
    """
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_FILES:
                raise HTTPException(
                    status_code=413,
                    detail=f"Archive contains more than {MAX_ARCHIVE_FILES:,} entries.",
                )
            total = sum(member.file_size for member in members)
            if total > MAX_UNCOMPRESSED_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Archive expands beyond the 500 MB extraction limit.",
                )
            root = extract_dir.resolve()
            for member in members:
                if (
                    member.file_size > 1024 * 1024
                    and member.compress_size
                    and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO
                ):
                    raise HTTPException(
                        status_code=413,
                        detail="Archive entry has an implausible compression ratio.",
                    )
                target = (extract_dir / member.filename).resolve()
                if not target.is_relative_to(root):
                    raise HTTPException(
                        status_code=400,
                        detail="Archive contains an unsafe path.",
                    )
            archive.extractall(extract_dir)
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Corrupt zip archive.") from exc


def validate_ruleset(ruleset: str) -> str:
    """Allow only known Semgrep configs; anything else is a client bug."""
    if ruleset not in ALLOWED_RULESETS:
        allowed = ", ".join(sorted(ALLOWED_RULESETS))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported ruleset. Choose one of: {allowed}.",
        )
    return ruleset


def validate_format(value: str, allowed: set[str], default: str) -> str:
    """Allow only known response formats; anything else is a client bug."""
    fmt = (value or default).strip().lower()
    if fmt not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format. Choose one of: {', '.join(sorted(allowed))}.",
        )
    return fmt


def run_semgrep(scan_dir: Path, ruleset: str = DEFAULT_RULESET) -> dict:
    """Run Semgrep against the extracted tree and return parsed JSON results."""
    results_path = scan_dir / "results.json"
    command = [
        "semgrep", "scan",
        "--config", ruleset,
        "--json",
        "--output", str(results_path),
        str(scan_dir),
    ]
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(scan_dir),
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Semgrep scan timed out.") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Semgrep binary not found in container.") from exc

    if not results_path.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Semgrep produced no results. stderr: {process.stderr[-500:]}",
        )
    try:
        return json.loads(results_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Could not parse Semgrep output.") from exc


def enrich(raw: dict, file_lines: dict[str, list[str]] | None = None) -> dict:
    """Turn raw Semgrep JSON into the enriched, grouped dashboard payload.

    `file_lines` maps relative paths (posix-style, as Semgrep reports them)
    to the file's source lines. When provided, every finding gains a nullable
    `suggested_fix` with a rule-aware code repair from the autofix engine.
    """
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    findings: list[dict] = []
    for result in raw.get("results", []):
        rule_id = result.get("check_id", "unknown-rule")
        message = result.get("extra", {}).get("message", "")
        severity_raw = result.get("extra", {}).get("severity", "INFO")
        severity = SEVERITY_MAP.get(severity_raw.upper(), "Low")
        category = classify_owasp(rule_id, message)
        remediation = get_remediation(category)

        lines = result.get("start", {}).get("line", 0), result.get("end", {}).get("line", 0)

        # Semgrep may report absolute container paths (…/scan-<uuid>/source/
        # app.py); normalize to the path inside the extracted tree so the
        # dashboard shows clean names and autofix can find the file.
        raw_path = result.get("path", "")
        path = normalize_rel_path(raw_path)

        suggested_fix = None
        fix_lines = (file_lines or {}).get(path)
        if fix_lines is None and file_lines:
            # Suffix fallback for unexpected path shapes.
            norm = raw_path.replace("\\", "/")
            for key, candidate in file_lines.items():
                if norm.endswith(key):
                    fix_lines = candidate
                    break
        if fix_lines:
            fix = compute_suggested_fix(rule_id, message, lines[0], lines[1], fix_lines)
            if fix:
                suggested_fix = {
                    "patched_code": fix.patched_code,
                    "explanation": fix.explanation,
                    "confidence": fix.confidence,
                    "edits": [[s, e, r] for s, e, r in fix.edits],
                }

        findings.append({
            "id": f"{rule_id}:{path}:{result.get('start', {}).get('line')}",
            "rule_id": rule_id,
            "message": message,
            "file": path or "unknown",
            "start_line": lines[0],
            "end_line": lines[1],
            "code_snippet": result.get("extra", {}).get("lines", "").rstrip("\n"),
            "severity": severity,
            "owasp_category": category,
            "remediation": remediation,
            "suggested_fix": suggested_fix,
        })

    # Merge findings that point at the same code location. Rulesets such as
    # p/owasp-top-ten contain overlapping rules that flag the same line; keep
    # the most severe as the primary finding and list the others as related
    # rules so the dashboard shows one card per location without losing info.
    by_location: dict[tuple[str, int, int], list[dict]] = {}
    for finding in findings:
        key = (finding["file"], finding["start_line"], finding["end_line"])
        by_location.setdefault(key, []).append(finding)

    merged: list[dict] = []
    for loc_findings in by_location.values():
        loc_findings.sort(key=lambda f: severity_rank.get(f["severity"], 9))
        primary = loc_findings[0]
        primary["related_rules"] = sorted({f["rule_id"] for f in loc_findings[1:]})
        merged.append(primary)

    # Group findings by OWASP category for the dashboard.
    grouped: dict[str, dict] = {}
    for finding in merged:
        cat = finding["owasp_category"]
        group = grouped.setdefault(cat, {
            "category": cat,
            "title": remediation_title(cat),
            "findings": [],
        })
        group["findings"].append(finding)

    groups = sorted(grouped.values(), key=lambda g: min(
        (severity_rank.get(f["severity"], 9) for f in g["findings"]), default=9
    ))

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in merged:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "scan_id": str(uuid.uuid4()),
        "total_findings": len(merged),
        "severity_counts": counts,
        "groups": groups,
        "errors": raw.get("errors", []),
    }


def collect_file_lines(root: Path) -> dict[str, list[str]]:
    """Read the extracted tree into {relative_posix_path: [lines]} for autofix."""
    out: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue  # skip huge files; fix suggestions aren't worth it
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out[path.relative_to(root).as_posix()] = text.splitlines()
    return out


def scan_extracted(
    extract_dir: Path,
    ruleset: str = DEFAULT_RULESET,
    file_lines: dict[str, list[str]] | None = None,
) -> dict:
    """Scan an extracted tree and return the enriched dashboard payload.

    ``file_lines`` lets callers that already read the tree (``/api/fix``)
    avoid a second pass over every file.
    """
    raw = run_semgrep(extract_dir, ruleset)
    return enrich(
        raw, file_lines if file_lines is not None else collect_file_lines(extract_dir)
    )


def remediation_title(category: str) -> str:
    return get_remediation(category)["title"]


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/remediation")
def remediation_catalog() -> dict:
    """Browsable OWASP Top 10 knowledge base for the /remediation page.

    Exposes the same notes that are attached to individual findings, so the
    frontend does not have to duplicate the guidance.
    """
    categories = [
        {"category": category, **note}
        for category, note in REMEDIATION_NOTES.items()
    ]
    categories.sort(key=lambda entry: entry["category"])
    return {"count": len(categories), "categories": categories}


@app.post("/api/scan")
def scan(
    file: UploadFile = File(...),
    ruleset: str = Form(DEFAULT_RULESET),
    label: str = Form(""),
    format: str = Form("json"),
) -> Response:
    """Scan an upload and return the enriched dashboard payload.

    Declared ``def`` on purpose: FastAPI then runs the handler in a worker
    thread, so the blocking Semgrep subprocess and file I/O never stall the
    event loop (health checks keep answering while a scan runs).

    Every scan is stored in the history database and compared with the most
    recent previous scan of the same target (same set of file paths), so the
    response carries a ``baseline`` of new / fixed / unchanged findings.
    ``format=sarif`` returns a SARIF 2.1.0 log instead of the dashboard JSON.
    """
    validate_ruleset(ruleset)
    output_format = validate_format(format, ALLOWED_SCAN_FORMATS, "json")
    data = file.file.read()
    validate_zip(file.filename or "", data)
    target_label = (label or file.filename or "upload.zip").strip()[:200]

    # Unique temp directory per scan; never reuse, never predictable.
    scan_dir = SCAN_DIR / f"scan-{uuid.uuid4().hex}"
    scan_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Extract the zip safely.
        zip_path = scan_dir / "upload.zip"
        zip_path.write_bytes(data)
        extract_dir = scan_dir / "source"
        extract_dir.mkdir()
        extract_zip(zip_path, extract_dir)

        # 2. Read the tree once: autofix and the target fingerprint share it.
        file_lines = collect_file_lines(extract_dir)
        payload = scan_extracted(extract_dir, ruleset, file_lines)

        # 3. Compare with the previous scan of this target, then record it.
        fingerprint = store.fingerprint_of(file_lines)
        previous = store.latest_for(fingerprint, exclude_scan_id=payload["scan_id"])
        if previous is not None:
            store.annotate_baseline(payload, previous)
        store.save_scan(
            scan_id=payload["scan_id"],
            label=target_label,
            ruleset=ruleset,
            fingerprint=fingerprint,
            payload=payload,
        )

        if output_format == "sarif":
            return Response(
                content=json.dumps(to_sarif(payload), indent=2),
                media_type="application/sarif+json",
                headers={
                    "Content-Disposition": 'attachment; filename="scan-report.sarif"'
                },
            )
        return JSONResponse(payload)
    finally:
        # Aggressive cleanup: the temp directory never outlives this request.
        shutil.rmtree(scan_dir, ignore_errors=True)


@app.post("/api/fix")
def fix(
    file: UploadFile = File(...),
    ruleset: str = Form(DEFAULT_RULESET),
    format: str = Form("zip"),
) -> Response:
    """Re-scan an upload and stream back fixed-source.zip with fixes applied.

    Same zip validation as /api/scan. The response archive contains the
    patched source tree plus a `_FIX_REPORT.json` listing which findings were
    auto-fixed and which were left untouched (with reasons). Original uploads
    are never modified.

    ``format=patch`` returns a unified diff (``git apply``-able) instead of
    the archive, with the applied/unfixed counts in ``X-Fixes-`` headers.
    """
    validate_ruleset(ruleset)
    fix_format = validate_format(format, ALLOWED_FIX_FORMATS, "zip")
    data = file.file.read()
    validate_zip(file.filename or "", data)

    scan_dir = SCAN_DIR / f"fix-{uuid.uuid4().hex}"
    scan_dir.mkdir(parents=True, exist_ok=True)

    try:
        zip_path = scan_dir / "upload.zip"
        zip_path.write_bytes(data)
        extract_dir = scan_dir / "source"
        extract_dir.mkdir()
        extract_zip(zip_path, extract_dir)

        file_lines = collect_file_lines(extract_dir)
        payload = scan_extracted(extract_dir, ruleset, file_lines)

        # Group candidate fixes per file in report order.
        applied: list[dict] = []
        unfixed: list[dict] = []
        candidates: dict[str, list[tuple[dict, list[tuple[int, int, str]], dict]]] = {}
        for group in payload["groups"]:
            for finding in group["findings"]:
                base = {
                    "id": finding["id"],
                    "rule_id": finding["rule_id"],
                    "file": finding["file"],
                    "start_line": finding["start_line"],
                }
                sf = finding.get("suggested_fix")
                rel = finding["file"]
                if rel not in file_lines:
                    rel = normalize_rel_path(rel)
                if not sf or rel not in file_lines:
                    unfixed.append({**base, "reason": "No automatic fix available."})
                    continue
                edits = [(e[0], e[1], e[2]) for e in sf["edits"]]
                candidates.setdefault(rel, []).append((base, edits, sf))

        # Merge edits per file. Two fixers may legitimately anchor the same
        # line (e.g. two `import` insertions after the same import statement);
        # those are combined. Any other overlap rolls the later finding back
        # and reports it as unfixed instead of applying edits on top of stale
        # line numbers.
        file_edits: dict[str, list[tuple[int, int, str]]] = {}
        for rel, entries in candidates.items():
            merged: dict[tuple[int, int], str] = {}
            for base, edits, sf in entries:
                touched: list[tuple[tuple[int, int], str | None]] = []
                collision = False
                for s, e, r in edits:
                    key = (s, e)
                    if key not in merged:
                        touched.append((key, None))
                        merged[key] = r
                        continue
                    existing = merged[key]
                    # Mergeable when the replacement keeps the same anchor
                    # line and only appends new lines (import insertions).
                    mergeable = (
                        len(r.split("\n")) > 1
                        and r.split("\n")[0] == existing.split("\n")[0]
                    )
                    if not mergeable:
                        collision = True
                        break
                    touched.append((key, existing))
                    extra = [ln for ln in r.split("\n")[1:]
                             if ln not in existing.split("\n")]
                    if extra:
                        merged[key] = existing + "\n" + "\n".join(extra)
                if collision:
                    for key, prev in touched:
                        if prev is None:
                            merged.pop(key, None)
                        else:
                            merged[key] = prev
                    unfixed.append({
                        **base,
                        "reason": "Overlaps another applied fix; skipped.",
                    })
                else:
                    applied.append({
                        **base,
                        "explanation": sf["explanation"],
                        "confidence": sf["confidence"],
                    })
            file_edits[rel] = [(s, e, r) for (s, e), r in merged.items()]

        # Apply every edit bottom-up per file (apply_edits sorts internally).
        patched = {
            rel: "\n".join(apply_edits(file_lines[rel], edits)) + "\n"
            for rel, edits in file_edits.items()
        }

        # A patch is applied to the user's own checkout, so it has to be
        # relative to the repo root (`a/path`, `b/path`) like git writes it.
        if fix_format == "patch":
            return Response(
                content=to_unified_diff(
                    {rel: "\n".join(file_lines[rel]) + "\n" for rel in patched},
                    patched,
                ),
                media_type="text/x-patch; charset=utf-8",
                headers={
                    "Content-Disposition": 'attachment; filename="sast-fixes.patch"',
                    "X-Fixes-Applied": str(len(applied)),
                    "X-Fixes-Unfixed": str(len(unfixed)),
                },
            )

        for rel, text in patched.items():
            target = extract_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

        report = {
            "applied": applied,
            "unfixed": unfixed,
            "total_findings": payload["total_findings"],
        }
        (extract_dir / "_FIX_REPORT.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(extract_dir.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(extract_dir).as_posix())
        return Response(
            content=buffer.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="fixed-source.zip"',
                "X-Fixes-Applied": str(len(applied)),
                "X-Fixes-Unfixed": str(len(unfixed)),
            },
        )
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


@app.get("/api/scans")
def scan_history(limit: int = 50) -> dict:
    """Most recent scans, newest first — metadata only, no payloads."""
    limit = max(1, min(limit, store.MAX_STORED_SCANS))
    scans = store.list_scans(limit=limit)
    return {"count": len(scans), "scans": scans}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    """One stored report, in the exact shape /api/scan returns."""
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=404, detail="Scan not found or no longer stored."
        )
    return scan


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
