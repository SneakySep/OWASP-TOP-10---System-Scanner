"""SQLite-backed scan history and baseline comparison.

Scans are stored as JSON in a single SQLite file: the deployment stays one
container with no extra service, and the stored payload is exactly what
``/api/scan`` returned, so a permalink renders from the same shape as a live
scan. History is a convenience, not an archive — only the newest
``MAX_STORED_SCANS`` rows are kept.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections import Counter
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path

# Kept outside the per-request temp dirs that /api/scan deletes; under Docker
# SCAN_DB points at the `scan_history` volume.
DB_PATH = Path(os.environ.get("SCAN_DB", "/tmp/scans/history.db"))

MAX_STORED_SCANS = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    ruleset         TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    created_at      REAL NOT NULL,
    total_findings  INTEGER NOT NULL,
    severity_counts TEXT NOT NULL,
    new_findings    INTEGER NOT NULL DEFAULT 0,
    fixed_findings  INTEGER NOT NULL DEFAULT 0,
    payload         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_target ON scans (fingerprint, created_at DESC);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.executescript(_SCHEMA)
    return connection


def fingerprint_of(paths: Iterable[str]) -> str:
    """Stable identity for a scanned target.

    The fingerprint covers the *set of file paths*, not their contents:
    content changes constantly — that is exactly when a baseline is wanted —
    while a path set still separates two different uploads. Order does not
    matter, so a re-packaged archive keeps its history chain.
    """
    joined = "\n".join(sorted(set(paths)))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def finding_key(finding: dict) -> str:
    """Identity of a finding that survives line shifts.

    Line numbers move whenever code above the sink changes, so the key uses
    the rule, the file and the whitespace-normalised snippet instead.
    """
    snippet = " ".join((finding.get("code_snippet") or "").split())
    return "\x00".join(
        [finding.get("rule_id") or "", finding.get("file") or "", snippet]
    )


def _finding_summary(finding: dict) -> dict:
    return {
        "id": finding.get("id"),
        "rule_id": finding.get("rule_id"),
        "file": finding.get("file"),
        "start_line": finding.get("start_line"),
        "severity": finding.get("severity"),
    }


def save_scan(
    *,
    scan_id: str,
    label: str,
    ruleset: str,
    fingerprint: str,
    payload: dict,
    created_at: float | None = None,
) -> None:
    """Insert or replace one scan and prune the oldest rows."""
    baseline_counts = (payload.get("baseline") or {}).get("counts") or {}
    with closing(_connect()) as connection, connection:
        connection.execute(
            "INSERT OR REPLACE INTO scans (scan_id, label, ruleset, fingerprint,"
            " created_at, total_findings, severity_counts, new_findings,"
            " fixed_findings, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                label,
                ruleset,
                fingerprint,
                time.time() if created_at is None else created_at,
                int(payload.get("total_findings") or 0),
                json.dumps(payload.get("severity_counts") or {}),
                int(baseline_counts.get("new") or 0),
                int(baseline_counts.get("fixed") or 0),
                json.dumps(payload),
            ),
        )
        connection.execute(
            "DELETE FROM scans WHERE scan_id NOT IN (SELECT scan_id FROM scans"
            " ORDER BY created_at DESC, rowid DESC LIMIT ?)",
            (MAX_STORED_SCANS,),
        )


def _summary_from_row(row: sqlite3.Row) -> dict:
    return {
        "scan_id": row["scan_id"],
        "label": row["label"],
        "ruleset": row["ruleset"],
        "created_at": row["created_at"],
        "total_findings": row["total_findings"],
        "severity_counts": json.loads(row["severity_counts"]),
        "new_findings": row["new_findings"],
        "fixed_findings": row["fixed_findings"],
    }


def list_scans(limit: int = 50) -> list[dict]:
    """Scan metadata, newest first. Payloads are deliberately not included."""
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT scan_id, label, ruleset, created_at, total_findings,"
            " severity_counts, new_findings, fixed_findings FROM scans"
            " ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (max(0, int(limit)),),
        ).fetchall()
    return [_summary_from_row(row) for row in rows]


def get_scan(scan_id: str) -> dict | None:
    """One stored scan, metadata plus payload — the permalink shape."""
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    scan = _summary_from_row(row)
    scan["fingerprint"] = row["fingerprint"]
    scan["payload"] = json.loads(row["payload"])
    return scan


def latest_for(fingerprint: str, exclude_scan_id: str | None = None) -> dict | None:
    """Most recent stored scan of the same target, payload included."""
    query = "SELECT scan_id, created_at, payload FROM scans WHERE fingerprint = ?"
    params: list[object] = [fingerprint]
    if exclude_scan_id:
        query += " AND scan_id != ?"
        params.append(exclude_scan_id)
    query += " ORDER BY created_at DESC, rowid DESC LIMIT 1"
    with closing(_connect()) as connection:
        row = connection.execute(query, params).fetchone()
    if row is None:
        return None
    return {
        "scan_id": row["scan_id"],
        "created_at": row["created_at"],
        "payload": json.loads(row["payload"]),
    }


def annotate_baseline(payload: dict, previous: dict) -> dict:
    """Attach ``baseline`` and per-finding ``is_new`` to ``payload`` in place.

    Findings are matched by :func:`finding_key`, so editing code elsewhere in
    the file does not make every finding look new. Duplicate keys (the same
    rule flagging identical code twice in one file) are matched by count
    rather than collapsed.
    """
    previous_findings = [
        finding
        for group in previous["payload"].get("groups", [])
        for finding in group.get("findings", [])
    ]
    previous_counts = Counter(finding_key(f) for f in previous_findings)
    by_key: dict[str, list[dict]] = {}
    for finding in previous_findings:
        by_key.setdefault(finding_key(finding), []).append(finding)

    current_counts: Counter[str] = Counter()
    seen: Counter[str] = Counter()
    new_findings: list[dict] = []
    unchanged = 0
    for group in payload.get("groups", []):
        for finding in group.get("findings", []):
            key = finding_key(finding)
            current_counts[key] += 1
            seen[key] += 1
            # Occurrence-aware: only the extra copies beyond the previous
            # count are new.
            finding["is_new"] = seen[key] > previous_counts.get(key, 0)
            if finding["is_new"]:
                new_findings.append(_finding_summary(finding))
            else:
                unchanged += 1

    fixed_findings = [
        _finding_summary(finding)
        for key, matches in by_key.items()
        for finding in matches[current_counts.get(key, 0) :]
    ]

    payload["baseline"] = {
        "previous_scan_id": previous["scan_id"],
        "previous_created_at": previous["created_at"],
        "new": new_findings,
        "fixed": fixed_findings,
        "unchanged": unchanged,
        "counts": {
            "new": len(new_findings),
            "fixed": len(fixed_findings),
            "unchanged": unchanged,
        },
    }
    return payload
