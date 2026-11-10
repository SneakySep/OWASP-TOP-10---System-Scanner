"""Report formats derived from the enriched scan payload.

SARIF lets results land in GitHub code scanning (or any other SARIF
consumer); the unified diff lets ``/api/fix`` hand back a patch that applies
to the user's own checkout instead of replacing it.
"""

from __future__ import annotations

import difflib

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF only has error/warning/note; map the dashboard's four buckets onto it.
SARIF_LEVELS = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


def _flatten(payload: dict) -> list[dict]:
    return [
        finding
        for group in payload.get("groups", [])
        for finding in group.get("findings", [])
    ]


def to_sarif(payload: dict) -> dict:
    """Render the dashboard payload as a SARIF 2.1.0 log."""
    findings = _flatten(payload)

    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for finding in findings:
        rule_id = finding.get("rule_id") or "unknown-rule"
        if rule_id in rule_index:
            continue
        rule_index[rule_id] = len(rules)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.rsplit(".", 1)[-1],
                "shortDescription": {"text": finding.get("message") or rule_id},
                "properties": {"owasp_category": finding.get("owasp_category")},
            }
        )

    results: list[dict] = []
    for finding in findings:
        rule_id = finding.get("rule_id") or "unknown-rule"
        start = max(1, int(finding.get("start_line") or 1))
        end = max(start, int(finding.get("end_line") or start))
        suggested_fix = finding.get("suggested_fix") or {}
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": SARIF_LEVELS.get(finding.get("severity"), "warning"),
                "message": {"text": finding.get("message") or rule_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("file") or "unknown",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": start, "endLine": end},
                        }
                    }
                ],
                # Stable across runs, so GitHub can track a result over time.
                "partialFingerprints": {
                    "primaryLocationLineHash": str(finding.get("id") or "")
                },
                "properties": {
                    "severity": finding.get("severity"),
                    "owasp_category": finding.get("owasp_category"),
                    "suggested_fix_confidence": suggested_fix.get("confidence"),
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sast-scanner",
                        "version": "1.0.0",
                        "informationUri": "https://owasp.org/Top10/",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scan_id": payload.get("scan_id"),
                    "total_findings": payload.get("total_findings", len(results)),
                },
            }
        ],
    }


def to_unified_diff(
    originals: dict[str, str],
    patched: dict[str, str],
    context: int = 3,
) -> str:
    """Render changed files as a ``git apply``-able unified diff.

    Paths carry the usual ``a/`` and ``b/`` prefixes so the patch applies from
    the root of the checkout the archive was made from. Unchanged files are
    skipped, so an unfixable file cannot show up as an empty hunk.
    """
    chunks: list[str] = []
    for path in sorted(patched):
        before = originals.get(path)
        after = patched[path]
        if before is None or before == after:
            continue
        diff = list(
            difflib.unified_diff(
                before.splitlines(),
                after.splitlines(),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                lineterm="",
                n=context,
            )
        )
        if not diff:
            continue
        chunks.append(f"diff --git a/{path} b/{path}\n")
        chunks.extend(f"{line}\n" for line in diff)
    return "".join(chunks)
