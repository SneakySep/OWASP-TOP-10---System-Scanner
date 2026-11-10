"""Report-format tests: SARIF structure and patch generation (no semgrep)."""

import json

from reports import to_sarif, to_unified_diff


def payload() -> dict:
    return {
        "scan_id": "scan-1",
        "total_findings": 2,
        "severity_counts": {"Critical": 1, "High": 0, "Medium": 1, "Low": 0},
        "errors": [],
        "groups": [
            {
                "category": "A03:2021-Injection",
                "title": "A03: Injection",
                "findings": [
                    {
                        "id": "rule.sql:app.py:10",
                        "rule_id": "python.lang.security.tainted-sql-string",
                        "message": "SQL injection",
                        "file": "app.py",
                        "start_line": 10,
                        "end_line": 12,
                        "severity": "Critical",
                        "owasp_category": "A03:2021-Injection",
                        "suggested_fix": {"confidence": "high"},
                    },
                    {
                        "id": "rule.md5:hash.js:3",
                        "rule_id": "javascript.weak-md5",
                        "message": "Weak hash",
                        "file": "hash.js",
                        "start_line": 3,
                        "end_line": 3,
                        "severity": "Medium",
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "suggested_fix": None,
                    },
                ],
            }
        ],
    }


def test_sarif_log_has_one_result_per_finding():
    sarif = to_sarif(payload())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "sast-scanner"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2
    json.dumps(sarif)  # must be serialisable as-is


def test_sarif_levels_locations_and_rule_indices():
    first, second = to_sarif(payload())["runs"][0]["results"]

    assert first["level"] == "error"
    assert second["level"] == "warning"
    location = first["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app.py"
    assert location["region"] == {"startLine": 10, "endLine": 12}
    assert first["ruleIndex"] == 0
    assert second["ruleIndex"] == 1


def test_sarif_maps_low_severity_to_note():
    data = payload()
    data["groups"][0]["findings"][0]["severity"] = "Low"
    assert to_sarif(data)["runs"][0]["results"][0]["level"] == "note"


def test_patch_is_a_git_applyable_unified_diff():
    originals = {"app.py": "import os\n\nquery = 'x' + user\ncursor.execute(query)\n"}
    patched = {
        "app.py": "import os\n\nquery = 'x = ?'\ncursor.execute(query, (user,))\n"
    }

    patch = to_unified_diff(originals, patched)

    assert patch.startswith("diff --git a/app.py b/app.py\n")
    assert "--- a/app.py\n" in patch
    assert "+++ b/app.py\n" in patch
    assert "@@" in patch
    assert "-query = 'x' + user" in patch
    assert "+query = 'x = ?'" in patch


def test_patch_skips_unchanged_files_and_orders_paths():
    originals = {"b.py": "one\n", "a.py": "same\n", "c.py": "two\n"}
    patched = {"a.py": "same\n", "b.py": "ONE\n", "c.py": "TWO\n"}

    patch = to_unified_diff(originals, patched)

    assert "a.py" not in patch
    assert patch.index("b.py") < patch.index("c.py")
