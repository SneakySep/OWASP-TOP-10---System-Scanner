"""Scan-history storage and baseline comparison (no semgrep needed)."""

import pytest

import store


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "history.db")
    return store


def make_payload(scan_id: str, *specs: tuple[str, str, int, str]) -> dict:
    findings = [
        {
            "id": f"{rule_id}:{file}:{line}",
            "rule_id": rule_id,
            "message": "flagged",
            "file": file,
            "start_line": line,
            "end_line": line,
            "code_snippet": snippet,
            "severity": "High",
            "owasp_category": "A03:2021-Injection",
        }
        for rule_id, file, line, snippet in specs
    ]
    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "severity_counts": {
            "Critical": 0,
            "High": len(findings),
            "Medium": 0,
            "Low": 0,
        },
        "groups": [
            {
                "category": "A03:2021-Injection",
                "title": "A03: Injection",
                "findings": findings,
            }
        ],
        "errors": [],
    }


def findings(payload: dict) -> list[dict]:
    return [f for group in payload["groups"] for f in group["findings"]]


def test_round_trip_save_list_get(db):
    db.save_scan(
        scan_id="s1",
        label="repo.zip",
        ruleset="p/owasp-top-ten",
        fingerprint="fp",
        payload=make_payload("s1", ("rule.a", "app.py", 3, "x = 1")),
    )

    listed = db.list_scans()
    assert [row["scan_id"] for row in listed] == ["s1"]
    assert listed[0]["label"] == "repo.zip"
    assert listed[0]["total_findings"] == 1
    assert listed[0]["severity_counts"]["High"] == 1

    stored = db.get_scan("s1")
    assert stored["payload"]["scan_id"] == "s1"
    assert stored["fingerprint"] == "fp"
    assert db.get_scan("missing") is None


def test_history_is_newest_first(db):
    db.save_scan(
        scan_id="old",
        label="a",
        ruleset="r",
        fingerprint="fp",
        payload=make_payload("old"),
        created_at=100.0,
    )
    db.save_scan(
        scan_id="new",
        label="a",
        ruleset="r",
        fingerprint="fp",
        payload=make_payload("new"),
        created_at=200.0,
    )

    assert [row["scan_id"] for row in db.list_scans()] == ["new", "old"]
    assert db.latest_for("fp")["scan_id"] == "new"
    assert db.latest_for("fp", exclude_scan_id="new")["scan_id"] == "old"


def test_baseline_marks_new_and_fixed_findings(db):
    db.save_scan(
        scan_id="s1",
        label="repo",
        ruleset="r",
        fingerprint="fp",
        payload=make_payload(
            "s1", ("rule.a", "app.py", 3, "x = 1"), ("rule.b", "app.py", 9, "y = 2")
        ),
        created_at=100.0,
    )

    current = make_payload(
        "s2", ("rule.b", "app.py", 9, "y = 2"), ("rule.c", "api.js", 4, "fetch(url)")
    )
    db.annotate_baseline(current, db.latest_for("fp", exclude_scan_id="s2"))

    assert current["baseline"]["counts"] == {"new": 1, "fixed": 1, "unchanged": 1}
    assert current["baseline"]["previous_scan_id"] == "s1"
    assert [f["rule_id"] for f in current["baseline"]["new"]] == ["rule.c"]
    assert [f["rule_id"] for f in current["baseline"]["fixed"]] == ["rule.a"]
    assert {f["rule_id"]: f["is_new"] for f in findings(current)} == {
        "rule.b": False,
        "rule.c": True,
    }


def test_line_shifts_are_not_new_findings(db):
    """Editing code above a sink moves its line number; that is not a new bug."""
    db.save_scan(
        scan_id="s1",
        label="repo",
        ruleset="r",
        fingerprint="fp",
        payload=make_payload("s1", ("rule.a", "app.py", 3, "query = user_input")),
        created_at=100.0,
    )

    current = make_payload("s2", ("rule.a", "app.py", 27, "query = user_input"))
    db.annotate_baseline(current, db.latest_for("fp", exclude_scan_id="s2"))

    assert current["baseline"]["counts"] == {"new": 0, "fixed": 0, "unchanged": 1}


def test_duplicate_findings_are_counted_not_collapsed(db):
    """The same rule flagging identical code twice stays two findings."""
    db.save_scan(
        scan_id="s1",
        label="repo",
        ruleset="r",
        fingerprint="fp",
        payload=make_payload("s1", ("rule.a", "app.py", 3, "x = 1")),
        created_at=100.0,
    )

    current = make_payload(
        "s2", ("rule.a", "app.py", 3, "x = 1"), ("rule.a", "app.py", 30, "x = 1")
    )
    db.annotate_baseline(current, db.latest_for("fp", exclude_scan_id="s2"))

    assert current["baseline"]["counts"] == {"new": 1, "fixed": 0, "unchanged": 1}
    assert [f["is_new"] for f in findings(current)] == [False, True]


def test_fingerprint_ignores_path_order_and_content(db):
    assert db.fingerprint_of(["a.py", "b/c.py"]) == db.fingerprint_of(
        ["b/c.py", "a.py"]
    )
    assert db.fingerprint_of(["a.py"]) != db.fingerprint_of(["a.py", "b.py"])
