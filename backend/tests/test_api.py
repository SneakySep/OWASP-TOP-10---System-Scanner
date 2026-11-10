"""API tests: upload validation, zip-bomb guards and the fixture round-trip.

The fixtures are the contract: `vulnerable-sample/` is documented to produce
seven findings that all carry a suggested fix, and applying them is documented
to leave nothing for a re-scan to find. Those tests need the semgrep binary;
they skip with a clear reason when it is not installed.
"""

import io
import json
import shutil
import zipfile

import pytest

import main

RULESET = "p/owasp-top-ten"

requires_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="the semgrep CLI is not installed; fixture integration tests need it",
)


def zip_of(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def post_zip(
    client,
    data: bytes,
    *,
    ruleset: str = RULESET,
    name: str = "upload.zip",
):
    return client.post(
        "/api/scan",
        files={"file": (name, data, "application/zip")},
        data={"ruleset": ruleset},
    )


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------


def test_rejects_non_zip_filename(client):
    response = client.post(
        "/api/scan", files={"file": ("notes.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 400


def test_rejects_empty_upload(client):
    response = client.post(
        "/api/scan", files={"file": ("empty.zip", b"", "application/zip")}
    )
    assert response.status_code == 400


def test_rejects_wrong_magic_bytes(client):
    response = post_zip(client, b"definitely not a zip archive")
    assert response.status_code == 400


def test_rejects_unknown_ruleset(client):
    response = post_zip(
        client, zip_of({"app.py": b"x = 1\n"}), ruleset="p/not-allowed"
    )
    assert response.status_code == 400
    assert "Unsupported ruleset" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Zip-bomb and path-traversal guards
# ---------------------------------------------------------------------------


def test_rejects_archive_over_entry_limit(client):
    data = zip_of({f"file{i}.py": b"x = 1\n" for i in range(main.MAX_ARCHIVE_FILES + 1)})
    response = post_zip(client, data)
    assert response.status_code == 413
    assert "entries" in response.json()["detail"]


def test_rejects_archive_over_uncompressed_limit(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_UNCOMPRESSED_BYTES", 10)
    response = post_zip(client, zip_of({"big.py": b"x = 1\n" * 100}))
    assert response.status_code == 413
    assert "extraction limit" in response.json()["detail"]


def test_rejects_implausible_compression_ratio(client):
    response = post_zip(client, zip_of({"zeros.py": b"\0" * (2 * 1024 * 1024)}))
    assert response.status_code == 413
    assert "compression ratio" in response.json()["detail"]


def test_rejects_path_traversal_member(client):
    response = post_zip(client, zip_of({"../../evil.py": b"x = 1\n"}))
    assert response.status_code == 400
    assert "unsafe path" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Path normalization (regression: lstrip("./") ate leading dots)
# ---------------------------------------------------------------------------


def test_normalize_rel_path_keeps_dotfiles():
    assert main.normalize_rel_path("/tmp/scans/scan-1/source/.env") == ".env"
    assert (
        main.normalize_rel_path("/tmp/scans/scan-1/source/.github/workflows/ci.yml")
        == ".github/workflows/ci.yml"
    )
    assert main.normalize_rel_path("./app.py") == "app.py"
    assert main.normalize_rel_path("source\\app.py") == "source/app.py"


# ---------------------------------------------------------------------------
# Fixture integration (requires semgrep)
# ---------------------------------------------------------------------------


@requires_semgrep
def test_vulnerable_fixture_reports_seven_fixable_findings(client, make_zip):
    response = post_zip(client, make_zip("vulnerable-sample"))
    assert response.status_code == 200, response.text
    payload = response.json()
    findings = [f for group in payload["groups"] for f in group["findings"]]

    assert payload["total_findings"] == 7
    assert len(findings) == 7
    assert sum(payload["severity_counts"].values()) == 7
    assert all(finding["remediation"]["steps"] for finding in findings)
    assert all(finding["suggested_fix"] for finding in findings)
    # Relative paths only: no absolute container paths, no mangled dotfiles.
    assert {finding["file"] for finding in findings} == {
        "insecure_api.js",
        "vulnerable_app.py",
    }


@requires_semgrep
def test_fixed_fixture_is_clean(client, make_zip):
    response = post_zip(client, make_zip("fixed-sample"))
    assert response.status_code == 200, response.text
    assert response.json()["total_findings"] == 0


@requires_semgrep
def test_fix_applies_every_fix_and_rescans_clean(client, make_zip):
    response = client.post(
        "/api/fix",
        files={
            "file": (
                "vulnerable-sample.zip",
                make_zip("vulnerable-sample"),
                "application/zip",
            )
        },
        data={"ruleset": RULESET},
    )
    assert response.status_code == 200, response.text
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="fixed-source.zip"'
    )

    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        report = json.loads(archive.read("_FIX_REPORT.json"))

    assert report["total_findings"] == 7
    assert len(report["applied"]) == 7
    assert report["unfixed"] == []

    rescan = post_zip(client, response.content, name="fixed-source.zip")
    assert rescan.status_code == 200, rescan.text
    assert rescan.json()["total_findings"] == 0


# ---------------------------------------------------------------------------
# History, baseline and report formats
# ---------------------------------------------------------------------------


def test_history_starts_empty_and_unknown_ids_404(client):
    listing = client.get("/api/scans")
    assert listing.status_code == 200
    assert listing.json() == {"count": 0, "scans": []}
    assert client.get("/api/scans/does-not-exist").status_code == 404


def test_rejects_unknown_scan_format(client):
    response = client.post(
        "/api/scan",
        files={
            "file": ("upload.zip", zip_of({"app.py": b"x = 1\n"}), "application/zip")
        },
        data={"ruleset": RULESET, "format": "xml"},
    )
    assert response.status_code == 400
    assert "Unsupported format" in response.json()["detail"]


def test_rejects_unknown_fix_format(client):
    response = client.post(
        "/api/fix",
        files={
            "file": ("upload.zip", zip_of({"app.py": b"x = 1\n"}), "application/zip")
        },
        data={"ruleset": RULESET, "format": "tar"},
    )
    assert response.status_code == 400
    assert "Unsupported format" in response.json()["detail"]


@requires_semgrep
def test_scans_are_recorded_and_compared_with_the_previous_one(client, make_zip):
    first = post_zip(
        client, make_zip("vulnerable-sample"), name="vulnerable-sample.zip"
    )
    assert first.status_code == 200, first.text
    assert first.json().get("baseline") is None

    second = post_zip(
        client, make_zip("vulnerable-sample"), name="vulnerable-sample.zip"
    )
    body = second.json()
    assert body["baseline"]["previous_scan_id"] == first.json()["scan_id"]
    assert body["baseline"]["counts"] == {"new": 0, "fixed": 0, "unchanged": 7}
    assert not any(f["is_new"] for g in body["groups"] for f in g["findings"])

    history = client.get("/api/scans").json()
    assert history["count"] == 2
    assert history["scans"][0]["scan_id"] == body["scan_id"]
    assert history["scans"][0]["label"] == "vulnerable-sample.zip"

    stored = client.get(f"/api/scans/{body['scan_id']}").json()
    assert stored["payload"]["total_findings"] == 7


@requires_semgrep
def test_sarif_format_returns_a_sarif_log(client, make_zip):
    response = client.post(
        "/api/scan",
        files={
            "file": (
                "vulnerable-sample.zip",
                make_zip("vulnerable-sample"),
                "application/zip",
            )
        },
        data={"ruleset": RULESET, "format": "sarif"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/sarif+json")
    sarif = response.json()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 7


@requires_semgrep
def test_patch_format_returns_a_git_applyable_diff(client, make_zip):
    response = client.post(
        "/api/fix",
        files={
            "file": (
                "vulnerable-sample.zip",
                make_zip("vulnerable-sample"),
                "application/zip",
            )
        },
        data={"ruleset": RULESET, "format": "patch"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["x-fixes-applied"] == "7"
    patch = response.text
    assert "diff --git a/vulnerable_app.py b/vulnerable_app.py" in patch
    assert "--- a/insecure_api.js" in patch
    assert "+++ b/insecure_api.js" in patch
    assert "@@" in patch
