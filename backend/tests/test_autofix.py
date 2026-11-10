"""Unit tests for the rule-aware autofix engine.

Each fixture mirrors the exact source shape the corresponding Semgrep rule
flags, so a fixer regression fails here without needing the semgrep binary.
"""

from autofix import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    apply_edits,
    compute_suggested_fix,
)

SQL_RULE = "python.flask.security.injection.tainted-sql-string.tainted-sql-string"
SUBPROCESS_RULE = (
    "python.flask.security.injection.subprocess-injection.subprocess-injection"
)
MD5_RULE = "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5"
FLASK_RUN_RULE = (
    "python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host"
)
DIRECT_WRITE_RULE = (
    "javascript.express.security.audit.xss.direct-response-write.direct-response-write"
)
OPEN_REDIRECT_RULE = (
    "javascript.express.security.audit.express-open-redirect.express-open-redirect"
)


def patched(lines: list[str], fix) -> str:
    assert fix is not None
    return "\n".join(apply_edits(lines, fix.edits))


def test_sql_injection_is_parameterized():
    lines = [
        "def get_user():",
        "    user_id = request.args.get('id')",
        "    conn = sqlite3.connect(DATABASE)",
        '    query = "SELECT * FROM users WHERE id = \'" + user_id + "\'"',
        "    cursor.execute(query)",
    ]
    fix = compute_suggested_fix(SQL_RULE, "User input in a SQL query.", 4, 4, lines)

    assert fix is not None
    assert fix.confidence == CONFIDENCE_HIGH
    result = patched(lines, fix)
    assert 'query = "SELECT * FROM users WHERE id = ?"' in result
    assert "cursor.execute(query, (user_id,))" in result


def test_shell_true_is_replaced_with_shlex_split():
    lines = [
        "import subprocess",
        "",
        "def ping():",
        '    host = request.args.get("host")',
        '    subprocess.run("ping -c 1 " + host, shell=True)',
    ]
    fix = compute_suggested_fix(SUBPROCESS_RULE, "", 5, 5, lines)

    assert fix is not None
    assert fix.confidence == CONFIDENCE_MEDIUM
    result = patched(lines, fix)
    assert 'shlex.split("ping -c 1 " + host)' in result
    assert "shell=False" in result
    assert "import shlex" in result


def test_import_insertion_is_idempotent():
    lines = [
        "import subprocess",
        "import shlex",
        "",
        'subprocess.run("ls", shell=True)',
    ]
    fix = compute_suggested_fix(SUBPROCESS_RULE, "", 4, 4, lines)

    assert fix is not None
    assert patched(lines, fix).count("import shlex") == 1


def test_md5_password_hash_becomes_pbkdf2():
    lines = [
        "import hashlib",
        "",
        "def hash_password(password):",
        "    return hashlib.md5(password.encode()).hexdigest()",
    ]
    fix = compute_suggested_fix(MD5_RULE, "", 4, 4, lines)

    assert fix is not None
    assert fix.confidence == CONFIDENCE_MEDIUM
    result = patched(lines, fix)
    assert 'hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()' in result
    assert "salt = os.urandom(16)" in result
    assert "import os" in result


def test_md5_digest_becomes_sha256():
    lines = ["import hashlib", "", "digest = hashlib.md5(data).hexdigest()"]
    fix = compute_suggested_fix(MD5_RULE, "", 3, 3, lines)

    assert fix is not None
    result = patched(lines, fix)
    assert "hashlib.sha256(data).hexdigest()" in result
    assert "pbkdf2" not in result


def test_flask_debug_run_is_hardened():
    lines = ['app.run(host="0.0.0.0", port=5000, debug=True)']
    fix = compute_suggested_fix(FLASK_RUN_RULE, "", 1, 1, lines)

    assert fix is not None
    assert fix.confidence == CONFIDENCE_HIGH
    result = patched(lines, fix)
    assert 'host="127.0.0.1"' in result
    assert "debug=False" in result


def test_innerhtml_write_becomes_textcontent():
    lines = [
        "app.get('/search', (req, res) => {",
        "  const query = req.query.q;",
        '  res.send("<script>document.getElementById(\'results\').innerHTML = \\"${query}\\";</script>");',
        "});",
    ]
    fix = compute_suggested_fix(DIRECT_WRITE_RULE, "", 3, 3, lines)

    assert fix is not None
    assert fix.confidence == CONFIDENCE_HIGH
    result = patched(lines, fix)
    assert ".textContent =" in result
    assert ".innerHTML" not in result


def test_open_redirect_gets_allow_list():
    lines = [
        'app.get("/redirect", (req, res) => {',
        "  res.redirect(req.query.url);",
        "});",
    ]
    fix = compute_suggested_fix(OPEN_REDIRECT_RULE, "", 2, 2, lines)

    assert fix is not None
    assert fix.confidence == CONFIDENCE_MEDIUM
    result = patched(lines, fix)
    assert "ALLOWED_REDIRECT_HOSTS" in result
    assert "res.redirect(req.query.url);" in result


def test_ssrf_echo_gets_host_allow_list():
    lines = [
        'app.get("/fetch", async (req, res) => {',
        "  const target = req.query.url;",
        "  const response = await fetch(target);",
        "  res.send(await response.text());",
        "});",
    ]
    fix = compute_suggested_fix(DIRECT_WRITE_RULE, "", 3, 4, lines)

    assert fix is not None
    assert fix.confidence == CONFIDENCE_MEDIUM
    result = patched(lines, fix)
    assert "SSRF_ALLOWED_HOSTS" in result
    assert 'res.type("text/plain").send(' in result


def test_unknown_rule_has_no_fix():
    assert compute_suggested_fix("generic.some.rule", "", 1, 1, ["x = 1"]) is None


def test_apply_edits_ignores_out_of_range_ranges():
    assert apply_edits(["a"], [(3, 5, "x")]) == ["a"]
