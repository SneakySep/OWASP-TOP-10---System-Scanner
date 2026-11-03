"""
Rule-aware auto-fix suggestions for the SAST scanner.

`compute_suggested_fix` receives a single finding plus the real source lines
of the flagged file and returns a best-effort *suggested* repair: a list of
1-based line edits, the patched snippet, a human explanation and a
confidence level. Fixers are deliberately conservative — they only fire when
the flagged code matches the exact patterns the rule targets, otherwise they
return None and the dashboard falls back to plain remediation guidance.

Suggestions are advice, not autonomous rewrites: `/api/scan` only attaches
them to the JSON payload, and `/api/fix` produces a separate
`fixed-source.zip` download. Original uploads are never modified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"


@dataclass
class FixResult:
    """A computed suggested fix for one finding."""

    # (start_line, end_line, replacement_text), 1-based inclusive ranges.
    edits: list[tuple[int, int, str]]
    explanation: str
    confidence: str
    patched_code: str


def apply_edits(lines: list[str], edits: list[tuple[int, int, str]]) -> list[str]:
    """Apply edits (1-based inclusive ranges) bottom-up to a copy of lines."""
    out = list(lines)
    for start, end, replacement in sorted(edits, key=lambda e: e[0], reverse=True):
        if start < 1 or end > len(out) or start > end:
            continue  # out-of-range guard; fixers validate their own ranges
        out[start - 1 : end] = replacement.split("\n")
    return out


def _map_edits_to_patched(
    edits: list[tuple[int, int, str]],
) -> list[tuple[int, int]]:
    """Map each edit (sorted by start) to its (start, end) in patched coords."""
    out: list[tuple[int, int]] = []
    shift = 0
    for s, e, r in sorted(edits, key=lambda x: x[0]):
        p_start = s + shift
        p_end = p_start + r.count("\n") + (e - s)
        shift += len(r.split("\n")) - (e - s + 1)
        out.append((p_start, p_end))
    return out


def _build_result(
    lines: list[str],
    edits: list[tuple[int, int, str]],
    explanation: str,
    confidence: str,
    focus: int | None = None,
) -> FixResult:
    """Validate edits, apply them, and render the patched snippet region.

    `focus` selects an original-file line to show the patched region of;
    otherwise the union of all edits is shown.
    """
    if not edits:
        raise ValueError("edits must not be empty")
    if any(s < 1 or e > len(lines) or s > e for s, e, _ in edits):
        raise ValueError("edit range outside file bounds")
    patched = apply_edits(lines, edits)
    ordered = sorted(edits, key=lambda x: x[0])
    mapped = _map_edits_to_patched(edits)
    if focus is not None:
        region = next(((ps, pe) for (s, e, _), (ps, pe) in zip(ordered, mapped)
                       if s <= focus <= e), mapped[0])
    else:
        region = (min(ps for ps, _ in mapped), max(pe for _, pe in mapped))
    lo, hi = region
    lo, hi = max(1, lo), min(len(patched), max(hi, lo))
    return FixResult(
        edits=list(edits),
        explanation=explanation,
        confidence=confidence,
        patched_code="\n".join(patched[lo - 1 : hi]),
    )


def _line_matches(lines: list[str], start: int, end: int, pattern: re.Pattern,
                  window: int = 0) -> bool:
    """True if `pattern` matches any line in [start-window, end+window]."""
    lo = max(1, start - window)
    hi = min(len(lines), end + window)
    return any(pattern.search(lines[i]) for i in range(lo - 1, hi))


def _insert_import(lines: list[str], module: str) -> tuple[int, int, str] | None:
    """Edit that adds `import <module>` after the last top-level import.

    Returns None when the import already exists or there is nowhere sane to
    put it. The edit replaces an existing import line with itself plus the
    new import so the fix stays a pure line-range replacement.
    """
    import_re = re.compile(r"^(?:import|from)\s+\S")
    last_import = None
    for i, line in enumerate(lines[:60], start=1):
        if import_re.match(line):
            last_import = i
        elif last_import is not None and line.strip() and not line[0].isspace():
            break  # imports block ended
    if last_import is None:
        return None
    if re.search(rf"^\s*import\s+{re.escape(module)}\b", "\n".join(lines), re.M):
        return None
    anchor = lines[last_import - 1]
    return (last_import, last_import, f"{anchor}\nimport {module}")


# Rule-id routing (rule ids arrive fully qualified, e.g.
# "python.flask.security.injection.tainted-sql-string.tainted-sql-string").
def compute_suggested_fix(
    rule_id: str,
    message: str,
    start_line: int,
    end_line: int,
    file_lines: list[str],
) -> FixResult | None:
    """Route a finding to its fixer; None when no fixer matches the code."""
    haystack = f"{rule_id} {message}"
    try:
        if re.search(r"tainted-sql-string|sql.inject", haystack, re.I):
            return _fix_tainted_sql(start_line, end_line, file_lines)
        if re.search(r"subprocess", haystack, re.I):
            return _fix_subprocess(start_line, end_line, file_lines)
        if re.search(r"insecure-hash-algorithm|md5|sha1", haystack, re.I):
            return _fix_weak_hash(rule_id, start_line, end_line, file_lines)
        if re.search(r"bad-host|debug-enabled|app-run-param-config", haystack, re.I):
            return _fix_flask_run_config(start_line, end_line, file_lines)
        if re.search(r"direct-response-write|raw-html-format", haystack, re.I):
            return _fix_direct_response_write(start_line, end_line, file_lines)
        if re.search(r"open-redirect", haystack, re.I):
            return _fix_open_redirect(start_line, end_line, file_lines)
    except (ValueError, IndexError):
        return None  # a malformed match must never break the scan response
    return None

# ---------------------------------------------------------------------------
# Python fixers
# ---------------------------------------------------------------------------

_ASSIGN_RE = re.compile(r"^(?P<indent>\s*)(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+?)\s*$")
_LITERAL_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"$')
_FSTRING_RE = re.compile(r'^f"((?:[^"\\]|\\.)*)"$')
_FSTRING_HOLE_RE = re.compile(r"\{([^{}]+)\}")
_EXECUTE_RE = re.compile(r"^(?P<indent>\s*)(?P<obj>[\w.]+)\.execute\(\s*(?P<arg>\w+)\s*\)\s*$")


def _fix_tainted_sql(start: int, end: int, lines: list[str]) -> FixResult | None:
    """`q = \"...\" + x + \"...\"` + `.execute(q)` -> parameterized query."""
    lo, hi = max(1, start - 2), min(len(lines), end + 2)
    assignment = None
    for i in range(lo, hi + 1):
        m = _ASSIGN_RE.match(lines[i - 1])
        if m and '"' in m.group("rhs"):
            assignment = (i, m)
            break
    if assignment is None:
        return None
    lineno, m = assignment
    indent, var, rhs = m.group("indent"), m.group("var"), m.group("rhs")

    params: list[str] = []

    def push_param(expr: str) -> str:
        expr = expr.strip()
        params.append(expr)
        return "?"

    fmatch = _FSTRING_RE.match(rhs)
    if fmatch:
        # f"SELECT ... {x} ..." -> "SELECT ... ? ..." with x as a parameter.
        sql_body = _FSTRING_HOLE_RE.sub(lambda mm: push_param(mm.group(1)),
                                        fmatch.group(1))
    else:
        # "A" + x + "B" -> "A?B"; a quote glued to a placeholder is a value
        # delimiter and gets dropped.
        parts = [p.strip() for p in rhs.split("+")]
        if len(parts) < 3:
            return None
        chunks: list[str] = []
        for idx, part in enumerate(parts):
            lit = _LITERAL_RE.match(part)
            if lit:
                chunks.append(lit.group(1))
            elif idx % 2 == 1:
                if chunks and chunks[-1].endswith(("'", '"')):
                    chunks[-1] = chunks[-1][:-1]
                chunks.append(push_param(part))
            else:
                return None
        sql_body = "".join(chunks)

    if not params:
        return None
    sql_body = re.sub(r"(\?)(['\"])", r"\1", sql_body)

    # Find the matching .execute(query) call within the next 10 lines; without
    # rewriting it the query would run with a literal ? and break.
    execute_edit = None
    for j in range(lineno + 1, min(len(lines), lineno + 10) + 1):
        em = _EXECUTE_RE.match(lines[j - 1])
        if em and em.group("arg") == var:
            joined = ", ".join(params)
            tuple_arg = f"({joined},)" if len(params) == 1 else f"({joined})"
            execute_edit = (j, j, f"{em.group('indent')}{em.group('obj')}"
                                  f".execute({var}, {tuple_arg})")
            break
    if execute_edit is None:
        return None

    return _build_result(
        lines,
        [(lineno, lineno, f'{indent}{var} = "{sql_body}"'), execute_edit],
        (
            "Replaced string concatenation in the SQL statement with a placeholder "
            f"and passed {', '.join(params)} as execute() parameters, so the driver "
            "escapes the values and SQL injection is no longer possible. Use %s "
            "instead of ? with PostgreSQL drivers (psycopg)."
        ),
        CONFIDENCE_HIGH,
    )



_SUBPROCESS_RE = re.compile(
    r"subprocess\.(?:run|call|check_call|check_output|Popen)\("
)


def _fix_subprocess(start: int, end: int, lines: list[str]) -> FixResult | None:
    """`subprocess.run(cmd, shell=True)` -> `subprocess.run(shlex.split(cmd))`."""
    lo, hi = max(1, start - 3), min(len(lines), end + 3)
    call_at = None
    for i in range(lo, hi + 1):
        if _SUBPROCESS_RE.search(lines[i - 1]) and "shell=True" in lines[i - 1]:
            call_at = i
            break
    if call_at is None:
        return None
    line = lines[call_at - 1]
    # Single-line call shape: first positional arg + kwarg list. Anything more
    # exotic is left to manual remediation.
    m = re.match(
        r"^(?P<pre>.*?subprocess\.(?:run|call|check_call|check_output|Popen)\()"
        r"(?P<arg>[^,()]+)(?P<rest>,.*)$",
        line,
    )
    if not m:
        return None
    arg = m.group("arg").strip()
    rest = m.group("rest")
    if arg.startswith(("shlex.", "[", "(")) or "shell=True" not in rest:
        return None
    new_line = (m.group("pre") + f"shlex.split({arg})"
                + rest.replace("shell=True", "shell=False", 1))
    edits = [(call_at, call_at, new_line)]
    import_edit = _insert_import(lines, "shlex")
    if import_edit:
        edits.append(import_edit)
    return _build_result(
        lines,
        edits,
        (
            "Replaced shell=True with shell=False and parsed the command with "
            "shlex.split(), so user input can no longer inject shell "
            "metacharacters. If the command genuinely needs shell features "
            "(pipes, globs), validate the input against a strict allow-list "
            "instead."
        ),
        CONFIDENCE_MEDIUM,
        focus=call_at,
    )


_MD5_RE = re.compile(
    r"^(?P<indent>\s*)(?P<prefix>return\s+|(?P<var>[A-Za-z_]\w*)\s*=\s*)"
    r"hashlib\.(?P<algo>md5|sha1)\((?P<inner>.*)\)\s*\.\s*hexdigest\(\)"
)
_PASSWORDISH_RE = re.compile(r"pass(word|wd)?|pwd", re.I)


def _fix_weak_hash(rule_id: str, start: int, end: int, lines: list[str]) -> FixResult | None:
    """MD5/SHA1 -> PBKDF2-HMAC for passwords, SHA-256 otherwise."""
    lo, hi = max(1, start - 2), min(len(lines), end + 2)
    hit = None
    for i in range(lo, hi + 1):
        hit = (i, _MD5_RE.match(lines[i - 1]))
        if hit[1]:
            break
    if not hit or not hit[1]:
        return None
    lineno, m = hit
    indent, inner = m.group("indent"), m.group("inner").strip()
    prefix = m.group("prefix") or ""
    is_return = prefix.strip() == "return"
    var = m.group("var")
    # Keep the original bytes conversion; PBKDF2/SHA-256 require bytes. If the
    # original passed a bare expression, append .encode() (assumes a str).
    enc = inner
    has_encode = bool(re.search(r"\.encode\s*\(", enc))

    if _PASSWORDISH_RE.search(rule_id) or _PASSWORDISH_RE.search(inner) \
            or (var and _PASSWORDISH_RE.search(var)):
        algo, salt_line, explain = (
            "pbkdf2_hmac",
            f'{indent}salt = os.urandom(16)  # store this salt with the hash',
            (
                "Replaced the broken MD5 password hash with PBKDF2-HMAC-SHA256 "
                "(600,000 iterations) and a random per-password salt. Store the "
                "salt next to the hash in your database and reuse it on verify; "
                "the input is assumed to be a str and encoded to bytes."
            ),
        )
        bytes_enc = enc if has_encode else f"{enc}.encode()"
        call = f'hashlib.{algo}("sha256", {bytes_enc}, salt, 600_000).hex()'
    else:
        salt_line = None
        explain = (
            "Replaced the weak MD5 digest with SHA-256 for general-purpose "
            "hashing. If this value is a password or token, prefer "
            "hashlib.pbkdf2_hmac (or argon2/bcrypt) with a per-item salt."
        )
        call = f"hashlib.sha256({enc}).hexdigest()"

    edits: list[tuple[int, int, str]] = []
    target = f"return {call}" if is_return else f"{var} = {call}"
    if salt_line:
        edits.append((lineno, lineno, f"{salt_line}\n{indent}{target}"))
    else:
        edits.append((lineno, lineno, f"{indent}{target}"))
    import_edit = _insert_import(lines, "os") if salt_line else None
    if import_edit:
        edits.append(import_edit)
    return _build_result(lines, edits, explain, CONFIDENCE_MEDIUM,
                         focus=lineno)


def _fix_flask_run_config(start: int, end: int, lines: list[str]) -> FixResult | None:
    """`app.run(host=\"0.0.0.0\", debug=True)` -> localhost + debug off."""
    lo, hi = max(1, start - 3), min(len(lines), end + 3)
    edits: list[tuple[int, int, str]] = []
    changed = False
    for i in range(lo, hi + 1):
        line = lines[i - 1]
        new_line = line
        if "0.0.0.0" in new_line:
            # Keep the surrounding quote characters as-is.
            new_line = re.sub(r"([\"'])0\.0\.0\.0\1",
                              r"\g<1>127.0.0.1\g<1>", new_line)
        if re.search(r"\bdebug\s*=\s*True\b", new_line):
            new_line = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", new_line)
        if new_line != line:
            # One edit per line so host and debug fixes can't collide.
            edits.append((i, i, new_line))
            changed = True
    if not changed:
        return None
    return _build_result(
        lines,
        edits,
        (
            "Bound the Flask development server to 127.0.0.1 instead of all "
            "interfaces and disabled debug mode: the Werkzeug debugger must "
            "never be reachable from the network (it allows arbitrary code "
            "execution). For production, serve the app behind a real WSGI "
            "server such as gunicorn."
        ),
        CONFIDENCE_HIGH,
    )


# ---------------------------------------------------------------------------
# JavaScript fixers
# ---------------------------------------------------------------------------

_INNERHTML_RE = re.compile(r"\.innerHTML\s*\+=")
_INNERHTML_ASSIGN_RE = re.compile(r"\.innerHTML\s*=")


def _fix_direct_response_write(start: int, end: int, lines: list[str]) -> FixResult | None:
    """Dispatch: innerHTML writes -> textContent; echoed fetch body -> SSRF gate."""
    # Tight window for innerHTML so an SSRF finding over a nearby handler
    # cannot steal the innerHTML card's fixer (and vice versa).
    tight = "\n".join(lines[max(0, start - 4):min(len(lines), end + 3)])
    loose = "\n".join(lines[max(0, start - 11):min(len(lines), end + 10)])
    if re.search(r"\.innerHTML\b", tight):
        return _fix_innerhtml(start, end, lines)
    if re.search(r"\bfetch\s*\(", loose) and re.search(r"res\.send\s*\(", loose):
        return _fix_ssrf_echo(start, end, lines)
    return None


def _fix_innerhtml(start: int, end: int, lines: list[str]) -> FixResult | None:
    """`el.innerHTML = <dynamic>` -> `el.textContent = <same>` (rendered as text)."""
    lo, hi = max(1, start - 10), min(len(lines), end + 10)
    for i in range(lo, hi + 1):
        line = lines[i - 1]
        if not _INNERHTML_ASSIGN_RE.search(line):
            continue
        rhs = line.split("=", 1)[1].strip()
        # A single constant string literal is safe as-is (no interpolation or
        # concatenation in the matched shape); anything dynamic gets fixed.
        if re.match(r'^["\'][^"\']*[\"\'];?$', rhs):
            continue
        new_line = _INNERHTML_ASSIGN_RE.sub(".textContent =", line)
        new_line = _INNERHTML_RE.sub(".textContent +=", new_line)
        if new_line == line:
            continue
        return _build_result(
            lines,
            [(i, i, new_line)],
            (
                "Assigned the value with textContent instead of innerHTML, so "
                "attacker-supplied input is rendered as plain text and cannot "
                "inject HTML or script tags. If rich HTML really is required, "
                "sanitise it with DOMPurify first."
            ),
            CONFIDENCE_HIGH,
        )
    return None


def _fix_ssrf_echo(start: int, end: int, lines: list[str]) -> FixResult | None:
    """Echoed `fetch(req.query.url)` body -> host allow-list + text/plain."""
    lo, hi = max(1, start - 10), min(len(lines), end + 10)
    target_line = None
    for i in range(lo, hi + 1):
        if re.search(r"\bfetch\s*\(\s*(\w+)\s*\)", lines[i - 1]):
            target_line = i
            m = re.search(r"\bfetch\s*\(\s*(\w+)\s*\)", lines[i - 1])
            var = m.group(1)
            break
    if target_line is None:
        return None
    indent_m = re.match(r"(\s*)", lines[target_line - 1])
    indent = indent_m.group(1) if indent_m else ""
    gate = (
        f"{indent}const SSRF_ALLOWED_HOSTS = new Set([\"api.example.com\"]);",
        f"{indent}let parsedUrl;",
        f"{indent}try {{",
        f"{indent}  parsedUrl = new URL({var});",
        f"{indent}}} catch {{",
        f"{indent}  return res.status(400).type(\"text/plain\").send(\"Invalid URL\");",
        f"{indent}}}",
        f"{indent}if (!SSRF_ALLOWED_HOSTS.has(parsedUrl.hostname) ||",
        f"{indent}    !/^https?:$/.test(parsedUrl.protocol)) {{",
        f"{indent}  return res.status(400).type(\"text/plain\").send(\"Blocked host\");",
        f"{indent}}}",
    )
    # Insert the gate directly above the fetch call, keeping that line (and
    # the variable's declaration above it) intact — this avoids a temporal
    # dead zone where the gate would run before the declaration.
    anchor = target_line
    send_line = next(
        (j for j in range(anchor, hi + 1) if re.search(r"res\.send\s*\(", lines[j - 1])),
        None,
    )
    edits = [(anchor, anchor, "\n".join(gate) + "\n" + lines[anchor - 1])]
    if send_line:
        # Force a non-HTML content type so an upstream body can't be rendered.
        edits.append((send_line, send_line,
                      re.sub(r"res\.send\(", 'res.type("text/plain").send(',
                             lines[send_line - 1])))
    return _build_result(
        lines,
        edits,
        (
            "Added an SSRF gate above the outbound fetch: only hosts on "
            "SSRF_ALLOWED_HOSTS may be requested, the URL must parse and use "
            "http(s), and the response is served as text/plain so it cannot be "
            "rendered as HTML. Replace the placeholder allow-list with the "
            "hosts your service actually needs to talk to."
        ),
        CONFIDENCE_MEDIUM,
    )


def _fix_open_redirect(start: int, end: int, lines: list[str]) -> FixResult | None:
    """`res.redirect(req.query.x)` -> allow-listed redirect targets."""
    lo, hi = max(1, start - 5), min(len(lines), end + 5)
    for i in range(lo, hi + 1):
        m = re.search(r"res\.redirect\(\s*([^)]+)\)", lines[i - 1])
        if not m:
            continue
        arg = m.group(1).strip()
        if arg.startswith(('"', "'")):
            continue  # constant target: already safe
        indent_m = re.match(r"(\s*)", lines[i - 1])
        indent = indent_m.group(1) if indent_m else ""
        gate = "\n".join([
            f'{indent}const ALLOWED_REDIRECT_HOSTS = new Set(["example.com", "www.example.com"]);',
            f"{indent}let redirectTarget;",
            f"{indent}try {{",
            f"{indent}  redirectTarget = new URL({arg});",
            f"{indent}}} catch {{",
            f'{indent}  return res.status(400).send("Invalid redirect URL");',
            f"{indent}}}",
            f"{indent}if (!ALLOWED_REDIRECT_HOSTS.has(redirectTarget.hostname)) {{",
            f'{indent}  return res.status(400).send("Redirect target not allowed");',
            f"{indent}}}",
        ])
        return _build_result(
            lines,
            [(i, i, f"{gate}\n{lines[i - 1]}")],
            (
                "Added an allow-list check before the redirect: only hosts in "
                "ALLOWED_REDIRECT_HOSTS are permitted and the URL must parse, "
                "otherwise the request is rejected with 400. Replace the "
                "placeholder hosts with your real domains. Relative-path "
                "redirects need extra handling (prefix them with your origin)."
            ),
            CONFIDENCE_MEDIUM,
        )
    return None

