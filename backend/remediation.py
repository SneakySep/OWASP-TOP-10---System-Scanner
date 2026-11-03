"""
Custom remediation knowledge base for the OWASP Top 10 (2021).

Each entry maps an OWASP category ID to instructional remediation notes.
These notes are appended to every Semgrep finding whose category matches,
so the dashboard shows actionable guidance next to each vulnerable snippet.
"""

REMEDIATION_NOTES: dict[str, dict] = {
    "A01:2021-Broken Access Control": {
        "title": "A01: Broken Access Control",
        "summary": (
            "Users can act outside of their intended permissions. Attackers exploit "
            "this to view, modify, or delete data belonging to other users or to "
            "reach administrative functions."
        ),
        "steps": [
            "Enforce authorization checks server-side on every request; never rely on client-side checks or hidden UI.",
            "Use a centralized access-control policy layer (RBAC/ABAC) instead of scattered per-route checks.",
            "Default deny: reject requests unless explicitly permitted for the caller's role.",
            "Verify object ownership on every read/write (e.g., WHERE user_id = :current_user) to stop IDOR.",
            "Prefer random, non-sequential identifiers (UUIDs) for object references; do not leak IDs in URLs.",
            "Disable directory listing and deny access to .git, .env, backup files at the web-server level.",
            "Log and alert on denied authorization events; rate-limit repeated failures.",
            "Write integration tests that assert a low-privilege user cannot reach privileged endpoints.",
        ],
        "references": [
            "OWASP Cheat Sheet: Authorization",
            "OWASP Top 10 2021: A01 Broken Access Control",
        ],
    },
    "A02:2021-Cryptographic Failures": {
        "title": "A02: Cryptographic Failures",
        "summary": (
            "Weak, missing, or misapplied cryptography exposes sensitive data in "
            "transit or at rest: plaintext passwords, deprecated ciphers, hardcoded "
            "keys, or unencrypted channels."
        ),
        "steps": [
            "Classify data; encrypt anything sensitive in transit (TLS 1.2+/1.3) and at rest (AES-256/GCM).",
            "Never store passwords reversibly: use Argon2id, bcrypt, or scrypt with per-user salts.",
            "Remove hardcoded secrets and keys from source; load them from a secrets manager or environment.",
            "Replace deprecated primitives (MD5, SHA1, DES, RC4, ECB mode) with modern equivalents (SHA-256+, AES-GCM).",
            "Use vetted libraries; never implement crypto yourself. Generate randomness with CSPRNGs only.",
            "Force HTTPS with HSTS; set secure, HttpOnly, SameSite cookie flags.",
            "Rotate keys and certificates on a schedule and document the rotation procedure.",
        ],
        "references": [
            "OWASP Cheat Sheet: Cryptographic Storage",
            "OWASP Cheat Sheet: Password Storage",
        ],
    },
    "A03:2021-Injection": {
        "title": "A03: Injection",
        "summary": (
            "Untrusted data is interpreted as code or query: SQL/NoSQL injection, "
            "OS command injection, LDAP, ORM, XPath, or template injection. This "
            "category also covers XSS in the 2021 list."
        ),
        "steps": [
            "Use parameterized queries / prepared statements for every database call; never concatenate SQL strings.",
            "Use allow-list input validation on all user-controlled input; reject or sanitize unexpected characters.",
            "For OS commands, prefer library APIs over shell calls; if unavoidable, escape with shlex.quote (Python) or equivalent.",
            "Escape output contextually (HTML, JS, URL, CSS) and use templating engines with auto-escaping enabled.",
            "Apply least-privilege DB accounts so injected queries cannot drop tables or read other schemas.",
            "Add CSP headers to reduce XSS impact; avoid eval(), innerHTML with user data, and dynamic includes.",
            "Add automated tests with payloads like ' OR 1=1 -- and $(id) against every sink.",
        ],
        "references": [
            "OWASP Cheat Sheet: SQL Injection Prevention",
            "OWASP Cheat Sheet: OS Command Injection Defense",
            "OWASP Cheat Sheet: Cross Site Scripting Prevention",
        ],
    },
    "A04:2021-Insecure Design": {
        "title": "A04: Insecure Design",
        "summary": (
            "The design itself lacks threat modeling and secure-by-default patterns: "
            "missing rate limits, flawed business logic, or trust boundaries that "
            "were never defined."
        ),
        "steps": [
            "Run threat modeling (STRIDE or similar) before building new features and trust boundaries.",
            "Apply secure design patterns and reference architectures; use paved-road libraries.",
            "Add rate limiting, throttling, and anti-automation (CAPTCHA where appropriate) to sensitive flows.",
            "Validate business logic server-side: transaction limits, workflow sequencing, replay protection.",
            "Write abuse-case tests alongside functional tests for every user story.",
            "Segment critical components so a compromise in one tier cannot pivot freely.",
        ],
        "references": [
            "OWASP Cheat Sheet: Threat Modeling",
            "OWASP ASVS 4.0 Chapter 1: Architecture",
        ],
    },
    "A05:2021-Security Misconfiguration": {
        "title": "A05: Security Misconfiguration",
        "summary": (
            "Insecure defaults, verbose errors, open cloud storage, unnecessary "
            "features enabled, or missing hardening across the stack."
        ),
        "steps": [
            "Build reproducible, minimal images; disable default accounts and unused features/services.",
            "Run hardening scanners on images and infrastructure (Docker bench, CIS benchmarks) in CI.",
            "Set security headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy.",
            "Return generic error messages to users; log full details server-side only.",
            "Segment environments: dev must never run with production secrets or data.",
            "Automate configuration drift detection and review IaC changes in pull requests.",
        ],
        "references": [
            "OWASP Cheat Sheet: Configuration and Deployment Management",
        ],
    },
    "A06:2021-Vulnerable and Outdated Components": {
        "title": "A06: Vulnerable and Outdated Components",
        "summary": (
            "Dependencies with known CVEs, unsupported libraries, or stale runtimes "
            "expand the attack surface without any code change of your own."
        ),
        "steps": [
            "Maintain a software inventory (SBOM) and scan dependencies continuously (Dependabot, pip-audit, npm audit).",
            "Pin dependency versions and update on a fixed cadence; subscribe to CVE feeds for your stack.",
            "Remove unused dependencies, dead features, and legacy code paths.",
            "Only pull packages from trusted registries; verify checksums and signatures where possible.",
            "Patch runtime images regularly: rebuild containers on fresh base images each release.",
        ],
        "references": [
            "OWASP Cheat Sheet: Vulnerable Dependency Management",
        ],
    },
    "A07:2021-Identification and Authentication Failures": {
        "title": "A07: Identification and Authentication Failures",
        "summary": (
            "Credential stuffing, weak passwords, missing MFA, broken session "
            "handling, and predictable tokens let attackers impersonate users."
        ),
        "steps": [
            "Enforce MFA where possible and rate-limit/delay failed login attempts with lockout backoff.",
            "Check new passwords against known-breach lists (e.g., k-anonymity APIs); require length over complexity.",
            "Use vetted session management: regenerate session IDs on login, set secure/HttpOnly/SameSite flags, expire idle sessions.",
            "Never expose session tokens in URLs; rotate refresh tokens on use.",
            "Use time-safe comparison for tokens and secrets (hmac.compare_digest in Python).",
            "Log authentication events and alert on anomalous patterns (impossible travel, credential stuffing waves).",
        ],
        "references": [
            "OWASP Cheat Sheet: Authentication",
            "OWASP Cheat Sheet: Session Management",
        ],
    },
    "A08:2021-Software and Data Integrity Failures": {
        "title": "A08: Software and Data Integrity Failures",
        "summary": (
            "Unverified updates, insecure deserialization, and CI/CD pipelines "
            "without integrity checks allow malicious code or data into the system."
        ),
        "steps": [
            "Verify signatures and checksums for all dependencies, updates, and artifacts (Sigstore, GPG).",
            "Never deserialize untrusted data with pickle, yaml.load (unsafe), or native object serializers; prefer JSON with schema validation.",
            "Pin CI/CD actions and base images by digest; protect pipeline credentials with least privilege.",
            "Sign releases and verify them at deploy time; enable immutable artifact storage.",
            "Validate integrity of serialized state (HMAC) before trusting client-submitted blobs.",
        ],
        "references": [
            "OWASP Cheat Sheet: Deserialization",
            "OWASP Top 10 2021: A08 Software and Data Integrity Failures",
        ],
    },
    "A09:2021-Security Logging and Monitoring Failures": {
        "title": "A09: Security Logging and Monitoring Failures",
        "summary": (
            "Attacks go unnoticed because auditable events are not logged, alerts "
            "do not fire, or logs leak sensitive data."
        ),
        "steps": [
            "Log all authentication, access-control, and validation failures with enough context to identify the actor.",
            "Ensure logs are generated in a machine-readable format and shipped to a central, tamper-evident store.",
            "Never log passwords, tokens, session IDs, or full card numbers; redact sensitive fields.",
            "Set actionable alerts for high-signal events (auth spikes, privilege escalation, mass data export).",
            "Adopt an incident response plan and test it; define retention per compliance requirements.",
        ],
        "references": [
            "OWASP Cheat Sheet: Logging",
        ],
    },
    "A10:2021-Server-Side Request Forgery (SSRF)": {
        "title": "A10: Server-Side Request Forgery (SSRF)",
        "summary": (
            "The server fetches a URL supplied by a user without validation, letting "
            "attackers probe internal networks, hit metadata services, or exfiltrate "
            "data."
        ),
        "steps": [
            "Allow-list permitted destination schemes, ports, and domains for any user-supplied URL fetch.",
            "Block requests to private/internal IP ranges (10/8, 172.16/12, 192.168/16, 169.254/16, ::1, link-local) after DNS resolution.",
            "Do not follow redirects blindly; re-validate each hop against the allow-list.",
            "Disable verbose HTTP error responses that leak internal topology.",
            "Run outbound fetches from an isolated network segment with egress filtering.",
            "Never send raw server responses from the fetch back to the client.",
        ],
        "references": [
            "OWASP Cheat Sheet: Server Side Request Forgery Prevention",
        ],
    },
}

# Fallback for findings whose OWASP category is not in the map above.
DEFAULT_REMEDIATION = {
    "title": "General Security Finding",
    "summary": (
        "A Semgrep rule flagged this code pattern. Review the rule's message and "
        "the flagged lines, then apply secure-coding guidance appropriate to the "
        "sink and language."
    ),
    "steps": [
        "Read the Semgrep rule message and understand why the pattern is dangerous.",
        "Trace data flow from user input to the flagged sink; confirm whether the input is validated.",
        "Apply the framework's recommended safe API for this operation.",
        "Add a regression test covering the malicious input case.",
    ],
    "references": ["OWASP Top 10 2021", "Semgrep documentation"],
}


def get_remediation(category: str | None) -> dict:
    """Return the remediation note for an OWASP category, or the default note."""
    if not category:
        return DEFAULT_REMEDIATION
    if category in REMEDIATION_NOTES:
        return REMEDIATION_NOTES[category]
    # Semgrep may return variants like "A03:2021 - Injection" or bare "A03".
    normalized = category.replace(" ", "").upper()
    for key, value in REMEDIATION_NOTES.items():
        key_norm = key.replace(" ", "").upper()
        if normalized == key_norm or normalized.startswith(key_norm.split(":")[0] + ":"):
            return value
    return DEFAULT_REMEDIATION
