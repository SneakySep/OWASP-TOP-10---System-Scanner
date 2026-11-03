"""Intentionally vulnerable sample app for testing the SAST scanner.

Every vulnerability in this file should be flagged by the OWASP Top 10
ruleset (p/owasp-top-ten) used by the scanner. DO NOT run in production.
"""

import hashlib
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

DATABASE = "app.db"
# A02:2021 - Cryptographic Failures: hardcoded credentials
DB_PASSWORD = "super_secret_admin_password_123"
API_KEY = "EXAMPLE_API_KEY_NOT_A_REAL_SECRET_1234567890"


@app.route("/user")
def get_user():
    # A03:2021 - Injection: user input concatenated into SQL
    user_id = request.args.get("id")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    # A03:2021 - Injection: command injection via shell=True
    host = request.args.get("host", "localhost")
    output = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return output.stdout.decode()


@app.route("/load")
def load_state():
    # A08:2021 - Software and Data Integrity Failures: unsafe deserialization
    blob = request.args.get("state", "")
    data = pickle.loads(blob.encode())
    return str(data)


def hash_password(password):
    # A02:2021 - Cryptographic Failures: weak hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/greet")
def greet():
    # A03:2021 - Injection: eval on user-controlled input
    name = request.args.get("name", "world")
    return eval("'Hello ' + name")  # noqa: S307


if __name__ == "__main__":
    # A05:2021 - Security Misconfiguration: debug mode in production
    app.run(host="0.0.0.0", port=5000, debug=True)
