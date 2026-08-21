"""Second Vulnerable Flask Application — Email Authentication Service.

This is an intentionally vulnerable application for testing SentinelForge
generalization. It differs from Application A (vulnerable_app) in:
- Different route names (/authenticate instead of /login)
- Different database schema (email-based, not username-based)
- Different source code structure (class-based, not function-based)
- Different request parameters (JSON, not form-encoded)
- Different application flow (API-first)

Both contain SQL injection, but the implementation is entirely different.
DO NOT deploy this to production.

Security issues present (intentional):
- SQL injection in /authenticate (A03:2021-Injection)
- Hardcoded secret key
- Debug mode enabled
"""

import logging
import os
import sqlite3

from flask import Flask, request, jsonify

app = Flask(__name__)
app.secret_key = "test-secret-key-not-real"

logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger("auth_audit")

DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            display_name TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            token TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        )
    """)
    try:
        conn.execute(
            "INSERT INTO accounts (email, password, display_name) VALUES (?, ?, ?)",
            ("alice@example.com", "s3cret123", "Alice"),
        )
        conn.execute(
            "INSERT INTO accounts (email, password, display_name) VALUES (?, ?, ?)",
            ("bob@example.com", "p@ssw0rd", "Bob"),
        )
        conn.execute(
            "INSERT INTO tokens (account_id, token, expires_at) VALUES (?, ?, ?)",
            (1, "tok_alice_abc123", "2026-12-31"),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return jsonify({"service": "Auth Service", "version": "1.0"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/authenticate", methods=["POST"])
def authenticate():
    """Authenticate a user by email and password.

    VULNERABLE: SQL injection via f-string formatting.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    # VULNERABLE: SQL injection via f-string
    query = f"SELECT * FROM accounts WHERE email='{email}' AND password='{password}'"
    try:
        account = conn.execute(query).fetchone()
    except Exception as e:
        conn.close()
        return jsonify({"error": "Authentication failed"}), 500
    conn.close()

    if account:
        audit_logger.info(f"AUTH_SUCCESS: email={email}")
        return jsonify({
            "status": "authenticated",
            "display_name": account["display_name"],
            "account_id": account["id"],
        })
    else:
        audit_logger.info(f"AUTH_FAILURE: email={email}")
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/accounts/<int:account_id>")
def get_account(account_id):
    """Get account info (no auth for test simplicity)."""
    conn = get_db()
    account = conn.execute(
        "SELECT id, email, display_name, is_active FROM accounts WHERE id=?",
        (account_id,),
    ).fetchone()
    conn.close()
    if account:
        return jsonify(dict(account))
    return jsonify({"error": "Account not found"}), 404


@app.route("/tokens", methods=["GET"])
def list_tokens():
    """List tokens (API endpoint for test)."""
    conn = get_db()
    tokens = conn.execute(
        "SELECT t.id, t.token, t.expires_at, a.email FROM tokens t JOIN accounts a ON t.account_id = a.id"
    ).fetchall()
    conn.close()
    return jsonify([dict(t) for t in tokens])


@app.route("/search", methods=["POST"])
def search_accounts():
    """Search accounts by display name.

    VULNERABLE: SQL injection via f-string in LIKE clause.
    """
    data = request.get_json(silent=True) or {}
    q = data.get("q", "")
    if not q:
        return jsonify({"error": "Missing search query 'q'"}), 400

    conn = get_db()
    sql = f"SELECT id, email, display_name FROM accounts WHERE display_name LIKE '%{q}%'"
    try:
        results = conn.execute(sql).fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"error": f"Search error: {str(e)}"}), 500
    conn.close()
    return jsonify({"results": [dict(r) for r in results]})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
