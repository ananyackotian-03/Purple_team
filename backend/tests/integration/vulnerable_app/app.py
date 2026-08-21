"""Vulnerable Flask Application for SentinelForge E2E Testing.

This application contains a deliberate SQL injection vulnerability in the
login endpoint for testing the remediation pipeline. DO NOT deploy this
to production.

Security issues present (intentional):
- SQL injection in login (A03:2021-Injection)
- Hardcoded secret key
- No CSRF protection
- Debug mode enabled
"""

import logging
import os
import sqlite3
import time
from datetime import datetime

from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = "super-secret-key-do-not-use"

logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger("audit")

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            detail TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
        conn.execute("INSERT INTO users (username, password, role) VALUES ('user', 'password123', 'user')")
        conn.execute("INSERT INTO notes (user_id, title, content) VALUES (1, 'System Config', 'Database credentials: admin/admin123')")
        conn.execute("INSERT INTO notes (user_id, title, content) VALUES (2, 'My Note', 'Hello world')")
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()


def log_audit(event_type, username=None, detail=None):
    audit_logger.info(f"{event_type}: user={username} detail={detail}")
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (event_type, username, detail, ip_address) VALUES (?, ?, ?, ?)",
            (event_type, username, detail, request.remote_addr if request else None),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
    <form method="POST">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>Role: {{ role }}</p>
    <a href="/api/users">Users</a> |
    <a href="/api/audit-log">Audit Log</a> |
    <a href="/logout">Logout</a>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes — Primary vulnerability (SQL injection)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "username" in session:
        return render_template_string(
            DASHBOARD_TEMPLATE,
            username=session["username"],
            role=session.get("role", "user"),
        )
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()
        # VULNERABLE: SQL injection via string formatting
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            user = conn.execute(query).fetchone()
        except Exception:
            user = None
        conn.close()

        if user:
            log_audit("LOGIN_SUCCESS", username)
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        else:
            log_audit("LOGIN_FAILURE", username)
            error = "Invalid username or password"

    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route("/logout")
def logout():
    log_audit("LOGOUT", session.get("username"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# API Routes — Realistic application endpoints
# ---------------------------------------------------------------------------

@app.route("/api/users")
def api_users():
    conn = get_db()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


@app.route("/api/users/<int:user_id>")
def api_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404


@app.route("/api/notes")
def api_notes():
    if "username" not in session:
        return jsonify({"error": "Authentication required"}), 401
    conn = get_db()
    notes = conn.execute("SELECT id, title, content, created_at FROM notes").fetchall()
    conn.close()
    return jsonify([dict(n) for n in notes])


@app.route("/api/search", methods=["POST"])
def api_search():
    data = request.get_json(silent=True) or {}
    query_term = data.get("q", "")
    if not query_term:
        return jsonify({"error": "Missing search query 'q'"}), 400

    conn = get_db()
    # VULNERABLE: SQL injection via f-string in search
    sql = f"SELECT id, title, content FROM notes WHERE title LIKE '%{query_term}%' OR content LIKE '%{query_term}%'"
    try:
        results = conn.execute(sql).fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"error": f"Search failed: {str(e)}"}), 500
    conn.close()
    return jsonify({"results": [dict(r) for r in results]})


@app.route("/api/audit-log")
def api_audit_log():
    conn = get_db()
    logs = conn.execute(
        "SELECT id, event_type, username, detail, ip_address, timestamp FROM audit_log ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
