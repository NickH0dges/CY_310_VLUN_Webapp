import os
import sqlite3
import time
from flask import Flask, request, render_template_string

DB_PATH = "vuln_demo.db"
app = Flask(__name__)

# ------------------------
#   LOCKOUT SETTINGS
# ------------------------
failed_attempts = {}     # { ip: count }
lockout_until = {}       # { ip: timestamp }
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 1800   # 30 minutes


# ======================================================
# DATABASE SETUP
# ======================================================
def init_db():
    if os.path.exists(DB_PATH):
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Users table (plaintext passwords — intentionally insecure)
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    """)

    # Seed demo users
    cur.execute("INSERT INTO users (username, password) VALUES ('alice', 'password123');")
    cur.execute("INSERT INTO users (username, password) VALUES ('bob', 'hunter2');")
    cur.execute("INSERT INTO users (username, password) VALUES ('charlie', 'qwerty');")

    # Secrets table
    cur.execute("""
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
    """)

    secrets = [
        ("2026 Product Roadmap", "Next-gen XR headset moved to Q4."),
        ("Internal Credentials", "Staging login: admin / Winter2025!"),
        ("Financial Projection Draft", "Revenue revised from 12.8M to 9.4M."),
        ("HR Confidential Memo", "Complaint filed against DevOps lead."),
        ("Security Investigation #441", "Suspicious outbound traffic on server-13."),
        ("Vendor Negotiation Notes", "CyberLink demanding +18% increase."),
        ("Incident Report", "3-hour outage caused by rogue script."),
        ("Patent Draft", "Cooling method for embedded ARM modules."),
        ("Internal Email Thread", "Project Hurricane moved off Slack."),
        ("Executive Meeting Notes", "Discussing acquisition of AI startup.")
    ]

    cur.executemany("INSERT INTO secrets (title, content) VALUES (?, ?)", secrets)

    conn.commit()
    conn.close()
    print("[+] Database initialized.")


# ======================================================
# SHARED CSS (unchanged)
# ======================================================
BASE_CSS = """
<style>
  body { background:#e5e9f0; font-family:Segoe UI, Tahoma; }
  .page-wrapper { min-height:100vh; display:flex; justify-content:center; align-items:center; padding:20px; }
  .card { width:900px; background:white; border-radius:6px; padding:26px; border:1px solid #d0d7e2; box-shadow:0 8px 18px rgba(0,0,0,0.08); }
  .card-header { display:flex; gap:14px; align-items:center; }
  .card-header img { width:60px; height:60px; border-radius:4px; border:1px solid #ccc; }
  .card-title { font-size:1.3rem; font-weight:600; margin:0; }
  .card-subtitle { font-size:0.9rem; color:#666; margin:0; }
  label { display:block; margin-top:10px; font-size:0.9rem; }
  input { width:100%; padding:7px; border:1px solid #ccc; border-radius:4px; }
  button { margin-top:12px; padding:8px 16px; background:#0078d7; border:none; color:white; border-radius:4px; cursor:pointer; }
  button:hover { background:#0063b3; }
  .error { margin-top:10px; padding:10px; background:#fde7e9; border:1px solid #e81123; color:#a80000; border-radius:4px; }
  .info-text { font-size:0.85rem; margin-top:10px; color:#555; }
  table { width:100%; border-collapse:collapse; margin-top:14px; font-size:0.85rem; }
  th, td { border:1px solid #d0d7e2; padding:6px; text-align:left; }
  th { background:#f3f5f8; }
</style>
"""

# ======================================================
# HTML TEMPLATES (unchanged)
# ======================================================
LOGIN_PAGE = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Login</title>""" + BASE_CSS + """</head>
<body>
<div class="page-wrapper"><div class="card">
<div class="card-header">
<img src="https://media.istockphoto.com/id/1199316627/vector/confidential-file-information.jpg?s=612x612&w=0&k=20&c=1NgVSNZtl5KD1fV7MtU2-Q09ssYc-Lu3yYITN3zsqL0=">
<div><p class="card-title">Company Secrets Vault</p>
<p class="card-subtitle">Sign in to access confidential files.</p></div></div>

<form method="post" action="/login">
<label>Username</label><input name="username">
<label>Password</label><input type="password" name="password">
<button type="submit">Enter vault</button>

{% if error %}<div class="error">{{ error }}</div>{% endif %}
</form>

<p class="info-text"><strong>Educational use only.</strong> Created for CY310 Info Security & Assurance at Southeast Missouri State University by Nick Hodges.</p>
<p class="info-text">Default login: <code>alice / password123</code></p>

</div></div></body></html>
"""

DASHBOARD_PAGE = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Dashboard</title>""" + BASE_CSS + """</head>
<body>
<div class="page-wrapper"><div class="card">

<div class="card-header">
<img src="https://media.istockphoto.com/id/1199316627/vector/confidential-file-information.jpg?s=612x612&w=0&k=20&c=1NgVSNZtl5KD1fV7MtU2-Q09ssYc-Lu3yYITN3zsqL0=">
<div><p class="card-title">Access granted</p>
<p>Welcome, {{ username }}.</p></div></div>

<h2>Company secrets</h2>
<table><tr><th>ID</th><th>Title</th><th>Content</th></tr>
{% for s in secrets %}
<tr><td>{{ s[0] }}</td><td>{{ s[1] }}</td><td>{{ s[2] }}</td></tr>
{% endfor %}
</table>

<h2>Users</h2>
<table><tr><th>ID</th><th>Username</th><th>Password</th></tr>
{% for u in users %}
<tr><td>{{ u[0] }}</td><td>{{ u[1] }}</td><td>{{ u[2] }}</td></tr>
{% endfor %}
</table>

</div></div></body></html>
"""


# ======================================================
# ROUTES (SQL injection fix + lockout)
# ======================================================
@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    now = time.time()

    # -------------------------
    # ACTIVE LOCKOUT CHECK
    # -------------------------
    if ip in lockout_until and now < lockout_until[ip]:
        remaining = int(lockout_until[ip] - now)
        return render_template_string(
            LOGIN_PAGE,
            error=f"Too many failed attempts. Try again in {remaining // 60} minutes."
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # =====================================================
    # SAFE PARAMETERIZED QUERY — SQLi FIX
    # =====================================================
    query = """
        SELECT id, username, password FROM users
        WHERE username = ? AND password = ?;
    """

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    try:
        cur.execute(query, (username, password))   # SAFE
        row = cur.fetchone()
    except sqlite3.Error as e:
        conn.close()
        return render_template_string(LOGIN_PAGE, error=f"Database error: {e}")

    # -------------------------
    # LOGIN FAILED
    # -------------------------
    if row is None:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if failed_attempts[ip] >= MAX_ATTEMPTS:
            lockout_until[ip] = now + LOCKOUT_DURATION
            failed_attempts[ip] = 0

        conn.close()
        return render_template_string(LOGIN_PAGE, error="Invalid credentials.")

    # -------------------------
    # LOGIN SUCCESS
    # -------------------------
    failed_attempts[ip] = 0

    cur.execute("SELECT id, username, password FROM users;")
    users = cur.fetchall()

    cur.execute("SELECT id, title, content FROM secrets;")
    secrets = cur.fetchall()

    conn.close()

    return render_template_string(
        DASHBOARD_PAGE,
        username=row[1],
        users=users,
        secrets=secrets
    )


# ======================================================
# MAIN
# ======================================================
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=True)
