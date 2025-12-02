import os
import sqlite3
import time
from flask import Flask, request, render_template_string, session, redirect, url_for

DB_PATH = "vuln_demo.db"
app = Flask(__name__)

# ======================================================
# SESSION AND LOCKOUT SETTINGS
# ======================================================

# --- New Session Configuration ---
# WARNING: In a real application, retrieve this from an environment variable!
app.secret_key = os.urandom(24) 
INACTIVITY_TIMEOUT = 900        # 15 minutes (15 * 60 seconds)

# --- Lockout Settings (Existing) ---
failed_attempts = {}      # { ip: count }
lockout_until = {}        # { ip: timestamp }
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 1800    # 30 minutes


# ======================================================
# DATABASE SETUP (Unchanged)
# ======================================================
def init_db():
    # If the database exists, delete it to ensure clean testing environment 
    # and consistent seeding. (Remove this for production use)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH) 

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
# SHARED CSS (Unchanged)
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
    button { margin-top:12px; padding:8px 16px; border:none; color:white; border-radius:4px; cursor:pointer; }
    button.login-btn { background:#0078d7; }
    button.register-btn { background:#28a745; }
    button:hover { background:#0063b3; }
    .error { margin-top:10px; padding:10px; background:#fde7e9; border:1px solid #e81123; color:#a80000; border-radius:4px; }
    .success { margin-top:10px; padding:10px; background:#e6ffed; border:1px solid #28a745; color:#28a745; border-radius:4px; }
    .info-text { font-size:0.85rem; margin-top:10px; color:#555; }
    table { width:100%; border-collapse:collapse; margin-top:14px; font-size:0.85rem; }
    th, td { border:1px solid #d0d7e2; padding:6px; text-align:left; }
    th { background:#f3f5f8; }
</style>
"""

# ======================================================
# HTML TEMPLATES (Updated: Registration form moved from LOGIN to DASHBOARD)
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

{% if error %}<div class="error">{{ error }}</div>{% endif %}
{% if success %}<div class="success">{{ success }}</div>{% endif %}

<form method="post" action="/login">
<label>Username</label><input name="username">
<label>Password</label><input type="password" name="password">
<button type="submit" class="login-btn">Enter vault</button>
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
<p>Welcome, {{ username }}. <a href="/logout">Logout</a></p></div></div>

{% if error %}<div class="error">{{ error }}</div>{% endif %}
{% if success %}<div class="success">{{ success }}</div>{% endif %}

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

<hr style="margin: 20px 0;">
<p class="card-title" style="font-size:1.1rem; margin-bottom: 10px;">Add New User</p>
<p class="card-subtitle">Policy: Password must be >= 8 characters and contain at least one letter and one digit.</p>
<form method="post" action="/register">
<label>New Username</label><input name="username">
<label>New Password</label><input type="password" name="password">
<button type="submit" class="register-btn">Register</button>
</form>
</div></div></body></html>
"""

# ======================================================
# SESSION CHECK HELPER (Unchanged)
# ======================================================
def check_session_timeout():
    """
    Checks if the user session has timed out due to inactivity (15 mins).
    If active, it updates the last_activity time.
    """
    now = time.time()
    
    # Check if the session is active and if the timeout limit is reached
    if 'username' in session and (now - session.get('last_activity', now)) > INACTIVITY_TIMEOUT:
        session.clear() # Clear the entire session data
        return True
    
    # If the session is active and not timed out, update the last activity time
    if 'username' in session:
        session['last_activity'] = now
    
    return False


# ======================================================
# BASIC PASSWORD POLICY (Unchanged)
# ======================================================
def password_meets_policy(pw: str) -> bool:
    if len(pw) < 8:
        return False
    has_letter = any(c.isalpha() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    return has_letter and has_digit


# ======================================================
# ROUTES (Updated Access Control)
# ======================================================
@app.route("/", methods=["GET"])
def index():
    if 'username' in session:
        # Check if the user is already logged in and if the session has timed out
        if check_session_timeout():
            return redirect(url_for('logout', timeout=1))
        
        # If logged in, redirect to the dashboard
        return redirect(url_for('dashboard')) 
    
    # Handle error/success messages passed from other redirects
    error_message = request.args.get('error', None)
    success_message = request.args.get('success', None)
    
    return render_template_string(LOGIN_PAGE, error=error_message, success=success_message)


@app.route("/register", methods=["POST"])
def register():
    """
    Handles new user registration and enforces the password policy.
    REQUIRES A USER TO BE LOGGED IN to proceed.
    """
    
    # --- ACCESS CONTROL: MUST BE LOGGED IN ---
    if not 'username' in session:
        return redirect(url_for('index', error="You must be logged in to add a new user."))
    
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # 1. Check Password Policy
    policy_error_msg = "Registration failed: Password does not meet the policy."
    if not password_meets_policy(password):
        return redirect(url_for('dashboard', error=policy_error_msg))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 2. Check if username already exists
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return redirect(url_for('dashboard', error=f"Registration failed: Username '{username}' already exists."))

    # 3. Create User (Policy met)
    try:
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        success_msg = f"User '{username}' created successfully and added to the database."
        return redirect(url_for('dashboard', success=success_msg))
    except sqlite3.Error as e:
        conn.close()
        return redirect(url_for('dashboard', error=f"Database error during registration: {e}"))


@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    now = time.time()

    # -------------------------
    # ACTIVE LOCKOUT CHECK (Existing)
    # -------------------------
    if ip in lockout_until and now < lockout_until[ip]:
        remaining = int(lockout_until[ip] - now)
        return render_template_string(
            LOGIN_PAGE,
            error=f"Too many failed attempts. Try again in {remaining // 60} minutes."
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- Basic Password Policy Check on Login Attempt ---
    if not password_meets_policy(password):
        return render_template_string(LOGIN_PAGE, error="Password does not meet policy.")

    # =====================================================
    # SAFE PARAMETERIZED QUERY — SQLi FIX (Existing)
    # =====================================================
    query = """
        SELECT id, username, password FROM users
        WHERE username = ?
        AND password = ?;
    """

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    try:
        cur.execute(query, (username, password))    # SAFE
        row = cur.fetchone()
    except sqlite3.Error as e:
        conn.close()
        return render_template_string(LOGIN_PAGE, error=f"Database error: {e}")

    # -------------------------
    # LOGIN FAILED (Existing)
    # -------------------------
    if row is None:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if failed_attempts[ip] >= MAX_ATTEMPTS:
            lockout_until[ip] = now + LOCKOUT_DURATION
            failed_attempts[ip] = 0

        conn.close()
        return render_template_string(LOGIN_PAGE, error="Invalid credentials.")

    # -------------------------
    # LOGIN SUCCESS (Modified for Sessions)
    # -------------------------
    failed_attempts[ip] = 0
    
    # Store username and last activity time in the session
    session['username'] = row[1]
    session['last_activity'] = now
    
    # Redirect to the dashboard
    conn.close()
    return redirect(url_for('dashboard'))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    # -------------------------
    # SESSION AND TIMEOUT CHECK (New)
    # -------------------------
    if not 'username' in session:
        # Not logged in, redirect to index with an error message
        return redirect(url_for('index', error="Please log in to view the vault."))

    if check_session_timeout():
        # Timed out, redirect to logout with timeout message flag
        return redirect(url_for('logout', timeout=1))    
        
    # -------------------------
    # DISPLAY DASHBOARD (Moved from old login success)
    # -------------------------
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT id, username, password FROM users;")
    users = cur.fetchall()

    cur.execute("SELECT id, title, content FROM secrets;")
    secrets = cur.fetchall()

    conn.close()

    # Pass error/success messages from registration attempts to the dashboard template
    error_message = request.args.get('error', None)
    success_message = request.args.get('success', None)

    return render_template_string(
        DASHBOARD_PAGE,
        username=session['username'],
        users=users,
        secrets=secrets,
        error=error_message,
        success=success_message
    )


@app.route("/logout")
def logout():
    is_timeout = request.args.get('timeout') == '1'
    
    # Clear the session data
    session.clear() 
    
    error_message = None
    if is_timeout:
        error_message = "Session timed out due to 15 minutes of inactivity. Please log in again."
        
    # Redirect to the index page, which will render LOGIN_PAGE with the error message
    return redirect(url_for('index', error=error_message))


# ======================================================
# MAIN (Unchanged)
# ======================================================
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=True)
