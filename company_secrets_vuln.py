import os
import sqlite3
import time
from datetime import datetime
from flask import Flask, request, render_template_string, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash


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
# ACCESS LOGGING HELPER
# ======================================================
def log_access(username, action, ip_address, status, details=""):
    """
    Logs access attempts and actions to the database.
    
    Args:
        username: Username attempting access (or "N/A" if not applicable)
        action: Type of action (e.g., "LOGIN_ATTEMPT", "LOGIN_SUCCESS", "LOGOUT", "REGISTER", "VIEW_DASHBOARD")
        ip_address: IP address of the requester
        status: Status of the action (e.g., "SUCCESS", "FAILED", "LOCKED_OUT")
        details: Additional details about the action
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        cur.execute(
            "INSERT INTO access_logs (timestamp, username, action, ip_address, status, details) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, username, action, ip_address, status, details)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"[!] Error logging access: {e}")
    finally:
        conn.close()


# ======================================================
# DATABASE SETUP (Fix: Indentation corrected)
# ======================================================
def init_db():
    # If the database exists, delete it to ensure clean testing environment 
    # and consistent seeding.
    # (Remove this for production use) 
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
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?);",
        ("alice", generate_password_hash("password123"))
    )
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?);",
        ("bob", generate_password_hash("hunter2"))
    )
   
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?);",
        ("charlie", generate_password_hash("qwerty"))
    )

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

    # Access logs table
    cur.execute("""
        CREATE TABLE access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT
        );
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized.")


# ======================================================
# SHARED CSS (Fix: Added word-break: break-all;)
# ======================================================
BASE_CSS = """
<style>
    body { background:#e5e9f0;
font-family:Segoe UI, Tahoma; }
    .page-wrapper { min-height:100vh; display:flex; justify-content:center; align-items:center; padding:20px;
}
    .card { width:900px; background:white; border-radius:6px; padding:26px; border:1px solid #d0d7e2; box-shadow:0 8px 18px rgba(0,0,0,0.08);
}
    .card-header { display:flex; gap:14px; align-items:center; }
    .card-header img { width:60px; height:60px; border-radius:4px;
border:1px solid #ccc; }
    .card-title { font-size:1.3rem; font-weight:600; margin:0; }
    .card-subtitle { font-size:0.9rem; color:#666;
margin:0; }
    label { display:block; margin-top:10px; font-size:0.9rem; }
    input { width:100%; padding:7px;
border:1px solid #ccc; border-radius:4px; }
    button { margin-top:12px; padding:8px 16px; border:none; color:white; border-radius:4px; cursor:pointer;
}
    button.login-btn { background:#0078d7; }
    button.register-btn { background:#28a745;
}
    button:hover { background:#0063b3; }
    .error { margin-top:10px; padding:10px; background:#fde7e9; border:1px solid #e81123; color:#a80000;
border-radius:4px; }
    .success { margin-top:10px; padding:10px; background:#e6ffed; border:1px solid #28a745; color:#28a745; border-radius:4px;
}
    .info-text { font-size:0.85rem; margin-top:10px; color:#555; }
    table { width:100%; border-collapse:collapse; margin-top:14px; font-size:0.85rem;
}
    th, td { border:1px solid #d0d7e2; padding:6px; text-align:left; word-break: break-all; }
    th { background:#f3f5f8;
}
    .log-entry { font-size:0.8rem; }
    .status-success { color:#28a745; font-weight:600; }
    .status-failed { color:#e81123; font-weight:600; }
    .status-locked { color:#ff8c00; font-weight:600; }
    .nav-links { margin-top:15px; padding-top:15px; border-top:1px solid #d0d7e2; }
    .nav-links a { margin-right:15px; color:#0078d7; text-decoration:none; }
    .nav-links a:hover { text-decoration:underline; }
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
<p>Welcome, {{ username }}.
 <a href="/logout">Logout</a></p></div></div>

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

<div class="nav-links">
<a href="/access-logs">View Access Logs</a>
</div>

</div></div></body></html>
"""

ACCESS_LOGS_PAGE = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Access Logs</title>""" + BASE_CSS + """</head>
<body>
<div class="page-wrapper"><div class="card">

<div class="card-header">
<img src="https://media.istockphoto.com/id/1199316627/vector/confidential-file-information.jpg?s=612x612&w=0&k=20&c=1NgVSNZtl5KD1fV7MtU2-Q09ssYc-Lu3yYITN3zsqL0=">
<div><p class="card-title">Access Logs</p>
<p class="card-subtitle">System access and authentication logs</p></div></div>

<h2>Recent Access Activity</h2>
<table class="log-entry">
<tr>
<th>Timestamp</th>
<th>Username</th>
<th>Action</th>
<th>IP Address</th>
<th>Status</th>
<th>Details</th>
</tr>
{% for log in logs %}
<tr>
<td>{{ log[1] }}</td>
<td>{{ log[2] }}</td>
<td>{{ log[3] }}</td>
<td>{{ log[4] }}</td>
<td>
{% if log[5] == 'SUCCESS' %}
<span class="status-success">{{ log[5] }}</span>
{% elif log[5] == 'FAILED' %}
<span class="status-failed">{{ log[5] }}</span>
{% elif log[5] == 'LOCKED_OUT' %}
<span class="status-locked">{{ log[5] }}</span>
{% else %}
{{ log[5] }}
{% endif %}
</td>
<td>{{ log[6] if log[6] else '-' }}</td>
</tr>
{% endfor %}
</table>

<div class="nav-links">
<a href="/dashboard">Back to Dashboard</a> | <a href="/logout">Logout</a>
</div>

</div></div></body></html>
"""

# ======================================================
# SESSION CHECK HELPER (Unchanged)
# ======================================================
def check_session_timeout():
    """
    Checks if the user session has timed 
 out due to inactivity (15 mins).
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
        # Check if the user is already logged in and if the 
        # session has timed out
        if check_session_timeout():
            return redirect(url_for('logout', timeout=1))
        
        # If logged in, redirect to the dashboard
        return redirect(url_for('dashboard')) 
    
    # Handle error/success messages passed from other redirects
    error_message = request.args.get('error', None)
    success_message = request.args.get('success', None)
    
    return render_template_string(LOGIN_PAGE, error=error_message, success=success_message)


@app.route("/register", 
methods=["POST"])
def register():
    """
    Handles new user registration and enforces the password policy.
 REQUIRES A USER TO BE LOGGED IN to proceed.
    """
    
    # --- ACCESS CONTROL: MUST BE LOGGED IN ---
    if not 'username' in session:
        log_access("N/A", "REGISTER_ATTEMPT", request.remote_addr, "FAILED", "Not logged in")
        return redirect(url_for('index', error="You must be logged in to add a new user."))
    
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # 1. Check Password Policy
    policy_error_msg = "Registration failed: Password does not meet the policy."
    if not password_meets_policy(password):
        log_access(session['username'], "REGISTER_ATTEMPT", request.remote_addr, "FAILED", f"Password policy violation for username: {username}")
        return redirect(url_for('dashboard', error=policy_error_msg))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 2. Check if username already exists
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        log_access(session['username'], "REGISTER_ATTEMPT", request.remote_addr, "FAILED", f"Username already exists: {username}")
        return redirect(url_for('dashboard', error=f"Registration failed: Username '{username}' already exists."))
    # 3. Create User (Policy met) - store hashed password
    try:
        hashed_password = generate_password_hash(password)
    
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        conn.close()
        log_access(session['username'], "REGISTER", request.remote_addr, "SUCCESS", f"Created new user: {username}")
        success_msg = f"User '{username}' created successfully and added to the database."
        return redirect(url_for('dashboard', success=success_msg))
    except sqlite3.Error as e:
        conn.close()
        log_access(session['username'], "REGISTER_ATTEMPT", request.remote_addr, "FAILED", f"Database error: {e}")
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
        log_access(request.form.get("username", "N/A"), "LOGIN_ATTEMPT", ip, "LOCKED_OUT", f"{remaining} seconds remaining")
        return render_template_string(
            LOGIN_PAGE,
       
            error=f"Too many failed attempts. Try again in {remaining // 60} minutes."
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- Basic Password Policy Check on Login Attempt ---
    if not password_meets_policy(password):
        log_access(username, "LOGIN_ATTEMPT", ip, "FAILED", "Password does not meet policy")
        return render_template_string(LOGIN_PAGE, error="Password does not meet policy.")

    # =====================================================
    # SAFE PARAMETERIZED QUERY FOR LOGIN — 
    # =====================================================
    query = """
   
        SELECT id, username, password FROM users
        WHERE username = ?;
    """

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    try:
        cur.execute(query, (username,))
        row = cur.fetchone()

    except sqlite3.Error as e:
        conn.close()
        log_access(username, "LOGIN_ATTEMPT", ip, "FAILED", f"Database error: {e}")
        return render_template_string(LOGIN_PAGE, error=f"Database error: {e}")

    # -------------------------
    # LOGIN FAILED OR WRONG PASSWORD
    # -------------------------
    login_ok = False
    if row is not None:
     
        stored_hash = row[2]  # hashed password from DB
        if check_password_hash(stored_hash, password):
            login_ok = True

    if not login_ok:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if failed_attempts[ip] >= MAX_ATTEMPTS:
            lockout_until[ip] = now + LOCKOUT_DURATION
            failed_attempts[ip] = 0
            log_access(username, "LOGIN_ATTEMPT", ip, "LOCKED_OUT", f"Account locked after {MAX_ATTEMPTS} failed attempts")
        else:
            log_access(username, "LOGIN_ATTEMPT", ip, "FAILED", f"Invalid credentials (Attempt {failed_attempts[ip]}/{MAX_ATTEMPTS})")

        conn.close()
        return render_template_string(LOGIN_PAGE, error="Invalid credentials.")

    # -------------------------
    # LOGIN SUCCESS (with hashed passwords)
    # -------------------------
    failed_attempts[ip] = 0

    session['username'] = row[1]
    session['last_activity'] = now

    log_access(row[1], "LOGIN", ip, "SUCCESS", "User successfully authenticated")

    conn.close()
    return redirect(url_for('dashboard'))



@app.route("/dashboard", methods=["GET"])
def dashboard():
    # -------------------------
    # SESSION AND TIMEOUT CHECK (New)
    # -------------------------
    if not 'username' in session:
        # Not logged 
        # in, redirect to index with an error message
        return redirect(url_for('index', error="Please log in to view the vault."))

    if check_session_timeout():
        # Timed out, redirect to logout with timeout message flag
        return redirect(url_for('logout', timeout=1))    
        
    # -------------------------
    # DISPLAY DASHBOARD (Moved from old login success)
    # -------------------------
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor() # <-- FIX: Completed statement on one line

    cur.execute("SELECT id, username, password FROM users;")
    users = cur.fetchall()

    cur.execute("SELECT id, title, content FROM secrets;")
    secrets = cur.fetchall()

    conn.close()

    # Log dashboard access
    log_access(session['username'], "VIEW_DASHBOARD", request.remote_addr, "SUCCESS", "Accessed dashboard")

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


@app.route("/access-logs", methods=["GET"])
def access_logs():
    # -------------------------
    # SESSION AND TIMEOUT CHECK
    # -------------------------
    if not 'username' in session:
        return redirect(url_for('index', error="Please log in to view access logs."))

    if check_session_timeout():
        return redirect(url_for('logout', timeout=1))
    
    # -------------------------
    # RETRIEVE ACCESS LOGS
    # -------------------------
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Get all logs, most recent first
    cur.execute("SELECT * FROM access_logs ORDER BY id DESC LIMIT 100;")
    logs = cur.fetchall()

    conn.close()

    # Log access to logs page
    log_access(session['username'], "VIEW_ACCESS_LOGS", request.remote_addr, "SUCCESS", "Viewed access logs")

    return render_template_string(
        ACCESS_LOGS_PAGE,
        logs=logs
    )


@app.route("/logout")
def logout():
    is_timeout = request.args.get('timeout') == '1'
    
    # Log logout before clearing session
    if 'username' in session:
        log_access(session['username'], "LOGOUT", request.remote_addr, "SUCCESS", "User logged out" + (" (timeout)" if is_timeout else ""))
    
    # Clear the session data
    session.clear() 
    
    error_message = None
    if is_timeout:
        error_message = "Session timed out due to 15 minutes of inactivity.\
 Please log in again." # <-- FIX: Backslash added for string continuation
        
    # Redirect to the index page, which will render LOGIN_PAGE with the error message
    return redirect(url_for('index', error=error_message))


# ======================================================
# MAIN (Unchanged)
# ======================================================
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=True)
