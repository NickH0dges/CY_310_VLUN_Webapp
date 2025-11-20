import os
import sqlite3
from flask import Flask, request, render_template_string

DB_PATH = "vuln_demo.db"

app = Flask(__name__)


# ===== DATABASE SETUP =====
def init_db():
    """Create the SQLite database with demo users and fake company secrets."""
    if os.path.exists(DB_PATH):
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # USERS table (intentionally insecure: plaintext passwords)
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
        """
    )

    # Seed demo users
    cur.execute("INSERT INTO users (username, password) VALUES ('alice', 'password123');")
    cur.execute("INSERT INTO users (username, password) VALUES ('bob', 'hunter2');")
    cur.execute("INSERT INTO users (username, password) VALUES ('charlie', 'qwerty');")

    # SECRETS table with realistic fake internal data
    cur.execute(
        """
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
        """
    )

    fake_secrets = [
        (
            "2026 Product Roadmap",
            "Next-gen XR headset prototype launch moved to Q4; early demos show overheating issues.",
        ),
        (
            "Internal Credentials",
            "Staging server login: admin / Winter2025! — rotate before client audit.",
        ),
        (
            "Financial Projection Draft",
            "Expected revenue for Q2 revised from $12.8M to $9.4M due to supply chain delays.",
        ),
        (
            "HR Confidential Memo",
            "Anonymous employee complaint filed against team lead in DevOps — under review.",
        ),
        (
            "Security Investigation #441",
            "Suspicious outbound traffic detected on server-13; possible credential stuffing attempt.",
        ),
        (
            "Vendor Negotiation Notes",
            "CyberLink wants 18% increase in licensing costs; counteroffer prepared at 12%.",
        ),
        (
            "Incident Report",
            "3-hour outage on 05/11 caused by rogue automation script deleting temp tables.",
        ),
        (
            "Patent Draft",
            "Preliminary patent text written for adaptive cooling method for embedded ARM modules.",
        ),
        (
            "Internal Email Thread",
            "'Project Hurricane' discussions moved off Slack pending legal review.",
        ),
        (
            "Executive Meeting Notes",
            "Considering acquisition of small AI startup — confidentiality required.",
        ),
    ]

    cur.executemany("INSERT INTO secrets (title, content) VALUES (?, ?)", fake_secrets)

    conn.commit()
    conn.close()
    print("[+] Database initialized with users + fake company secrets.")


# ===== SHARED CSS (simple ~2015 style, wider card) =====
BASE_CSS = """
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 0;
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    background: #e5e9f0;
    color: #222;
  }
  .page-wrapper {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .card {
    background: #ffffff;
    border-radius: 6px;
    border: 1px solid #d0d7e2;
    max-width: 900px;   /* wider layout */
    width: 100%;
    padding: 24px 26px 22px;
    box-shadow: 0 8px 18px rgba(0,0,0,0.08);
  }
  .card-header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 18px;
  }
  .card-header img {
    width: 60px;
    height: 60px;
    border-radius: 4px;
    border: 1px solid #d0d7e2;
    background: #f5f5f5;
    object-fit: cover;
  }
  .card-title {
    font-size: 1.3rem;
    font-weight: 600;
    margin: 0 0 4px 0;
  }
  .card-subtitle {
    font-size: 0.9rem;
    color: #666;
    margin: 0;
  }

  h2 {
    margin: 10px 0 12px 0;
    font-size: 1rem;
    font-weight: 600;
  }

  label {
    display: block;
    font-size: 0.85rem;
    margin-bottom: 4px;
    color: #444;
  }

  input[type="text"],
  input[type="password"] {
    width: 100%;
    padding: 8px 9px;
    border-radius: 3px;
    border: 1px solid #c3cad5;
    font-size: 0.9rem;
    margin-bottom: 10px;
  }
  input[type="text"]:focus,
  input[type="password"]:focus {
    border-color: #0078d7;
    outline: none;
    box-shadow: 0 0 0 1px rgba(0,120,215,0.25);
  }

  button {
    display: inline-block;
    border: none;
    padding: 8px 18px;
    border-radius: 3px;
    background-color: #0078d7;
    color: #ffffff;
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
  }
  button:hover {
    background-color: #0063b3;
  }

  .error {
    margin-top: 8px;
    padding: 8px 9px;
    border-radius: 3px;
    background: #fde7e9;
    border: 1px solid #e81123;
    color: #a80000;
    font-size: 0.85rem;
  }

  .info-text {
    font-size: 0.8rem;
    color: #777;
    margin-top: 8px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
    font-size: 0.85rem;
  }
  th, td {
    border: 1px solid #d0d7e2;
    padding: 6px 8px;
    text-align: left;
    vertical-align: top;
  }
  th {
    background: #f3f5f8;
    font-weight: 600;
  }

  .welcome {
    font-size: 0.95rem;
    margin-top: 4px;
    color: #444;
  }

  .link-back {
    display: inline-block;
    margin-top: 10px;
    font-size: 0.85rem;
    color: #0078d7;
    text-decoration: none;
  }
  .link-back:hover {
    text-decoration: underline;
  }

  code {
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.85rem;
    background: #f3f5f8;
    padding: 2px 4px;
    border-radius: 3px;
  }
</style>
"""


# ===== HTML TEMPLATES =====
LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Company Secrets Vault – Login</title>
  """ + BASE_CSS + """
</head>
<body>
  <div class="page-wrapper">
    <div class="card">
      <div class="card-header">
        <img src="https://media.istockphoto.com/id/1199316627/vector/confidential-file-information.jpg?s=612x612&w=0&k=20&c=1NgVSNZtl5KD1fV7MtU2-Q09ssYc-Lu3yYITN3zsqL0=" alt="Confidential file">
        <div>
          <p class="card-title">Company Secrets Vault</p>
          <p class="card-subtitle">Sign in to access internal confidential files.</p>
        </div>
      </div>

      <h2>Operator sign-in</h2>
      <form method="post" action="{{ url_for('login') }}">
        <label>Username</label>
        <input type="text" name="username" autocomplete="username">

        <label>Password</label>
        <input type="password" name="password" autocomplete="current-password">

        <button type="submit">Enter vault</button>

        {% if error %}
          <div class="error">{{ error }}</div>
        {% endif %}
      </form>

      <p class="info-text">
        This demo simulates a confidential portal used to store sensitive company information.
        In this lab environment, several serious security flaws are present on purpose.
      </p>

      <p class="info-text">
        <strong>Educational use only.</strong> This application was created for penetration
        testing exercises in <strong>CY310 Information Security &amp; Assurance</strong> at
        <strong>Southeast Missouri State University</strong>.
        Developed by <strong>Nick Hodges</strong>.
      </p>

      <p class="info-text">
        Default demo login: username <code>alice</code>, password <code>password123</code>.
      </p>
    </div>
  </div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Company Secrets Vault – Access Granted</title>
  """ + BASE_CSS + """
</head>
<body>
  <div class="page-wrapper">
    <div class="card">
      <div class="card-header">
        <img src="https://media.istockphoto.com/id/1199316627/vector/confidential-file-information.jpg?s=612x612&w=0&k=20&c=1NgVSNZtl5KD1fV7MtU2-Q09ssYc-Lu3yYITN3zsqL0=" alt="Confidential file">
        <div>
          <p class="card-title">Access granted</p>
          <p class="welcome">Access granted, welcome {{ username }}.</p>
        </div>
      </div>

      <h2>Company secret records</h2>
      <p class="info-text">
        These are sensitive internal records. Through SQL injection or weak controls, an attacker
        could retrieve all of this information without proper authorization.
      </p>

      <table>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Content</th>
        </tr>
        {% for s in secrets %}
          <tr>
            <td>#{{ s[0] }}</td>
            <td>{{ s[1] }}</td>
            <td>{{ s[2] }}</td>
          </tr>
        {% endfor %}
      </table>

      <h2 style="margin-top:24px;">User table (plaintext passwords)</h2>
      <p class="info-text">
        For demonstration purposes, user passwords are stored in plaintext. This is another severe
        security issue that you will address in the “secure coding” version of the application.
      </p>

      <table>
        <tr>
          <th>ID</th>
          <th>Username</th>
          <th>Password</th>
        </tr>
        {% for u in users %}
          <tr>
            <td>#{{ u[0] }}</td>
            <td>{{ u[1] }}</td>
            <td>{{ u[2] }}</td>
          </tr>
        {% endfor %}
      </table>

      <a class="link-back" href="{{ url_for('index') }}">← Exit vault</a>
    </div>
  </div>
</body>
</html>
"""


# ===== ROUTES (INTENTIONALLY VULNERABLE) =====
@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # *************** VULNERABLE CODE (ON PURPOSE) ***************
    # Builds SQL via string concatenation with untrusted input → SQL injection.
    query = (
        "SELECT id, username, password FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "';"
    )
    print("[!] Executing query:", query)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        conn.close()
        # Verbose DB error is itself an information-disclosure issue.
        return render_template_string(LOGIN_PAGE, error="Database error: {}".format(e))

    if row is None:
        conn.close()
        return render_template_string(LOGIN_PAGE, error="Invalid credentials.")

    # On "success", show all users and all secrets to demonstrate impact.
    cur.execute("SELECT id, username, password FROM users;")
    users = cur.fetchall()
    cur.execute("SELECT id, title, content FROM secrets;")
    secrets = cur.fetchall()
    conn.close()

    return render_template_string(
        DASHBOARD_PAGE,
        username=row[1],
        users=users,
        secrets=secrets,
    )


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=True)
