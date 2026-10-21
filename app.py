import base64
import os
import pickle
import sqlite3
import urllib.request
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(
    title="CustomerPortal",
    description="A customer portal application demonstrating automated CI/CD security scanning across diverse vulnerability types.",
    version="1.1.0"
)

# ---------------------------------------------------------------------
# Vulnerability Type 1: Hardcoded Secrets & Credentials (CWE-798)
# ---------------------------------------------------------------------
JWT_SECRET_KEY = "supersecret_jwt_signing_key_998877"
ADMIN_API_TOKEN = "ghp_9876543210abcdefghijklmnopqrstuvwxyz"

DB_PATH = "portal.db"
REPORTS_DIR = "reports"


def init_db():
    """Initialize database and seed sample records."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    sample_report = os.path.join(REPORTS_DIR, "quarterly_summary.txt")
    if not os.path.exists(sample_report):
        with open(sample_report, "w", encoding="utf-8") as f:
            f.write("CustomerPortal Q3 Summary: Service availability at 99.98%.\n")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            [
                ("alice", "alice@example.com", "customer"),
                ("bob", "bob@example.com", "customer"),
                ("charlie", "charlie@example.com", "customer"),
                ("admin", "admin@internal.portal", "admin"),
            ],
        )
    conn.commit()
    conn.close()


init_db()


@app.get("/")
def index():
    return {
        "message": "Welcome to CustomerPortal API",
        "docs": "/docs",
        "endpoints": [
            "/search",
            "/download",
            "/status",
            "/webhook/trigger",
            "/session/restore",
            "/tools/calc",
            "/welcome",
        ]
    }


# ---------------------------------------------------------------------
# Vulnerability Type 2: SQL Injection (CWE-89)
# ---------------------------------------------------------------------
@app.get("/search")
def search_users(username: str = Query(..., description="Username to search")):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABLE: Direct string interpolation into raw SQL statement
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    return [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]


# ---------------------------------------------------------------------
# Vulnerability Type 3: Path Traversal (CWE-22)
# ---------------------------------------------------------------------
@app.get("/download", response_class=PlainTextResponse)
def download_report(filename: str = Query(..., description="Report filename to download")):
    # VULNERABLE: Direct path joining allows directory traversal (e.g., ../app.py)
    file_path = os.path.join(REPORTS_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------
# Vulnerability Type 4: OS Command Injection (CWE-78)
# ---------------------------------------------------------------------
@app.get("/status")
def diagnostic_status(ip: str = Query(..., description="IP or hostname to ping")):
    # VULNERABLE: Unsanitized user parameter passed directly to shell execution
    cmd = f"ping -c 1 {ip}"
    exit_code = os.system(cmd)

    return {
        "host": ip,
        "exit_code": exit_code,
        "reachable": exit_code == 0
    }


# ---------------------------------------------------------------------
# Vulnerability Type 5: Server-Side Request Forgery / SSRF (CWE-918)
# ---------------------------------------------------------------------
@app.get("/webhook/trigger")
def trigger_webhook(target_url: str = Query(..., description="External callback URL")):
    """Fetch external webhook URL directly without domain/IP validation."""
    # VULNERABLE: Untrusted user-supplied URL passed directly to HTTP client
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "CustomerPortal-Webhook"})
        with urllib.request.urlopen(req, timeout=5) as response:
            preview = response.read(200).decode("utf-8", errors="ignore")
        return {"status": "success", "target_url": target_url, "preview": preview}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Webhook request failed: {str(exc)}")


# ---------------------------------------------------------------------
# Vulnerability Type 6: Insecure Deserialization (CWE-502)
# ---------------------------------------------------------------------
@app.post("/session/restore")
def restore_session(payload: str = Query(..., description="Base64-encoded pickled session data")):
    """Restore customer session state from client-supplied serialized object."""
    # VULNERABLE: Insecure deserialization via pickle.loads on untrusted data
    try:
        raw_bytes = base64.b64decode(payload)
        session_obj = pickle.loads(raw_bytes)
        return {"status": "session restored", "session_type": str(type(session_obj))}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Deserialization error: {str(exc)}")


# ---------------------------------------------------------------------
# Vulnerability Type 7: Arbitrary Code Execution / Eval Injection (CWE-95)
# ---------------------------------------------------------------------
@app.get("/tools/calc")
def dynamic_calculator(expr: str = Query(..., description="Mathematical calculation formula")):
    """Evaluate mathematical expressions entered by user."""
    # VULNERABLE: Passing untrusted string directly to Python eval()
    try:
        computed = eval(expr)
        return {"expression": expr, "result": computed}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Calculation error: {str(exc)}")


# ---------------------------------------------------------------------
# Vulnerability Type 8: Reflected Cross-Site Scripting / XSS (CWE-79)
# ---------------------------------------------------------------------
@app.get("/welcome", response_class=HTMLResponse)
def welcome_user(name: str = Query(..., description="User display name")):
    """Render welcome banner."""
    # VULNERABLE: Direct string interpolation into raw HTML response without escaping
    html_content = f"""
    <!DOCTYPE html>
    <html>
      <head><title>Welcome</title></head>
      <body>
        <h1>Welcome back, {name}!</h1>
        <p>Your CustomerPortal session is active.</p>
      </body>
    </html>
    """
    return html_content


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
