import os
import sqlite3
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse

app = FastAPI(
    title="CustomerPortal",
    description="A minimal customer portal application demonstrating automated CI/CD security scanning.",
    version="1.0.0"
)

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
        "endpoints": ["/search", "/download", "/status"]
    }


# ---------------------------------------------------------------------
# Endpoint 1: User Search
# FLAW: SQL Injection (concatenating user input directly into SQLite query)
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
# Endpoint 2: Report Download
# FLAW: Path Traversal (opening file from user path without canonical validation)
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
# Endpoint 3: Diagnostic Status Ping
# FLAW: OS Command Injection (passing user-controlled input directly to os.system)
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
