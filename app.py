import os
from pathlib import Path
import sqlite3
import subprocess
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
# REMEDIATED: Parameterized SQL query prevents SQL Injection
# ---------------------------------------------------------------------
@app.get("/search")
def search_users(username: str = Query(..., description="Username to search")):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # SECURE: Parameterized query ensures untrusted input cannot alter SQL syntax
    query = "SELECT id, username, email, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    rows = cursor.fetchall()
    conn.close()

    return [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]


# ---------------------------------------------------------------------
# Endpoint 2: Report Download
# REMEDIATED: Canonical path resolution prevents Path Traversal
# ---------------------------------------------------------------------
@app.get("/download", response_class=PlainTextResponse)
def download_report(filename: str = Query(..., description="Report filename to download")):
    # SECURE: Validate that the resolved canonical path remains inside REPORTS_DIR
    base_dir = Path(REPORTS_DIR).resolve()
    target_path = (base_dir / filename).resolve()

    if base_dir not in target_path.parents and target_path != base_dir:
        raise HTTPException(status_code=403, detail="Directory traversal detected")

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="Report file not found")

    with open(target_path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------
# Endpoint 3: Diagnostic Status Ping
# REMEDIATED: Subprocess execution without shell prevents Command Injection
# ---------------------------------------------------------------------
@app.get("/status")
def diagnostic_status(ip: str = Query(..., description="IP or hostname to ping")):
    # SECURE: Execute ping as an argument vector without shell interpretation
    result = subprocess.run(
        ["ping", "-c", "1", ip],
        capture_output=True,
        text=True,
        shell=False
    )

    return {
        "host": ip,
        "exit_code": result.returncode,
        "reachable": result.returncode == 0
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
