# CustomerPortal

A minimal, realistic Python web service designed to showcase automated CI/CD security scanning, SARIF alert reporting, and AI-driven automated remediation using the [`ShlokGarg22/SecureCode`](https://github.com/ShlokGarg22/SecureCode) GitHub Action.

---

## 🎯 Architecture & Intentional Flaws

The project contains a lightweight FastAPI backend (`app.py`) featuring 3 realistic, high-severity security flaws for demonstration purposes:

1. **SQL Injection (`/search`)**: Concatenates raw user input into an SQLite query string without parameterization.
   - *Example Attack*: `GET /search?username=' OR '1'='1`
2. **Path Traversal (`/download`)**: Opens files from a user-supplied filename without canonical directory resolution.
   - *Example Attack*: `GET /download?filename=../app.py`
3. **OS Command Injection (`/status`)**: Passes unvalidated IP/hostname parameters directly into `os.system(...)`.
   - *Example Attack*: `GET /status?ip=127.0.0.1; whoami`

---

## 🚀 Quick Local Run

```bash
# 1. Create and activate a virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the application
python app.py
```

The API will be available at `http://localhost:8000`. You can test endpoints interactively via Swagger UI at `http://localhost:8000/docs`.

---

## 🛡️ CI/CD Security Demo Walkthrough

### 1. Push this Repository to GitHub

Create a new repository on GitHub (e.g., `CustomerPortal`), then push this code:

```bash
git init
git add .
git commit -m "feat: initial commit with CustomerPortal service"
git branch -M main
git remote add origin https://github.com/<YOUR_USERNAME>/CustomerPortal.git
git push -u origin main
```

---

### 2. Automated Pipeline Interception (Red ❌)

When your push reaches GitHub:

1. **Trigger**: The workflow `.github/workflows/securecode.yml` triggers on the push.
2. **Scan**: `ShlokGarg22/SecureCode@main` scans the codebase with `fail-on: "high"` and `enable-ai: "true"`.
3. **Block**: It detects the 3 High-severity flaws (SQL Injection, Path Traversal, and Command Injection) and halts the build with a **Red X** failure status.
4. **SARIF Publishing**: The scanner publishes a SARIF report to GitHub Security (**Security** tab → **Code scanning alerts**).
5. **Remediation Artifact**: The AI remediation engine generates `remediation.patch` and uploads it as a workflow artifact.

---

### 3. One-Command Fix & Turn the Build Green (Green ✅)

To remediate all detected vulnerabilities automatically:

1. Navigate to your failed GitHub Actions run under the **Actions** tab.
2. Download and unzip the `remediation-patch` artifact to get `remediation.patch` in your repository root (or apply it directly).
3. Apply the patch and push:

```bash
# Apply the unified remediation patch
git apply remediation.patch

# Stage, commit, and push the fixes
git add .
git commit -m "fix(security): apply automated SecureCode remediation patch"
git push origin main
```

SecureCode re-analyzes the codebase, detects 0 high-severity vulnerabilities, and turns the build status to a **Green Checkmark (✅)**.
