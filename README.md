# SQLi Lab — Interactive SQL Injection Educational Platform

An interactive, premium educational web application designed to demonstrate SQL Injection (SQLi) vulnerabilities, password cracking risks, and secure coding practices. The lab includes dual-mode authentication, query inspection, live hash visualization, and interactive flow diagrams.

---

## 🚀 Key Features

* **Dual-Mode Login (Demo 1 & Demo 2)**:
  * **Demo 1 (Legacy Login)**: Simulates vulnerable code using raw string concatenation versus secure code using parameterized queries.
  * **Demo 2 (Modern Login)**: Demonstrates that even if an attacker bypasses the SQL lookup via injection, the authentication fails because passwords are not stored in plaintext—they are verified via `bcrypt.checkpw()`.
* **Interactive SQL Query Inspector**: Live syntax highlighting, risk analysis (SAFE/LOW/MEDIUM/HIGH/CRITICAL), and real-time security score updates.
* **SQL Search UNION Demo**: Real-time visualization of UNION-based injection payloads with responsive, pre-wrapped query output blocks.
* **Live Hash Visualizer**: Shows plaintext passwords vs. secure bcrypt hashes in real-time using a cost factor of 12.
* **Attack Flow Visualizer**: Side-by-side animated step comparison showing how an injection request breaks the logic in Vulnerable Mode versus how it is safely handled in Secure Mode.
* **Security Code Comparison**: Displays side-by-side, syntax-highlighted code comparisons (PHP and Python) showing vulnerable vs. secure parameterized implementations.
* **Teacher/Instructor Dashboard**: Includes global mode toggling, classroom database reset/seeding options, user history tracking, and step-by-step guided injection walkthroughs.

---

## 🛠️ Project Structure

```text
SQLInjectionAndPasswordCracking/
├── .venv/                     # Python virtual environment (managed by uv)
├── src/                       # Application source code
│   ├── config.py              # Configuration schemas (pydantic-settings)
│   ├── schemas/               # Shared Pydantic data schemas
│   ├── api/                   # API routes, blueprints, and Flask setup
│   ├── auth/                  # Authentication & database seeding logic
│   └── query_builder/         # Dynamic SQL query generation contracts & implementations
├── static/                    # Frontend files (HTML pages, CSS, JS)
│   └── pages/                 # Lab pages (login, register, search, inspector, etc.)
├── tests/                     # Unit & integration tests mirroring src/
├── .env.example               # Environment variables template
├── pyproject.toml             # uv dependencies & linter config
└── uv.lock                    # Dependency lockfile
```

---

## ⚙️ Prerequisites

* **Python**: `3.12` or newer
* **uv**: A fast Python package installer and resolver. Install it with:
  * **macOS/Linux**: `curl -LsSf https://astral.sh/uv/install.sh | sh`
  * **Windows**: `powershell -c "irm https://astral.sh/uv/install.exe | iex"`

---

## 📦 Installation & Setup

1. **Clone the Repository & Submodules**:
   Ensure you pull down submodules alongside the main repository:
   ```bash
   git clone --recursive https://github.com/imtoiteu/SQLiDemo.git
   cd SQLiDemo
   ```

2. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and fill in local details:
   ```bash
   cp .env.example .env
   ```

3. **Sync Dependencies**:
   Create the virtual environment and install all packages:
   ```bash
   uv sync
   ```

---

## 🏃 Running the Application

The web server runs on port `5001` by default. Use the following commands depending on your operating system:

### 🍎 macOS
To kill any running processes on port `5001`, wait a second, navigate to the directory, and start the app:
```bash
lsof -ti:5001 | xargs kill -9 2>/dev/null; sleep 1 && cd /Users/imtoiteu/Desktop/SQLInjectionAndPasswordCracking && uv run python run.py
```

### 🪟 Windows

#### Using PowerShell:
To kill any existing process running on port `5001`, wait a second, navigate to the directory, and start the app:
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 5001 -ErrorAction SilentlyContinue).OwningProcess | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
cd C:\path\to\SQLInjectionAndPasswordCracking
uv run python run.py
```

#### Using Command Prompt (cmd.exe):
```cmd
for /f "tokens=5" %a in ('netstat -aon ^| findstr 5001') do taskkill /f /pid %a
timeout /t 1 >nul
cd C:\path\to\SQLInjectionAndPasswordCracking
uv run python run.py
```

Once running, navigate to `http://localhost:5001` in your browser.

---

## 🧪 Testing & Linting

You can run automated tests and quality checks in your terminal:

```bash
# Run pytest unit tests
uv run pytest

# Run Ruff linter checks
uv run ruff check .

# Run Mypy static type verification
uv run mypy src/
```
