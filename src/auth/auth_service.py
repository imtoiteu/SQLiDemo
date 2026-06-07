"""Concrete implementation of AuthServicePort."""

import re
from datetime import datetime, timezone

from src.auth.base import AuthServicePort
from src.database.base import DatabasePort
from src.hasher.base import PasswordHasherPort
from src.query_builder.base import QueryBuilderPort
from src.schemas.user import LoginResult, UserCreate, UserRecord

# ──────────────────────────────────────────────────────────────
# SQL injection detection patterns (for educational analysis)
# ──────────────────────────────────────────────────────────────
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"'\s*(or|and)\s+[\d'\"]", re.IGNORECASE),
        "Tautology: OR/AND with constant (e.g. ' OR '1'='1)",
    ),
    (
        re.compile(r"--\s*$", re.IGNORECASE),
        "SQL comment operator (--) truncating the query",
    ),
    (
        re.compile(r"#\s*$"),
        "MySQL comment (#) truncating the query",
    ),
    (
        re.compile(r"/\*"),
        "Block comment (/*) injected into query",
    ),
    (
        re.compile(r"\bunion\b.*\bselect\b", re.IGNORECASE),
        "UNION SELECT — attempting data exfiltration",
    ),
    (
        re.compile(r"\bsleep\s*\(", re.IGNORECASE),
        "SLEEP() — time-based blind injection",
    ),
    (
        re.compile(r"\bwaitfor\s+delay\b", re.IGNORECASE),
        "WAITFOR DELAY — MSSQL time-based injection",
    ),
    (
        re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
        "BENCHMARK() — CPU-based blind injection",
    ),
    (
        re.compile(r"'\s*=\s*'", re.IGNORECASE),
        "String equality bypass ('=')",
    ),
    (
        re.compile(r"\bor\s+true\b", re.IGNORECASE),
        "Boolean TRUE literal bypass",
    ),
    (
        re.compile(r"'\s*or\s*'[^']*'\s*=\s*'[^']*", re.IGNORECASE),
        "Classic quote-break tautology",
    ),
    (
        re.compile(r"'or'", re.IGNORECASE),
        "Compact no-space OR bypass",
    ),
    (
        re.compile(r"\bdrop\b|\bdelete\b|\btruncate\b", re.IGNORECASE),
        "Destructive DDL/DML keywords (DROP/DELETE/TRUNCATE)",
    ),
]

# Sample users created by seed_sample_users()
# Passwords below are hashed with bcrypt before storage.
# These exact plaintext values must match what is shown in the
# Demo 2 "Normal Login" Quick Payload chips on the login page.
_SAMPLE_USERS = [
    {
        "username": "teacher",
        "email": "teacher@sqlilab.local",
        "password": "teach2024",
        "role": "teacher",
    },
    {
        "username": "alice",
        "email": "alice@sqlilab.local",
        "password": "alice99",
        "role": "student",
    },
    {
        "username": "bob",
        "email": "bob@sqlilab.local",
        "password": "hunter2",
        "role": "student",
    },
    {
        "username": "charlie",
        "email": "charlie@sqlilab.local",
        "password": "charlie1",
        "role": "student",
    },
]

# Demo 1 legacy accounts — intentionally weak PLAINTEXT passwords.
# These are inserted into the `legacy_users` table and are used
# to demonstrate classic SQL Injection login bypass.
_LEGACY_USERS: list[dict[str, str]] = [
    {
        "username": "admin",
        "password": "admin123",
        "role":     "admin",
        "email":    "admin@legacy.local",
    },
    {
        "username": "alice",
        "password": "password",
        "role":     "student",
        "email":    "alice@legacy.local",
    },
    {
        "username": "bob",
        "password": "123456",
        "role":     "student",
        "email":    "bob@legacy.local",
    },
    {
        "username": "charlie",
        "password": "letmein",
        "role":     "student",
        "email":    "charlie@legacy.local",
    },
]


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _detect_injection(value: str) -> list[str]:
    """Return a list of injection pattern descriptions found in value.

    Args:
        value: User-supplied input string to analyse.

    Returns:
        List of human-readable descriptions of detected patterns.
        Empty list means no injection detected.
    """
    found: list[str] = []
    for pattern, description in _INJECTION_PATTERNS:
        if pattern.search(value):
            found.append(description)
    return found


def _row_to_record(row: dict) -> UserRecord:  # type: ignore[type-arg]
    """Convert a database row dict to a UserRecord.

    Args:
        row: Dict from SQLite with user columns.

    Returns:
        Populated UserRecord instance.
    """
    return UserRecord(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        password_hash=row["password_hash"],
        role=row["role"],
        created_at=row["created_at"],
    )


class AuthService(AuthServicePort):
    """Concrete authentication service.

    Depends on abstractions (DatabasePort, PasswordHasherPort,
    QueryBuilderPort) injected via constructor — satisfying DIP.

    Args:
        db: Database access port.
        hasher: Password hasher port.
        query_builder: SQL query builder port.
    """

    def __init__(
        self,
        db: DatabasePort,
        hasher: PasswordHasherPort,
        query_builder: QueryBuilderPort,
    ) -> None:
        """Initialise with injected dependencies.

        Args:
            db: Database port instance.
            hasher: Password hasher port instance.
            query_builder: Query builder port instance.
        """
        self._db = db
        self._hasher = hasher
        self._qb = query_builder

    def register(self, data: UserCreate) -> UserRecord:
        """Register a new user with a bcrypt-hashed password.

        Args:
            data: Validated UserCreate input.

        Returns:
            The newly created UserRecord.

        Raises:
            ValueError: If username or email already taken.
        """
        # Check uniqueness
        existing = self._db.fetchone(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (data.username, data.email),
        )
        if existing:
            raise ValueError(
                "Username or email already exists."
            )

        password_hash = self._hasher.hash(data.password)
        now = _now_iso()

        self._db.execute(
            """
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'student', ?)
            """,
            (data.username, str(data.email), password_hash, now),
        )

        row = self._db.fetchone(
            "SELECT * FROM users WHERE username = ?",
            (data.username,),
        )
        if row is None:
            raise RuntimeError("Failed to retrieve created user.")
        return _row_to_record(row)

    def login_secure(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate using parameterised queries (safe mode).

        SQL injection is impossible here because user input is bound
        as data, never interpolated into the query string.

        Args:
            username: Raw username input.
            password: Raw password input.

        Returns:
            LoginResult with injection analysis for educational output.
        """
        detected = _detect_injection(username) + _detect_injection(password)
        is_injection = bool(detected)

        # Build the parameterised query for display
        gen_query = self._qb.build_secure(username, password)

        # Step 1: Look up the user by username only (parameterised).
        # Passwords are NEVER compared inside SQL in a bcrypt application.
        row = self._db.fetchone(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        )

        explanation = (
            "Parameterised query used. The SQL only looks up the user by "
            "username — passwords are never compared inside SQL.\n\n"
            "Step 1 (SQL): SELECT * FROM users WHERE username = ?\n"
            "  → username bound as data, injection structurally impossible.\n\n"
            "Step 2 (Python): bcrypt.checkpw(plaintext, stored_hash)\n"
            "  → password verified in application code, not in the database."
        )

        if is_injection:
            explanation += (
                "\n\n🛡️  Injection attempt detected, but the parameterised "
                "query treated it as a literal string. bcrypt.checkpw() "
                "was never reached — the lookup returned no matching row."
            )

        # Step 2: Verify password in application code using bcrypt.
        if row and self._hasher.verify(password, row["password_hash"]):
            self._db.execute(
                """INSERT INTO login_attempts
                   (username, password, mode, is_injection, success)
                   VALUES (?, ?, 'secure', ?, 1)""",
                (username, password, int(is_injection)),
            )
            return LoginResult(
                success=True,
                username=row["username"],
                role=row["role"],
                generated_query=gen_query,
                is_injection=is_injection,
                explanation=explanation,
            )

        self._db.execute(
            """INSERT INTO login_attempts
               (username, password, mode, is_injection, success)
               VALUES (?, ?, 'secure', ?, 0)""",
            (username, password, int(is_injection)),
        )
        return LoginResult(
            success=False,
            generated_query=gen_query,
            is_injection=is_injection,
            explanation=explanation,
        )

    def login_vulnerable(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate using raw string concatenation (insecure).

        ⚠️  EDUCATIONAL DEMO ONLY.

        Real bcrypt applications never compare passwords in SQL.
        The SQL only looks up the user by username. The vulnerability
        is in that username lookup: injecting into username can make
        the WHERE clause always-true, returning all rows.

        Authentication is determined ENTIRELY by the rows returned
        from the raw SQL query:
          • rows returned → session granted as rows[0] (bypass)
          • no rows       → authentication failed

        For a normal login (no injection), bcrypt.checkpw() is run
        after the lookup. Injection bypasses this step entirely.

        Pattern detection is informational only — it does NOT
        influence the outcome.

        Args:
            username: Raw username (may contain SQL injection).
            password: Raw password (checked with bcrypt after SQL
                      lookup — never embedded in the query).

        Returns:
            LoginResult driven by the SQL query result.
        """
        # ── 1. Build the raw concatenated SQL (the vulnerability) ─────
        #    Only the USERNAME is in the SQL. Passwords are NEVER
        #    compared in SQL in a real bcrypt application.
        raw_query = self._qb.build_vulnerable(username, password)

        # ── 2. Execute it against the real database ───────────────────
        rows, sql_error = self._db.execute_raw(raw_query)

        row_count  = len(rows)
        first: dict = rows[0] if rows else {}  # type: ignore[type-arg]

        # All matched rows — exposed for educational display.
        all_matched: list[dict[str, str]] = [
            {
                "id":       str(r.get("id", "")),
                "username": str(r.get("username", "")),
                "role":     str(r.get("role", "")),
            }
            for r in rows
        ]

        # ── 3. Pattern detection — INFORMATIONAL ONLY ─────────────────
        detected = (
            _detect_injection(username) + _detect_injection(password)
        )
        is_injection = bool(detected)
        bypass_method = "; ".join(detected) if detected else ""

        # ── 4. Determine authentication outcome ───────────────────────
        #    bcrypt.checkpw() is ALWAYS called when a row is found.
        #    SQL injection can retrieve the row (data exposure) but
        #    cannot bypass bcrypt verification — the attacker must still
        #    supply the correct password.
        #
        #    Case A: Injection returns rows → bcrypt.checkpw() called.
        #             If password wrong → login DENIED.
        #             If password correct → login SUCCESS.
        #    Case B: Normal username+password login.
        #    Case C: No rows returned → authentication failed.
        authenticated = False
        bcrypt_check_called = False
        bcrypt_check_result: bool | None = None

        if rows:
            bcrypt_check_called = True
            try:
                bcrypt_check_result = self._hasher.verify(
                    password, str(first.get("password_hash", ""))
                )
                authenticated = bcrypt_check_result
            except Exception:
                bcrypt_check_result = False
                authenticated = False

        # ── 5. Build educational explanation ──────────────────────────
        explanation_lines = [
            "Vulnerable Mode: raw string concatenation used for "
            "username lookup.",
            "Passwords are NEVER compared inside SQL. The application "
            "always calls bcrypt.checkpw() in Python after the lookup.",
            f"Generated query:\n  {raw_query}",
            f"STEP 1 — SQL query returned: {row_count} row(s)",
        ]
        if is_injection and row_count > 0:
            explanation_lines.append(
                f"SQL Injection succeeded: the injected payload caused "
                f"the WHERE clause to match {row_count} row(s). "
                f"The attacker retrieved the account of "
                f"'{first.get('username', '?')}' (rows[0])."
            )
        elif is_injection and row_count == 0:
            explanation_lines.append(
                "SQL Injection attempted but returned 0 rows. "
                "The WHERE clause evaluated to false for all rows, "
                "or the targeted username does not exist."
            )
        if row_count > 1:
            explanation_lines.append(
                f"Multiple rows matched ({row_count} users). "
                "Application uses rows[0] — the first row in the "
                "table (no ORDER BY guarantee)."
            )
        if sql_error:
            explanation_lines.append(f"SQL error: {sql_error}")

        explanation_lines.append(
            f"STEP 2 — bcrypt.checkpw() called: {bcrypt_check_called}"
        )
        if bcrypt_check_called:
            explanation_lines.append(
                f"  bcrypt.checkpw('{password[:20]}…' if len > 20 "
                f"else '{password}', stored_hash) "
                f"→ {bcrypt_check_result}"
            )

        explanation_lines.append(
            f"STEP 3 — Authentication: {'GRANTED' if authenticated else 'DENIED'}"
        )
        if is_injection and row_count > 0 and not authenticated:
            explanation_lines.append(
                "☠️  SQL Injection exposed the account row, but "
                "bcrypt.checkpw() returned False — wrong password "
                "supplied. Modern hashing STOPS the bypass. "
                "The attacker must know the real password to log in."
            )
        elif is_injection and row_count > 0 and authenticated:
            explanation_lines.append(
                "⚠️  SQL Injection retrieved the row AND the correct "
                "password was supplied. Login succeeded — but only "
                "because the correct password was known. "
                "This is NOT a classic SQL injection bypass."
            )
        elif authenticated:
            explanation_lines.append(
                "✅  Normal login: username found, "
                "bcrypt.checkpw(plaintext, stored_hash) returned True."
            )
        else:
            explanation_lines.append(
                "❌  Authentication failed: "
                + ("No rows returned by SQL." if not rows
                   else "bcrypt.checkpw() returned False — wrong password.")
                + (" Refine your payload." if is_injection and not rows
                   else "")
            )
        explanation = "\n".join(explanation_lines)

        # ── 6. Log the attempt ────────────────────────────────────────
        self._db.execute(
            """INSERT INTO login_attempts
               (username, password, mode, is_injection, success)
               VALUES (?, ?, 'vulnerable', ?, ?)""",
            (username, password, int(is_injection), int(authenticated)),
        )

        if authenticated:
            return LoginResult(
                success=True,
                username=str(first.get("username", "???")),
                role=str(first.get("role", "unknown")),
                generated_query=raw_query,
                is_injection=is_injection,
                bypass_method=bypass_method,
                explanation=explanation,
                rows_returned=row_count,
                all_matched_users=all_matched,
                bcrypt_check_called=bcrypt_check_called,
                bcrypt_check_result=bcrypt_check_result,
            )

        return LoginResult(
            success=False,
            generated_query=raw_query,
            is_injection=is_injection,
            bypass_method=bypass_method,
            explanation=explanation,
            rows_returned=row_count,
            all_matched_users=all_matched,
            bcrypt_check_called=bcrypt_check_called,
            bcrypt_check_result=bcrypt_check_result,
        )

    def get_all_users(self) -> list[UserRecord]:
        """Return all user records for educational DB dump.

        Returns:
            List of all UserRecord objects in the database.
        """
        rows = self._db.fetchall(
            "SELECT * FROM users ORDER BY id"
        )
        return [_row_to_record(r) for r in rows]

    def seed_admin(
        self,
        username: str,
        email: str,
        password: str,
    ) -> None:
        """Seed the admin user if not already present.

        Args:
            username: Admin username.
            email: Admin email.
            password: Admin plaintext password.
        """
        existing = self._db.fetchone(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        )
        if existing:
            return  # Already seeded

        password_hash = self._hasher.hash(password)
        now = _now_iso()
        self._db.execute(
            """INSERT INTO users (username, email, password_hash, role, created_at)
               VALUES (?, ?, ?, 'admin', ?)""",
            (username, email, password_hash, now),
        )

    def seed_sample_users(self) -> list[UserRecord]:
        """Create demonstration users for classroom use.

        Returns:
            List of newly created (or skipped existing) UserRecord objects.
        """
        created: list[UserRecord] = []
        for sample in _SAMPLE_USERS:
            existing = self._db.fetchone(
                "SELECT id FROM users WHERE username = ?",
                (sample["username"],),
            )
            if existing:
                continue

            password_hash = self._hasher.hash(sample["password"])
            now = _now_iso()
            self._db.execute(
                """INSERT INTO users
                   (username, email, password_hash, role, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    sample["username"],
                    sample["email"],
                    password_hash,
                    sample["role"],
                    now,
                ),
            )
            row = self._db.fetchone(
                "SELECT * FROM users WHERE username = ?",
                (sample["username"],),
            )
            if row:
                created.append(_row_to_record(row))
        return created

    # ──────────────────────────────────────────────────────────────
    # Demo 1 — Legacy Application
    # ──────────────────────────────────────────────────────────────

    def login_legacy(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate against legacy_users using raw SQL concatenation.

        ⚠️  EDUCATIONAL DEMO ONLY.

        Simulates a Legacy Application where:
          • Passwords are stored in PLAINTEXT.
          • Login query is built by raw string concatenation.
          • SQL injection in username OR password field bypasses auth.

        The generated query is:
          SELECT * FROM legacy_users
          WHERE username = '<input>' AND password = '<input>'

        Classic payloads:
          username: admin' --      → truncates AND password check
          username: ' OR 1=1--    → returns all rows
          password: ' OR '1'='1   → makes AND clause always true

        Args:
            username: Raw username (may contain SQL injection).
            password: Raw password (may contain SQL injection).

        Returns:
            LoginResult driven by the SQL query result.
        """
        raw_query = self._qb.build_legacy_vulnerable(username, password)
        rows, sql_error = self._db.execute_raw(raw_query)

        row_count = len(rows)
        first: dict = rows[0] if rows else {}  # type: ignore[type-arg]
        authenticated = bool(rows)

        all_matched: list[dict[str, str]] = [
            {
                "id":       str(r.get("id", "")),
                "username": str(r.get("username", "")),
                "role":     str(r.get("role", "")),
                # PLAINTEXT — educational: shows why plaintext storage is
                # catastrophic; attacker sees password with no cracking
                "password": str(r.get("password", "")),
            }
            for r in rows
        ]

        detected = (
            _detect_injection(username) + _detect_injection(password)
        )
        is_injection = bool(detected)
        bypass_method = "; ".join(detected) if detected else ""

        explanation_lines = [
            "⚠️  LEGACY APPLICATION — Demo 1",
            "Passwords stored in PLAINTEXT. Query built by string "
            "concatenation. Both username and password fields are "
            "vulnerable to SQL injection.",
            f"Generated query:\n  {raw_query}",
            f"Rows returned: {row_count}",
        ]
        if row_count > 1:
            explanation_lines.append(
                f"Multiple rows matched ({row_count}). "
                "Application uses rows[0] — the first user in the table."
            )
        if sql_error:
            explanation_lines.append(f"SQL error: {sql_error}")
        if authenticated and is_injection:
            explanation_lines.append(
                f"☠️  BYPASS: Injection modified the WHERE clause. "
                f"Logged in as: {first.get('username', '?')} (rows[0]). "
                f"Plaintext password '{first.get('password', '?')}' "
                f"is now visible to the attacker — no cracking needed."
            )
        elif authenticated:
            explanation_lines.append(
                "✅  Normal login: username + plaintext password matched."
            )
        else:
            explanation_lines.append(
                "❌  No rows returned — authentication failed."
                + (" Refine your payload." if is_injection else "")
            )

        self._db.execute(
            """INSERT INTO login_attempts
               (username, password, mode, is_injection, success)
               VALUES (?, ?, 'legacy', ?, ?)""",
            (username, password, int(is_injection), int(authenticated)),
        )

        if authenticated:
            return LoginResult(
                success=True,
                username=str(first.get("username", "???")),
                role=str(first.get("role", "unknown")),
                generated_query=raw_query,
                is_injection=is_injection,
                bypass_method=bypass_method,
                explanation="\n".join(explanation_lines),
                rows_returned=row_count,
                all_matched_users=all_matched,
            )
        return LoginResult(
            success=False,
            generated_query=raw_query,
            is_injection=is_injection,
            bypass_method=bypass_method,
            explanation="\n".join(explanation_lines),
            rows_returned=row_count,
            all_matched_users=all_matched,
        )

    def login_legacy_secure(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate against legacy_users using parameterised query.

        EDUCATIONAL DEMO ONLY — safe variant of login_legacy.

        Same database and users as login_legacy, but SQL uses ?
        placeholders so injection payloads are treated as literal data.
        Demonstrates that parameterised queries defeat SQL injection at
        the construction stage, before the DB ever sees the input.

        Args:
            username: Raw username (may contain injection chars).
            password: Raw password (may contain injection chars).

        Returns:
            LoginResult. is_injection reflects detected patterns, but
            success depends only on an exact username+password match.
        """
        detected = (
            _detect_injection(username) + _detect_injection(password)
        )
        is_injection = bool(detected)
        bypass_method = "; ".join(detected) if detected else ""

        display_query = self._qb.build_legacy_secure(username, password)

        # Parameterised execution — the payload is data, never SQL.
        row = self._db.fetchone(
            "SELECT * FROM legacy_users "
            "WHERE username = ? AND password = ?",
            (username, password),
        )
        authenticated = row is not None
        row_count = 1 if authenticated else 0

        all_matched: list[dict[str, str]] = []
        if row:
            all_matched = [{
                "id":       str(row.get("id", "")),
                "username": str(row.get("username", "")),
                "role":     str(row.get("role", "")),
                "password": str(row.get("password", "")),
            }]

        explanation_lines = [
            "SECURE MODE — Demo 1B: parameterised query.",
            "Same database. Same users. Same plaintext passwords.",
            "Only the query construction changed.\n",
            "SQL template sent to DB driver:",
            "  SELECT * FROM legacy_users",
            "  WHERE username = ?",
            "  AND password = ?\n",
            "Bound parameters (passed separately, never interpreted as SQL):",
            f"  params = ({username!r}, {password!r})\n",
            f"Rows returned: {row_count}",
        ]
        if is_injection and not authenticated:
            explanation_lines.append(
                f"BLOCKED: Payload {username!r} searched literally. "
                "No account has that exact username. 0 rows returned. "
                "The WHERE clause was never modified."
            )
        elif authenticated:
            explanation_lines.append(
                "Normal login: exact username + plaintext password "
                "matched a row in legacy_users."
            )
        else:
            explanation_lines.append(
                "No rows returned — no account with that exact "
                "username and password."
            )

        self._db.execute(
            """INSERT INTO login_attempts
               (username, password, mode, is_injection, success)
               VALUES (?, ?, 'legacy', ?, ?)""",
            (username, password, int(is_injection), int(authenticated)),
        )

        if authenticated:
            return LoginResult(
                success=True,
                username=str(row.get("username", "???")),  # type: ignore[union-attr]
                role=str(row.get("role", "unknown")),  # type: ignore[union-attr]
                generated_query=display_query,
                is_injection=is_injection,
                bypass_method=bypass_method,
                explanation="\n".join(explanation_lines),
                rows_returned=row_count,
                all_matched_users=all_matched,
            )
        return LoginResult(
            success=False,
            generated_query=display_query,
            is_injection=is_injection,
            bypass_method=bypass_method,
            explanation="\n".join(explanation_lines),
            rows_returned=row_count,
            all_matched_users=all_matched,
        )

    def seed_legacy_users(self) -> None:
        """Seed the legacy_users table with plaintext demo accounts.

        Idempotent — skips accounts that already exist.
        """
        for user in _LEGACY_USERS:
            existing = self._db.fetchone(
                "SELECT id FROM legacy_users WHERE username = ?",
                (user["username"],),
            )
            if existing:
                continue
            self._db.execute(
                """INSERT INTO legacy_users
                   (username, password, role, email)
                   VALUES (?, ?, ?, ?)""",
                (
                    user["username"],
                    user["password"],  # PLAINTEXT — intentional
                    user["role"],
                    user["email"],
                ),
            )
