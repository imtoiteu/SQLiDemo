"""Concrete SQL query builder implementation."""

import re
from typing import Literal

from src.query_builder.base import QueryBuilderPort
from src.schemas.user import InspectResult

# ──────────────────────────────────────────────────────────────
# Injection pattern catalogue (pattern, description, risk)
# ──────────────────────────────────────────────────────────────
_PATTERNS: list[
    tuple[re.Pattern[str], str, Literal["low", "medium", "high", "critical"]]
] = [
    (
        re.compile(r"'\s*--", re.IGNORECASE),
        "SQL comment (--) — truncates query, ignores password check",
        "critical",
    ),
    (
        re.compile(r"'\s*#", re.IGNORECASE),
        "MySQL comment (#) — truncates query",
        "critical",
    ),
    (
        re.compile(r"\bunion\b.*\bselect\b", re.IGNORECASE),
        "UNION SELECT — data exfiltration attempt",
        "critical",
    ),
    (
        re.compile(r"'\s*(or|and)\s+[\"'\d]", re.IGNORECASE),
        "Tautology (OR/AND constant) — authentication bypass",
        "critical",
    ),
    (
        re.compile(r"\bsleep\s*\(", re.IGNORECASE),
        "SLEEP() — time-based blind injection",
        "high",
    ),
    (
        re.compile(r"\bwaitfor\s+delay\b", re.IGNORECASE),
        "WAITFOR DELAY — MSSQL time-based injection",
        "high",
    ),
    (
        re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
        "BENCHMARK() — CPU exhaustion / blind injection",
        "high",
    ),
    (
        re.compile(r"/\*.*\*/", re.IGNORECASE | re.DOTALL),
        "Block comment (/*...*/) — WAF evasion",
        "medium",
    ),
    (
        re.compile(r"\bor\s+true\b|\bor\s+1\s*=\s*1\b", re.IGNORECASE),
        "Boolean bypass (OR true / OR 1=1)",
        "critical",
    ),
    (
        re.compile(r"\bdrop\b|\bdelete\b|\btruncate\b", re.IGNORECASE),
        "Destructive SQL (DROP/DELETE/TRUNCATE)",
        "critical",
    ),
    (
        re.compile(r"0x[0-9a-f]+", re.IGNORECASE),
        "Hex-encoded payload — obfuscation attempt",
        "medium",
    ),
    (
        re.compile(r"'or'", re.IGNORECASE),
        "Compact no-space bypass ('or')",
        "high",
    ),
]

_RISK_ORDER: dict[str, int] = {
    "safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4
}


def _max_risk(
    risks: list[Literal["low", "medium", "high", "critical"]],
) -> Literal["safe", "low", "medium", "high", "critical"]:
    """Return the highest risk level from a list.

    Args:
        risks: List of risk level strings.

    Returns:
        The highest severity level, or 'safe' if the list is empty.
    """
    if not risks:
        return "safe"
    return max(risks, key=lambda r: _RISK_ORDER.get(r, 0))


class SqlQueryBuilder(QueryBuilderPort):
    """Builds SQL query strings for educational inspection.

    Produces both the vulnerable string-concatenated form and the
    safe parameterised template, plus a full InspectResult report.
    """

    def build_vulnerable(self, username: str, password: str) -> str:
        """Build the vulnerable query with username concatenated raw.

        Real bcrypt applications NEVER compare passwords in SQL.
        The SQL only performs a username lookup. The vulnerability is
        in that lookup — injecting into ``username`` can make the
        WHERE clause always true and return all rows.

        The application then takes ``rows[0]`` for the session, which
        is exactly how a real vulnerable application behaves.

        Args:
            username: Raw username input (may contain SQL injection).
            password: Plaintext password — used by bcrypt.checkpw()
                after the SQL step, never embedded in the query.

        Returns:
            Complete SQL string with username embedded literally.
        """
        return (
            f"SELECT * FROM users "
            f"WHERE username = '{username}'"
        )

    def build_secure(self, username: str, password: str) -> str:
        """Build the parameterised query + bcrypt step display string.

        Real bcrypt authentication is a two-step process:
          1. Retrieve the stored hash by username (parameterised).
          2. Verify the plaintext password against the hash with
             bcrypt.checkpw() — never in SQL.

        Args:
            username: Username (shown as bound value).
            password: Password (shown masked, used only by checkpw).

        Returns:
            Display string showing both steps.
        """
        masked = "*" * min(len(password), 8)
        return (
            f"-- Step 1: Lookup user by username only (no password in SQL)\n"
            f"SELECT * FROM users WHERE username = ?\n\n"
            f"-- Bound parameters:\n"
            f"params = ('{username}',)\n\n"
            f"-- Step 2: Verify password in application code\n"
            f"bcrypt.checkpw(\n"
            f"    password='{masked}',  # plaintext from login form\n"
            f"    hashed_password=row['password_hash'],  # from DB\n"
            f")"
        )

    def inspect(self, username: str, password: str) -> InspectResult:
        """Perform full injection analysis on both input fields.

        Args:
            username: Raw username input.
            password: Raw password input.

        Returns:
            InspectResult with detected patterns and explanations.
        """
        combined = f"{username} {password}"
        found_descs: list[str] = []
        found_risks: list[Literal["low", "medium", "high", "critical"]] = []

        for pattern, description, risk in _PATTERNS:
            if pattern.search(combined):
                found_descs.append(description)
                found_risks.append(risk)

        is_injection = bool(found_descs)
        risk_level = _max_risk(found_risks)

        if is_injection:
            explanation = (
                "⚠️  SQL injection detected in username field.\n\n"
                "Real bcrypt applications never compare passwords inside "
                "SQL. The query only looks up a user by username — the "
                "vulnerability is entirely in that username lookup.\n\n"
                "When the attacker injects into the username field, the "
                "WHERE clause becomes always-true (e.g. OR 1=1) and the "
                "database returns every row. The application then takes "
                "rows[0] and creates a session — bypassing both the "
                "username check AND the bcrypt.checkpw() step entirely.\n\n"
                "In a secure application using parameterised queries, "
                "the injected text is treated as a literal string — no "
                "rows are returned and bcrypt.checkpw() is never reached."
            )
        else:
            explanation = (
                "✅  No SQL injection patterns detected.\n\n"
                "The input appears safe. In this bcrypt-based application "
                "the SQL query only looks up the user by username — "
                "passwords are never compared in SQL. A correct password "
                "is verified afterwards using bcrypt.checkpw(). Always "
                "use parameterised queries; input sanitisation alone is "
                "not sufficient defence."
            )

        return InspectResult(
            raw_username=username,
            raw_password=password,
            vulnerable_query=self.build_vulnerable(username, password),
            secure_query=self.build_secure(username, password),
            is_injection=is_injection,
            detected_patterns=found_descs,
            explanation=explanation,
            risk_level=risk_level,
        )

    # ── Demo 1: Legacy Application ────────────────────────────────

    def build_legacy_vulnerable(
        self, username: str, password: str
    ) -> str:
        """Build the Demo-1 legacy login query.

        Simulates a legacy application where passwords are stored in
        plaintext and the login query is built by string concatenation.
        Both fields are injectable — classic bypass payloads work here.

        Args:
            username: Raw username (may contain SQL injection).
            password: Raw password (may contain SQL injection).

        Returns:
            Complete SQL string with both fields embedded literally.
        """
        return (
            f"SELECT * FROM legacy_users "
            f"WHERE username = '{username}' "
            f"AND password = '{password}'"
        )

    def build_legacy_secure(
        self, username: str, password: str
    ) -> str:
        """Build the Demo-1 legacy query in parameterised form.

        Returns a display string showing the safe template with ?
        placeholders and the bound values passed separately.

        Args:
            username: Raw username (shown as bound value, not embedded).
            password: Raw password (shown as bound value, not embedded).

        Returns:
            Display string showing template + bound params.
        """
        u_safe = username[:60] if len(username) <= 60 else username[:57] + "..."
        p_safe = password[:60] if len(password) <= 60 else password[:57] + "..."
        return (
            "-- Parameterised query (? = safe placeholder):\n"
            "SELECT * FROM legacy_users\n"
            "WHERE username = ?\n"
            "AND password = ?\n\n"
            "-- Bound parameters (never interpreted as SQL):\n"
            f"params = ({u_safe!r}, {p_safe!r})"
        )

    # ── Demo 2: Modern Application — Vulnerable Search ────────────

    def build_search_vulnerable(self, query: str) -> str:
        """Build the vulnerable article search query.

        Simulates an article search feature in a modern application
        that is still vulnerable to SQL injection even though the
        login flow uses bcrypt. Demonstrates that SQL injection can
        be present in any feature, not just login forms.

        A UNION payload such as:
          0 UNION SELECT username,password_hash,role FROM users--
        will expose bcrypt hashes from the users table.

        Args:
            query: Raw user-supplied category_id value.

        Returns:
            SQL string with query value embedded literally.
        """
        return (
            f"SELECT id, title, content "
            f"FROM articles "
            f"WHERE category_id = {query}"
        )

    def build_search_secure(self, query: str) -> str:
        """Build the parameterised article search display string.

        Args:
            query: User-supplied value (for display — shown as bound).

        Returns:
            Display string showing parameterised template + binding.
        """
        safe_preview = query[:40] if len(query) <= 40 else query[:37] + "..."
        return (
            f"-- Parameterised query (? = safe placeholder):\n"
            f"SELECT id, title, content\n"
            f"FROM articles\n"
            f"WHERE category_id = ?\n\n"
            f"-- Bound parameters:\n"
            f"params = ({safe_preview!r},)"
        )
