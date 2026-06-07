"""Search API routes — Demo 2 Modern Application.

Exposes a vulnerable article search endpoint that demonstrates
SQL injection can exist in any feature, not just login forms.

Even after adopting bcrypt for passwords, a vulnerable search
feature allows UNION-based data exfiltration that exposes
bcrypt hashes — which can then be cracked offline.
"""

import sqlite3
import re
from typing import Literal

from flask import Blueprint, current_app, jsonify, request

from src.database.base import DatabasePort
from src.query_builder.base import QueryBuilderPort

search_bp = Blueprint("search", __name__)

# ──────────────────────────────────────────────────────────────
# Article seed data — injected on app startup
# ──────────────────────────────────────────────────────────────

ARTICLE_SEEDS = [
    {
        "title": "Introduction to Web Security",
        "content": (
            "Web security covers a broad range of practices designed "
            "to protect applications from malicious actors."
        ),
        "category_id": 1,
        "author": "Dr. Smith",
    },
    {
        "title": "Common Vulnerabilities in 2024",
        "content": (
            "OWASP Top 10 continues to highlight injection flaws, "
            "broken authentication, and sensitive data exposure."
        ),
        "category_id": 1,
        "author": "Prof. Johnson",
    },
    {
        "title": "Password Storage Best Practices",
        "content": (
            "Always use bcrypt, Argon2, or scrypt. Never store "
            "plaintext passwords. Salting is automatic with bcrypt."
        ),
        "category_id": 2,
        "author": "Dr. Smith",
    },
    {
        "title": "SQL Injection in Depth",
        "content": (
            "SQL Injection remains one of the most dangerous "
            "vulnerabilities. Parameterised queries are the only "
            "reliable defence."
        ),
        "category_id": 2,
        "author": "Prof. Chen",
    },
    {
        "title": "bcrypt and its Limitations",
        "content": (
            "bcrypt prevents offline cracking at scale but does NOT "
            "prevent SQL Injection from stealing hashes in the first "
            "place. Both defences are necessary."
        ),
        "category_id": 3,
        "author": "Prof. Johnson",
    },
    {
        "title": "Modern Attack Chains",
        "content": (
            "Attackers increasingly target data exfiltration via "
            "SQL Injection rather than authentication bypass. "
            "Stolen hashes can be cracked offline with wordlists."
        ),
        "category_id": 3,
        "author": "Prof. Chen",
    },
]

# ──────────────────────────────────────────────────────────────
# Injection pattern detection (subset for search context)
# ──────────────────────────────────────────────────────────────
_SEARCH_PATTERNS: list[
    tuple[re.Pattern[str], str, Literal["low", "medium", "high", "critical"]]
] = [
    (
        re.compile(r"\bunion\b.*\bselect\b", re.IGNORECASE),
        "UNION SELECT — data exfiltration attempt",
        "critical",
    ),
    (
        re.compile(r"--\s*$", re.IGNORECASE),
        "SQL comment (--) — truncating remainder of query",
        "critical",
    ),
    (
        re.compile(r"#\s*$"),
        "MySQL comment (#) — truncating remainder of query",
        "critical",
    ),
    (
        re.compile(r"/\*"),
        "Block comment (/*) — possible WAF bypass",
        "medium",
    ),
    (
        re.compile(r"\bor\b.*\b1\s*=\s*1\b", re.IGNORECASE),
        "Boolean bypass (OR 1=1)",
        "critical",
    ),
    (
        re.compile(r"\bdrop\b|\bdelete\b|\btruncate\b", re.IGNORECASE),
        "Destructive SQL (DROP/DELETE/TRUNCATE)",
        "critical",
    ),
    (
        re.compile(r"'"),
        "Single quote — breaking out of string context",
        "high",
    ),
    (
        re.compile(r"\bsleep\s*\(", re.IGNORECASE),
        "SLEEP() — time-based blind injection",
        "high",
    ),
]

_RISK_ORDER: dict[str, int] = {
    "safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4
}


def _detect_search(
    value: str,
) -> tuple[
    list[str],
    list[Literal["low", "medium", "high", "critical"]],
]:
    """Return (descriptions, risks) of injection patterns in value.

    Args:
        value: Raw user-supplied search string.

    Returns:
        Tuple of (pattern descriptions list, risk levels list).
    """
    descs: list[str] = []
    risks: list[Literal["low", "medium", "high", "critical"]] = []
    for pattern, desc, risk in _SEARCH_PATTERNS:
        if pattern.search(value):
            descs.append(desc)
            risks.append(risk)
    return descs, risks


def _get_db() -> DatabasePort:
    """Return the database port from the app config.

    Returns:
        The injected DatabasePort instance.
    """
    return current_app.config["DB"]  # type: ignore[return-value]


def _get_qb() -> QueryBuilderPort:
    """Return the query builder port from the app config.

    Returns:
        The injected QueryBuilderPort instance.
    """
    return current_app.config["QB"]  # type: ignore[return-value]


def seed_articles(db: DatabasePort) -> None:
    """Seed the articles table if it is empty.

    Idempotent — skips if any article already exists.

    Args:
        db: Database port instance.
    """
    existing = db.fetchone("SELECT id FROM articles LIMIT 1")
    if existing:
        return
    for art in ARTICLE_SEEDS:
        db.execute(
            """INSERT INTO articles (title, content, category_id, author)
               VALUES (?, ?, ?, ?)""",
            (art["title"], art["content"], art["category_id"], art["author"]),
        )


# ──────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────

@search_bp.route("/vulnerable", methods=["GET"])
def search_vulnerable() -> object:
    """Execute a raw SQL article search (vulnerable).

    ⚠️  EDUCATIONAL DEMO ONLY — intentionally insecure.

    The category_id parameter is embedded directly into the SQL
    string. A UNION payload such as:
      0 UNION SELECT username,password_hash,role FROM users--
    will expose bcrypt hashes from the users table.

    Query params:
        q: Raw search value (category_id or UNION payload).

    Returns:
        200 with SearchResult-shaped JSON.
    """
    raw = request.args.get("q", "1").strip()
    db = _get_db()
    qb = _get_qb()

    generated = qb.build_search_vulnerable(raw)
    descs, risks = _detect_search(raw)
    is_injection = bool(descs)

    # Execute raw query — intentionally unsafe.
    rows, sql_error = db.execute_raw(generated)

    # Determine columns from first row keys (may differ with UNION).
    columns: list[str] = list(rows[0].keys()) if rows else []
    str_rows = [
        {k: str(v) for k, v in row.items()} for row in rows
    ]

    max_risk: Literal["safe", "low", "medium", "high", "critical"] = (
        max(risks, key=lambda r: _RISK_ORDER.get(r, 0))
        if risks
        else "safe"
    )

    if is_injection:
        explanation = (
            "⚠️  SQL injection detected in search input.\n\n"
            "The category_id value was embedded directly into the SQL "
            "query without sanitisation. An attacker can append a UNION "
            "SELECT to retrieve data from any table — including the "
            "users table containing bcrypt hashes.\n\n"
            "This is how modern attackers steal password hashes even "
            "when bcrypt is used: SQL injection bypasses the application "
            "layer entirely and reads straight from the database.\n\n"
            "Defence: use parameterised queries for ALL SQL, not just "
            "login forms."
        )
    else:
        explanation = (
            "✅  Normal search executed.\n\n"
            "The query returned article rows for the requested category. "
            "Try injecting into this field with a UNION SELECT payload to "
            "demonstrate data exfiltration:\n\n"
            "  0 UNION SELECT username,password_hash,role FROM users--"
        )

    return jsonify({
        "rows":               str_rows,
        "generated_query":    generated,
        "is_injection":       is_injection,
        "detected_patterns":  descs,
        "explanation":        explanation,
        "row_count":          len(rows),
        "columns":            columns,
        "risk_level":         max_risk,
        "sql_error":          sql_error,
    })


@search_bp.route("/secure", methods=["GET"])
def search_secure() -> object:
    """Execute a parameterised article search (secure).

    Query params:
        q: Category ID to search (coerced to int, 1 on error).

    Returns:
        200 with SearchResult-shaped JSON.
    """
    raw = request.args.get("q", "1").strip()
    qb = _get_qb()
    db = _get_db()

    generated = qb.build_search_secure(raw)

    # Safe execution: coerce to int, reject non-numeric input.
    try:
        cat_id = int(raw)
    except (ValueError, TypeError):
        cat_id = 0  # returns empty result set safely

    rows = db.fetchall(
        "SELECT id, title, content FROM articles WHERE category_id = ?",
        (cat_id,),
    )
    columns = ["id", "title", "content"]
    str_rows = [{k: str(v) for k, v in r.items()} for r in rows]

    descs, _ = _detect_search(raw)
    is_injection = bool(descs)

    if is_injection:
        explanation = (
            "🛡️  Injection attempt detected, but the parameterised query "
            "treated your input as a literal value.\n\n"
            "The SQL driver converts category_id = ? with your input "
            "bound as data — it can never be interpreted as SQL code. "
            "UNION SELECT payloads are completely neutralised."
        )
    else:
        explanation = (
            "✅  Secure parameterised query executed.\n\n"
            "User input is bound as a typed parameter, not interpolated "
            "into the SQL string. UNION injection is structurally "
            "impossible in this code path."
        )

    return jsonify({
        "rows":              str_rows,
        "generated_query":   generated,
        "is_injection":      is_injection,
        "detected_patterns": descs,
        "explanation":       explanation,
        "row_count":         len(rows),
        "columns":           columns,
        "risk_level":        "safe",
        "sql_error":         None,
    })
