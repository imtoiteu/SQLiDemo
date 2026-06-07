"""Pydantic schemas for the vulnerable search feature (Demo 2).

The search module exposes an article lookup that is intentionally
vulnerable to UNION-based SQL injection, demonstrating that SQL
injection remains dangerous even after bcrypt adoption.
"""

from typing import Literal

from pydantic import BaseModel


class SearchResult(BaseModel):
    """Result of a search query execution.

    Attributes:
        rows: List of row dicts from the query.
        generated_query: The SQL string that was executed.
        is_injection: Whether injection patterns were detected.
        detected_patterns: Human-readable list of detected patterns.
        explanation: Educational explanation of what occurred.
        row_count: Number of rows returned.
        columns: Column names present in the result rows.
        sql_error: SQLite error string if the query failed, else None.
    """

    rows: list[dict[str, str]] = []
    generated_query: str = ""
    is_injection: bool = False
    detected_patterns: list[str] = []
    explanation: str = ""
    row_count: int = 0
    columns: list[str] = []
    sql_error: str | None = None


class SearchInspectResult(BaseModel):
    """Full inspection of a search input value.

    Attributes:
        raw_query: The raw user-supplied search value.
        vulnerable_query: String-concatenated SQL (insecure).
        secure_query: Parameterised SQL template (safe).
        is_injection: Whether injection patterns were detected.
        detected_patterns: List of detected pattern descriptions.
        explanation: Educational explanation.
        risk_level: Severity of the detected patterns.
    """

    raw_query: str
    vulnerable_query: str
    secure_query: str
    is_injection: bool
    detected_patterns: list[str]
    explanation: str
    risk_level: Literal["safe", "low", "medium", "high", "critical"]
