"""Concrete SQLite implementation of DatabasePort."""

import sqlite3
import threading
from typing import Any

from src.database.base import DatabasePort

# ──────────────────────────────────────────────────────────────
# DDL — Table definitions
# ──────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'student'
                          CHECK(role IN ('admin','teacher','student')),
    created_at    TEXT    NOT NULL
                          DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL,
    password     TEXT    NOT NULL,
    mode         TEXT    NOT NULL
                         CHECK(mode IN ('vulnerable','secure','legacy')),
    is_injection INTEGER NOT NULL DEFAULT 0,
    success      INTEGER NOT NULL DEFAULT 0,
    timestamp    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Demo 1: Legacy Application ────────────────────────────────
-- Stores passwords in PLAINTEXT intentionally to demonstrate
-- why plaintext storage + SQL injection = complete compromise.
-- NEVER use this pattern in production.
CREATE TABLE IF NOT EXISTS legacy_users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL UNIQUE,
    password TEXT    NOT NULL,
    role     TEXT    NOT NULL DEFAULT 'student'
                     CHECK(role IN ('admin','teacher','student')),
    email    TEXT    NOT NULL DEFAULT ''
);

-- ── Demo 2: Modern Application search target ──────────────────
-- Articles table used by the vulnerable search feature so that
-- students can demonstrate UNION-based data exfiltration without
-- needing to touch the authentication flow.
CREATE TABLE IF NOT EXISTS articles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    content     TEXT    NOT NULL,
    category_id INTEGER NOT NULL,
    author      TEXT    NOT NULL
);
"""

_DROP_SQL = """
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS app_settings;
DROP TABLE IF EXISTS articles;
DROP TABLE IF EXISTS legacy_users;
DROP TABLE IF EXISTS users;
"""

# How long (seconds) to wait for a SQLite lock before raising.
# Python's sqlite3 module uses this as the `timeout` argument
# to sqlite3.connect().  The value is intentionally generous
# so that brief contention (e.g. two simultaneous login POSTs)
# does not produce an immediate "database is locked" error.
_CONNECT_TIMEOUT: int = 10


class SQLiteDatabase(DatabasePort):
    """SQLite-backed database implementation.

    Connection strategy
    -------------------
    For file-backed databases each OS thread keeps exactly ONE
    open sqlite3.Connection stored in thread-local storage.  The
    connection is created lazily on first use within a thread and
    reused for the lifetime of that thread.

    This eliminates the primary cause of "database is locked"
    errors: previously _get_conn() opened a brand-new connection
    on every call, leaving multiple connections simultaneously
    open inside a single request and competing for the write lock.

    WAL mode is enabled once when the connection is first opened
    (it persists at the file level, so subsequent connections see
    it automatically).

    For :memory: databases (used in tests) a single shared
    connection is used unchanged, because in-memory databases are
    not visible across connections.

    Args:
        db_path: File path for the SQLite database, or ':memory:'
            for an in-process ephemeral database used in tests.
    """

    def __init__(self, db_path: str) -> None:
        """Initialise the SQLite database.

        Args:
            db_path: Path to the SQLite file or ':memory:'.
        """
        self._path = db_path
        # Thread-local storage: one connection slot per OS thread.
        self._local: threading.local = threading.local()

        # For :memory: databases the same single connection must be
        # reused everywhere (a second sqlite3.connect(':memory:')
        # would create an independent, empty database).
        if db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = (
                sqlite3.connect(":memory:", check_same_thread=False)
            )
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys=ON;")
        else:
            self._mem_conn = None

    # ── Internal helpers ──────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Return the thread-local connection, creating it if needed.

        For file databases: one connection is created per thread and
        reused for all subsequent calls on that thread.  This avoids
        multiple open connections competing for the SQLite write lock.

        Returns:
            An sqlite3.Connection with row_factory=sqlite3.Row.
        """
        # :memory: path — single shared connection.
        if self._mem_conn is not None:
            return self._mem_conn

        # File path — reuse the per-thread connection if it exists.
        conn: sqlite3.Connection | None = getattr(
            self._local, "conn", None
        )
        if conn is not None:
            return conn

        # First use on this thread: open a new connection.
        conn = sqlite3.connect(
            self._path,
            timeout=_CONNECT_TIMEOUT,   # wait up to 10 s for locks
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row

        # WAL mode allows concurrent readers without blocking writers
        # and is the standard recommendation for Flask + SQLite.
        # busy_timeout is set in milliseconds at the SQLite level as a
        # second line of defence alongside the Python-level timeout.
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        conn.execute("PRAGMA foreign_keys=ON;")

        self._local.conn = conn
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        """Convert a sqlite3.Row to a plain Python dict.

        Args:
            row: A sqlite3.Row result object.

        Returns:
            Dict mapping column name to value.
        """
        return dict(row)

    # ── Public interface ──────────────────────────────────────

    def init_schema(self) -> None:
        """Create all tables if they do not already exist.

        Raises:
            RuntimeError: On schema initialisation failure.
        """
        try:
            conn = self._get_conn()
            conn.executescript(_SCHEMA_SQL)
            conn.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(
                f"Failed to initialise schema: {exc}"
            ) from exc

    def execute(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> None:
        """Execute a parameterised write statement.

        Commits on success.  Rolls back and re-raises on any
        sqlite3.Error so the connection is not left with an open
        transaction.

        Args:
            sql: SQL with ? placeholders.
            params: Values to bind to placeholders.

        Raises:
            RuntimeError: On database write error.
        """
        conn = self._get_conn()
        try:
            conn.execute(sql, params)
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise RuntimeError(
                f"Database write failed: {exc}"
            ) from exc

    def fetchone(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> dict[str, Any] | None:
        """Execute a SELECT and return the first row.

        Args:
            sql: Parameterised SELECT statement.
            params: Bound values.

        Returns:
            Dict of the first row, or None if no rows found.
        """
        conn = self._get_conn()
        row = conn.execute(sql, params).fetchone()
        return self._row_to_dict(row) if row else None

    def fetchall(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        """Execute a SELECT and return all rows.

        Args:
            sql: Parameterised SELECT statement.
            params: Bound values.

        Returns:
            List of row dicts (may be empty).
        """
        conn = self._get_conn()
        rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def execute_raw(
        self, sql: str
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Execute a raw, un-parameterised SQL string.

        EDUCATIONAL USE ONLY — simulates SQL injection.
        Never use this pattern in production code.

        The result of the raw query is fetched immediately so no
        implicit read-transaction is left open after this call
        returns.

        Args:
            sql: Raw SQL string (may contain injected input).

        Returns:
            Tuple of (rows, error_message). rows is empty on error.
            error_message is None on success, or the SQLite error
            string — used by login_vulnerable to detect parse
            failures caused by ambiguous tautology payloads.
        """
        conn = self._get_conn()
        try:
            cursor = conn.execute(sql)
            rows = cursor.fetchall()
            # Commit so that SQLite does not hold any implicit
            # transaction open after the results are fetched.
            conn.commit()
            return [self._row_to_dict(r) for r in rows], None
        except sqlite3.Error as exc:
            conn.rollback()
            return [], str(exc)

    def reset(self) -> None:
        """Drop all tables and re-initialise the schema.

        Used by teacher dashboard to reset demo state.
        """
        conn = self._get_conn()
        conn.executescript(_DROP_SQL)
        conn.commit()
        self.init_schema()
