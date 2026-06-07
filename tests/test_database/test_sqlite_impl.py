"""Tests for SQLiteDatabase implementation."""

import pytest

from src.database.factory import create_database
from src.database.sqlite_impl import SQLiteDatabase


@pytest.fixture()
def db() -> SQLiteDatabase:
    """Create an in-memory SQLite database for testing.

    Returns:
        Initialised SQLiteDatabase backed by :memory:.
    """
    instance = SQLiteDatabase(":memory:")
    instance.init_schema()
    return instance


class TestSQLiteDatabase:
    """Unit tests for SQLiteDatabase."""

    def test_init_schema_creates_users_table(
        self, db: SQLiteDatabase
    ) -> None:
        """init_schema should create the users table.

        Args:
            db: In-memory database fixture.
        """
        rows = db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        table_names = [r["name"] for r in rows]
        assert "users" in table_names

    def test_init_schema_creates_login_attempts_table(
        self, db: SQLiteDatabase
    ) -> None:
        """init_schema should create login_attempts table.

        Args:
            db: In-memory database fixture.
        """
        rows = db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        assert "login_attempts" in [r["name"] for r in rows]

    def test_execute_inserts_row(self, db: SQLiteDatabase) -> None:
        """execute() should persist a row to the database.

        Args:
            db: In-memory database fixture.
        """
        db.execute(
            """INSERT INTO users
               (username, email, password_hash, role, created_at)
               VALUES (?, ?, ?, 'student', datetime('now'))""",
            ("alice", "alice@test.com", "$2b$12$fake"),
        )
        row = db.fetchone(
            "SELECT username FROM users WHERE username = ?", ("alice",)
        )
        assert row is not None
        assert row["username"] == "alice"

    def test_fetchone_returns_none_when_not_found(
        self, db: SQLiteDatabase
    ) -> None:
        """fetchone() should return None for a missing record.

        Args:
            db: In-memory database fixture.
        """
        result = db.fetchone(
            "SELECT * FROM users WHERE username = ?", ("ghost",)
        )
        assert result is None

    def test_fetchall_returns_all_rows(self, db: SQLiteDatabase) -> None:
        """fetchall() should return all matching rows.

        Args:
            db: In-memory database fixture.
        """
        for name in ("bob", "carol"):
            db.execute(
                """INSERT INTO users
                   (username, email, password_hash, role, created_at)
                   VALUES (?, ?, ?, 'student', datetime('now'))""",
                (name, f"{name}@test.com", "$2b$12$fake"),
            )
        rows = db.fetchall("SELECT username FROM users")
        assert len(rows) == 2  # noqa: PLR2004

    def test_execute_raw_runs_unparameterised_sql(
        self, db: SQLiteDatabase
    ) -> None:
        """execute_raw() should execute a literal SQL string.

        Args:
            db: In-memory database fixture.
        """
        db.execute(
            """INSERT INTO users
               (username, email, password_hash, role, created_at)
               VALUES (?, ?, ?, 'admin', datetime('now'))""",
            ("admin", "admin@test.com", "$2b$12$adminhash"),
        )
        rows, err = db.execute_raw(
            "SELECT * FROM users WHERE username = 'admin'"
        )
        assert err is None
        assert len(rows) == 1
        assert rows[0]["username"] == "admin"

    def test_execute_raw_returns_empty_on_bad_sql(
        self, db: SQLiteDatabase
    ) -> None:
        """execute_raw() should return [] on malformed SQL.

        Args:
            db: In-memory database fixture.
        """
        rows, err = db.execute_raw("THIS IS NOT SQL !!!")
        assert rows == []
        assert err is not None  # error message returned

    def test_reset_drops_and_recreates_tables(
        self, db: SQLiteDatabase
    ) -> None:
        """reset() should clear all data and re-init schema.

        Args:
            db: In-memory database fixture.
        """
        db.execute(
            """INSERT INTO users
               (username, email, password_hash, role, created_at)
               VALUES (?, ?, ?, 'student', datetime('now'))""",
            ("victim", "v@v.com", "$2b$12$fake"),
        )
        db.reset()
        rows = db.fetchall("SELECT * FROM users")
        assert rows == []

    def test_factory_creates_initialised_database(self) -> None:
        """create_database() should return a ready DatabasePort.

        Returns:
            None. Asserts the database port contract.
        """
        from src.database.base import DatabasePort

        db = create_database(":memory:")
        assert isinstance(db, DatabasePort)
