"""Abstract base class for the database port.

All database operations go through this contract.
High-level modules depend only on DatabasePort, never on
the concrete SQLite implementation.
"""

from abc import ABC, abstractmethod
from typing import Any


class DatabasePort(ABC):
    """Abstract database interface (port in hexagonal architecture).

    Defines the minimal contract for database access needed by this
    application. Concrete implementations (e.g., SQLiteDatabase)
    fulfil this contract.
    """

    @abstractmethod
    def init_schema(self) -> None:
        """Create all tables if they do not already exist.

        Raises:
            RuntimeError: If the schema cannot be initialised.
        """
        ...

    @abstractmethod
    def execute(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> None:
        """Execute a write statement (INSERT, UPDATE, DELETE).

        Args:
            sql: The SQL statement to execute.
            params: Positional parameters for safe parameterisation.

        Raises:
            RuntimeError: On any database error.
        """
        ...

    @abstractmethod
    def fetchone(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> dict[str, Any] | None:
        """Execute a SELECT and return the first row as a dict.

        Args:
            sql: The SQL SELECT statement.
            params: Positional parameters.

        Returns:
            A dict mapping column names to values, or None if not found.
        """
        ...

    @abstractmethod
    def fetchall(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        """Execute a SELECT and return all rows as a list of dicts.

        Args:
            sql: The SQL SELECT statement.
            params: Positional parameters.

        Returns:
            A list of dicts, one per row.
        """
        ...

    @abstractmethod
    def execute_raw(
        self, sql: str
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Execute a raw SQL string WITHOUT parameterisation.

        WARNING: Only used in the educational Vulnerable Mode demo
        to intentionally simulate SQL injection. Never call this
        with untrusted input in a real application.

        Args:
            sql: Raw SQL string (potentially malicious in demo mode).

        Returns:
            Tuple of (rows, error). rows is a list of dicts; error is
            None on success or the SQLite error string on failure.
        """
        ...

    @abstractmethod
    def reset(self) -> None:
        """Drop all tables and re-initialise the schema.

        Used by the Teacher Dashboard to reset the demo database.
        """
        ...
