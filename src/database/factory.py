"""Factory for DatabasePort instances.

High-level modules call create_database() — they never
instantiate SQLiteDatabase directly, satisfying DIP.
"""

from src.database.base import DatabasePort
from src.database.sqlite_impl import SQLiteDatabase


def create_database(db_path: str) -> DatabasePort:
    """Create and return a DatabasePort instance.

    Args:
        db_path: Path to the SQLite file (or ':memory:' for tests).

    Returns:
        A fully initialised DatabasePort implementation.
    """
    db = SQLiteDatabase(db_path)
    db.init_schema()
    return db
