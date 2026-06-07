"""Auth service factory."""

from src.auth.auth_service import AuthService
from src.auth.base import AuthServicePort
from src.database.base import DatabasePort
from src.hasher.base import PasswordHasherPort
from src.query_builder.base import QueryBuilderPort


def create_auth_service(
    db: DatabasePort,
    hasher: PasswordHasherPort,
    query_builder: QueryBuilderPort,
) -> AuthServicePort:
    """Create and return an AuthServicePort instance.

    Args:
        db: Injected database port.
        hasher: Injected password hasher port.
        query_builder: Injected query builder port.

    Returns:
        A fully wired AuthServicePort implementation.
    """
    return AuthService(db=db, hasher=hasher, query_builder=query_builder)
