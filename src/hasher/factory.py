"""Factory for PasswordHasherPort instances."""

from src.hasher.base import PasswordHasherPort
from src.hasher.bcrypt_impl import BcryptHasher


def create_hasher(rounds: int = 12) -> PasswordHasherPort:
    """Create and return a PasswordHasherPort implementation.

    Args:
        rounds: bcrypt cost factor (default 12).

    Returns:
        A PasswordHasherPort-compatible hasher instance.
    """
    return BcryptHasher(rounds=rounds)
