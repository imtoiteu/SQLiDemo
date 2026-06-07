"""bcrypt-backed password hasher implementation."""

import bcrypt

from src.hasher.base import PasswordHasherPort

_ROUNDS = 12  # bcrypt work factor — higher = slower = safer


class BcryptHasher(PasswordHasherPort):
    """Password hasher using the bcrypt algorithm.

    bcrypt is intentionally slow (controlled by the work factor /
    cost parameter), making brute-force attacks impractical.
    Each hash includes a unique random salt, so identical passwords
    produce different hashes — rainbow table attacks are defeated.

    Args:
        rounds: The bcrypt cost factor (default 12). Each increment
            doubles the computation time. Minimum 10 for production.
    """

    def __init__(self, rounds: int = _ROUNDS) -> None:
        """Initialise the hasher with a given cost factor.

        Args:
            rounds: bcrypt cost factor (10–14 recommended).
        """
        self._rounds = rounds

    def hash(self, plaintext: str) -> str:
        """Hash a plaintext password with bcrypt.

        A unique salt is generated automatically by bcrypt.gensalt().
        The salt is embedded in the returned hash string, so it does
        not need to be stored separately.

        Args:
            plaintext: Raw password string.

        Returns:
            A bcrypt hash string, e.g.:
            '$2b$12$SALT_AND_HASH_HERE'
        """
        salt = bcrypt.gensalt(rounds=self._rounds)
        hashed: bytes = bcrypt.hashpw(plaintext.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    def verify(self, plaintext: str, hashed: str) -> bool:
        """Verify a plaintext password against a bcrypt hash.

        Uses a constant-time comparison to prevent timing attacks.

        Args:
            plaintext: Raw password to check.
            hashed: bcrypt hash string retrieved from the database.

        Returns:
            True if the password matches, False otherwise.
        """
        try:
            return bcrypt.checkpw(
                plaintext.encode("utf-8"),
                hashed.encode("utf-8"),
            )
        except (ValueError, TypeError):
            # Invalid hash format — treat as failed verification
            return False
