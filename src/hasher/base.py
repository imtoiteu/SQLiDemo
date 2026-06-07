"""Abstract base class for the password hasher port."""

from abc import ABC, abstractmethod


class PasswordHasherPort(ABC):
    """Contract for password hashing and verification.

    Implementations must be one-way: given a hash, it must be
    computationally infeasible to recover the original password.
    """

    @abstractmethod
    def hash(self, plaintext: str) -> str:
        """Hash a plaintext password.

        Args:
            plaintext: The raw password supplied by the user.

        Returns:
            A secure, salted hash string safe to store in a database.
        """
        ...

    @abstractmethod
    def verify(self, plaintext: str, hashed: str) -> bool:
        """Verify a plaintext password against a stored hash.

        Args:
            plaintext: The raw password to verify.
            hashed: The stored hash to compare against.

        Returns:
            True if the password matches the hash, False otherwise.
        """
        ...
