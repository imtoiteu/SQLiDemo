"""Tests for BcryptHasher implementation."""

import pytest

from src.hasher.bcrypt_impl import BcryptHasher
from src.hasher.factory import create_hasher


class TestBcryptHasher:
    """Unit tests for BcryptHasher."""

    @pytest.fixture()
    def hasher(self) -> BcryptHasher:
        """Create a hasher with low rounds for test speed.

        Returns:
            BcryptHasher with cost factor 4 (minimum valid).
        """
        return BcryptHasher(rounds=4)

    def test_hash_returns_bcrypt_prefix(
        self, hasher: BcryptHasher
    ) -> None:
        """Hash should start with '$2b$' (bcrypt identifier).

        Args:
            hasher: BcryptHasher fixture.
        """
        result = hasher.hash("testpassword")
        assert result.startswith("$2b$")

    def test_hash_embeds_work_factor(
        self, hasher: BcryptHasher
    ) -> None:
        """Hash should embed the configured work factor.

        Args:
            hasher: BcryptHasher fixture.
        """
        result = hasher.hash("testpassword")
        # '$2b$04$...' — index 4 is the cost factor field
        assert "$04$" in result

    def test_hash_same_password_produces_different_hashes(
        self, hasher: BcryptHasher
    ) -> None:
        """Two hashes of the same password must differ (unique salts).

        Args:
            hasher: BcryptHasher fixture.
        """
        h1 = hasher.hash("samepassword")
        h2 = hasher.hash("samepassword")
        assert h1 != h2

    def test_verify_correct_password_returns_true(
        self, hasher: BcryptHasher
    ) -> None:
        """verify() must return True for a matching password.

        Args:
            hasher: BcryptHasher fixture.
        """
        hashed = hasher.hash("correcthorse")
        assert hasher.verify("correcthorse", hashed) is True

    def test_verify_wrong_password_returns_false(
        self, hasher: BcryptHasher
    ) -> None:
        """verify() must return False for an incorrect password.

        Args:
            hasher: BcryptHasher fixture.
        """
        hashed = hasher.hash("correcthorse")
        assert hasher.verify("wrongpassword", hashed) is False

    def test_verify_invalid_hash_returns_false(
        self, hasher: BcryptHasher
    ) -> None:
        """verify() must return False (not raise) on a malformed hash.

        Args:
            hasher: BcryptHasher fixture.
        """
        assert hasher.verify("password", "not-a-valid-hash") is False

    def test_factory_returns_hasher_port(self) -> None:
        """create_hasher() factory must return a PasswordHasherPort."""
        from src.hasher.base import PasswordHasherPort

        hasher = create_hasher(rounds=4)
        assert isinstance(hasher, PasswordHasherPort)
