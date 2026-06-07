"""Abstract auth service port."""

from abc import ABC, abstractmethod

from src.schemas.user import LoginResult, UserCreate, UserRecord


class AuthServicePort(ABC):
    """Contract for the authentication service.

    Defines registration, secure login, and vulnerable-mode login.
    High-level modules (Flask routes) depend only on this ABC.
    """

    @abstractmethod
    def register(self, data: UserCreate) -> UserRecord:
        """Register a new user.

        Hashes the password and stores the user record.

        Args:
            data: Validated registration input.

        Returns:
            The created UserRecord with assigned id.

        Raises:
            ValueError: If username or email already exists.
        """
        ...

    @abstractmethod
    def login_secure(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate using a parameterised query (safe).

        Uses prepared statements — SQL injection is impossible
        because user input is never interpolated into the query.

        Args:
            username: Raw username input.
            password: Raw password input.

        Returns:
            A LoginResult describing the outcome.
        """
        ...

    @abstractmethod
    def login_vulnerable(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate using string concatenation (insecure).

        ⚠️  EDUCATIONAL DEMO ONLY — intentionally vulnerable.
        Demonstrates how SQL injection enables authentication bypass.

        Args:
            username: Raw username input (may contain SQL).
            password: Raw password input (may contain SQL).

        Returns:
            A LoginResult describing the outcome, including whether
            injection was detected and what bypass occurred.
        """
        ...

    @abstractmethod
    def get_all_users(self) -> list[UserRecord]:
        """Return all user records (for DB exposure simulation).

        Returns:
            List of all UserRecord objects in the database.
        """
        ...

    @abstractmethod
    def seed_admin(
        self,
        username: str,
        email: str,
        password: str,
    ) -> None:
        """Seed the admin account if it does not already exist.

        Args:
            username: Admin username.
            email: Admin email.
            password: Admin plaintext password (will be hashed).
        """
        ...

    @abstractmethod
    def seed_sample_users(self) -> list[UserRecord]:
        """Create a set of sample users for classroom demonstrations.

        Returns:
            List of newly created UserRecord objects.
        """
        ...

    @abstractmethod
    def login_legacy(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate against legacy_users using raw SQL concatenation.

        ⚠️  EDUCATIONAL DEMO ONLY — intentionally insecure.

        Simulates a legacy application that stores passwords in plaintext
        and builds login queries by string concatenation. This makes
        classic SQL injection bypass ('' OR 1=1--) fully effective.

        Args:
            username: Raw username input (may contain SQL injection).
            password: Raw password input (may contain SQL injection).

        Returns:
            A LoginResult describing the outcome.
        """
        ...

    @abstractmethod
    def seed_legacy_users(self) -> None:
        """Seed the legacy_users table with plaintext demo accounts.

        Idempotent — safe to call multiple times on startup.
        """
        ...
