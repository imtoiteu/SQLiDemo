"""Abstract query builder port."""

from abc import ABC, abstractmethod

from src.schemas.user import InspectResult


class QueryBuilderPort(ABC):
    """Contract for building SQL query strings for inspection/demo.

    Provides both a vulnerable (concatenated) and a secure
    (parameterised template) form of the same authentication query.
    """

    @abstractmethod
    def build_vulnerable(self, username: str, password: str) -> str:
        """Build an intentionally vulnerable SQL query string.

        Uses f-string/concatenation — user input is embedded raw.

        Args:
            username: Raw username input (may contain SQL).
            password: Raw password input (may contain SQL).

        Returns:
            A complete SQL string with input embedded literally.
        """
        ...

    @abstractmethod
    def build_secure(self, username: str, password: str) -> str:
        """Build the parameterised (safe) query display string.

        Shows the template with ? placeholders and bound values.

        Args:
            username: Username (shown as bound parameter).
            password: Password (shown masked, for display).

        Returns:
            A display string showing the parameterised query template.
        """
        ...

    @abstractmethod
    def inspect(self, username: str, password: str) -> InspectResult:
        """Analyse user input for SQL injection and return full report.

        Args:
            username: Raw username input.
            password: Raw password input.

        Returns:
            An InspectResult with both query forms and analysis.
        """
        ...

    # ── Demo 1: Legacy Application ────────────────────────────────

    @abstractmethod
    def build_legacy_vulnerable(
        self, username: str, password: str
    ) -> str:
        """Build the Demo-1 legacy query with username AND password raw.

        Simulates a legacy app that stores plaintext passwords and
        builds: WHERE username = '...' AND password = '...'

        Args:
            username: Raw username (may contain SQL).
            password: Raw password (may contain SQL).

        Returns:
            Complete SQL string embedded in legacy_users table.
        """
        ...

    @abstractmethod
    def build_legacy_secure(
        self, username: str, password: str
    ) -> str:
        """Build the Demo-1 legacy query in parameterised (safe) form.

        Shows the ? placeholder template plus bound values so students
        can compare it directly against the vulnerable concatenated form.

        Args:
            username: Raw username (shown as bound param, not embedded).
            password: Raw password (shown as bound param, not embedded).

        Returns:
            Display string showing parameterised template + bindings.
        """
        ...

    @abstractmethod
    def build_search_vulnerable(self, query: str) -> str:
        """Build the vulnerable article search query (raw concat).

        Args:
            query: Raw user-supplied category value.

        Returns:
            SQL string with query embedded literally.
        """
        ...

    @abstractmethod
    def build_search_secure(self, query: str) -> str:
        """Build the parameterised search query display string.

        Args:
            query: User-supplied search value (for display only).

        Returns:
            Display string showing the parameterised template.
        """
        ...
