"""Abstract base class for the password-cracker port."""

from abc import ABC, abstractmethod
from collections.abc import Callable, Generator
from typing import Any

from src.schemas.crack import CrackReport


class CrackerPort(ABC):
    """Contract for offline dictionary-based password analysis.

    Implementations use SecLists wordlist profiles and bcrypt
    verification. No external tools, GPU, or custom lists.
    """

    @abstractmethod
    def inspect_db(
        self, db_path: str
    ) -> dict[str, Any]:
        """Parse a SQLite DB and return its structure + users preview.

        Args:
            db_path: Absolute path to the SQLite file.

        Returns:
            Dict with keys: tables, users, has_users_table,
            education, profiles.

        Raises:
            ValueError: If the file is not a valid SQLite database.
        """
        ...

    @abstractmethod
    def stream_analyze(
        self,
        db_path: str,
        profile: str = "quick",
        targets: list[int] | None = None,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Crack passwords and yield progress events as a generator.

        Event ``type`` values:

        - ``start``:     {type, total_accounts, wordlist_size,
                          profile, profile_name}
        - ``testing``:   {type, account_index, total, username,
                          candidate, candidate_index, wordlist_size}
        - ``result``:    {type, entry: CrackEntry.model_dump()}
        - ``cancelled``: {type, completed_accounts, cracked_count,
                          candidates_tried, message}
        - ``complete``:  {type, report: CrackReport.model_dump()}
        - ``error``:     {type, message}

        Args:
            db_path: Absolute path to the uploaded SQLite file.
            profile: Profile key — ``"quick"``, ``"common"``, or
                     ``"breach"``. Defaults to ``"quick"``.
            targets: Optional list of user IDs to crack.  If ``None``
                     or empty, all users in the DB are analyzed.
            is_cancelled: Zero-argument callable that returns ``True``
                     when the analysis should stop early.  Checked
                     between each candidate — max latency = one
                     bcrypt round (~400ms).

        Yields:
            JSON-serialisable dicts.
        """
        ...

    @abstractmethod
    def profiles(self) -> list[dict[str, Any]]:
        """Return metadata for all available cracking profiles.

        Returns:
            List of profile descriptor dicts (key, name, candidates,
            description, runtime_hint, color, examples).
        """
        ...
