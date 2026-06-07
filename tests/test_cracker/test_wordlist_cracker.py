"""Tests for the WordlistCracker implementation."""

import sqlite3

import bcrypt
import pytest

from src.cracker.base import CrackerPort
from src.cracker.factory import create_cracker
from src.cracker.profiles import PROFILES, iter_wordlist, profile_path


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture()
def sample_db(tmp_path: object) -> str:
    """SQLite DB with two users — one weak password, one strong.

    alice → '123456' (in 500-worst)
    bob   → 'xT#9mP!2qL$vN7rT' (not in any wordlist)

    Args:
        tmp_path: pytest tmp_path fixture.

    Returns:
        Absolute path to the temp DB file.
    """
    db_path = str(tmp_path) + "/test.db"  # type: ignore[operator]
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, email TEXT,
            role TEXT, password_hash TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE login_attempts (id INTEGER PRIMARY KEY)"""
    )
    weak_hash   = bcrypt.hashpw(b"123456", bcrypt.gensalt(rounds=4))
    strong_hash = bcrypt.hashpw(
        b"xT#9mP!2qL$vN7rT", bcrypt.gensalt(rounds=4)
    )
    conn.execute(
        "INSERT INTO users (username,email,role,password_hash) VALUES (?,?,?,?)",
        ("alice", "alice@example.com", "user", weak_hash.decode()),
    )
    conn.execute(
        "INSERT INTO users (username,email,role,password_hash) VALUES (?,?,?,?)",
        ("bob", "bob@example.com", "admin", strong_hash.decode()),
    )
    conn.commit()
    conn.close()
    return db_path


# ── Profile module tests ───────────────────────────────────────────────

class TestProfiles:
    """Tests for the profiles module."""

    def test_profiles_dict_has_expected_keys(self) -> None:
        """PROFILES must contain quick, common, and breach."""
        assert "quick"  in PROFILES
        assert "common" in PROFILES
        assert "breach" in PROFILES

    def test_profile_path_returns_existing_file(self) -> None:
        """profile_path() must return a path to an existing file."""
        import os
        for key in PROFILES:
            path = profile_path(key)
            assert os.path.isfile(path), f"Missing file for '{key}'"

    def test_profile_path_raises_on_unknown_key(self) -> None:
        """profile_path() must raise KeyError for unknown profiles."""
        with pytest.raises(KeyError):
            profile_path("nonexistent")

    def test_iter_wordlist_yields_non_empty_strings(self) -> None:
        """iter_wordlist('quick') must yield non-empty strings."""
        for c in list(iter_wordlist("quick"))[:10]:
            assert isinstance(c, str) and len(c) > 0

    def test_iter_wordlist_quick_contains_known_passwords(self) -> None:
        """Quick profile must contain '123456' and 'password'."""
        candidates = list(iter_wordlist("quick"))
        assert "123456"  in candidates
        assert "password" in candidates


# ── WordlistCracker tests ─────────────────────────────────────────────

class TestWordlistCracker:
    """Unit tests for WordlistCracker via the factory."""

    def test_factory_returns_cracker_port(self) -> None:
        """create_cracker() must return a CrackerPort instance."""
        assert isinstance(create_cracker(), CrackerPort)

    def test_profiles_returns_three_items(self) -> None:
        """profiles() must return exactly 3 profiles."""
        cracker = create_cracker()
        profs = cracker.profiles()
        assert len(profs) == 3
        assert {p["key"] for p in profs} == {"quick", "common", "breach"}

    # ── inspect_db ────────────────────────────────────────────────────

    def test_inspect_db_lists_all_tables(
        self, sample_db: str
    ) -> None:
        """inspect_db() must list every table in the database."""
        result = create_cracker().inspect_db(sample_db)
        names = [t["name"] for t in result["tables"]]
        assert "users"         in names
        assert "login_attempts" in names

    def test_inspect_db_exposes_role(self, sample_db: str) -> None:
        """inspect_db() must include the role column."""
        result = create_cracker().inspect_db(sample_db)
        bob = next(u for u in result["users"] if u["username"] == "bob")
        assert bob["role"] == "admin"

    def test_inspect_db_truncates_hash(self, sample_db: str) -> None:
        """inspect_db() must produce truncated hashes ending with …."""
        result = create_cracker().inspect_db(sample_db)
        for u in result["users"]:
            assert u["hash_truncated"].endswith("…")

    def test_inspect_db_returns_profiles(self, sample_db: str) -> None:
        """inspect_db() must include all three profiles."""
        result = create_cracker().inspect_db(sample_db)
        assert len(result["profiles"]) == 3

    def test_inspect_db_raises_on_corrupt_file(
        self, tmp_path: object
    ) -> None:
        """inspect_db() must raise ValueError on a non-SQLite file."""
        bad = str(tmp_path) + "/bad.db"  # type: ignore[operator]
        with open(bad, "wb") as f:
            f.write(b"not a sqlite database")
        with pytest.raises(ValueError):
            create_cracker().inspect_db(bad)

    # ── stream_analyze: basic ─────────────────────────────────────────

    def test_stream_start_event_contains_profile(
        self, sample_db: str
    ) -> None:
        """First event must be 'start' with profile info."""
        events = list(create_cracker().stream_analyze(sample_db, "quick"))
        first = events[0]
        assert first["type"] == "start"
        assert first["profile"] == "quick"
        assert first["total_accounts"] == 2

    def test_stream_complete_event(self, sample_db: str) -> None:
        """Last event must be 'complete' with a report."""
        events = list(create_cracker().stream_analyze(sample_db, "quick"))
        assert events[-1]["type"] == "complete"
        assert "report" in events[-1]

    def test_stream_cracks_weak_password(self, sample_db: str) -> None:
        """alice's '123456' must be recovered."""
        results = [
            e["entry"] for e in create_cracker().stream_analyze(sample_db, "quick")
            if e["type"] == "result"
        ]
        alice = next(r for r in results if r["username"] == "alice")
        assert alice["status"] == "cracked"
        assert alice["recovered_password"] == "123456"

    def test_stream_does_not_crack_strong_password(
        self, sample_db: str
    ) -> None:
        """bob's strong password must not be recovered."""
        results = [
            e["entry"] for e in create_cracker().stream_analyze(sample_db, "quick")
            if e["type"] == "result"
        ]
        bob = next(r for r in results if r["username"] == "bob")
        assert bob["status"] == "not_cracked"
        assert bob["recovered_password"] == ""

    def test_stream_error_on_unknown_profile(
        self, sample_db: str
    ) -> None:
        """Unknown profile must yield an error event."""
        events = list(
            create_cracker().stream_analyze(sample_db, "badprofile")
        )
        assert events[0]["type"] == "error"
        assert "Unknown profile" in events[0]["message"]

    # ── stream_analyze: target filtering ─────────────────────────────

    def test_stream_targets_single_user(self, sample_db: str) -> None:
        """targets=[1] must analyze only alice (id=1)."""
        events = list(
            create_cracker().stream_analyze(sample_db, "quick", targets=[1])
        )
        start = events[0]
        assert start["total_accounts"] == 1
        results = [e for e in events if e["type"] == "result"]
        assert len(results) == 1
        assert results[0]["entry"]["username"] == "alice"

    def test_stream_targets_invalid_id_yields_error(
        self, sample_db: str
    ) -> None:
        """targets=[999] (non-existent) must yield an error event."""
        events = list(
            create_cracker().stream_analyze(sample_db, "quick", targets=[999])
        )
        assert events[0]["type"] == "error"

    def test_stream_targets_none_analyzes_all(
        self, sample_db: str
    ) -> None:
        """targets=None must analyze all users."""
        events = list(
            create_cracker().stream_analyze(sample_db, "quick", targets=None)
        )
        assert events[0]["total_accounts"] == 2

    # ── stream_analyze: cancellation ─────────────────────────────────

    def test_stream_cancellation_yields_cancelled_event(
        self, sample_db: str
    ) -> None:
        """is_cancelled that always returns True must emit 'cancelled'."""
        events = list(
            create_cracker().stream_analyze(
                sample_db, "quick", is_cancelled=lambda: True
            )
        )
        types = [e["type"] for e in events]
        assert "cancelled" in types

    def test_stream_cancellation_event_has_progress(
        self, sample_db: str
    ) -> None:
        """'cancelled' event must carry progress fields."""
        events = list(
            create_cracker().stream_analyze(
                sample_db, "quick", is_cancelled=lambda: True
            )
        )
        ev = next(e for e in events if e["type"] == "cancelled")
        assert "candidates_tried"   in ev
        assert "cracked_count"      in ev
        assert "elapsed_seconds"    in ev

    def test_stream_no_complete_after_cancel(
        self, sample_db: str
    ) -> None:
        """After cancellation, 'complete' must NOT be emitted."""
        events = list(
            create_cracker().stream_analyze(
                sample_db, "quick", is_cancelled=lambda: True
            )
        )
        assert not any(e["type"] == "complete" for e in events)

    # ── analyze (batch) ───────────────────────────────────────────────

    def test_analyze_aggregate_counts(self, sample_db: str) -> None:
        """Batch analyze() aggregate counts must be accurate."""
        report = create_cracker().analyze(sample_db, "quick")
        assert report.total_accounts   == 2
        assert report.cracked_count    == 1
        assert report.not_cracked_count == 1

    def test_analyze_targets_single_user(self, sample_db: str) -> None:
        """analyze() with targets=[1] must only analyze alice."""
        report = create_cracker().analyze(sample_db, "quick", targets=[1])
        assert report.total_accounts == 1
        assert report.entries[0].username == "alice"

    def test_analyze_raises_on_missing_table(
        self, tmp_path: object
    ) -> None:
        """analyze() must raise ValueError if no users table."""
        db_path = str(tmp_path) + "/empty.db"  # type: ignore[operator]
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE other (id INTEGER)")
        conn.commit()
        conn.close()
        with pytest.raises(ValueError):
            create_cracker().analyze(db_path, "quick")

    def test_report_education_keys(self, sample_db: str) -> None:
        """Report education dict must contain all expected keys."""
        report = create_cracker().analyze(sample_db, "quick")
        assert "separate_phases"  in report.education
        assert "cracked_means"    in report.education
        assert "not_cracked_means" in report.education
