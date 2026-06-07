"""Concrete wordlist-based bcrypt cracker implementation.

Uses SecLists wordlist profiles and Python's bcrypt library.
No external tools, GPU, or custom user-supplied wordlists.
"""

import sqlite3
import time
from collections.abc import Callable, Generator
from typing import Any

import bcrypt

from src.cracker.base import CrackerPort
from src.cracker.profiles import (
    DEFAULT_PROFILE,
    PROFILES,
    iter_wordlist,
    profiles_metadata,
)
from src.schemas.crack import CrackEntry, CrackReport

# ── Educational content ────────────────────────────────────────────────

_EDUCATION_DB: dict[str, str | list[str]] = {
    "what_is_hash": (
        "A password hash is the output of a one-way cryptographic "
        "function. The database never stores your real password — only "
        "its hash. Even the server cannot recover your password from the "
        "hash alone."
    ),
    "bcrypt_notice": (
        "bcrypt hashes always start with $2b$ (or $2a$). The number "
        "after it (e.g. $2b$12$…) is the work factor — how many rounds "
        "of computation are applied. This lab uses work factor 12: each "
        "hash verification takes ~100-400ms on CPU."
    ),
    "no_plaintext": (
        "No plaintext passwords exist in this database. The breach "
        "exposed only bcrypt hashes. An attacker must try every candidate "
        "password and check whether it produces the same hash. This is "
        "called an offline dictionary attack."
    ),
    "attack_phases": (
        "SQL Injection and password cracking are two separate attack "
        "phases. SQL Injection stole the database. The dictionary attack "
        "now runs entirely offline — the compromised server is no longer "
        "needed."
    ),
}

_EDUCATION_CRACK: dict[str, str | list[str]] = {
    "headline": "What just happened?",
    "not_reversed": (
        "We did NOT reverse the bcrypt hash. Cryptographic hashes are "
        "one-way functions — reversing them is computationally infeasible."
    ),
    "how_cracked": (
        "We recovered passwords by iterating every candidate in the "
        "selected wordlist and calling bcrypt.checkpw() to test whether "
        "it matches the stored hash. This is an offline dictionary attack."
    ),
    "cracked_means": (
        "A recovered password means it was present in the attacker's "
        "candidate list — not that bcrypt was broken. If the password "
        "had been unique and random, it would not be in any wordlist."
    ),
    "not_cracked_means": (
        "The database was compromised, but the password could not be "
        "recovered using the selected wordlist. This does not guarantee "
        "safety — a larger wordlist might still succeed."
    ),
    "why_it_works": (
        "Weak or common passwords exist in every attacker's wordlist. "
        "When your password appears in real breach data, it can be "
        "recovered in seconds — regardless of how strong the hashing "
        "algorithm is."
    ),
    "bcrypt_strength": (
        "bcrypt with cost=12 is deliberately slow — ~200ms per check. "
        "A truly random 12-character password would take centuries to "
        "brute-force. The weakness is the password choice, not bcrypt."
    ),
    "hashing_vs_encryption": (
        "Hashing is NOT encryption. Encryption is reversible with a key. "
        "Hashing is one-way — there is no key and no decryption function."
    ),
    "separate_phases": (
        "SQL Injection and password cracking are separate attack phases. "
        "SQL Injection gave the attacker the database. The dictionary "
        "attack runs entirely offline — the compromised server is no "
        "longer needed at this stage."
    ),
    "lessons": [
        "Use a unique, randomly generated password for every service.",
        "Length and randomness matter more than character substitutions.",
        "A password manager generates and stores strong unique passwords.",
        "Even strong hashing cannot protect a weak or reused password.",
        "The greatest post-breach risk is credential reuse, not hash reversal.",
        "SQL Injection and offline cracking are distinct, sequential threats.",
    ],
    "attacker_actions": [
        "Reuse recovered passwords on other services (credential stuffing).",
        "Sell recovered credentials on dark-web markets.",
        "Use recovered emails + passwords for targeted phishing.",
        "Pivot into internal systems if passwords are reused.",
    ],
}


def _cracked_explanation(pw: str, idx: int, t: float) -> str:
    return (
        f"Password recovered via dictionary attack. "
        f"'{pw}' was found at position #{idx} in the wordlist. "
        f"bcrypt.checkpw() confirmed the match in {t:.3f}s. "
        f"This password was recovered because it was present in the "
        f"attacker's candidate list, not because bcrypt was reversed."
    )


def _not_cracked_explanation(profile_name: str, n: int) -> str:
    return (
        f"Not recovered using the '{profile_name}' profile ({n:,} "
        f"candidates tried). The database was compromised, but the "
        f"password could not be recovered using the selected wordlist."
    )


class WordlistCracker(CrackerPort):
    """Offline dictionary cracker using SecLists wordlist profiles.

    Implements CrackerPort. Uses bcrypt.checkpw() for verification
    against candidates read line-by-line from the profile's file.
    Supports target filtering and cooperative cancellation.
    """

    def profiles(self) -> list[dict[str, Any]]:
        """Return metadata for all available cracking profiles.

        Returns:
            List of profile descriptor dicts.
        """
        return profiles_metadata()

    # ── inspect_db ────────────────────────────────────────────────────

    def inspect_db(self, db_path: str) -> dict[str, Any]:
        """Parse a SQLite DB and return its structure + users preview.

        Args:
            db_path: Absolute path to the SQLite file.

        Returns:
            Dict with tables, users preview, profiles, and education.

        Raises:
            ValueError: If the file is not a valid SQLite database.
        """
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            raise ValueError(f"Cannot open database: {exc}") from exc

        try:
            table_rows = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' ORDER BY name"
            ).fetchall()

            tables: list[dict[str, Any]] = []
            for tr in table_rows:
                tname = tr["name"]
                try:
                    count = conn.execute(
                        f'SELECT COUNT(*) as c FROM "{tname}"'
                    ).fetchone()["c"]
                    cols_info = conn.execute(
                        f'PRAGMA table_info("{tname}")'
                    ).fetchall()
                    cols = [c["name"] for c in cols_info]
                except sqlite3.Error:
                    count, cols = 0, []
                tables.append({"name": tname, "row_count": count, "columns": cols})

            has_users = any(t["name"] == "users" for t in tables)
            users_preview: list[dict[str, str]] = []

            if has_users:
                try:
                    rows = conn.execute(
                        "SELECT id, username, email, role, password_hash "
                        "FROM users ORDER BY id"
                    ).fetchall()
                    has_role = True
                except sqlite3.Error:
                    try:
                        rows = conn.execute(
                            "SELECT id, username, email, password_hash "
                            "FROM users ORDER BY id"
                        ).fetchall()
                        has_role = False
                    except sqlite3.Error:
                        rows, has_role = [], False

                for row in rows:
                    d = dict(row)
                    phash = str(d.get("password_hash", ""))
                    algo = "bcrypt" if phash.startswith("$2") else "unknown"
                    users_preview.append({
                        "id":             str(d.get("id", "")),
                        "username":       str(d.get("username", "")),
                        "email":          str(d.get("email", "")),
                        "role":           str(d.get("role", "")) if has_role else "—",
                        "hash_truncated":  phash[:29] + "…",
                        "hash_full":       phash,
                        "hash_algorithm":  algo,
                    })

            return {
                "tables":          tables,
                "users":           users_preview,
                "has_users_table": has_users,
                "education":       _EDUCATION_DB,
                "profiles":        profiles_metadata(),
            }

        except sqlite3.Error as exc:
            raise ValueError(f"Cannot open database: {exc}") from exc
        finally:
            conn.close()

    # ── stream_analyze ────────────────────────────────────────────────

    def stream_analyze(
        self,
        db_path: str,
        profile: str = DEFAULT_PROFILE,
        targets: list[int] | None = None,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Crack passwords and yield SSE-compatible progress events.

        Args:
            db_path: Absolute path to the uploaded SQLite file.
            profile: Profile key (``"quick"``, ``"common"``,
                     ``"breach"``).
            targets: Optional list of user IDs to crack. ``None``
                     means all users.
            is_cancelled: Callable returning ``True`` when the caller
                     wants to stop. Checked before each candidate.

        Yields:
            Dict events: start / testing / result / cancelled /
            complete / error.
        """
        if profile not in PROFILES:
            yield {
                "type":    "error",
                "message": f"Unknown profile '{profile}'. Valid: {list(PROFILES)}",
            }
            return

        profile_meta = PROFILES[profile]
        profile_name = profile_meta["name"]
        wl_size      = profile_meta["candidates"]

        try:
            all_users = self._load_users(db_path)
        except ValueError as exc:
            yield {"type": "error", "message": str(exc)}
            return

        # Filter by selected targets
        if targets:
            target_set = set(targets)
            users = [u for u in all_users if int(u["id"]) in target_set]
            if not users:
                yield {
                    "type":    "error",
                    "message": "None of the selected targets were found in the database.",
                }
                return
        else:
            users = all_users

        if not users:
            yield {"type": "error", "message": "No users found in the database."}
            return

        total = len(users)

        yield {
            "type":           "start",
            "total_accounts": total,
            "wordlist_size":  wl_size,
            "profile":        profile,
            "profile_name":   profile_name,
        }

        run_start   = time.monotonic()
        entries: list[CrackEntry] = []
        cracked     = 0
        total_tried = 0

        for i, user in enumerate(users, start=1):
            # Cancellation check between users
            if is_cancelled and is_cancelled():
                yield {
                    "type":               "cancelled",
                    "completed_accounts": i - 1,
                    "cracked_count":      cracked,
                    "candidates_tried":   total_tried,
                    "elapsed_seconds":    round(time.monotonic() - run_start, 2),
                    "message":            "Analysis stopped by user.",
                }
                return

            uid      = int(user["id"])
            username = str(user["username"])
            phash    = str(user["password_hash"])
            truncated = phash[:29] + "…"

            try:
                hash_bytes = phash.encode("utf-8")
            except Exception:
                entry = CrackEntry(
                    user_id=uid, username=username,
                    hash_truncated=truncated, hash_full=phash,
                    status="not_cracked",
                    explanation="Invalid hash encoding.",
                )
                entries.append(entry)
                yield {"type": "result", "entry": entry.model_dump()}
                continue

            start = time.monotonic()
            found = False
            last_idx = 0

            for idx, candidate in enumerate(iter_wordlist(profile), start=1):
                last_idx = idx
                total_tried += 1

                # Cancellation check every 5 candidates (max latency ~1-2s)
                if is_cancelled and idx % 5 == 0 and is_cancelled():
                    elapsed = time.monotonic() - run_start
                    yield {
                        "type":               "cancelled",
                        "completed_accounts": i - 1,
                        "cracked_count":      cracked,
                        "candidates_tried":   total_tried,
                        "elapsed_seconds":    round(elapsed, 2),
                        "current_username":   username,
                        "message":            "Analysis stopped by user.",
                    }
                    return

                # Emit testing event every 25 candidates
                if idx % 25 == 1:
                    yield {
                        "type":            "testing",
                        "account_index":   i,
                        "total":           total,
                        "username":        username,
                        "candidate":       candidate,
                        "candidate_index": idx,
                        "wordlist_size":   wl_size,
                        "profile_name":    profile_name,
                        "elapsed":         round(time.monotonic() - run_start, 1),
                    }

                try:
                    if bcrypt.checkpw(candidate.encode("utf-8"), hash_bytes):
                        elapsed = time.monotonic() - start
                        entry = CrackEntry(
                            user_id=uid, username=username,
                            hash_truncated=truncated, hash_full=phash,
                            status="cracked",
                            recovered_password=candidate,
                            time_seconds=round(elapsed, 3),
                            candidate_index=idx,
                            explanation=_cracked_explanation(candidate, idx, elapsed),
                        )
                        entries.append(entry)
                        cracked += 1
                        found = True
                        yield {"type": "result", "entry": entry.model_dump()}
                        break
                except Exception:
                    continue

            if not found:
                elapsed = time.monotonic() - start
                entry = CrackEntry(
                    user_id=uid, username=username,
                    hash_truncated=truncated, hash_full=phash,
                    status="not_cracked",
                    time_seconds=round(elapsed, 3),
                    explanation=_not_cracked_explanation(profile_name, last_idx),
                )
                entries.append(entry)
                yield {"type": "result", "entry": entry.model_dump()}

        total_time = time.monotonic() - run_start
        report = CrackReport(
            total_accounts=total,
            cracked_count=cracked,
            not_cracked_count=total - cracked,
            wordlist_size=wl_size,
            total_time_seconds=round(total_time, 3),
            entries=entries,
            education=_EDUCATION_CRACK,
        )
        yield {"type": "complete", "report": report.model_dump()}

    # ── analyze (batch wrapper) ───────────────────────────────────────

    def analyze(
        self,
        db_path: str,
        profile: str = DEFAULT_PROFILE,
        targets: list[int] | None = None,
    ) -> CrackReport:
        """Run analysis synchronously and return a CrackReport.

        Args:
            db_path: Absolute path to the uploaded SQLite file.
            profile: Profile key.
            targets: Optional user ID filter.

        Returns:
            CrackReport.

        Raises:
            ValueError: On DB error or unknown profile.
        """
        report: CrackReport | None = None
        error_msg: str | None = None

        for event in self.stream_analyze(db_path, profile, targets):
            if event["type"] == "error":
                error_msg = event["message"]
                break
            if event["type"] == "complete":
                report = CrackReport(**event["report"])
                break

        if error_msg:
            raise ValueError(error_msg)
        if report is None:
            raise ValueError("Cracking did not complete.")
        return report

    # ── private helpers ───────────────────────────────────────────────

    def _load_users(self, db_path: str) -> list[dict[str, Any]]:
        """Return all rows from the users table.

        Args:
            db_path: Path to the SQLite database.

        Returns:
            List of user dicts with id, username, password_hash.

        Raises:
            ValueError: On read error or missing table.
        """
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, username, password_hash FROM users"
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.Error as exc:
            raise ValueError(f"Could not read database: {exc}") from exc
