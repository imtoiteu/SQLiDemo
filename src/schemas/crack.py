"""Pydantic schemas for the password-cracking analysis feature.

These are the canonical data models for the Password Analysis
post-breach demonstration. Business logic never constructs raw
dicts — it uses these models.
"""

from pydantic import BaseModel


class CrackEntry(BaseModel):
    """Result for a single user's password hash.

    Attributes:
        user_id: Database row ID.
        username: The account username.
        hash_truncated: First 20 chars of the bcrypt hash + '…'.
        hash_full: Full bcrypt hash (exposed in breach — educational).
        status: 'cracked' | 'not_cracked'.
        recovered_password: Plaintext password if cracked, else ''.
        time_seconds: Seconds taken to find the match (0.0 if not found).
        candidate_index: Position of the winning candidate in the wordlist
            (1-indexed, 0 if not found).
        explanation: Educational explanation of how / why this happened.
    """

    user_id: int
    username: str
    hash_truncated: str
    hash_full: str
    status: str          # 'cracked' | 'not_cracked'
    recovered_password: str = ""
    time_seconds: float = 0.0
    candidate_index: int = 0
    explanation: str = ""


class CrackReport(BaseModel):
    """Aggregate report for a cracking run.

    Attributes:
        total_accounts: How many user rows were in the uploaded DB.
        cracked_count: How many were recovered.
        not_cracked_count: How many were not found.
        wordlist_size: Number of candidates tried.
        total_time_seconds: Wall-clock time for the whole run.
        entries: Per-user results.
        education: Static educational copy shown in the UI.
    """

    total_accounts: int
    cracked_count: int
    not_cracked_count: int
    wordlist_size: int
    total_time_seconds: float
    entries: list[CrackEntry]
    education: dict[str, str | list[str]]
