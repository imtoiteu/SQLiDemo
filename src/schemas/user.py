"""Shared Pydantic schemas for user-related data transfer.

These are the canonical data models used across all layers.
Business logic never constructs raw dicts — it uses these models.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator


# ──────────────────────────────────────────────────────────────
# Input schemas (request bodies)
# ──────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    """Schema for creating a new user via registration.

    Attributes:
        username: Unique display name (3–32 chars, alphanumeric + _).
        email: Valid email address.
        password: Plaintext password (hashed before storage).
        confirm_password: Must match password exactly.
    """

    username: str = Field(
        ..., min_length=3, max_length=32, pattern=r"^\w+$"
    )
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("confirm_password")
    @classmethod
    def passwords_must_match(cls, v: str, info: object) -> str:
        """Validate that confirm_password equals password.

        Args:
            v: The confirm_password value.
            info: Validation info containing other field values.

        Returns:
            The confirm_password value if valid.

        Raises:
            ValueError: If passwords do not match.
        """
        data = getattr(info, "data", {})
        if "password" in data and v != data["password"]:
            raise ValueError("Passwords do not match.")
        return v


class LoginInput(BaseModel):
    """Schema for login form input.

    Attributes:
        username: User-supplied username.
        password: User-supplied plaintext password.
    """

    username: str = Field(..., min_length=1, max_length=256)
    # min_length=0 allows empty password — common in injection demos
    # where the password field is made irrelevant by SQL comments.
    password: str = Field("", min_length=0, max_length=256)


# ──────────────────────────────────────────────────────────────
# Domain / read schemas (database records)
# ──────────────────────────────────────────────────────────────

class UserRecord(BaseModel):
    """Represents a user row returned from the database.

    Attributes:
        id: Auto-incremented primary key.
        username: Unique username.
        email: User email address.
        password_hash: bcrypt hash stored as string (hex-encoded).
        role: User role — 'admin', 'teacher', or 'student'.
        created_at: ISO timestamp of account creation.
    """

    id: int
    username: str
    email: str
    password_hash: str
    role: Literal["admin", "teacher", "student"] = "student"
    created_at: str


class LoginResult(BaseModel):
    """Result of a login attempt.

    Attributes:
        success: Whether authentication succeeded.
        username: Authenticated username (empty string on failure).
        role: User role (empty string on failure).
        generated_query: The SQL query that was built and executed.
        is_injection: Whether SQL injection was detected in input.
        bypass_method: Description of the bypass technique used.
        explanation: Educational explanation of what happened.
        rows_returned: Number of rows the raw SQL query returned.
        all_matched_users: All users from the result set (id, username,
            role). Exposed for educational display — shows which accounts
            would be accessible in a real breach.
    """

    success: bool
    username: str = ""
    role: str = ""
    generated_query: str = ""
    is_injection: bool = False
    bypass_method: str = ""
    explanation: str = ""
    rows_returned: int = 0
    all_matched_users: list[dict[str, str]] = []
    # Demo 2 — three-stage breakdown
    bcrypt_check_called: bool = False
    bcrypt_check_result: bool | None = None


class InspectResult(BaseModel):
    """Result of SQL query inspection.

    Attributes:
        raw_username: Raw username input.
        raw_password: Raw password input.
        vulnerable_query: Query as built by string concatenation.
        secure_query: Parameterized query template.
        is_injection: Whether injection patterns were detected.
        detected_patterns: List of pattern descriptions found.
        explanation: Step-by-step explanation.
        risk_level: 'safe', 'low', 'medium', 'high', 'critical'.
    """

    raw_username: str
    raw_password: str
    vulnerable_query: str
    secure_query: str
    is_injection: bool
    detected_patterns: list[str]
    explanation: str
    risk_level: Literal["safe", "low", "medium", "high", "critical"]


class UserPublic(BaseModel):
    """User record safe for exposure in educational DB dump.

    Attributes:
        id: Row ID.
        username: Username.
        email: Email.
        password_hash: bcrypt hash (educational — shows hashing works).
        role: User role.
        created_at: Timestamp.
    """

    id: int
    username: str
    email: str
    password_hash: str
    role: str
    created_at: str
