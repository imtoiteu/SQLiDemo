"""Application configuration via pydantic-settings.

All settings are loaded from environment variables or .env file.
Never access os.environ directly in business logic — use this module.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings loaded from environment / .env.

    Attributes:
        secret_key: Flask session signing key. Must be kept secret.
        database_path: Path to the SQLite database file.
        admin_username: Seeded admin account username.
        admin_email: Seeded admin account email.
        admin_password: Seeded admin account plaintext password
            (hashed on first run — never stored in plain).
        debug: Enable Flask debug mode. Never True in production.
    """

    secret_key: str = Field(
        ...,
        description="Flask secret key for session signing.",
    )
    database_path: str = Field(
        default="sqlilab.db",
        description="Path to SQLite database file.",
    )
    admin_username: str = Field(
        default="admin",
        description="Seeded admin username.",
    )
    admin_email: str = Field(
        default="admin@sqlilab.local",
        description="Seeded admin email.",
    )
    admin_password: str = Field(
        ...,
        description="Seeded admin plaintext password (hashed on seed).",
    )
    debug: bool = Field(
        default=False,
        description="Flask debug mode flag.",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )
