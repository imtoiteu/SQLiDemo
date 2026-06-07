"""Shared pytest fixtures for the SQLiLab test suite."""

import pytest

from src.api.app import create_app
from src.config import Settings


@pytest.fixture()
def test_settings() -> Settings:
    """Return Settings configured for in-memory testing.

    Returns:
        Settings instance pointing to an in-memory SQLite database.
    """
    return Settings(
        secret_key="test-secret-key-do-not-use-in-production",
        database_path=":memory:",
        admin_username="admin",
        admin_email="admin@test.local",
        admin_password="Admin@Test123!",
        debug=False,
    )


@pytest.fixture()
def app(test_settings: Settings) -> object:
    """Create a Flask test application instance.

    Args:
        test_settings: Injected test settings fixture.

    Returns:
        Flask app configured for testing with in-memory database.
    """
    application = create_app(settings=test_settings)
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app: object) -> object:
    """Return a Flask test client.

    Args:
        app: Flask application fixture.

    Returns:
        Flask test client for making HTTP requests.
    """
    return app.test_client()  # type: ignore[attr-defined]


@pytest.fixture()
def admin_client(client: object) -> object:
    """Return a test client pre-authenticated as admin.

    Args:
        client: Flask test client fixture.

    Returns:
        Test client with active admin session.
    """
    client.post(  # type: ignore[attr-defined]
        "/api/auth/login/secure",
        json={"username": "admin", "password": "Admin@Test123!"},
    )
    return client
