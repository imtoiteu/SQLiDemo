"""Integration tests for auth API routes."""

import pytest


class TestRegisterRoute:
    """Tests for POST /api/auth/register."""

    def test_register_valid_user_returns_201(self, client: object) -> None:
        """Valid registration should return 201 with user data.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/register",
            json={
                "username":         "testuser",
                "email":            "test@example.com",
                "password":         "Test@Pass99!",
                "confirm_password": "Test@Pass99!",
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["username"] == "testuser"
        assert data["password_hash"].startswith("$2b$")

    def test_register_mismatched_passwords_returns_400(
        self, client: object
    ) -> None:
        """Mismatched passwords should return 400.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/register",
            json={
                "username":         "testuser2",
                "email":            "test2@example.com",
                "password":         "Pass1!",
                "confirm_password": "Pass2!",
            },
        )
        assert resp.status_code == 400

    def test_register_duplicate_username_returns_409(
        self, client: object
    ) -> None:
        """Duplicate username should return 409.

        Args:
            client: Flask test client fixture.
        """
        payload = {
            "username":         "dupuser",
            "email":            "dup@example.com",
            "password":         "Test@Pass99!",
            "confirm_password": "Test@Pass99!",
        }
        client.post("/api/auth/register", json=payload)  # type: ignore[attr-defined]

        payload["email"] = "dup2@example.com"
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/register", json=payload
        )
        assert resp.status_code == 409

    def test_register_response_includes_education_field(
        self, client: object
    ) -> None:
        """Registration response should include educational info.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/register",
            json={
                "username":         "eduuser",
                "email":            "edu@example.com",
                "password":         "Edu@Pass99!",
                "confirm_password": "Edu@Pass99!",
            },
        )
        data = resp.get_json()
        assert "education" in data
        assert data["education"]["algorithm"] == "bcrypt"


class TestLoginSecureRoute:
    """Tests for POST /api/auth/login/secure."""

    def test_login_secure_valid_credentials_succeeds(
        self, client: object
    ) -> None:
        """Valid credentials should return success=True.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/secure",
            json={"username": "admin", "password": "Admin@Test123!"},
        )
        data = resp.get_json()
        assert data["success"] is True
        assert data["username"] == "admin"

    def test_login_secure_wrong_password_fails(
        self, client: object
    ) -> None:
        """Wrong password should return success=False.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/secure",
            json={"username": "admin", "password": "wrongpassword"},
        )
        data = resp.get_json()
        assert data["success"] is False

    def test_login_secure_injection_detected_but_not_bypassed(
        self, client: object
    ) -> None:
        """SQL injection in secure mode is detected but login still fails.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/secure",
            json={"username": "admin' --", "password": "anything"},
        )
        data = resp.get_json()
        assert data["is_injection"] is True
        assert data["success"] is False

    def test_login_secure_returns_generated_query(
        self, client: object
    ) -> None:
        """Login response should include the parameterised query.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/secure",
            json={"username": "admin", "password": "Admin@Test123!"},
        )
        data = resp.get_json()
        assert "generated_query" in data
        assert "?" in data["generated_query"]


class TestLoginVulnerableRoute:
    """Tests for POST /api/auth/login/vulnerable."""

    def test_login_vulnerable_wrong_password_fails(
        self, client: object
    ) -> None:
        """Wrong password fails in vulnerable mode via bcrypt.checkpw.

        In the new design the SQL only looks up the user by username
        (no password in SQL). A wrong plaintext password then fails
        bcrypt.checkpw() in application code.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/vulnerable",
            json={"username": "admin", "password": "WRONG_PASSWORD"},
        )
        data = resp.get_json()
        # SQL lookup finds admin row, but bcrypt.checkpw returns False.
        assert data["success"] is False
        assert data["is_injection"] is False

    def test_login_vulnerable_correct_creds_succeed(
        self, client: object
    ) -> None:
        """Correct credentials succeed in vulnerable mode.

        The SQL lookup finds the user; bcrypt.checkpw then confirms
        the password. This is how a real bcrypt app works in its
        normal (non-injected) code path.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/vulnerable",
            json={"username": "admin", "password": "Admin@Test123!"},
        )
        data = resp.get_json()
        assert data["success"] is True
        assert data["is_injection"] is False

    def test_login_vulnerable_injection_bypasses_auth(
        self, client: object
    ) -> None:
        """SQL injection retrieves the row but bcrypt still blocks login
        when the wrong password is supplied.

        The correct Demo 2 behaviour:
        1. SQL injection makes WHERE clause return the admin row.
        2. bcrypt.checkpw(wrong_password, admin_hash) is still called.
        3. bcrypt returns False  →  login is DENIED.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/vulnerable",
            json={"username": "admin' --", "password": "wrong"},
        )
        data = resp.get_json()
        assert data["is_injection"] is True
        # SQL injection retrieved a row — bcrypt check was performed
        assert data["rows_returned"] >= 1
        assert data["bcrypt_check_called"] is True
        # Wrong password → bcrypt returns False → login denied
        assert data["bcrypt_check_result"] is False
        assert data["success"] is False

    def test_login_vulnerable_tautology_calls_bcrypt(
        self, client: object
    ) -> None:
        """Tautology injection returns all rows; bcrypt is still called
        on rows[0] with the supplied password.

        Correct Demo 2 behaviour:
        1. ' OR 1=1-- returns all rows in the users table.
        2. bcrypt.checkpw(empty_password, rows[0].hash) is called.
        3. Empty string does not match the hash  →  login DENIED.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/vulnerable",
            json={"username": "' OR 1=1--", "password": ""},
        )
        data = resp.get_json()
        assert data["is_injection"] is True
        assert data["rows_returned"] >= 1
        assert data["bcrypt_check_called"] is True
        # Empty password cannot match bcrypt hash  →  denied
        assert data["bcrypt_check_result"] is False
        assert data["success"] is False

    def test_login_vulnerable_returns_raw_query(
        self, client: object
    ) -> None:
        """Vulnerable login response should include the raw SQL.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/vulnerable",
            json={"username": "admin' --", "password": "x"},
        )
        data = resp.get_json()
        assert "admin' --" in data["generated_query"]


class TestLogoutRoute:
    """Tests for POST /api/auth/logout."""

    def test_logout_clears_session(self, client: object) -> None:
        """After logout, /me should return 401.

        Args:
            client: Flask test client fixture.
        """
        client.post(  # type: ignore[attr-defined]
            "/api/auth/login/secure",
            json={"username": "admin", "password": "Admin@Test123!"},
        )
        client.post("/api/auth/logout")  # type: ignore[attr-defined]
        resp = client.get("/api/auth/me")  # type: ignore[attr-defined]
        assert resp.status_code == 401


class TestLoginLegacyRoute:
    """Tests for POST /api/auth/login/legacy (Demo 1 — Legacy App)."""

    def test_legacy_normal_login_succeeds(
        self, client: object
    ) -> None:
        """Valid credentials succeed in legacy mode.

        The SQL query is: WHERE username='admin' AND password='admin123'
        — a normal match against the plaintext password in legacy_users.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/legacy",
            json={"username": "admin", "password": "admin123"},
        )
        data = resp.get_json()
        assert data["success"] is True
        assert data["username"] == "admin"
        assert data["is_injection"] is False

    def test_legacy_wrong_password_fails(
        self, client: object
    ) -> None:
        """Wrong password returns no rows in legacy mode.

        The WHERE clause with the wrong plaintext password matches
        no rows in legacy_users — no bcrypt involved.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/legacy",
            json={"username": "admin", "password": "wrongpassword"},
        )
        data = resp.get_json()
        assert data["success"] is False
        assert data["is_injection"] is False

    def test_legacy_or_injection_bypasses_auth(
        self, client: object
    ) -> None:
        """' OR 1=1-- payload bypasses legacy auth.

        The generated query becomes:
          WHERE username = '' OR 1=1--' AND password = ''
        which always returns all rows.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/legacy",
            json={"username": "' OR 1=1--", "password": ""},
        )
        data = resp.get_json()
        assert data["success"] is True
        assert data["is_injection"] is True

    def test_legacy_admin_comment_bypasses_auth(
        self, client: object
    ) -> None:
        """admin' -- payload truncates the AND clause.

        The generated query becomes:
          WHERE username = 'admin' --' AND password = ''
        The comment removes the password check entirely.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/legacy",
            json={"username": "admin' --", "password": ""},
        )
        data = resp.get_json()
        assert data["success"] is True
        assert data["is_injection"] is True
        assert data["username"] == "admin"

    def test_legacy_password_field_injection(
        self, client: object
    ) -> None:
        """SQL injection in the password field also bypasses auth.

        The password field is also vulnerable in legacy mode.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/legacy",
            json={"username": "admin", "password": "' OR '1'='1"},
        )
        data = resp.get_json()
        assert data["success"] is True
        assert data["is_injection"] is True

    def test_legacy_session_mode_is_legacy(
        self, client: object
    ) -> None:
        """Successful legacy login sets session login_mode to legacy.

        Args:
            client: Flask test client fixture.
        """
        client.post(  # type: ignore[attr-defined]
            "/api/auth/login/legacy",
            json={"username": "admin", "password": "admin123"},
        )
        me = client.get(  # type: ignore[attr-defined]
            "/api/auth/me"
        ).get_json()
        assert me["login_mode"] == "legacy"

    def test_legacy_query_contains_plaintext_password(
        self, client: object
    ) -> None:
        """The generated_query must show password in plaintext (no hash).

        This confirms the educational point: legacy apps store and
        compare passwords in plaintext inside SQL.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/auth/login/legacy",
            json={"username": "alice", "password": "password"},
        )
        data = resp.get_json()
        assert "password" in data["generated_query"]
        assert "AND" in data["generated_query"].upper()
