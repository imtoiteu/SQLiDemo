"""Integration tests for demo and admin API routes."""

import pytest


class TestInspectRoute:
    """Tests for POST /api/demo/inspect."""

    def test_inspect_detects_injection(self, client: object) -> None:
        """Inspector should flag SQL injection in input.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/demo/inspect",
            json={"username": "admin' --", "password": "x"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["is_injection"] is True
        assert data["risk_level"] == "critical"

    def test_inspect_safe_input_returns_safe(
        self, client: object
    ) -> None:
        """Clean input should return risk_level='safe'.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/demo/inspect",
            json={"username": "alice", "password": "MyPass99!"},
        )
        data = resp.get_json()
        assert data["is_injection"] is False
        assert data["risk_level"] == "safe"

    def test_inspect_returns_both_query_forms(
        self, client: object
    ) -> None:
        """Inspector response must include vulnerable and secure queries.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/demo/inspect",
            json={"username": "bob", "password": "hunter2"},
        )
        data = resp.get_json()
        assert "vulnerable_query" in data
        assert "secure_query" in data
        assert "?" in data["secure_query"]

    def test_inspect_empty_body_returns_400(
        self, client: object
    ) -> None:
        """Empty body should return 400.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/demo/inspect",
            json={},
        )
        assert resp.status_code == 400


class TestHashDemoRoute:
    """Tests for POST /api/demo/hash-demo."""

    def test_hash_demo_returns_bcrypt_and_md5(
        self, client: object
    ) -> None:
        """hash-demo should return both bcrypt and MD5 hashes.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/demo/hash-demo",
            json={"password": "password"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "bcrypt" in data
        assert "md5" in data
        assert data["bcrypt"]["secure"] is True
        assert data["md5"]["secure"] is False

    def test_hash_demo_detects_rainbow_table_hit(
        self, client: object
    ) -> None:
        """hash-demo should flag MD5 of 'password' in rainbow table.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/demo/hash-demo",
            json={"password": "password"},
        )
        data = resp.get_json()
        assert data["md5"]["in_rainbow_table"] is True
        assert data["md5"]["cracked"] == "password"

    def test_hash_demo_bcrypt_not_in_rainbow_table(
        self, client: object
    ) -> None:
        """bcrypt hash should never appear in rainbow table.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post(  # type: ignore[attr-defined]
            "/api/demo/hash-demo",
            json={"password": "password"},
        )
        data = resp.get_json()
        assert data["bcrypt"]["in_rainbow_table"] is False


class TestAdminRoutes:
    """Tests for admin-protected routes."""

    def test_list_users_returns_users(self, client: object) -> None:
        """GET /api/admin/users should return the users list.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get("/api/admin/users")  # type: ignore[attr-defined]
        assert resp.status_code == 200
        data = resp.get_json()
        assert "users" in data
        assert any(u["username"] == "admin" for u in data["users"])

    def test_reset_requires_admin_role(self, client: object) -> None:
        """POST /api/admin/reset should return 403 without admin role.

        Args:
            client: Flask test client fixture.
        """
        resp = client.post("/api/admin/reset")  # type: ignore[attr-defined]
        assert resp.status_code == 403

    def test_reset_succeeds_as_admin(
        self, admin_client: object
    ) -> None:
        """POST /api/admin/reset should succeed as admin.

        Args:
            admin_client: Pre-authenticated admin client fixture.
        """
        resp = admin_client.post("/api/admin/reset")  # type: ignore[attr-defined]
        assert resp.status_code == 200

    def test_global_mode_set_and_get(
        self, admin_client: object
    ) -> None:
        """Global mode toggle should persist between set and get.

        Args:
            admin_client: Pre-authenticated admin client fixture.
        """
        admin_client.post(  # type: ignore[attr-defined]
            "/api/admin/global-mode",
            json={"mode": "vulnerable"},
        )
        resp = admin_client.get("/api/admin/global-mode")  # type: ignore[attr-defined]
        data = resp.get_json()
        assert data["mode"] == "vulnerable"
