"""Tests for the /api/search vulnerable and secure endpoints."""

import pytest


class TestSearchVulnerable:
    """Tests for GET /api/search/vulnerable."""

    def test_normal_category_returns_articles(
        self, client: object
    ) -> None:
        """A normal integer category_id should return articles.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get(  # type: ignore[attr-defined]
            "/api/search/vulnerable?q=1"
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert "rows" in data
        assert data["row_count"] >= 0
        assert "generated_query" in data

    def test_normal_query_is_not_injection(
        self, client: object
    ) -> None:
        """A plain integer query should not be flagged as injection.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get(  # type: ignore[attr-defined]
            "/api/search/vulnerable?q=2"
        )
        data = resp.get_json()
        assert data["is_injection"] is False

    def test_union_payload_is_detected(
        self, client: object
    ) -> None:
        """A UNION SELECT payload must be detected as injection.

        Args:
            client: Flask test client fixture.
        """
        payload = "0 UNION SELECT username,password_hash,role FROM users--"
        resp = client.get(  # type: ignore[attr-defined]
            f"/api/search/vulnerable?q={payload}"
        )
        data = resp.get_json()
        assert data["is_injection"] is True
        assert any(
            "UNION" in p for p in data["detected_patterns"]
        )

    def test_union_payload_exposes_users_table(
        self, client: object
    ) -> None:
        """UNION SELECT against users should return rows from users table.

        The UNION maps to the first SELECT's column names (id, title,
        content), so 'admin' appears as a cell value rather than under
        a 'username' key. Verify the data is present in the result set.

        Args:
            client: Flask test client fixture.
        """
        payload = "0 UNION SELECT username,password_hash,role FROM users--"
        resp = client.get(  # type: ignore[attr-defined]
            f"/api/search/vulnerable?q={payload}"
        )
        data = resp.get_json()
        # admin is seeded — their username value appears somewhere in rows
        all_values = [
            str(v)
            for row in data["rows"]
            for v in row.values()
        ]
        assert "admin" in all_values

    def test_vulnerable_query_uses_raw_concatenation(
        self, client: object
    ) -> None:
        """The generated_query should embed the input literally.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get(  # type: ignore[attr-defined]
            "/api/search/vulnerable?q=99"
        )
        data = resp.get_json()
        assert "99" in data["generated_query"]
        assert "?" not in data["generated_query"]

    def test_risk_level_critical_for_union_injection(
        self, client: object
    ) -> None:
        """Risk level must be critical for UNION SELECT payloads.

        Args:
            client: Flask test client fixture.
        """
        payload = "0 UNION SELECT username,password_hash,role FROM users--"
        resp = client.get(  # type: ignore[attr-defined]
            f"/api/search/vulnerable?q={payload}"
        )
        data = resp.get_json()
        assert data["risk_level"] == "critical"

    def test_response_schema_complete(
        self, client: object
    ) -> None:
        """Response must include all expected fields.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get(  # type: ignore[attr-defined]
            "/api/search/vulnerable?q=1"
        )
        data = resp.get_json()
        required = {
            "rows", "generated_query", "is_injection",
            "detected_patterns", "explanation", "row_count",
            "columns", "risk_level",
        }
        assert required.issubset(data.keys())


class TestSearchSecure:
    """Tests for GET /api/search/secure."""

    def test_normal_category_returns_articles(
        self, client: object
    ) -> None:
        """A normal integer query returns article rows safely.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get(  # type: ignore[attr-defined]
            "/api/search/secure?q=1"
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["row_count"] >= 0

    def test_union_payload_is_neutralised(
        self, client: object
    ) -> None:
        """UNION SELECT must return zero article rows in secure mode.

        The parameterised query coerces the value to int — UNION
        is structurally impossible, so no user data is exposed.

        Args:
            client: Flask test client fixture.
        """
        payload = "0 UNION SELECT username,password_hash,role FROM users--"
        resp = client.get(  # type: ignore[attr-defined]
            f"/api/search/secure?q={payload}"
        )
        data = resp.get_json()
        # Injection detected but no bypass occurred
        assert data["is_injection"] is True
        # Rows should contain only articles (or empty) — no user data
        for row in data["rows"]:
            for val in row.values():
                assert "$2b$" not in val, (
                    "bcrypt hash must not appear in secure results"
                )

    def test_secure_query_uses_placeholders(
        self, client: object
    ) -> None:
        """The secure generated_query display must show ? placeholder.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get(  # type: ignore[attr-defined]
            "/api/search/secure?q=1"
        )
        data = resp.get_json()
        assert "?" in data["generated_query"]

    def test_risk_level_safe_for_secure_mode(
        self, client: object
    ) -> None:
        """Risk level must always be safe in secure mode.

        Args:
            client: Flask test client fixture.
        """
        payload = "0 UNION SELECT username,password_hash,role FROM users--"
        resp = client.get(  # type: ignore[attr-defined]
            f"/api/search/secure?q={payload}"
        )
        data = resp.get_json()
        assert data["risk_level"] == "safe"

    def test_non_numeric_query_returns_empty(
        self, client: object
    ) -> None:
        """A non-numeric category_id in secure mode returns empty.

        The value is coerced to int — invalid strings become 0,
        which matches no category and returns an empty result set.

        Args:
            client: Flask test client fixture.
        """
        resp = client.get(  # type: ignore[attr-defined]
            "/api/search/secure?q=notanumber"
        )
        data = resp.get_json()
        assert data["row_count"] == 0
