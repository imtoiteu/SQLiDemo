"""Tests for SqlQueryBuilder implementation."""

import pytest

from src.query_builder.sql_query_builder import SqlQueryBuilder


@pytest.fixture()
def qb() -> SqlQueryBuilder:
    """Create a SqlQueryBuilder instance.

    Returns:
        SqlQueryBuilder instance.
    """
    return SqlQueryBuilder()


class TestSqlQueryBuilder:
    """Unit tests for SqlQueryBuilder."""

    # ── build_vulnerable ──────────────────────────────────────────────

    def test_build_vulnerable_embeds_username(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_vulnerable() must embed username literally.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_vulnerable("alice", "pass")
        assert "alice" in result

    def test_build_vulnerable_username_only_no_password_hash(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_vulnerable() must NOT include password_hash in SQL.

        Real bcrypt apps never compare passwords in SQL — the query
        only looks up the user by username.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_vulnerable("alice", "pass")
        assert "password_hash" not in result
        assert "password" not in result.lower().replace("pass", "")

    def test_build_vulnerable_query_contains_where_username(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_vulnerable() must use WHERE username = '...' form.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_vulnerable("testuser", "anypass")
        assert "WHERE username = 'testuser'" in result

    def test_build_vulnerable_embeds_injection_in_username(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_vulnerable() must embed SQL injection chars raw.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        payload = "' OR 1=1--"
        result = qb.build_vulnerable(payload, "pass")
        assert payload in result

    def test_build_vulnerable_comment_payload_closes_query(
        self, qb: SqlQueryBuilder
    ) -> None:
        """admin' -- payload must appear literally in the query.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_vulnerable("admin' --", "anything")
        assert "admin' --" in result

    # ── build_secure ──────────────────────────────────────────────────

    def test_build_secure_uses_placeholder(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_secure() must show ? placeholder in the SQL step.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_secure("alice", "pass")
        assert "?" in result

    def test_build_secure_masks_password(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_secure() must not expose the plaintext password.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_secure("alice", "secretpassword")
        assert "secretpassword" not in result

    def test_build_secure_shows_bcrypt_checkpw_step(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_secure() must show the bcrypt.checkpw() step.

        The two-step process (SQL lookup + bcrypt verify) must both
        be visible in the display string.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_secure("alice", "pass")
        assert "bcrypt.checkpw" in result

    def test_build_secure_no_password_hash_in_sql_clause(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_secure() SQL template must not include AND password_hash.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_secure("alice", "pass")
        assert "AND password_hash" not in result

    # ── inspect ───────────────────────────────────────────────────────

    def test_inspect_detects_comment_bypass(
        self, qb: SqlQueryBuilder
    ) -> None:
        """inspect() must detect the SQL comment (--) bypass.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.inspect("admin' --", "anything")
        assert result.is_injection is True
        assert result.risk_level == "critical"

    def test_inspect_detects_tautology_in_username(
        self, qb: SqlQueryBuilder
    ) -> None:
        """inspect() must detect OR 1=1 tautology in username.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.inspect("' OR 1=1--", "pass")
        assert result.is_injection is True

    def test_inspect_detects_union_select(
        self, qb: SqlQueryBuilder
    ) -> None:
        """inspect() must detect UNION SELECT.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.inspect("' UNION SELECT 1,2,3--", "x")
        assert result.is_injection is True
        assert any("UNION" in p for p in result.detected_patterns)

    def test_inspect_returns_safe_for_clean_input(
        self, qb: SqlQueryBuilder
    ) -> None:
        """inspect() must return safe risk level for clean input.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.inspect("alice", "AlicePass99!")
        assert result.is_injection is False
        assert result.risk_level == "safe"

    def test_inspect_returns_both_query_forms(
        self, qb: SqlQueryBuilder
    ) -> None:
        """inspect() must populate both query fields.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.inspect("bob", "hunter2")
        assert "bob" in result.vulnerable_query
        assert "?" in result.secure_query
        assert "bcrypt.checkpw" in result.secure_query

    def test_inspect_vulnerable_query_no_password_hash(
        self, qb: SqlQueryBuilder
    ) -> None:
        """inspect() vulnerable_query must not contain password_hash.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.inspect("bob", "hunter2")
        assert "password_hash" not in result.vulnerable_query

    def test_inspect_explanation_mentions_bcrypt(
        self, qb: SqlQueryBuilder
    ) -> None:
        """inspect() explanation for safe input must mention bcrypt.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.inspect("bob", "cleanpass")
        assert "bcrypt" in result.explanation.lower()


class TestLegacyQueryBuilder:
    """Tests for build_legacy_vulnerable (Demo 1 — Legacy App)."""

    def test_build_legacy_embeds_username(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_legacy_vulnerable() must embed username literally.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_legacy_vulnerable("alice", "pass")
        assert "alice" in result

    def test_build_legacy_embeds_password(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_legacy_vulnerable() must embed password literally.

        Unlike the modern mode, the legacy query includes the
        password directly in the SQL — no bcrypt comparison.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_legacy_vulnerable("alice", "secret")
        assert "secret" in result

    def test_build_legacy_targets_legacy_users_table(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_legacy_vulnerable() must query the legacy_users table.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_legacy_vulnerable("alice", "pass")
        assert "legacy_users" in result

    def test_build_legacy_has_and_password_clause(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_legacy_vulnerable() must include AND password = clause.

        This confirms both fields are in the SQL — the key difference
        from the modern mode which only includes the username lookup.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_legacy_vulnerable("alice", "pass")
        assert "AND" in result.upper()
        assert "password" in result.lower()

    def test_build_legacy_comment_payload_works(
        self, qb: SqlQueryBuilder
    ) -> None:
        """admin' -- payload truncates the AND clause visibly in output.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_legacy_vulnerable("admin' --", "")
        assert "admin' --" in result

    def test_build_legacy_password_injection_embedded(
        self, qb: SqlQueryBuilder
    ) -> None:
        """SQL in the password field must appear literally in the query.

        Both fields are vulnerable in legacy mode.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        payload = "' OR '1'='1"
        result = qb.build_legacy_vulnerable("alice", payload)
        assert payload in result


class TestSearchQueryBuilder:
    """Tests for build_search_vulnerable and build_search_secure."""

    def test_build_search_vulnerable_embeds_input(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_search_vulnerable() must embed the raw value literally.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_search_vulnerable("1")
        assert "1" in result

    def test_build_search_vulnerable_targets_articles(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_search_vulnerable() must query the articles table.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_search_vulnerable("1")
        assert "articles" in result

    def test_build_search_vulnerable_no_placeholder(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_search_vulnerable() must NOT use ? placeholders.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_search_vulnerable("1")
        assert "?" not in result

    def test_build_search_vulnerable_union_payload_embedded(
        self, qb: SqlQueryBuilder
    ) -> None:
        """UNION payload must appear literally in the vulnerable query.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        payload = "0 UNION SELECT username,password_hash,role FROM users--"
        result = qb.build_search_vulnerable(payload)
        assert "UNION" in result.upper()
        assert "users" in result

    def test_build_search_secure_uses_placeholder(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_search_secure() must show ? in the query template.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_search_secure("1")
        assert "?" in result

    def test_build_search_secure_targets_articles(
        self, qb: SqlQueryBuilder
    ) -> None:
        """build_search_secure() must reference the articles table.

        Args:
            qb: SqlQueryBuilder fixture.
        """
        result = qb.build_search_secure("1")
        assert "articles" in result
