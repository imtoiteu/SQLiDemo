"""Admin API routes — teacher dashboard operations."""

import os

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    send_file,
    session,
)

from src.auth.base import AuthServicePort
from src.database.base import DatabasePort

admin_bp = Blueprint("admin", __name__)


def _require_admin() -> tuple[bool, object]:
    """Check that the current session has admin or teacher role.

    Returns:
        (True, None) if authorised.
        (False, error_response) if not authorised.
    """
    role = session.get("role", "")
    if role not in ("admin", "teacher"):
        return False, (
            jsonify({"error": "Admin or teacher role required."}),
            403,
        )
    return True, None


def _get_auth() -> AuthServicePort:
    """Get auth service from app config."""
    return current_app.config["AUTH_SERVICE"]  # type: ignore[return-value]


def _get_db() -> DatabasePort:
    """Get database from app config."""
    return current_app.config["DB"]  # type: ignore[return-value]


@admin_bp.route("/users", methods=["GET"])
def list_users() -> object:
    """Return all users for the DB exposure educational simulation.

    Returns:
        200 with user list (including bcrypt hashes — educational).
        403 if not authenticated.
    """
    # Note: DB exposure is allowed without auth for demo purposes
    # (the educational point is that breach = hashes, not plaintext)
    auth = _get_auth()
    users = auth.get_all_users()

    user_list = [
        {
            "id":            u.id,
            "username":      u.username,
            "email":         u.email,
            "password_hash": u.password_hash,
            "role":          u.role,
            "created_at":    u.created_at,
        }
        for u in users
    ]

    return jsonify({
        "users": user_list,
        "count": len(user_list),
        "education": {
            "notice": (
                "These are real bcrypt hashes from the SQLite database. "
                "Notice: even with full database access, the attacker "
                "cannot see plaintext passwords — only hashes. "
                "Brute-forcing bcrypt at cost=12 takes years per hash."
            ),
            "safe_fields": ["id", "username", "email", "role"],
            "sensitive_fields": ["password_hash"],
        },
    })


@admin_bp.route("/reset", methods=["POST"])
def reset_database() -> object:
    """Reset the demo database (teacher use only).

    Drops all tables, re-creates schema, and re-seeds admin + samples.

    Returns:
        200 on success.
        403 if not admin/teacher.
    """
    ok, err = _require_admin()
    if not ok:
        return err  # type: ignore[return-value]

    db = _get_db()
    db.reset()

    # Re-seed after reset
    from src.config import Settings
    cfg = Settings()  # type: ignore[call-arg]
    auth = _get_auth()
    auth.seed_admin(
        username=cfg.admin_username,
        email=cfg.admin_email,
        password=cfg.admin_password,
    )
    created = auth.seed_sample_users()

    return jsonify({
        "message":      "Database reset successfully.",
        "users_seeded": len(created) + 1,  # +1 for admin
    })


@admin_bp.route("/seed-users", methods=["POST"])
def seed_users() -> object:
    """Create the standard set of sample users.

    Returns:
        200 with list of created users.
        403 if not admin/teacher.
    """
    ok, err = _require_admin()
    if not ok:
        return err  # type: ignore[return-value]

    auth = _get_auth()
    created = auth.seed_sample_users()

    return jsonify({
        "message":      f"Created {len(created)} sample users.",
        "created":      [
            {"username": u.username, "role": u.role} for u in created
        ],
    })


@admin_bp.route("/delete-user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id: int) -> object:
    """Delete a user by ID (teacher use only).

    Args:
        user_id: The numeric user ID to delete.

    Returns:
        200 on success.
        400 if attempting to delete admin (id=1).
        403 if not admin/teacher.
    """
    ok, err = _require_admin()
    if not ok:
        return err  # type: ignore[return-value]

    if user_id == 1:
        return jsonify({"error": "Cannot delete the admin account."}), 400

    db = _get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"message": f"User {user_id} deleted."})


@admin_bp.route("/download-db", methods=["GET"])
def download_db() -> object:
    """Download the SQLite database file.

    This endpoint simulates what an attacker could do after a
    successful SQL injection + file read exploit. For educational
    demonstration in vulnerable mode.

    Returns:
        200 with the .db file as an attachment.
        403 if session is not flagged as injection-bypassed or admin.
        404 if the DB file is not found.
    """
    is_admin = session.get("role") in ("admin", "teacher")
    is_bypassed = session.get("injection_bypass", False)

    if not (is_admin or is_bypassed):
        return jsonify({
            "error": (
                "Access denied. You must either:\n"
                "1. Login as admin/teacher, or\n"
                "2. Successfully demonstrate a SQL injection bypass "
                "   in Vulnerable Mode to access this endpoint."
            )
        }), 403

    from src.config import Settings
    cfg = Settings()  # type: ignore[call-arg]
    db_path = os.path.abspath(cfg.database_path)

    if not os.path.exists(db_path):
        return jsonify({"error": "Database file not found."}), 404

    # Force WAL checkpoint before streaming the file.
    # SQLite WAL mode keeps recent writes in a -wal sidecar file
    # until a checkpoint merges them into the main DB file.
    # Without this, newly-registered accounts are missing from the
    # downloaded copy because they only exist in the WAL journal.
    try:
        import sqlite3 as _sq
        _c = _sq.connect(db_path)
        _c.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        _c.commit()
        _c.close()
    except Exception:
        pass  # non-fatal; download proceeds with whatever is on disk

    return send_file(
        db_path,
        as_attachment=True,
        download_name="sqlilab_breached.db",
        mimetype="application/octet-stream",
    )


@admin_bp.route("/exposed-legacy-data", methods=["GET"])
def exposed_legacy_data() -> object:
    """Return all rows from the legacy_users table.

    ⚠️  EDUCATIONAL DEMO ONLY.

    Used by Demo 1 to show that plaintext password storage means
    every user's password is immediately readable after a DB breach —
    no cracking required.

    Only accessible after a successful SQL injection bypass or as
    admin/teacher.

    Returns:
        200 with list of legacy_users rows including plaintext passwords.
        403 if not authorised.
    """
    is_admin = session.get("role") in ("admin", "teacher")
    is_bypassed = session.get("injection_bypass", False)

    if not (is_admin or is_bypassed):
        return jsonify({"error": "Access denied."}), 403

    db = current_app.config["DB"]
    rows = db.fetchall(
        "SELECT id, username, password, role, email FROM legacy_users"
    )
    return jsonify({
        "table":   "legacy_users",
        "columns": ["id", "username", "password", "role", "email"],
        "rows":    [dict(r) for r in rows],
        "note": (
            "These passwords are stored in PLAINTEXT. "
            "No cracking was required — they are immediately readable "
            "from the database file."
        ),
    })


@admin_bp.route("/login-history", methods=["GET"])
def login_history() -> object:
    """Return the login attempt history log.

    Returns:
        200 with paginated login attempt records.
        403 if not admin/teacher.
    """
    ok, err = _require_admin()
    if not ok:
        return err  # type: ignore[return-value]

    db = _get_db()
    limit = min(int(request.args.get("limit", 50)), 200)
    rows = db.fetchall(
        """SELECT id, username, password, mode, is_injection,
                  success, timestamp
           FROM login_attempts
           ORDER BY id DESC
           LIMIT ?""",
        (limit,),
    )

    return jsonify({
        "history": rows,
        "count":   len(rows),
    })


@admin_bp.route("/global-mode", methods=["POST"])
def set_global_mode() -> object:
    """Set the global demo mode (vulnerable/secure) for all clients.

    This setting is stored in the DB settings table so all
    browser sessions reflect the teacher's choice.

    Expects JSON body: {mode: "vulnerable"|"secure"}

    Returns:
        200 on success.
        400 on invalid mode.
        403 if not admin/teacher.
    """
    ok, err = _require_admin()
    if not ok:
        return err  # type: ignore[return-value]

    body = request.get_json(silent=True) or {}
    mode = body.get("mode", "")
    if mode not in ("vulnerable", "secure"):
        return jsonify({"error": "mode must be 'vulnerable' or 'secure'"}), 400

    db = _get_db()
    db.execute(
        """INSERT OR REPLACE INTO app_settings (key, value)
           VALUES ('global_mode', ?)""",
        (mode,),
    )
    return jsonify({"message": f"Global mode set to '{mode}'.", "mode": mode})


@admin_bp.route("/global-mode", methods=["GET"])
def get_global_mode() -> object:
    """Get the current global demo mode.

    Returns:
        200 with current mode string.
    """
    db = _get_db()
    row = db.fetchone(
        "SELECT value FROM app_settings WHERE key = 'global_mode'"
    )
    mode = row["value"] if row else "secure"
    return jsonify({"mode": mode})
