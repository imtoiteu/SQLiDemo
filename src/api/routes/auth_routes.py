"""Auth API routes — registration, login, logout."""

from flask import Blueprint, current_app, jsonify, request, session

from src.auth.base import AuthServicePort
from src.schemas.user import LoginInput, UserCreate

auth_bp = Blueprint("auth", __name__)


def _get_auth() -> AuthServicePort:
    """Retrieve the auth service from the Flask application config.

    Returns:
        The injected AuthServicePort instance.
    """
    return current_app.config["AUTH_SERVICE"]  # type: ignore[return-value]


@auth_bp.route("/register", methods=["POST"])
def register() -> object:
    """Register a new user account.

    Expects JSON body: {username, email, password, confirm_password}

    Returns:
        201 with user data on success.
        400 with error message on validation failure.
        409 on duplicate username/email.
    """
    body = request.get_json(silent=True) or {}
    try:
        data = UserCreate(**body)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400

    auth = _get_auth()
    try:
        user = auth.register(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    # Educational: return the hash (not the password) for display
    return jsonify({
        "id":            user.id,
        "username":      user.username,
        "email":         user.email,
        "password_hash": user.password_hash,
        "role":          user.role,
        "created_at":    user.created_at,
        "education": {
            "message": (
                "Your password was hashed using bcrypt before storage. "
                "The hash above is what is saved — your plaintext "
                "password never touches the database."
            ),
            "algorithm": "bcrypt",
            "work_factor": 12,
        },
    }), 201


@auth_bp.route("/login/secure", methods=["POST"])
def login_secure() -> object:
    """Authenticate via parameterised query (safe mode).

    Expects JSON body: {username, password}

    Returns:
        200 with login result and educational explanation.
        400 on invalid input.
    """
    body = request.get_json(silent=True) or {}
    try:
        inp = LoginInput(**body)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400

    auth = _get_auth()
    result = auth.login_secure(inp.username, inp.password)

    if result.success:
        session["user_id"] = result.username
        session["username"] = result.username
        session["role"] = result.role
        session["login_mode"] = "secure"

    return jsonify({
        "success":         result.success,
        "username":        result.username,
        "role":            result.role,
        "generated_query": result.generated_query,
        "is_injection":    result.is_injection,
        "bypass_method":   result.bypass_method,
        "explanation":     result.explanation,
    })


@auth_bp.route("/login/vulnerable", methods=["POST"])
def login_vulnerable() -> object:
    """Authenticate via string-concatenated query (vulnerable mode).

    ⚠️  EDUCATIONAL DEMO ONLY — intentionally insecure.

    Expects JSON body: {username, password}

    Returns:
        200 with login result, generated SQL, and bypass analysis.
        400 on invalid input.
    """
    body = request.get_json(silent=True) or {}
    try:
        inp = LoginInput(**body)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400

    auth = _get_auth()
    result = auth.login_vulnerable(inp.username, inp.password)

    if result.success:
        session["user_id"] = result.username
        session["username"] = result.username
        session["role"] = result.role
        session["login_mode"] = "vulnerable"
        session["injection_bypass"] = result.is_injection

    return jsonify({
        "success":             result.success,
        "username":            result.username,
        "role":                result.role,
        "generated_query":     result.generated_query,
        "is_injection":        result.is_injection,
        "bypass_method":       result.bypass_method,
        "explanation":         result.explanation,
        "rows_returned":       result.rows_returned,
        "all_matched_users":   result.all_matched_users,
        "bcrypt_check_called": result.bcrypt_check_called,
        "bcrypt_check_result": result.bcrypt_check_result,
    })


@auth_bp.route("/login/legacy", methods=["POST"])
def login_legacy() -> object:
    """Authenticate against legacy_users via raw SQL (Demo 1).

    ⚠️  EDUCATIONAL DEMO ONLY — intentionally insecure.

    Simulates a legacy application with:
      - Passwords stored in PLAINTEXT
      - Login query built by string concatenation
      - SQL injection in either field fully bypasses auth

    Expects JSON body: {username, password}

    Returns:
        200 with login result, generated SQL, bypass analysis.
        400 on invalid input.
    """
    body = request.get_json(silent=True) or {}
    try:
        inp = LoginInput(**body)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400

    auth = _get_auth()
    result = auth.login_legacy(inp.username, inp.password)

    if result.success:
        session["user_id"] = result.username
        session["username"] = result.username
        session["role"] = result.role
        session["login_mode"] = "legacy"
        session["injection_bypass"] = result.is_injection

    return jsonify({
        "success":         result.success,
        "username":        result.username,
        "role":            result.role,
        "generated_query": result.generated_query,
        "is_injection":    result.is_injection,
        "bypass_method":   result.bypass_method,
        "explanation":     result.explanation,
        "rows_returned":   result.rows_returned,
        "all_matched_users": result.all_matched_users,
    })


@auth_bp.route("/login/legacy/secure", methods=["POST"])
def login_legacy_secure() -> object:
    """Authenticate against legacy_users via parameterised query (Demo 1B).

    EDUCATIONAL DEMO — same database as login_legacy but safe query
    construction. Injection payloads are bound as data, never as SQL.

    Expects JSON body: {username, password}

    Returns:
        200 with login result and educational explanation of why the
        injection failed to modify the query.
        400 on invalid input.
    """
    body = request.get_json(silent=True) or {}
    try:
        inp = LoginInput(**body)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400

    auth = _get_auth()
    result = auth.login_legacy_secure(inp.username, inp.password)

    if result.success:
        session["user_id"] = result.username
        session["username"] = result.username
        session["role"] = result.role
        session["login_mode"] = "legacy"

    return jsonify({
        "success":           result.success,
        "username":          result.username,
        "role":              result.role,
        "generated_query":   result.generated_query,
        "is_injection":      result.is_injection,
        "bypass_method":     result.bypass_method,
        "explanation":       result.explanation,
        "rows_returned":     result.rows_returned,
        "all_matched_users": result.all_matched_users,
    })


@auth_bp.route("/logout", methods=["POST"])
def logout() -> object:
    """Clear the user session.

    Returns:
        200 on success.
    """
    session.clear()
    return jsonify({"message": "Logged out successfully."})


@auth_bp.route("/me", methods=["GET"])
def me() -> object:
    """Return the current session user info.

    Returns:
        200 with username and role if logged in.
        401 if not authenticated.
    """
    if "user_id" not in session:
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated":    True,
        "username":         session.get("username"),
        "role":             session.get("role"),
        "login_mode":       session.get("login_mode"),
        "injection_bypass": session.get("injection_bypass", False),
    })
