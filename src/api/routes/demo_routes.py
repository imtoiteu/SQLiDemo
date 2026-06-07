"""Demo API routes — SQL query inspector and hash analysis."""

from flask import Blueprint, jsonify, request

from src.query_builder.factory import create_query_builder

demo_bp = Blueprint("demo", __name__)

# Singleton query builder for the demo routes
_qb = create_query_builder()

# MD5 hash lookup table for hash-cracking demo (weak passwords)
_RAINBOW_TABLE: dict[str, str] = {
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "25d55ad283aa400af464c76d713c07ad": "12345678",
    "827ccb0eea8a706c4c34a16891f84e7b": "12345",
    "21232f297a57a5a743894a0e4a801fc3": "admin",
    "5ebe2294ecd0e0f08eab7690d2a6ee69": "secret",
    "7c6a180b36896a0a8c02787eeafb0e4c": "password1",
    "f25a2fc72690b780b2a14e140ef6a9e0": "iloveyou",
    "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
    "3bc15c8aae3e4124dd409035f32ea2fd": "hunter2",
    "482c811da5d5b4bc6d497ffa98491e38": "password!",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "96e79218965eb72c92a549dd5a330112": "111111",
    "f379eaf3c831b04de153469d1bec345e": "1234567",
    "fcea920f7412b5da7be0cf42b8c93759": "1234567890",
}


@demo_bp.route("/inspect", methods=["POST"])
def inspect() -> object:
    """Perform SQL injection analysis on user-supplied input.

    Expects JSON body: {username, password}

    Returns:
        200 with full InspectResult including both query forms,
        detected patterns, risk level, and educational explanation.
        400 on invalid input.
    """
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    if not username and not password:
        return jsonify({"error": "username and password required"}), 400

    result = _qb.inspect(username, password)

    return jsonify({
        "raw_username":       result.raw_username,
        "raw_password":       result.raw_password,
        "vulnerable_query":   result.vulnerable_query,
        "secure_query":       result.secure_query,
        "is_injection":       result.is_injection,
        "detected_patterns":  result.detected_patterns,
        "explanation":        result.explanation,
        "risk_level":         result.risk_level,
    })


@demo_bp.route("/hash-demo", methods=["POST"])
def hash_demo() -> object:
    """Demonstrate bcrypt vs MD5 hashing for a given password.

    Shows why MD5 is insecure and bcrypt is the correct choice.
    Includes rainbow-table lookup simulation for MD5.

    Expects JSON body: {password}

    Returns:
        200 with comparison data and educational explanation.
    """
    import hashlib

    body = request.get_json(silent=True) or {}
    password = str(body.get("password", ""))

    if not password:
        return jsonify({"error": "password is required"}), 400

    # MD5 (insecure — for educational comparison only)
    md5_hash = hashlib.md5(password.encode()).hexdigest()  # noqa: S324
    md5_cracked = _RAINBOW_TABLE.get(md5_hash)

    # bcrypt (secure — use in production)
    import bcrypt as _bcrypt
    salt = _bcrypt.gensalt(rounds=12)
    bcrypt_hash = _bcrypt.hashpw(
        password.encode("utf-8"), salt
    ).decode("utf-8")

    return jsonify({
        "password": password,
        "md5": {
            "algorithm": "MD5",
            "hash": md5_hash,
            "cracked": md5_cracked,
            "in_rainbow_table": md5_cracked is not None,
            "secure": False,
            "explanation": (
                "MD5 is NOT a password hashing algorithm. It is a "
                "message-digest function designed to be FAST — which "
                "makes it terrible for passwords. An attacker can "
                "compute billions of MD5 hashes per second. "
                "No salt means identical passwords have identical hashes "
                "— rainbow tables can crack them instantly."
            ),
        },
        "bcrypt": {
            "algorithm": "bcrypt",
            "hash": bcrypt_hash,
            "cracked": None,
            "in_rainbow_table": False,
            "secure": True,
            "work_factor": 12,
            "explanation": (
                "bcrypt is a purpose-built password hashing function. "
                "It is intentionally SLOW (controlled by the work factor). "
                "Each hash includes a unique random salt embedded in the "
                "output, making rainbow tables useless. Increasing the "
                "work factor by 1 doubles the computation time, so "
                "bcrypt stays secure as hardware improves."
            ),
        },
        "education": {
            "lesson": "Always use bcrypt, scrypt, or Argon2 for passwords.",
            "never_use": ["MD5", "SHA1", "SHA256 (unsalted)"],
        },
    })


@demo_bp.route("/query-examples", methods=["GET"])
def query_examples() -> object:
    """Return predefined injection examples for the inspector UI.

    Returns:
        200 with a list of example injection scenarios.
    """
    examples = [
        {
            "name":     "Classic Comment Bypass",
            "username": "admin' --",
            "password": "anything",
            "category": "Auth Bypass",
        },
        {
            "name":     "Tautology Bypass",
            "username": "admin",
            "password": "' OR '1'='1",
            "category": "Auth Bypass",
        },
        {
            "name":     "Boolean True Bypass",
            "username": "' OR 1=1--",
            "password": "x",
            "category": "Auth Bypass",
        },
        {
            "name":     "UNION Data Exfil",
            "username": "' UNION SELECT 1,username,email,password_hash,role,datetime() FROM users--",
            "password": "x",
            "category": "UNION",
        },
        {
            "name":     "Time-Based Blind",
            "username": "admin",
            "password": "' OR SLEEP(5)--",
            "category": "Blind",
        },
        {
            "name":     "Compact No-Space Bypass",
            "username": "admin",
            "password": "'or'1'='1",
            "category": "Auth Bypass",
        },
        {
            "name":     "Boolean Boolean (no quotes)",
            "username": "admin",
            "password": "x' OR 1=1#",
            "category": "Auth Bypass",
        },
        {
            "name":     "Normal Login (safe)",
            "username": "alice",
            "password": "Alice@Secure99!",
            "category": "Safe",
        },
    ]
    return jsonify({"examples": examples})
