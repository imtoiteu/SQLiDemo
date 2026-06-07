"""Flask application factory.

create_app() is the single entry point for constructing the
Flask application. All dependencies are wired here.
"""

import os

from flask import Flask, jsonify, send_from_directory

from src.auth.factory import create_auth_service
from src.config import Settings
from src.database.factory import create_database
from src.hasher.factory import create_hasher
from src.query_builder.factory import create_query_builder


def create_app(settings: Settings | None = None) -> Flask:
    """Construct and configure the Flask application.

    Wires all dependencies (database, hasher, auth service, query
    builder) and registers all route blueprints. Designed to be
    called with overridden settings for testing.

    Args:
        settings: Optional Settings override (used in tests with
            in-memory DB and test secret key).

    Returns:
        A fully configured Flask application instance.
    """
    # Project root = two levels up from src/api/app.py
    _project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..")
    )

    app = Flask(
        __name__,
        static_folder=_project_root,
        static_url_path="/static",
    )

    cfg = settings or Settings()  # type: ignore[call-arg]

    # ── Flask config ─────────────────────────────────────────
    app.config["SECRET_KEY"] = cfg.secret_key
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["DEBUG"] = cfg.debug

    # ── Dependency graph ─────────────────────────────────────
    db = create_database(cfg.database_path)
    hasher = create_hasher(rounds=12)
    qb = create_query_builder()
    auth = create_auth_service(db=db, hasher=hasher, query_builder=qb)

    # Seed admin account on startup
    auth.seed_admin(
        username=cfg.admin_username,
        email=cfg.admin_email,
        password=cfg.admin_password,
    )

    # Store services in app context for blueprint access
    app.config["AUTH_SERVICE"] = auth
    app.config["DB"] = db
    app.config["QB"] = qb

    # ── Blueprints ────────────────────────────────────────────
    from src.api.routes.auth_routes import auth_bp
    from src.api.routes.admin_routes import admin_bp
    from src.api.routes.demo_routes import demo_bp
    from src.api.routes.crack_routes import crack_bp
    from src.api.routes.search_routes import search_bp, seed_articles

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(demo_bp, url_prefix="/api/demo")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(crack_bp, url_prefix="/api/crack")
    app.register_blueprint(search_bp, url_prefix="/api/search")

    # Seed startup data (after blueprints so imports are resolved)
    auth.seed_legacy_users()
    auth.seed_sample_users()   # Demo 2: alice, bob, charlie, teacher
    seed_articles(db)

    # ── Static HTML page routes ────────────────────────────────
    pages_dir = os.path.join(_project_root, "static", "pages")
    static_dir = _project_root

    @app.route("/")
    def index() -> object:
        """Serve the landing page."""
        return send_from_directory(static_dir, "index.html")

    @app.route("/style.css")
    def style_css() -> object:
        """Serve the root-level stylesheet."""
        return send_from_directory(static_dir, "style.css")

    @app.route("/app.js")
    def app_js() -> object:
        """Serve the root-level JavaScript bundle."""
        return send_from_directory(static_dir, "app.js")

    @app.route("/register")
    def register_page() -> object:
        """Serve the registration page."""
        return send_from_directory(pages_dir, "register.html")

    @app.route("/login")
    def login_page() -> object:
        """Serve the dual-mode login page."""
        return send_from_directory(pages_dir, "login.html")

    @app.route("/inspector")
    def inspector_page() -> object:
        """Serve the SQL query inspector page."""
        return send_from_directory(pages_dir, "inspector.html")

    @app.route("/dashboard")
    def dashboard_page() -> object:
        """Serve the post-login dashboard page."""
        return send_from_directory(pages_dir, "dashboard.html")

    @app.route("/admin")
    def admin_page() -> object:
        """Serve the admin control panel page."""
        return send_from_directory(pages_dir, "admin.html")

    @app.route("/flow")
    def flow_page() -> object:
        """Serve the attack flow visualization page."""
        return send_from_directory(pages_dir, "flow.html")

    @app.route("/compare")
    def compare_page() -> object:
        """Serve the security comparison panel page."""
        return send_from_directory(pages_dir, "compare.html")

    @app.route("/teacher")
    def teacher_page() -> object:
        """Serve the teacher dashboard page."""
        return send_from_directory(pages_dir, "teacher.html")

    @app.route("/crack")
    def crack_page() -> object:
        """Serve the Password Analysis (post-breach cracking) page."""
        return send_from_directory(pages_dir, "crack.html")

    @app.route("/search")
    def search_page() -> object:
        """Serve the Demo-2 UNION injection search page."""
        return send_from_directory(pages_dir, "search.html")

    @app.route("/legacy")
    def legacy_page() -> object:
        """Redirect to login page in Legacy Application mode."""
        from flask import redirect
        return redirect("/login?demo=legacy")

    @app.route("/modern")
    def modern_page() -> object:
        """Redirect to login page in Modern Application mode."""
        from flask import redirect
        return redirect("/login?demo=modern")

    # ── Health check ──────────────────────────────────────────
    @app.route("/api/health")
    def health() -> object:
        """Simple health-check endpoint."""
        return jsonify({"status": "ok", "service": "SQLiLab"})

    return app
