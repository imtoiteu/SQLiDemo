"""API routes for the Password Analysis / cracking feature.

Endpoints
---------
GET  /api/crack/profiles
    List all available cracking profiles with metadata.

POST /api/crack/inspect
    Upload a SQLite DB, parse tables + users, return forensic preview
    including profiles list. Returns a ``session_id``.

GET  /api/crack/stream?sid=<id>&profile=<key>&targets=<uid,uid,…>
    Server-Sent Events stream. Drives WordlistCracker.stream_analyze()
    with the selected profile and optional target user IDs, yielding
    ``data: <json>`` lines for every event.

POST /api/crack/cancel?sid=<id>
    Signal the running stream for ``sid`` to stop after the next
    cancellation checkpoint (max ~1–2s latency).
"""

import json
import os
import tempfile
import threading
import time
import uuid
from typing import Any

from flask import Blueprint, Response, jsonify, request, stream_with_context

from src.cracker.factory import create_cracker

crack_bp = Blueprint("crack", __name__)

# ── In-memory session store ────────────────────────────────────────────
# {sid: {path: str, expires: float, cancelled: bool}}
_sessions: dict[str, dict[str, Any]] = {}
_SESSION_TTL = 60 * 60   # 1 hour
_lock = threading.Lock()
_MAX_BYTES = 10 * 1024 * 1024  # 10 MB


def _cleanup() -> None:
    """Remove expired sessions and their temp files."""
    now = time.time()
    with _lock:
        expired = [s for s, i in _sessions.items() if now > i["expires"]]
        for sid in expired:
            path = _sessions.pop(sid, {}).get("path", "")
            try:
                if path and os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass


def _save_session(data: bytes) -> tuple[str, str]:
    """Write upload bytes to a temp file and register a session.

    Args:
        data: Raw bytes of the uploaded SQLite file.

    Returns:
        (session_id, temp_file_path).
    """
    _cleanup()
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.write(data)
    tmp.flush()
    tmp.close()
    sid = str(uuid.uuid4())
    with _lock:
        _sessions[sid] = {
            "path":      tmp.name,
            "expires":   time.time() + _SESSION_TTL,
            "cancelled": False,
        }
    return sid, tmp.name


def _get_path(sid: str) -> str | None:
    """Look up the temp file path for a session_id.

    Args:
        sid: Session identifier.

    Returns:
        Absolute path or None if not found / expired.
    """
    _cleanup()
    with _lock:
        info = _sessions.get(sid)
    if not info:
        return None
    if not os.path.exists(info["path"]):
        return None
    return info["path"]


# ── GET /api/crack/profiles ────────────────────────────────────────────

@crack_bp.route("/profiles", methods=["GET"])
def list_profiles() -> object:
    """Return all available cracking profile descriptors.

    Returns:
        200 with list of profiles.
    """
    cracker = create_cracker()
    return jsonify({"profiles": cracker.profiles()})


# ── POST /api/crack/inspect ────────────────────────────────────────────

@crack_bp.route("/inspect", methods=["POST"])
def inspect() -> object:
    """Upload a SQLite DB and return its forensic structure preview.

    Returns:
        200 with {session_id, tables, users, has_users_table,
                  education, profiles}.
        400 on missing file, oversized file, or parse error.
    """
    if "db_file" not in request.files:
        return jsonify({"error": "No db_file field in request."}), 400

    uploaded = request.files["db_file"]
    if not uploaded.filename:
        return jsonify({"error": "Empty filename."}), 400

    data = uploaded.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        return jsonify({"error": "File too large (max 10 MB)."}), 400

    try:
        sid, db_path = _save_session(data)
        cracker = create_cracker()
        preview = cracker.inspect_db(db_path)
        preview["session_id"] = sid
        return jsonify(preview)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover
        return jsonify({"error": f"Unexpected error: {exc}"}), 500


# ── POST /api/crack/cancel ─────────────────────────────────────────────

@crack_bp.route("/cancel", methods=["POST"])
def cancel() -> object:
    """Signal a running stream to stop at the next checkpoint.

    Query params:
        sid: Session ID of the stream to cancel.

    Returns:
        200 on success.
        404 if session not found.
    """
    sid = request.args.get("sid", "")
    if not sid:
        return jsonify({"error": "Missing sid parameter."}), 400

    with _lock:
        if sid not in _sessions:
            return jsonify({"error": "Session not found."}), 404
        _sessions[sid]["cancelled"] = True

    return jsonify({"message": "Cancellation requested.", "sid": sid})


# ── GET /api/crack/stream ──────────────────────────────────────────────

@crack_bp.route("/stream", methods=["GET"])
def stream() -> object:
    """SSE stream for the password cracking analysis.

    Query params:
        sid:     Session ID returned by POST /inspect.
        profile: One of ``quick``, ``common``, ``breach``.
                 Defaults to ``quick``.
        targets: Comma-separated user IDs to crack. Omit or leave
                 empty to crack all users.

    Returns:
        text/event-stream response.
        400 if sid is missing or unknown.
    """
    sid     = request.args.get("sid", "")
    profile = request.args.get("profile", "quick")
    targets_raw = request.args.get("targets", "")

    if not sid:
        return jsonify({"error": "Missing sid parameter."}), 400

    db_path = _get_path(sid)
    if not db_path:
        return jsonify({
            "error": "Session not found or expired. Re-upload the database."
        }), 400

    # Parse targets — comma-separated user IDs
    targets: list[int] | None = None
    if targets_raw.strip():
        try:
            targets = [
                int(x) for x in targets_raw.split(",")
                if x.strip()
            ]
        except ValueError:
            return jsonify({
                "error": "targets must be comma-separated integers."
            }), 400

    # Reset cancellation flag for this stream run
    with _lock:
        if sid in _sessions:
            _sessions[sid]["cancelled"] = False

    def is_cancelled() -> bool:
        """Check if cancellation was requested for this session."""
        with _lock:
            return _sessions.get(sid, {}).get("cancelled", False)

    def generate() -> Any:
        cracker = create_cracker()
        try:
            for event in cracker.stream_analyze(
                db_path, profile, targets, is_cancelled
            ):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as exc:  # pragma: no cover
            err = json.dumps({"type": "error", "message": str(exc)})
            yield f"data: {err}\n\n"
        finally:
            # Clean up temp file after stream ends (complete or cancel)
            try:
                if os.path.exists(db_path):
                    os.unlink(db_path)
            except OSError:
                pass
            with _lock:
                _sessions.pop(sid, None)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
