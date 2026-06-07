"""Application entry point.

Run with:
    uv run python run.py

Or for development:
    uv run flask --app run:app run --debug
"""

from src.api.app import create_app

app = create_app()

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=app.config.get("DEBUG", False))
