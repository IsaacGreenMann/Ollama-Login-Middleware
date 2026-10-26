"""Runtime configuration for the Ollama IAM gateway.

Values come from the environment when they are set. Paths and the JWT
signing key fall back to local files so a demo machine can start with
``uvicorn main:app`` and no extra setup. There is no shared production
secret checked into the source tree.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Local Ollama API. The gateway never edits Ollama; it only forwards to this URL.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")

DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "iam.db"))

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))
JWT_ISSUER = "ollama-iam"
COOKIE_NAME = "access_token"
# Keep this off for the local http://127.0.0.1 demo. Set it when serving over HTTPS.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}

# Per-user quota enforced before a request is proxied. The rate-limiting
# extension can replace the in-memory limiter without changing this contract.
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLES = (ROLE_ADMIN, ROLE_USER)

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"

# Model lifecycle operations. Chat and generate stay available to every role.
ADMIN_ONLY_API_PREFIXES = ("/api/pull", "/api/delete", "/api/push", "/api/copy")


def load_jwt_secret() -> str:
    """Return the HMAC secret used to sign access tokens.

    ``JWT_SECRET`` wins when it is set. Otherwise the key is read from
    ``.jwt_secret`` beside this file, and created there on the first launch.
    """
    configured = os.environ.get("JWT_SECRET", "").strip()
    if configured:
        return configured

    secret_path = BASE_DIR / ".jwt_secret"
    if secret_path.is_file():
        stored = secret_path.read_text(encoding="utf-8").strip()
        if stored:
            return stored

    generated = secrets.token_urlsafe(48)
    secret_path.write_text(generated + "\n", encoding="utf-8")
    print(
        f"Wrote a new JWT signing key to {secret_path}. Set JWT_SECRET to override it.",
        flush=True,
    )
    return generated


JWT_SECRET = load_jwt_secret()
