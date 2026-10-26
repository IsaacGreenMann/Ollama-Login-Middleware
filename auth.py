"""Password hashing, JWT sessions, and the current-user dependency.

A token identifies the account (``uid``). The role used for authorization is
always reloaded from SQLite, so a demotion takes effect on the next request
even if an older token is still inside its expiry window.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote

import jwt
from fastapi import HTTPException, Request, status
from passlib.context import CryptContext
from pydantic import BaseModel

from config import (
    ADMIN_ONLY_API_PREFIXES,
    COOKIE_NAME,
    COOKIE_SECURE,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    JWT_ALGORITHM,
    JWT_EXPIRE_HOURS,
    JWT_ISSUER,
    JWT_SECRET,
    ROLE_ADMIN,
)
from database import count_users, create_user, get_user_by_id, get_user_by_username

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Verification is deliberately slow. When the username is unknown we still
# run a compare against this hash so the response time does not reveal
# whether the account exists.
_DUMMY_PASSWORD_HASH = pwd_context.hash("not-a-real-account")


class PublicUser(BaseModel):
    """Account fields that are safe to show in JSON and HTML."""

    id: int
    username: str
    role: str
    created_at: str


def public_user(record: dict[str, Any]) -> dict[str, Any]:
    """Drop the password hash and any other private columns."""
    return PublicUser.model_validate(record).model_dump()


def hash_password(password: str) -> str:
    """Hash a password with bcrypt. The plaintext is never stored."""
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return True when ``password`` matches the stored bcrypt hash."""
    try:
        return pwd_context.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    """Validate credentials and return the public user, or None on failure."""
    record = get_user_by_username(username)
    password_hash = record["password_hash"] if record else _DUMMY_PASSWORD_HASH
    password_matches = verify_password(password, password_hash)
    if record is None or not password_matches:
        return None
    return public_user(record)


def create_access_token(user: dict[str, Any]) -> str:
    """Sign a JWT for ``user``. The token expires after ``JWT_EXPIRE_HOURS``."""
    issued_at = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "sub": user["username"],
        "uid": user["id"],
        "iat": issued_at,
        "exp": issued_at + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    """Return the JWT payload, or None when the token is missing, forged, or expired.

    The accepted algorithm list is fixed, which rejects unsigned ``alg=none`` tokens.
    """
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "sub", "uid", "iss"]},
        )
    except jwt.PyJWTError:
        return None


def resolve_user_from_token(token: str) -> dict[str, Any] | None:
    """Load the live account for a token.

    Returns None when the signature is bad, the account was deleted, or the
    username in the token no longer matches the database.
    """
    payload = decode_access_token(token)
    if payload is None:
        return None
    user_id = payload.get("uid")
    if not isinstance(user_id, int):
        return None
    record = get_user_by_id(user_id)
    if record is None or record["username"] != payload.get("sub"):
        return None
    return public_user(record)


def token_from_header_values(
    authorization: str | None,
    cookie_header: str | None,
) -> str | None:
    """Read a JWT from a Bearer header, then from the access-token cookie.

    API clients send the header. The browser login page relies on the cookie,
    which JavaScript cannot read because it is HTTP-only.
    """
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip()
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name == COOKIE_NAME and value:
            return unquote(value)
    return None


def token_from_request(request: Request) -> str | None:
    """Read the JWT attached to an incoming FastAPI request."""
    return token_from_header_values(
        request.headers.get("authorization"),
        request.headers.get("cookie"),
    )


def set_auth_cookie(response: Any, token: str) -> None:
    """Store the JWT in an HTTP-only cookie so the browser pages stay signed in."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=JWT_EXPIRE_HOURS * 3600,
        path="/",
    )


def clear_auth_cookie(response: Any) -> None:
    """Remove the authentication cookie."""
    response.delete_cookie(key=COOKIE_NAME, path="/")


def get_current_user(request: Request) -> dict[str, Any]:
    """FastAPI dependency that returns the authenticated public user.

    The API middleware may already have resolved the same token. Reusing that
    result avoids a second database read on proxied Ollama calls.
    """
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    token = token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = resolve_user_from_token(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_optional_user(request: Request) -> dict[str, Any] | None:
    """Return the signed-in user for HTML pages, or None if the visitor is anonymous.

    A bad cookie is treated as signed-out rather than as an error page, so a
    stale browser session can still open the login form.
    """
    token = token_from_request(request)
    if not token:
        return None
    return resolve_user_from_token(token)


def require_admin(request: Request) -> dict[str, Any]:
    """FastAPI dependency that allows only administrator accounts."""
    user = get_current_user(request)
    if user["role"] != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required.",
        )
    return user


def seed_default_admin() -> bool:
    """Create username ``admin`` / password ``admin`` when the database is empty.

    Returns True only on the call that inserts the account, which is the
    signal ``main`` uses to print the demo credentials once.
    """
    if count_users() > 0:
        return False
    try:
        create_user(
            DEFAULT_ADMIN_USERNAME,
            hash_password(DEFAULT_ADMIN_PASSWORD),
            ROLE_ADMIN,
        )
    except sqlite3.IntegrityError:
        return False
    return True


def requires_admin_api(path: str) -> bool:
    """Return True when ``path`` is an Ollama model-management endpoint.

    ``path`` must be the gateway path, including the ``/api`` prefix.
    """
    clean = path.split("?", 1)[0].rstrip("/") or "/"
    return any(
        clean == prefix or clean.startswith(prefix + "/")
        for prefix in ADMIN_ONLY_API_PREFIXES
    )
