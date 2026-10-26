"""SQLite storage for gateway accounts.

The schema is one table on purpose. Account operations are short, so they
use the standard library ``sqlite3`` driver directly instead of an ORM.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from config import DATABASE_PATH, ROLES


def _now_utc() -> str:
    """Return a UTC timestamp that is easy to read in the admin table."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _user_from_row(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a SQLite row into a plain dictionary.

    The password hash stays in this dictionary for the login check. Route
    handlers strip it before a user record reaches a response or a template.
    """
    return {
        "id": row["id"],
        "username": row["username"],
        "password_hash": row["password_hash"],
        "role": row["role"],
        "created_at": row["created_at"],
    }


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Open a connection that commits on success and always closes."""
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    """Create the users table if this database does not have it yet."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                created_at TEXT NOT NULL
            )
            """
        )


def count_users() -> int:
    """Return how many accounts are stored."""
    with get_connection() as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM users").fetchone()
    return int(row["total"])


def count_admins() -> int:
    """Return how many accounts currently have the admin role."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM users WHERE role = 'admin'"
        ).fetchone()
    return int(row["total"])


def create_user(username: str, password_hash: str, role: str) -> dict[str, Any]:
    """Insert an account and return the stored row, including the password hash.

    Raises:
        ValueError: ``role`` is not one of the two supported roles.
        sqlite3.IntegrityError: the username is already taken.
    """
    if role not in ROLES:
        raise ValueError("role must be 'admin' or 'user'")
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, password_hash, role, _now_utc()),
        )
        row = connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    return _user_from_row(row)


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    """Return one account by primary key, or None when it does not exist."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if row is None:
        return None
    return _user_from_row(row)


def get_user_by_username(username: str) -> dict[str, Any] | None:
    """Return one account by username, ignoring letter case."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    return _user_from_row(row)


def list_users() -> list[dict[str, Any]]:
    """Return every account, oldest first."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM users ORDER BY id ASC"
        ).fetchall()
    return [_user_from_row(row) for row in rows]


def update_user_role(user_id: int, role: str) -> dict[str, Any] | None:
    """Change an account's role. Returns the updated row, or None if missing.

    Raises:
        ValueError: ``role`` is not one of the two supported roles.
    """
    if role not in ROLES:
        raise ValueError("role must be 'admin' or 'user'")
    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, user_id),
        )
        if cursor.rowcount == 0:
            return None
        row = connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return _user_from_row(row)


def delete_user(user_id: int) -> bool:
    """Delete an account. Returns True when a row was removed."""
    with get_connection() as connection:
        cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0
