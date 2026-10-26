"""Security pipeline for proxied Ollama requests.

Every ``/api/*`` call passes through three gates, in this order:

1. Authenticate the JWT from the Authorization header or the login cookie.
2. Authorize the role. Model pull, delete, push, and copy require admin.
3. Consume one unit of that user's rate-limit window.

The request is then handed to ``routes/proxy_routes.py``. Forwarding is not
done inside this middleware. Starlette's ``BaseHTTPMiddleware`` buffers
response bodies, which would break Ollama's streaming NDJSON. This class is
plain ASGI middleware so those chunks stay streamed.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from auth import requires_admin_api, resolve_user_from_token, token_from_header_values
from rate_limiter import RateLimitDecision, rate_limiter

logger = logging.getLogger("iam.middleware")


def _header_map(scope: Scope) -> dict[str, str]:
    """Return request headers as a case-insensitive dictionary of strings."""
    values: dict[str, str] = {}
    for name, value in scope.get("headers", []):
        values[name.decode("latin-1").lower()] = value.decode("latin-1")
    return values


async def _send_json(
    send: Send,
    status_code: int,
    detail: str,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    """Send a small JSON error and stop the request before it reaches Ollama."""
    body = json.dumps({"detail": detail}).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status_code, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _annotate_rate_limit(send: Send, decision: RateLimitDecision) -> Send:
    """Add quota headers to the downstream response without buffering its body."""

    started = False

    async def send_with_limits(message: Message) -> None:
        nonlocal started
        if message["type"] == "http.response.start" and not started:
            started = True
            headers = list(message.get("headers") or [])
            headers.append((b"x-ratelimit-limit", str(decision.limit).encode("ascii")))
            headers.append(
                (b"x-ratelimit-remaining", str(decision.remaining).encode("ascii"))
            )
            message = {**message, "headers": headers}
        await send(message)

    return send_with_limits


class IAMMiddleware:
    """Authenticate, authorize, and rate limit ``/api/*`` before the proxy route."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Run the security pipeline for Ollama API traffic and pass other requests through."""
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope["path"]
        headers = _header_map(scope)
        token = token_from_header_values(
            headers.get("authorization"),
            headers.get("cookie"),
        )
        user = resolve_user_from_token(token) if token else None
        if user is None:
            logger.info("Denied %s %s: unauthenticated", method, path)
            await _send_json(
                send,
                401,
                "Authentication required." if not token else "Invalid or expired token.",
                extra_headers=[(b"www-authenticate", b"Bearer")],
            )
            return

        if requires_admin_api(path) and user["role"] != "admin":
            logger.info(
                "Denied %s %s: user %s is not an admin",
                method,
                path,
                user["username"],
            )
            await _send_json(send, 403, "Admin role required.")
            return

        decision = rate_limiter.check(str(user["id"]))
        if not decision.allowed:
            logger.info(
                "Denied %s %s: user %s exceeded the rate limit",
                method,
                path,
                user["username"],
            )
            await _send_json(
                send,
                429,
                "Rate limit exceeded for this user.",
                extra_headers=[
                    (b"retry-after", str(decision.retry_after).encode("ascii")),
                    (b"x-ratelimit-limit", str(decision.limit).encode("ascii")),
                    (b"x-ratelimit-remaining", b"0"),
                ],
            )
            return

        state: dict[str, Any] = scope.setdefault("state", {})
        state["user"] = user
        logger.info(
            "Allow %s %s for %s (%s), remaining=%s",
            method,
            path,
            user["username"],
            user["role"],
            decision.remaining,
        )
        await self.app(scope, receive, _annotate_rate_limit(send, decision))
