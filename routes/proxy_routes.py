"""Reverse proxy from the gateway's ``/api`` tree to the local Ollama process.

Ollama's generate and chat endpoints answer with a stream of newline-delimited
JSON. The body is forwarded chunk by chunk via ``httpx`` streaming, not
collected into one buffer first. Authentication, roles, and the per-user
quota have already run in ``IAMMiddleware``; the dependency below repeats the
login check so the route stays protected if the middleware is ever removed.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from auth import get_current_user, requires_admin_api
from config import OLLAMA_BASE_URL

logger = logging.getLogger("iam.proxy")

router = APIRouter(tags=["ollama-proxy"])

# Hop-by-hop and framing headers must not be copied blindly. The gateway
# forces identity encoding so NDJSON is not gzip-decoded halfway through.
_REQUEST_HEADERS_TO_DROP = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "cookie",
    "authorization",
    "accept-encoding",
}
_RESPONSE_HEADERS_TO_DROP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "content-type",
    "server",
    "date",
}


def _upstream_url(request: Request, path: str) -> str:
    """Build the Ollama URL for a gateway path that is already under ``/api``."""
    if path.startswith("/") or any(part == ".." for part in path.split("/")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid API path.",
        )
    target = f"{OLLAMA_BASE_URL}/api/{path}"
    if request.url.query:
        target = f"{target}?{request.url.query}"
    return target


def _forward_headers(request: Request) -> dict[str, str]:
    """Copy client headers that Ollama needs, and ask for an uncompressed stream."""
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in _REQUEST_HEADERS_TO_DROP
    }
    headers["accept-encoding"] = "identity"
    return headers


async def _stream_upstream(upstream: httpx.Response) -> AsyncIterator[bytes]:
    """Yield raw upstream bytes and always release the upstream connection."""
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    finally:
        await upstream.aclose()


@router.api_route(
    "/api/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
    summary="Forward a request to the local Ollama API",
)
async def proxy_ollama(
    path: str,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> StreamingResponse:
    """Stream one authenticated request to Ollama and stream the answer back.

    Model management paths are checked again here. The middleware already
    rejects them for a normal user; this keeps the route correct on its own.
    """
    gateway_path = f"/api/{path}"
    if requires_admin_api(gateway_path) and user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required.",
        )

    client: httpx.AsyncClient | None = getattr(request.app.state, "http_client", None)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="HTTP client is not ready.",
        )

    body = await request.body()
    upstream_request = client.build_request(
        request.method,
        _upstream_url(request, path),
        headers=_forward_headers(request),
        content=body if body else None,
    )
    try:
        upstream = await client.send(upstream_request, stream=True)
    except httpx.TimeoutException as exc:
        logger.warning("Timed out waiting for Ollama at %s", OLLAMA_BASE_URL)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Ollama did not respond in time.",
        ) from exc
    except httpx.TransportError as exc:
        # ConnectError covers a stopped Ollama. Protocol and read errors cover
        # a keep-alive connection that died after Ollama exited.
        logger.warning("Ollama is unreachable at %s (%s)", OLLAMA_BASE_URL, exc.__class__.__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Ollama is not reachable at {OLLAMA_BASE_URL}. "
                "Start it with `ollama serve`."
            ),
        ) from exc

    logger.info(
        "Proxied %s /api/%s for %s -> HTTP %s",
        request.method,
        path,
        user["username"],
        upstream.status_code,
    )
    response_headers = {
        name: value
        for name, value in upstream.headers.items()
        if name.lower() not in _RESPONSE_HEADERS_TO_DROP
    }
    response_headers["cache-control"] = "no-cache"
    response_headers["x-accel-buffering"] = "no"
    return StreamingResponse(
        _stream_upstream(upstream),
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )
