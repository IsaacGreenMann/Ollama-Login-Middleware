"""Ollama IAM gateway application entry point.

Start it from this directory:

    uvicorn main:app --reload --port 8080

The process listens on port 8080 and forwards ``/api/*`` to Ollama after
authentication, role checks, and the per-user rate limit.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from auth import seed_default_admin
from config import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    OLLAMA_BASE_URL,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    STATIC_DIR,
)
from database import init_db
from middleware import IAMMiddleware
from routes.admin_routes import router as admin_router
from routes.auth_routes import router as auth_router
from routes.proxy_routes import router as proxy_router


def configure_logging() -> None:
    """Show gateway logs under uvicorn, which leaves the root logger quiet."""
    gateway_logger = logging.getLogger("iam")
    gateway_logger.setLevel(logging.INFO)
    if gateway_logger.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    gateway_logger.addHandler(handler)
    gateway_logger.propagate = False


configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Prepare the database, the demo admin, and the shared Ollama HTTP client."""
    init_db()
    if seed_default_admin():
        print("Created default administrator because the user database was empty.", flush=True)
        print(f"  username: {DEFAULT_ADMIN_USERNAME}", flush=True)
        print(f"  password: {DEFAULT_ADMIN_PASSWORD}", flush=True)
        print("Use this account for the local demo, then promote another admin.", flush=True)
    # read=None keeps long /api/generate and /api/chat streams open.
    timeout = httpx.Timeout(connect=5.0, read=None, write=30.0, pool=5.0)
    app.state.http_client = httpx.AsyncClient(timeout=timeout, trust_env=False)
    print(
        "Ollama IAM gateway ready. "
        f"Proxying {OLLAMA_BASE_URL}. "
        f"Rate limit {RATE_LIMIT_REQUESTS} requests / {RATE_LIMIT_WINDOW_SECONDS}s per user.",
        flush=True,
    )
    yield
    await app.state.http_client.aclose()


app = FastAPI(
    title="Ollama IAM Gateway",
    description=(
        "Identity and access management reverse proxy for a local Ollama server. "
        "Sign in to receive a JWT, then call /api/* through this gateway."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(IAMMiddleware)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(proxy_router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)
