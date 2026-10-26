"""Login, registration, logout, and the signed-in home page."""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator

from auth import (
    PublicUser,
    authenticate_user,
    clear_auth_cookie,
    create_access_token,
    get_current_user,
    get_optional_user,
    hash_password,
    public_user,
    set_auth_cookie,
)
from config import (
    OLLAMA_BASE_URL,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    ROLE_ADMIN,
    ROLE_USER,
    TEMPLATES_DIR,
)
from database import create_user

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

_USERNAME = re.compile(r"[A-Za-z0-9_]{3,32}")


class LoginRequest(BaseModel):
    """Credentials submitted by the login form or an API client."""

    username: str
    password: str

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        """Trim surrounding space so a padded login still finds the account."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Username is required.")
        return cleaned

    @field_validator("password")
    @classmethod
    def require_password(cls, value: str) -> str:
        """Reject an empty password before the bcrypt compare."""
        if value == "":
            raise ValueError("Password is required.")
        return value


class RegisterRequest(BaseModel):
    """New account. Role is not accepted here, so nobody can self-assign admin."""

    username: str
    password: str

    @field_validator("username")
    @classmethod
    def check_username(cls, value: str) -> str:
        """Keep usernames short and safe to show in the admin table."""
        cleaned = value.strip()
        if _USERNAME.fullmatch(cleaned) is None:
            raise ValueError(
                "Username must be 3-32 characters and use only letters, digits, and underscore."
            )
        return cleaned

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        """Enforce the bcrypt 72-byte input limit up front."""
        if len(value) < 6:
            raise ValueError("Password must be at least 6 characters.")
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 bytes.")
        return value


class TokenResponse(BaseModel):
    """JWT payload returned to API clients. The browser also receives the cookie."""

    access_token: str
    token_type: str = "bearer"
    user: PublicUser


class MessageResponse(BaseModel):
    """Short status message."""

    detail: str


def render_page(
    request: Request,
    template_name: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """Render a Jinja page, always passing the request Starlette requires."""
    payload = {"request": request, **(context or {})}
    return templates.TemplateResponse(
        request,
        template_name,
        payload,
        status_code=status_code,
    )


def _home_for(user: dict[str, Any]) -> str:
    """Pick the page a user sees immediately after signing in."""
    if user["role"] == ROLE_ADMIN:
        return "/admin"
    return "/"


def _issue_session(response: Response, user: dict[str, Any]) -> TokenResponse:
    """Set the login cookie and build the JSON body that carries the same JWT."""
    token = create_access_token(user)
    set_auth_cookie(response, token)
    return TokenResponse(access_token=token, user=PublicUser.model_validate(user))


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request) -> Response:
    """Show the signed-in landing page, or send anonymous visitors to login."""
    user = get_optional_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return render_page(
        request,
        "home.html",
        {
            "user": user,
            "ollama_url": OLLAMA_BASE_URL,
            "rate_limit_requests": RATE_LIMIT_REQUESTS,
            "rate_limit_window": RATE_LIMIT_WINDOW_SECONDS,
        },
    )


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request) -> Response:
    """Render the login card. An existing session skips the form."""
    user = get_optional_user(request)
    if user is not None:
        return RedirectResponse(url=_home_for(user), status_code=status.HTTP_303_SEE_OTHER)
    return render_page(request, "login.html", {"user": None})


@router.get("/register", response_class=HTMLResponse, include_in_schema=False)
def register_page(request: Request) -> Response:
    """Render the registration card."""
    user = get_optional_user(request)
    if user is not None:
        return RedirectResponse(url=_home_for(user), status_code=status.HTTP_303_SEE_OTHER)
    return render_page(request, "register.html", {"user": None})


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, response: Response) -> TokenResponse:
    """Create a normal user account and sign them in immediately.

    Registration cannot choose a role. New accounts are always ``user`` until
    an administrator promotes them.
    """
    try:
        record = create_user(payload.username, hash_password(payload.password), ROLE_USER)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That username is already taken.",
        ) from exc
    return _issue_session(response, public_user(record))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, response: Response) -> TokenResponse:
    """Validate credentials, set an HTTP-only cookie, and return the JWT.

    The cookie covers the browser. The JSON body covers scripts and curl.
    """
    user = authenticate_user(payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    return _issue_session(response, user)


@router.post("/logout", response_model=MessageResponse)
def logout(response: Response) -> MessageResponse:
    """Clear the login cookie. Safe to call when no one is signed in."""
    clear_auth_cookie(response)
    return MessageResponse(detail="Logged out.")


@router.get("/me", response_model=PublicUser)
def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Return the account attached to the current cookie or bearer token."""
    return user
