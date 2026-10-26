"""Administrator dashboard and the user-management API."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from auth import PublicUser, get_optional_user, public_user, require_admin
from config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS, ROLE_ADMIN
from database import count_admins, delete_user, get_user_by_id, list_users, update_user_role
from routes.auth_routes import render_page

router = APIRouter(tags=["admin"])


class RoleUpdate(BaseModel):
    """New role for an existing account."""

    role: Literal["admin", "user"]


def _load_target(user_id: int) -> dict[str, Any]:
    """Return a stored account or raise 404."""
    record = get_user_by_id(user_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return record


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
def admin_page(request: Request) -> Response:
    """Render the user table for administrators and a 403 page for everyone else."""
    user = get_optional_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user["role"] != ROLE_ADMIN:
        return render_page(
            request,
            "forbidden.html",
            {"user": user},
            status_code=status.HTTP_403_FORBIDDEN,
        )
    users = [public_user(record) for record in list_users()]
    return render_page(
        request,
        "admin.html",
        {
            "user": user,
            "users": users,
            "rate_limit_requests": RATE_LIMIT_REQUESTS,
            "rate_limit_window": RATE_LIMIT_WINDOW_SECONDS,
        },
    )


@router.get("/admin/users", response_model=list[PublicUser])
def get_users(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
    """List every account. Password hashes are not included."""
    return [public_user(record) for record in list_users()]


@router.put("/admin/users/{user_id}/role", response_model=PublicUser)
def change_role(
    user_id: int,
    payload: RoleUpdate,
    actor: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Promote a user to admin or demote an admin to user.

    The signed-in administrator cannot change their own role, and the last
    remaining administrator cannot be demoted. Both rules keep the demo from
    locking the dashboard.
    """
    target = _load_target(user_id)
    if target["id"] == actor["id"] and payload.role != target["role"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role.",
        )
    if target["role"] == ROLE_ADMIN and payload.role != ROLE_ADMIN and count_admins() <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot demote the last admin.",
        )
    updated = update_user_role(user_id, payload.role)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return public_user(updated)


@router.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_user(
    user_id: int,
    actor: dict[str, Any] = Depends(require_admin),
) -> Response:
    """Delete an account. Self-deletion and deletion of the last admin are refused."""
    target = _load_target(user_id)
    if target["id"] == actor["id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account.",
        )
    if target["role"] == ROLE_ADMIN and count_admins() <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the last admin.",
        )
    delete_user(user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
