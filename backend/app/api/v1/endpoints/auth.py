"""Local console authentication: read-only guest and privileged administrator."""
from __future__ import annotations

import secrets
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import create_access_token, verify_password

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


def _token(subject: str, roles: list[str], elevated: bool, minutes: int) -> str:
    return create_access_token(
        uuid5(NAMESPACE_URL, f"pcd-console:{subject}"),
        expires_delta=timedelta(minutes=minutes),
        additional_claims={"roles": roles, "elevated": elevated},
    )


def _response(token: str, username: str, roles: list[str], elevated: bool, expires_minutes: int) -> dict:
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": username,
        "roles": roles,
        "elevated": elevated,
        "expires_in": expires_minutes * 60,
    }


@router.post("/login")
async def login(body: LoginRequest):
    """Authenticate the configured operator; configuration must supply a bcrypt hash."""
    configured_username = settings.OPERATOR_USERNAME
    configured_hash = settings.OPERATOR_PASSWORD_HASH
    valid = bool(configured_username and configured_hash) and secrets.compare_digest(body.username, configured_username)
    valid = valid and verify_password(body.password, configured_hash)
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    # The local console administrator is privileged at sign-in.  There is no
    # separate step-up state to drift out of sync with the UI or QR demo.
    token = _token(configured_username, ["admin"], True, settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return _response(token, configured_username, ["admin"], True, settings.ACCESS_TOKEN_EXPIRE_MINUTES)


@router.post("/guest")
async def guest_login():
    """Issue a short-lived read-only session. Mutating requests are blocked globally."""
    token = _token("guest", ["viewer"], False, settings.GUEST_TOKEN_EXPIRE_MINUTES)
    return _response(token, "guest", ["viewer"], False, settings.GUEST_TOKEN_EXPIRE_MINUTES)


@router.get("/session")
async def session(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["sub"], "roles": current_user.get("roles", []), "elevated": bool(current_user.get("elevated", False))}
