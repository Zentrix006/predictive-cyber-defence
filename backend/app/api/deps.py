"""
API Dependencies
"""
from typing import Optional, Dict, Any
from uuid import UUID
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError, jwt

from app.core.config import settings
from app.core.database import get_db as get_db_session
from app.core.security import decode_token
from app.models.asset import Asset


security = HTTPBearer(auto_error=False)


async def get_db() -> AsyncSession:
    """Get database session."""
    async for session in get_db_session():
        yield session


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """Get current authenticated user from JWT token."""
    if not credentials:
        # This bypass is intentionally explicit. DEBUG on its own must never
        # turn an unauthenticated request into an administrator.
        if settings.DEBUG and settings.DEV_AUTH_BYPASS:
            return {"sub": "dev-user", "roles": ["admin"]}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if payload.get("type") != "access" or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "sub": payload["sub"],
        "roles": payload.get("roles", []),
        "permissions": payload.get("permissions", []),
        "elevated": bool(payload.get("elevated", False)),
    }


async def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get current active user."""
    if not current_user.get("sub"):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_roles(*roles: str):
    """Dependency to require specific roles."""
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_roles = current_user.get("roles", [])
        if not any(role in user_roles for role in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user
    return role_checker
