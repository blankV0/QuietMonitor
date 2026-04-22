"""
QuietMonitor – routes/auth.py
──────────────────────────────
Authentication endpoints.

POST /login    – exchange credentials for a JWT token
GET  /me       – return the currently authenticated user's profile
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import LoginRequest, TokenResponse, UserResponse
from ..auth import verify_password, create_access_token, get_current_user
from ..models import User

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    """
    Validate username and password.
    Returns a JWT access token on success.
    The token must be sent as `Authorization: Bearer <token>` on all
    protected routes.
    """
    user = db.query(User).filter(User.username == credentials.username).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    token = create_access_token(data={"sub": user.username, "role": user.role})
    return TokenResponse(access_token=token, token_type="bearer", role=user.role)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Return the profile of the currently authenticated user."""
    return current_user
