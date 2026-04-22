"""
QuietMonitor – auth.py
──────────────────────
Handles all authentication concerns:
  - Password hashing with bcrypt via passlib
  - JWT creation and verification with python-jose
  - FastAPI dependency `get_current_user` for protected routes
  - FastAPI dependency `require_admin` for admin-only routes
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import os

from .database import get_db
from . import models

load_dotenv()

# ── Configuration ────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_key")
ALGORITHM  = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# ── Passlib context for bcrypt hashing ───────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── OAuth2 scheme – expects "Bearer <token>" in Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# ─────────────────────────────────────────────────────────────────
# PASSWORD UTILITIES
# ─────────────────────────────────────────────────────────────────
def hash_password(plain_password: str) -> str:
    """Return the bcrypt hash of a plain-text password."""
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if plain_password matches the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ─────────────────────────────────────────────────────────────────
# JWT UTILITIES
# ─────────────────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT token.
    `data` should contain at least {"sub": username, "role": role}.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT token, raising HTTPException on failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


# ─────────────────────────────────────────────────────────────────
# FASTAPI DEPENDENCIES
# ─────────────────────────────────────────────────────────────────
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    """
    Dependency that extracts and validates the JWT from the Authorization
    header, then fetches the matching user from the database.
    Raises 401 if the token is invalid or the user does not exist.
    """
    payload  = decode_token(token)
    username = payload.get("sub")
    user     = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or unknown user")
    return user


def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
    """
    Dependency that builds on get_current_user and additionally checks
    that the caller has the 'admin' role. Raises 403 otherwise.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user
