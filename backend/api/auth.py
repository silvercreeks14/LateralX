"""
Authentication & authorisation helpers — v4.

MFA: TOTP only (Google Authenticator / any RFC 6238-compatible app).
  Activated per-admin via POST /api/admin/totp/setup + /api/admin/totp/verify.
  Admin endpoints protected by require_mfa will return HTTP 403 until TOTP
  is configured, prompting the admin to complete setup first.
"""

import os
import io
import base64
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

import pyotp
import qrcode

from backend.db.models import get_db, UserModel

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-in-production-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 4   # 4-hour sliding sessions

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# ── Password helpers ───────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ── JWT helpers ────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ── User resolution ────────────────────────────────────────────────────────────

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserModel:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exc
    return user


def require_admin(current_user: UserModel = Depends(get_current_user)) -> UserModel:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


# ── TOTP (Google Authenticator) helpers ───────────────────────────────────────

_APP_NAME = "FIP Forensic Intelligence"


def generate_totp_secret() -> str:
    """Return a new random 32-char base32 TOTP secret."""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str) -> str:
    """Return the otpauth:// URI for provisioning an authenticator app."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=_APP_NAME)


def get_totp_qr_png_b64(username: str, secret: str) -> str:
    """Return a base64-encoded PNG of the QR code for the given TOTP secret."""
    uri = get_totp_uri(username, secret)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against the secret.
    valid_window=1 allows ±30s clock drift.
    """
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code.strip(), valid_window=1)
    except Exception:
        return False


# ── require_mfa dependency (TOTP only) ────────────────────────────────────────

def require_mfa(
    request: Request,
    current_user: UserModel = Depends(require_admin),
) -> UserModel:
    """
    FastAPI dependency for admin endpoints that require TOTP confirmation.

    First call (no X-MFA-Code header):
      → HTTP 202 with mfa_required, prompting the client to show the code input.

    Second call (with X-MFA-Code: <totp_code>):
      → Verifies against the admin's TOTP secret; proceeds if correct.

    If TOTP has not been configured yet the endpoint returns HTTP 403 with
    a message directing the admin to the TOTP setup panel.
    """
    if not (current_user.totp_enabled and current_user.totp_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "TOTP not configured. Set up Google Authenticator in the admin "
                "panel (Settings → TOTP Setup) before using this feature."
            ),
        )

    submitted = request.headers.get("X-MFA-Code")
    if not submitted:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={
                "mfa_required": True,
                "totp": True,
                "message": "Enter the 6-digit code from your authenticator app.",
            },
        )
    if not verify_totp(current_user.totp_secret, submitted):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid TOTP code. Check your authenticator app and try again.",
        )
    return current_user
