"""Single-admin JWT authentication.

Credentials and signing secret come from environment variables — there is no
user table. Set ADMIN_USERNAME / ADMIN_PASSWORD / JWT_SECRET to enable auth.
Set AUTH_ENABLED=false to disable it entirely (e.g. behind a trusted proxy).
"""
import hmac
import logging
import os
import time

import bcrypt
import jwt

logger = logging.getLogger(__name__)

ROLE_ADMIN    = "admin"
ROLE_READONLY = "readonly"

AUTH_ENABLED       = os.getenv("AUTH_ENABLED", "true").lower() not in ("false", "0", "no")
ADMIN_USERNAME     = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD     = os.getenv("ADMIN_PASSWORD", "")
JWT_SECRET         = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM      = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "720"))  # 12h

# Only paths under this prefix are guarded; everything else (the SPA, /health,
# static assets, openapi.json) stays public.
_PROTECTED_PREFIX = "/api/"
# /api/ paths that must remain reachable without a token.
_EXEMPT = {"/api/auth/login", "/api/auth/config"}


class AuthError(Exception):
    """Raised when a token is missing, malformed, or expired."""

    def __init__(self, detail: str = "Not authenticated"):
        self.detail = detail
        super().__init__(detail)


def is_configured() -> bool:
    """True when auth can actually issue/verify tokens."""
    return bool(ADMIN_PASSWORD and JWT_SECRET)


def requires_auth(path: str) -> bool:
    if not AUTH_ENABLED:
        return False
    if not path.startswith(_PROTECTED_PREFIX):
        return False
    return path not in _EXEMPT


def authenticate_env(username: str, password: str) -> bool:
    """Constant-time check against the env-configured bootstrap admin.

    Always accepted (as admin) so a misconfigured/empty users table can never
    lock everyone out.
    """
    if not is_configured():
        logger.warning("Login attempt but auth is not configured (ADMIN_PASSWORD/JWT_SECRET missing)")
        return False
    user_ok = hmac.compare_digest(username or "", ADMIN_USERNAME)
    pass_ok = hmac.compare_digest(password or "", ADMIN_PASSWORD)
    return user_ok and pass_ok


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str, role: str) -> str:
    now = int(time.time())
    payload = {"sub": subject, "role": role, "iat": now, "exp": now + JWT_EXPIRE_MINUTES * 60}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    if not token:
        raise AuthError()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.PyJWTError:
        raise AuthError("Invalid token")


def token_from_header(authorization: str | None) -> str:
    """Extract a bearer token from an Authorization header value."""
    if not authorization:
        return ""
    scheme, _, credentials = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return credentials.strip()
