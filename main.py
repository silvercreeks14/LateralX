"""
LateralX — FastAPI entry point.
Run with: uvicorn main:app --reload
"""

import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from backend.api.routes import router
from backend.db.models import init_db, SessionLocal, UserModel
from backend.api.auth import get_password_hash


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects OWASP-recommended security headers into every response.
    - nosniff   : prevents MIME-type sniffing attacks
    - DENY      : blocks clickjacking via iframes
    - XSS       : legacy XSS filter for older browsers
    - CSP       : restricts resource loading to same-origin only
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://cdn.jsdelivr.net; "
            "connect-src 'self'"
        )
        return response


app = FastAPI(
    title="LateralX API",
    description="Post-incident AD forensic investigation platform",
    version="1.0.0",
)

# Security headers on every response — registered before CORS so headers are
# always present even on preflight rejections
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {"status": "running", "docs": "/docs"}


def _bootstrap_admin() -> None:
    """Create the default admin account if no users exist."""
    db = SessionLocal()
    try:
        if db.query(UserModel).count() == 0:
            password = os.getenv("ADMIN_PASSWORD", "ForensicAdmin2024!")
            db.add(UserModel(
                username="admin",
                hashed_password=get_password_hash(password),
                role="admin",
            ))
            db.commit()
    finally:
        db.close()


# Initialise the SQLite database and seed default admin on startup
init_db()
_bootstrap_admin()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        # Only watch the backend Python source — keeps db/pkl/wal files from
        # triggering spurious reloads. watchfiles (installed) uses native OS
        # filesystem events instead of the polling StatReload used before,
        # which avoids the Windows mtime-race that caused continuous reload loops.
        reload_dirs=["backend"],
    )
