"""
QuietMonitor – main.py
───────────────────────
FastAPI application entry point.

Responsibilities:
  1. Create all database tables on startup (if they don't exist).
  2. Seed a default admin user on first run.
  3. Register all route modules with their URL prefixes.
  4. Configure CORS so the React frontend can call the API.
  5. Expose the Uvicorn server command for local development.

Run with:
    uvicorn app.main:app --reload --port 8000
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from .database import engine, SessionLocal
from .models import Base, User
from .auth import hash_password
from .routes import machines as machines_router
from .routes import auth as auth_router
from .routes import alerts as alerts_router
from .routes import compliance as compliance_router

load_dotenv()

# ─────────────────────────────────────────────────────────────────
# STARTUP / SHUTDOWN LIFECYCLE
# ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Code here runs once when the server starts.
    We create tables and seed the default admin account.
    """
    # Create all tables defined in models.py
    Base.metadata.create_all(bind=engine)

    # Seed default admin user if no users exist
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                username="admin",
                email="admin@quietmonitor.local",
                hashed_password=hash_password("admin123"),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            print("✅  Default admin user created  (username: admin | password: admin123)")
            print("⚠️  Change the default password immediately in production!")
    finally:
        db.close()

    yield  # Application runs here

    # (optional) cleanup on shutdown goes below the yield


# ─────────────────────────────────────────────────────────────────
# APP FACTORY
# ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="QuietMonitor API",
    description="Internal IT monitoring dashboard – REST backend",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────
# Allow the Vite dev server (port 5173) to call the API.
# Tighten this to specific origins in production.
cors_origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:5173")
cors_origins = [origin.strip() for origin in cors_origins_raw.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────
app.include_router(auth_router.router, tags=["Auth"])
app.include_router(machines_router.router, tags=["Machines"])
app.include_router(alerts_router.router, tags=["Alerts"])
app.include_router(compliance_router.router, tags=["Compliance"])


@app.get("/health", tags=["Health"])
def health_check():
    """Simple liveness probe – returns 200 OK if the server is running."""
    return {"status": "ok", "service": "QuietMonitor API"}
