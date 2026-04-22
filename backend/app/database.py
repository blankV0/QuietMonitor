"""
QuietMonitor – database.py
──────────────────────────
Sets up the SQLAlchemy engine, session factory, and declarative base.
All models import `Base` from here so a single call to
`Base.metadata.create_all(engine)` creates every table.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

# Load values from .env file
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./quietmonitor.db")

# connect_args is required only for SQLite to allow multi-threaded access
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

# Each request gets its own database session via FastAPI dependency injection
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# All ORM models inherit from this base class
Base = declarative_base()


def get_db():
    """
    FastAPI dependency that yields a database session and ensures it is
    properly closed after each request, even if an exception is raised.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
