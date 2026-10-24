"""Database engine, session management, and health checks for GuardRail run ledger."""

from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""

    pass


def get_engine(database_url: str | None = None) -> Any:
    """Create a SQLAlchemy engine configured for PostgreSQL or SQLite."""
    settings = get_settings()
    url = database_url or settings.sqlalchemy_database_url

    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_engine(
        url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


# Default engine and sessionmaker
engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(target_engine: Any = None) -> None:
    """Create all tables if they do not exist."""
    eng = target_engine or engine
    Base.metadata.create_all(bind=eng)


def check_db_health(target_engine: Any = None) -> bool:
    """Execute a lightweight probe to verify database connectivity."""
    eng = target_engine or engine
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
