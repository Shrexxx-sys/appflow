"""
database.py - connects SQLAlchemy to SQLite.

WHY SQLite: the whole database is ONE file (appflow.db). No server to install,
perfect for a hackathon. SQLAlchemy lets us write Python classes instead of SQL.
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import TypeDecorator

from app import config

# check_same_thread=False: FastAPI may use the connection from different threads.
_connect_args = {"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(config.DATABASE_URL, connect_args=_connect_args)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    """SQLite ignores foreign keys unless we switch them on for every connection."""
    if config.DATABASE_URL.startswith("sqlite"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """All table classes in models.py inherit from this."""


class UTCDateTime(TypeDecorator):
    """
    SQLite has no time zones. This column type always STORES plain UTC and
    always RETURNS a UTC-aware datetime, so the API prints "...Z" correctly.
    A timestamp sent WITHOUT a time zone is assumed to already be UTC.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):
        return value.replace(tzinfo=timezone.utc) if value is not None else None


def get_db():
    """
    FastAPI dependency: gives each request its own DB session and always
    closes it afterwards (even if the request crashed).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables if they don't exist yet (called once at startup)."""
    from app import models  # noqa: F401  (import registers the tables)
    Base.metadata.create_all(bind=engine)
