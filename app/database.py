"""
database.py - connects SQLAlchemy to SQLite.

WHY SQLite: the whole database is ONE file (appflow.db). No server to install,
perfect for a hackathon. SQLAlchemy lets us write Python classes instead of SQL.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import DateTime, create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import TypeDecorator

from app import config

log = logging.getLogger("appflow.db_migrate")

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
    """Create missing tables, then add missing columns to old tables (called once at startup)."""
    from app import models  # noqa: F401  (import registers the tables)
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


def _add_missing_columns() -> None:
    """
    create_all() only creates tables that don't exist; it never changes an existing table.
    So an appflow.db made by an older version lacks newer columns (e.g. domain_source), and every
    insert then fails. Here we add each missing column that may be empty (NULL): existing rows are
    kept and simply get NULL. Nothing is ever deleted. A missing NOT NULL column cannot be added
    safely, so we stop with a clear message instead of guessing.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            have = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in have:
                    continue
                if not column.nullable:
                    raise RuntimeError(
                        f"Database table '{table.name}' is missing required column '{column.name}'. "
                        "Your appflow.db was made by an older version. Stop the backend, rename "
                        "appflow.db (for example to appflow_old.db) and start again to get a fresh one.")
                col_type = column.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}'))
                log.warning("Upgraded old database: added missing column %s.%s (existing rows keep NULL)",
                            table.name, column.name)
