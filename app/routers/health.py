"""GET /health - a quick 'is the server alive?' check (no auth)."""
from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from app import config
from app.database import engine
from app.schemas import HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health():
    # Try a tiny query so /health also tells us whether the database works.
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        db_status = "error"
    return HealthOut(status="ok" if db_status == "ok" else "degraded", version=config.APP_VERSION,
                     time=datetime.now(timezone.utc), mode="database", database=db_status,
                     gemini_configured=bool(config.GEMINI_API_KEY))
