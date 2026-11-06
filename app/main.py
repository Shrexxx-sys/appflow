"""
main.py - creates the FastAPI app.

Run:  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
(--host 0.0.0.0 lets a phone on the same Wi-Fi reach your laptop.)
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import config
from app.database import init_db
from app.routers import dashboard, health, insights, live, mock, observations, reports, sessions

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("appflow")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Code before `yield` runs once at startup, code after it at shutdown."""
    init_db()  # create tables if missing
    os.makedirs(config.REPORTS_DIR, exist_ok=True)  # folder for generated PDFs
    if not config.API_KEY:
        log.warning("API_KEY is not set in .env - all protected endpoints will refuse requests.")
    if not config.GEMINI_API_KEY:
        log.info("GEMINI_API_KEY not set - insights will use the rule-based fallback text.")
    yield


app = FastAPI(
    title="AppFlow Sentinel API",
    version=config.APP_VERSION,
    lifespan=lifespan,
    description=(
        "Backend for AppFlow Sentinel. Stores and serves NETWORK METADATA "
        "(domains, IPs, ports, byte counts, timing) of a monitored Android app. "
        "Encrypted contents are never seen or stored.\n\n"
        "Protected endpoints need the `X-API-Key` header - click **Authorize**.\n\n"
        "Fake data for UI work is available under `/mock/...` (`is_mock: true`)."
    ),
)

# CORS: browsers block a page on one origin (localhost:5173) from calling
# another origin (localhost:8000) unless the server says it's allowed.
# We use header auth (not cookies), so allow_credentials can stay False,
# which is what makes the "*" wildcard legal.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if config.CORS_ALLOW_ALL else config.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    """
    Safety net for bugs: log the full error for us, but send the client a short,
    consistent JSON message (never a stack trace, which could leak internals).
    Expected errors (401, 404, 409, 422) are raised as HTTPException and never reach here.
    """
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error. See the server log."})


app.include_router(health.router)
app.include_router(sessions.router)
app.include_router(observations.router)
app.include_router(dashboard.router)
app.include_router(live.router)
app.include_router(insights.router)
app.include_router(reports.router)
app.include_router(mock.router, prefix="/mock", tags=["mock (fake data)"])
