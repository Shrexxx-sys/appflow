"""
config.py - reads settings from the .env file.

WHY: secrets (API key, Gemini key) must never be written inside the code,
because code gets pushed to GitHub. .env stays on your laptop only.
Real environment variables win over .env (handy for tests and Docker).
"""
import os

from dotenv import load_dotenv

load_dotenv()  # copies the values from .env into environment variables (does not overwrite existing ones)

APP_VERSION = "1.0.0"

API_KEY: str = os.getenv("API_KEY", "")

# --- Database ---------------------------------------------------------------
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./appflow.db")

# --- Gemini -----------------------------------------------------------------
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
# "gemini-flash-latest" is an alias Google keeps pointing at a current Flash model.
# To pin a specific one (e.g. gemini-3.5-flash), set GEMINI_MODEL in .env.
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
GEMINI_TIMEOUT_SECONDS: float = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "15"))

# --- Reports ----------------------------------------------------------------
REPORTS_DIR: str = os.getenv("REPORTS_DIR", "./reports")

# --- CORS -------------------------------------------------------------------
# During development we allow any website to call us (phone, teammates' laptops).
CORS_ALLOW_ALL: bool = os.getenv("CORS_ALLOW_ALL", "true").lower() == "true"
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]  # Vite dev server
