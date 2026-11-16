"""Application configuration, loaded from environment variables / a .env file.

Secrets (the Gemini API key) are never hard-coded and never written to disk by
the application. Copy ``.env.example`` to ``.env`` and fill in your own key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
PLACEHOLDER_KEYS = {"", "your_api_key_here", "changeme"}


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_float(value: str | None, default: float) -> float:
    try:
        return float(value) if value not in (None, "") else default
    except ValueError:
        return default


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value not in (None, "") else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str
    gemini_model: str
    ai_enabled: bool
    slow_threshold_seconds: float      # default "slow request" threshold in the Insights page
    max_packets: int                   # safety limit so a huge capture cannot exhaust memory
    ai_max_transactions: int           # how many HTTP transactions are summarised for Gemini
    ai_timeout_seconds: float

    @property
    def has_api_key(self) -> bool:
        return self.gemini_api_key.strip() not in PLACEHOLDER_KEYS

    @property
    def ai_ready(self) -> bool:
        return self.ai_enabled and self.has_api_key


def load_settings(env_file: Path | None = None) -> Settings:
    """Read settings from the environment (and from .env when it exists)."""
    load_dotenv(env_file or PROJECT_ROOT / ".env", override=False)
    return Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        gemini_model=os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_GEMINI_MODEL,
        ai_enabled=_as_bool(os.getenv("AI_ENABLED"), True),
        slow_threshold_seconds=_as_float(os.getenv("SLOW_THRESHOLD_MS"), 500.0) / 1000.0,
        max_packets=_as_int(os.getenv("MAX_PACKETS"), 500_000),
        ai_max_transactions=_as_int(os.getenv("AI_MAX_TRANSACTIONS"), 150),
        ai_timeout_seconds=_as_float(os.getenv("AI_TIMEOUT_SECONDS"), 45.0),
    )
