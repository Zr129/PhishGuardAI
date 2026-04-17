"""
Composition Root — only place concrete classes are wired together.
Configuration loaded from environment variables via .env file.
"""

import json
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load .env if present (pip install python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional — env vars can be set directly in production

from checks.tier1_checks import (
    BlacklistCheck, IPAddressCheck, IFrameTrapCheck,
    InsecurePasswordCheck, BrandImpersonationCheck,
)
from checks.tier2_checks import HeuristicCheck
from checks.tier3_ml import MLCheck
from providers.blacklist import FileBlacklist, LiveFeedBlacklist
from services.url_analysis import URLAnalyser
from utils.url_features import URLFeatureExtractor
from controllers.analysis import build_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhishGuard")

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
BRANDS_PATH = os.path.join(BASE_DIR, "config", "brands.json")

# ── Config from environment ───────────────────────────────

EXTENSION_ID  = os.getenv("EXTENSION_ID", "jalianmoiocjfglkikmfdpaphlafccic")
RATE_LIMIT    = os.getenv("RATE_LIMIT", "60/minute")
FEED_URL      = os.getenv("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
REFRESH_HOURS = float(os.getenv("BLACKLIST_REFRESH_HOURS", "6"))

ALLOWED_ORIGINS = [f"chrome-extension://{EXTENSION_ID}"]

if not os.getenv("EXTENSION_ID"):
    logger.warning(
        "[SECURITY] EXTENSION_ID not set in environment — using hardcoded default. "
        "Set EXTENSION_ID in .env before deploying."
    )

# ── Load brand config ─────────────────────────────────────

def _load_brands() -> dict | None:
    try:
        with open(BRANDS_PATH) as f:
            brands = json.load(f)
        logger.info(f"[INIT] Loaded {len(brands)} brands from {BRANDS_PATH}")
        return brands
    except FileNotFoundError:
        logger.info("[INIT] brands.json not found — using built-in defaults")
        return None

# ── Assemble pipeline ─────────────────────────────────────

brands             = _load_brands()
blacklist_provider = LiveFeedBlacklist(feed_url=FEED_URL, refresh_hours=REFRESH_HOURS)

checks = [
    BlacklistCheck(blacklist_provider),
    IPAddressCheck(),
    IFrameTrapCheck(),
    InsecurePasswordCheck(),
    BrandImpersonationCheck(brands),
    HeuristicCheck(),
    MLCheck(),
]

extractor = URLFeatureExtractor()
analyser  = URLAnalyser(checks=checks, extractor=extractor)

# ── FastAPI ───────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])
app     = FastAPI(title="PhishGuard API", version="2.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)

app.include_router(build_router(analyser, limiter))
