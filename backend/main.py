"""
Composition Root — only place concrete classes are wired together.
Configuration loaded from backend/.env explicitly so startup is independent
of the current working directory.
"""

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

try:
    from dotenv import load_dotenv
    ENV_PATH = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=ENV_PATH)
except ImportError:
    ENV_PATH = None

from checks.tier1_checks import (
    BlacklistCheck, IPAddressCheck, IFrameTrapCheck,
    InsecurePasswordCheck, BrandImpersonationCheck,
)
from checks.tier2_checks import HeuristicCheck
from checks.tier3_ml import MLCheck
from checks.whitelist_check import WhitelistCheck, UserBlacklistCheck
from providers.blacklist import LiveFeedBlacklist
from providers.user_lists import UserListProvider
from services.url_analysis import URLAnalyser
from utils.url_features import URLFeatureExtractor
from controllers.analysis import build_router
from controllers.lists import build_lists_router
from controllers.report import build_report_router
from services.report_generator import ReportGenerator
from utils.whois_lookup import DomainIntelligence

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhishGuard")

# ── Config from environment ───────────────────────────────

EXTENSION_ID  = os.getenv("EXTENSION_ID", "jalianmoiocjfglkikmfdpaphlafccic")
RATE_LIMIT    = os.getenv("RATE_LIMIT", "60/minute")
FEED_URL      = os.getenv("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
REFRESH_HOURS = float(os.getenv("BLACKLIST_REFRESH_HOURS", "6"))

ALLOWED_ORIGINS = [f"chrome-extension://{EXTENSION_ID}"]

logger.info("=" * 60)
logger.info("[STARTUP] PhishGuard backend starting")
logger.info(f"[STARTUP] ENV_PATH      = {ENV_PATH}")
logger.info(f"[STARTUP] EXTENSION_ID  = {EXTENSION_ID}")
logger.info(f"[STARTUP] RATE_LIMIT    = {RATE_LIMIT}")
logger.info(f"[STARTUP] FEED_URL      = {FEED_URL}")
logger.info(f"[STARTUP] REFRESH_HOURS = {REFRESH_HOURS}")
logger.info(f"[STARTUP] ALLOWED_ORIGINS = {ALLOWED_ORIGINS}")
logger.info(f"[STARTUP] GROQ key present = {bool(os.getenv('GROQ_API_KEY'))}")
logger.info("=" * 60)

if not os.getenv("EXTENSION_ID"):
    logger.warning("[SECURITY] EXTENSION_ID not set — using default. Set in .env before deploying.")

# ── Assemble pipeline ─────────────────────────────────────

blacklist_provider = LiveFeedBlacklist(feed_url=FEED_URL, refresh_hours=REFRESH_HOURS)
user_lists         = UserListProvider()

checks = [
    WhitelistCheck(user_lists),
    UserBlacklistCheck(user_lists),
    BlacklistCheck(blacklist_provider),
    IPAddressCheck(),
    IFrameTrapCheck(),
    InsecurePasswordCheck(),
    BrandImpersonationCheck(),
    HeuristicCheck(),
    MLCheck(),
]

extractor        = URLFeatureExtractor()
analyser         = URLAnalyser(checks=checks, extractor=extractor)
report_generator = ReportGenerator(DomainIntelligence())

logger.info(f"[STARTUP] Pipeline: {len(checks)} checks loaded:")
for i, c in enumerate(checks):
    logger.info(f"[STARTUP]   [{i}] {c.__class__.__name__}")

# ── FastAPI ───────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])
app     = FastAPI(title="PhishGuard API", version="2.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(build_router(analyser, limiter, RATE_LIMIT))
app.include_router(build_lists_router(user_lists, limiter, RATE_LIMIT))
app.include_router(build_report_router(report_generator, extractor, limiter))
