"""
Blacklist providers — DIP: URLAnalyser depends on BlacklistProvider,
not on any specific source.

FileBlacklist       — reads blacklist.txt (always available, offline-safe)
LiveFeedBlacklist   — fetches OpenPhish feed + auto-refreshes every N hours
                      falls back to FileBlacklist if feed is unreachable
"""

import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from typing import List

logger = logging.getLogger("PhishGuard")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BLACKLIST_PATH = os.path.join(BASE_DIR, "blacklist.txt")

OPENPHISH_FEED = "https://openphish.com/feed.txt"
REFRESH_HOURS  = 6


# ─────────────────────────────────────────────────
# Abstract interface
# ─────────────────────────────────────────────────

class BlacklistProvider(ABC):

    @abstractmethod
    def load(self) -> List[str]:
        ...

    @abstractmethod
    def contains(self, domain: str) -> bool:
        ...

    @property
    @abstractmethod
    def size(self) -> int:
        ...


# ─────────────────────────────────────────────────
# FileBlacklist — local text file
# ─────────────────────────────────────────────────

class FileBlacklist(BlacklistProvider):
    """
    Loads from blacklist.txt.
    Lines starting with # are treated as comments.
    """

    def __init__(self, path: str = DEFAULT_BLACKLIST_PATH):
        self._path    = path
        self._entries = self.load()

    def load(self) -> List[str]:
        try:
            with open(self._path) as f:
                entries = [
                    line.strip().lower()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            logger.info(f"[BLACKLIST] FileBlacklist: {len(entries)} entries from {self._path}")
            return entries
        except FileNotFoundError:
            logger.warning(f"[BLACKLIST] {self._path} not found — blacklist empty")
            return []

    def contains(self, domain: str) -> bool:
        d = domain.lower()
        return any(d == e or d.endswith("." + e) for e in self._entries)

    @property
    def size(self) -> int:
        return len(self._entries)


# ─────────────────────────────────────────────────
# LiveFeedBlacklist — OpenPhish + auto-refresh
# ─────────────────────────────────────────────────

class LiveFeedBlacklist(BlacklistProvider):
    """
    Fetches from OpenPhish on startup, then refreshes every REFRESH_HOURS.
    Falls back to FileBlacklist if the feed is unreachable.

    Thread-safe: uses a lock around domain set updates.
    """

    def __init__(
        self,
        feed_url:      str   = OPENPHISH_FEED,
        refresh_hours: float = REFRESH_HOURS,
        fallback_path: str   = DEFAULT_BLACKLIST_PATH,
    ):
        self._feed_url      = feed_url
        self._refresh_secs  = refresh_hours * 3600
        self._fallback      = FileBlacklist(fallback_path)
        self._lock          = threading.Lock()
        self._domains: set  = set()
        self._last_fetch: float = 0.0

        # Initial load — blocks briefly at startup
        self._fetch()

        # Background refresh thread (daemon = dies when main process exits)
        t = threading.Thread(target=self._refresh_loop, daemon=True)
        t.start()
        logger.info(f"[BLACKLIST] LiveFeedBlacklist: refresh every {refresh_hours}h")

    # ── Public interface ─────────────────────────

    def load(self) -> List[str]:
        with self._lock:
            return list(self._domains)

    def contains(self, domain: str) -> bool:
        d = domain.lower()
        with self._lock:
            live_hit = any(d == e or d.endswith("." + e) for e in self._domains)
        return live_hit or self._fallback.contains(d)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._domains) + self._fallback.size

    # ── Internal ─────────────────────────────────

    def _fetch(self):
        """Fetch feed and extract registered domains. Thread-safe."""
        import urllib.request
        import tldextract

        try:
            logger.info(f"[BLACKLIST] Fetching {self._feed_url} ...")
            req = urllib.request.Request(
                self._feed_url,
                headers={"User-Agent": "PhishGuard/2.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8", errors="ignore").splitlines()

            domains = set()
            for line in raw:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ext = tldextract.extract(line)
                    if ext.domain and ext.suffix:
                        domains.add(f"{ext.domain}.{ext.suffix}".lower())
                except Exception:
                    continue

            with self._lock:
                self._domains    = domains
                self._last_fetch = time.time()

            logger.info(f"[BLACKLIST] LiveFeed: loaded {len(domains)} domains")

        except Exception as e:
            logger.warning(f"[BLACKLIST] Feed fetch failed ({e}) — using FileBlacklist fallback")
            # Don't clear existing domains if we have them; just keep stale data
            if not self._domains:
                logger.info("[BLACKLIST] No cached data — falling back to file only")

    def _refresh_loop(self):
        """Background thread: re-fetch at the configured interval."""
        while True:
            time.sleep(self._refresh_secs)
            logger.info("[BLACKLIST] Scheduled refresh ...")
            self._fetch()
