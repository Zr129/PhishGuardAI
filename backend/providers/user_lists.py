"""
UserListProvider — manages user-defined blacklist and whitelist.

Both lists are stored in a JSON file (user_lists.json) and updated
via the /lists API endpoints. Thread-safe for concurrent requests.

Whitelist domains always ALLOW regardless of any other check.
User blacklist domains always BLOCK (same as the main blacklist).
"""

import json
import logging
import os
import threading
from typing import Set

logger = logging.getLogger("PhishGuard")

BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER_LISTS_PATH = os.path.join(BASE_DIR, "config", "user_lists.json")

_DEFAULT = {"blacklist": [], "whitelist": []}


class UserListProvider:
    """
    Persists and serves user-defined domain lists.
    Both lists are case-insensitive and support subdomain matching.
    """

    def __init__(self, path: str = USER_LISTS_PATH):
        self._path      = path
        self._lock      = threading.Lock()
        self._blacklist: Set[str] = set()
        self._whitelist: Set[str] = set()
        self._load()

    # ── Public read ──────────────────────────────────────

    def is_blacklisted(self, domain: str) -> bool:
        d = domain.lower()
        with self._lock:
            return any(d == e or d.endswith("." + e) for e in self._blacklist)

    def is_whitelisted(self, domain: str) -> bool:
        d = domain.lower()
        with self._lock:
            return any(d == e or d.endswith("." + e) for e in self._whitelist)

    def get_blacklist(self) -> list:
        with self._lock:
            return sorted(self._blacklist)

    def get_whitelist(self) -> list:
        with self._lock:
            return sorted(self._whitelist)

    # ── Public write ─────────────────────────────────────

    def add_blacklist(self, domain: str) -> bool:
        """Returns True if added, False if already present."""
        domain = self._clean(domain)
        if not domain:
            return False
        with self._lock:
            if domain in self._blacklist:
                return False
            self._blacklist.add(domain)
            # Remove from whitelist if present (can't be in both)
            self._whitelist.discard(domain)
        self._save()
        logger.info(f"[USERLIST] Added to blacklist: {domain}")
        return True

    def add_whitelist(self, domain: str) -> bool:
        """Returns True if added, False if already present."""
        domain = self._clean(domain)
        if not domain:
            return False
        with self._lock:
            if domain in self._whitelist:
                return False
            self._whitelist.add(domain)
            # Remove from blacklist if present
            self._blacklist.discard(domain)
        self._save()
        logger.info(f"[USERLIST] Added to whitelist: {domain}")
        return True

    def remove_blacklist(self, domain: str) -> bool:
        domain = self._clean(domain)
        with self._lock:
            if domain not in self._blacklist:
                return False
            self._blacklist.discard(domain)
        self._save()
        logger.info(f"[USERLIST] Removed from blacklist: {domain}")
        return True

    def remove_whitelist(self, domain: str) -> bool:
        domain = self._clean(domain)
        with self._lock:
            if domain not in self._whitelist:
                return False
            self._whitelist.discard(domain)
        self._save()
        logger.info(f"[USERLIST] Removed from whitelist: {domain}")
        return True

    # ── Internal ─────────────────────────────────────────

    @staticmethod
    def _clean(domain: str) -> str:
        """Normalise domain — strip protocol, www, trailing slash."""
        import tldextract
        if not domain or not isinstance(domain, str):
            return ""
        d = domain.strip().lower()
        # Strip protocol if present
        for prefix in ("https://", "http://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
        # Strip path
        d = d.split("/")[0]
        # Strip www
        if d.startswith("www."):
            d = d[4:]
        # Validate it's a real domain
        ext = tldextract.extract(d)
        if not ext.domain or not ext.suffix:
            return ""
        return f"{ext.domain}.{ext.suffix}"

    def _load(self):
        try:
            with open(self._path) as f:
                data = json.load(f)
            self._blacklist = set(data.get("blacklist", []))
            self._whitelist = set(data.get("whitelist", []))
            logger.info(
                f"[USERLIST] Loaded {len(self._blacklist)} blacklist, "
                f"{len(self._whitelist)} whitelist entries"
            )
        except FileNotFoundError:
            self._blacklist = set()
            self._whitelist = set()
            self._save()
        except Exception as e:
            logger.warning(f"[USERLIST] Load failed ({e}) — starting empty")
            self._blacklist = set()
            self._whitelist = set()

    def _save(self):
        """
        Atomic write: serialise to a sibling temp file, then os.replace().
        Prevents corruption if the process is killed mid-write.
        """
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with self._lock:
            data = {
                "blacklist": sorted(self._blacklist),
                "whitelist": sorted(self._whitelist),
            }
        tmp_path = f"{self._path}.tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self._path)   # atomic on POSIX & Windows
        except Exception as e:
            logger.error(f"[USERLIST] Save failed: {e}")
            # Best-effort cleanup of stale temp file
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
