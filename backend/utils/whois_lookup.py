"""
WHOIS and domain intelligence lookup.

Gathers additional context about a domain beyond what the extension scrapes:
  - Registration date / domain age
  - Registrar
  - Country
  - Expiry date
  - Name servers

Uses python-whois. Falls back gracefully if lookup fails or times out.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("PhishGuard")


class DomainIntelligence:
    """Wrapper around WHOIS lookup with safe fallback."""

    def lookup(self, domain: str) -> dict:
        """
        Returns a dict of domain intelligence.
        All fields are strings or None — never raises.
        """
        result = {
            "domain":       domain,
            "registrar":    None,
            "country":      None,
            "created":      None,
            "expires":      None,
            "age_days":     None,
            "name_servers": [],
            "error":        None,
        }

        try:
            import whois
            w = whois.whois(domain)

            result["registrar"]    = self._str(w.registrar)
            result["country"]      = self._str(w.country)
            result["name_servers"] = self._list(w.name_servers)

            # Creation date — pick earliest if multiple
            created = self._earliest_date(w.creation_date)
            if created:
                result["created"]  = created.strftime("%Y-%m-%d")
                # python-whois usually returns naive datetimes (no tzinfo).
                # Treat them as UTC if naive; convert to UTC if aware. The
                # previous code used .replace(tzinfo=...) which OVERWROTE
                # an existing timezone instead of converting it.
                if created.tzinfo is None:
                    created_utc = created.replace(tzinfo=timezone.utc)
                else:
                    created_utc = created.astimezone(timezone.utc)
                result["age_days"] = (datetime.now(timezone.utc) - created_utc).days

            # Expiry date
            expires = self._earliest_date(w.expiration_date)
            if expires:
                result["expires"] = expires.strftime("%Y-%m-%d")

        except Exception as e:
            logger.warning(f"[WHOIS] Lookup failed for {domain}: {e}")
            result["error"] = str(e)

        return result

    @staticmethod
    def _str(val) -> Optional[str]:
        if val is None:
            return None
        if isinstance(val, list):
            val = val[0] if val else None
        return str(val).strip() if val else None

    @staticmethod
    def _list(val) -> list:
        if val is None:
            return []
        if isinstance(val, str):
            return [val.lower()]
        return [str(v).lower() for v in val if v]

    @staticmethod
    def _earliest_date(val) -> Optional[datetime]:
        if val is None:
            return None
        if isinstance(val, list):
            dates = [d for d in val if isinstance(d, datetime)]
            return min(dates) if dates else None
        if isinstance(val, datetime):
            return val
        return None
