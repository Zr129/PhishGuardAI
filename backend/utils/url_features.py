"""
URLFeatureExtractor — extracts structured features from a URL and link list.

Key naming convention: all keys use PascalCase matching PhiUSIIL dataset
column names exactly. This means tier checks and FIELD_MAP can reference
them consistently without any translation layer.
"""

import re
import itertools
import logging
from typing import List
from urllib.parse import urlparse
import tldextract

logger = logging.getLogger("PhishGuard")


class URLFeatureExtractor:
    """Stateless extractor — safe to share as a singleton."""

    def extract(self, url: str, raw_links: List[str]) -> dict:
        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        features = {
            **self._url_features(url, ext),
            **self._link_features(raw_links, registered_domain),
            "registered_domain": registered_domain,
        }
        return features

    # ── URL string features ───────────────────────────────────

    def _url_features(self, url: str, ext) -> dict:
        host      = urlparse(url).hostname or ""
        tld       = ext.suffix or ""
        subdomain = ext.subdomain or ""
        domain    = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        url_len   = len(url)

        letters    = sum(c.isalpha()  for c in url)
        digits     = sum(c.isdigit()  for c in url)
        common     = set("/:.-_~@?=&#%+")
        specials   = sum(c not in common and not c.isalnum() for c in url)
        obfuscated = len(re.findall(r"%[0-9a-fA-F]{2}", url))

        sub_parts       = [s for s in subdomain.split(".") if s and s != "www"]
        subdomain_count = len(sub_parts)

        max_run = max((len(list(g)) for _, g in itertools.groupby(url)), default=0)
        is_ip   = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)))

        return {
            # ── PhiUSIIL column names (PascalCase) ──
            "URLLength":                  url_len,
            "DomainLength":               len(domain),
            "TLDLength":                  len(tld),
            "IsDomainIP":                 is_ip,
            "IsHTTPS":                    int(url.startswith("https")),
            "NoOfSubDomain":              subdomain_count,
            "HasObfuscation":             int("@" in url or obfuscated > 0),
            "NoOfObfuscatedChar":         obfuscated,
            "ObfuscationRatio":           round(obfuscated / url_len, 4) if url_len else 0,
            "NoOfLettersInURL":           letters,
            "LetterRatioInURL":           round(letters / url_len, 4) if url_len else 0,
            "NoOfDegitsInURL":            digits,
            "DegitRatioInURL":            round(digits / url_len, 4) if url_len else 0,
            "NoOfOtherSpecialCharsInURL": specials,
            "SpacialCharRatioInURL":      round(specials / url_len, 4) if url_len else 0,
            "NoOfEqualsInURL":            url.count("="),
            "NoOfQMarkInURL":             url.count("?"),
            "NoOfAmpersandInURL":         url.count("&"),
            "CharContinuationRate":       round(max_run / url_len, 4) if url_len else 0,
            "HasDomainDashes":            int("-" in ext.domain),

            # ── Legacy snake_case aliases used by Tier 1/2 checks ──
            # Kept so tier checks don't need changing — all point to same values
            "is_ip":             is_ip,
            "subdomain_count":   subdomain_count,
            "has_domain_dashes": int("-" in ext.domain),
        }

    # ── Link features ─────────────────────────────────────────

    def _link_features(self, raw_links: List[str], registered_domain: str) -> dict:
        total = external = 0

        for link in raw_links:
            if not link or not isinstance(link, str) or not link.startswith("http"):
                continue
            total += 1
            try:
                ext_link    = tldextract.extract(link)
                link_domain = f"{ext_link.domain}.{ext_link.suffix}" if ext_link.suffix else ext_link.domain
                if link_domain and link_domain != registered_domain:
                    external += 1
            except Exception:
                continue

        ratio = round(external / total, 4) if total > 0 else 0.0

        return {
            # PascalCase (for FIELD_MAP / ML)
            "NoOfExternalRef": external,
            "TotalLinks":      total,
            "ExternalRatio":   ratio,
            # snake_case alias (for tier2_checks)
            "external_ratio":  ratio,
        }


# Backwards-compatible module-level function
_default_extractor = URLFeatureExtractor()

def extract_refined_features(url: str, raw_links: List[str]) -> dict:
    return _default_extractor.extract(url, raw_links)
