"""
Tier 1 — Hard Rules.

Each check is self-contained: one class, one responsibility.
A triggered Tier 1 check sets is_block=True for immediate BLOCK.
"""

import logging
import tldextract
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest

logger = logging.getLogger("PhishGuard")


class BlacklistCheck(BaseCheck):
    """Blocks if the registered domain appears in the blacklist."""

    def __init__(self, blacklist_provider):
        self._provider = blacklist_provider

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        domain = refined.get("registered_domain", "")
        if self._provider.contains(domain):
            logger.info(f"[TIER1] BlacklistCheck triggered for {domain}")
            return CheckResult(
                triggered=True, is_block=True, score=14,
                reasons=["Known phishing domain"], tier="RULE",
            )
        return CheckResult.clean()


class IPAddressCheck(BaseCheck):
    """Blocks if the URL uses a raw IP address instead of a domain."""

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if refined.get("is_ip", False):
            logger.info("[TIER1] IPAddressCheck triggered")
            return CheckResult(
                triggered=True, is_block=True, score=14,
                reasons=["IP address used instead of domain"], tier="RULE",
            )
        return CheckResult.clean()


class IFrameTrapCheck(BaseCheck):
    """
    Blocks if a password field exists inside a non-main-frame iframe
    AND the iframe domain is not a trusted payment provider.
    """

    def __init__(self, trusted_domains: set = None):
        self._trusted = trusted_domains or {
            "stripe.com", "paypal.com", "braintreegateway.com",
            "squareup.com", "adyen.com",
        }

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if data.is_main_frame or not data.has_password_field:
            return CheckResult.clean()

        iframe_domain = refined.get("registered_domain", "")
        if any(iframe_domain == d or iframe_domain.endswith("." + d) for d in self._trusted):
            return CheckResult.clean()

        logger.info("[TIER1] IFrameTrapCheck triggered")
        return CheckResult(
            triggered=True, is_block=True, score=13,
            reasons=["Hidden login trap detected in iframe"], tier="RULE",
        )


class InsecurePasswordCheck(BaseCheck):
    """Blocks if a password field is served over plain HTTP."""

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if data.has_password_field and not data.is_https:
            logger.info("[TIER1] InsecurePasswordCheck triggered")
            return CheckResult(
                triggered=True, is_block=True, score=13,
                reasons=["Password field on insecure HTTP page"], tier="RULE",
            )
        return CheckResult.clean()


class BrandImpersonationCheck(BaseCheck):
    """
    Detects brand impersonation using smart domain-base matching.

    Instead of maintaining exhaustive lists of country-specific domains,
    we use tldextract to get the base domain name and check if it exactly
    matches a known brand.

    Logic:
      - amazon.co.jp  → base="amazon"        → matches brand → LEGIT
      - amazon-login.com → base="amazon-login" → no exact match → SUSPICIOUS
      - mypaypal.com  → base="mypaypal"      → no exact match → SUSPICIOUS

    Extra official domains handle subdomains and special cases
    (e.g. aws.amazon.com, mail.google.com, icloud.com for apple).

    - With password field → immediate BLOCK
    - Without password field → score added, no hard block
    """

    # Brand keyword → list of EXTRA official domains beyond the base pattern.
    # The base match (e.g. domain base == "google") handles all country TLDs
    # automatically. Only list domains where the base name differs.
    BRAND_EXTRAS = {
        "paypal":    ["paypal-corp.com"],
        "google":    ["gmail.com", "youtube.com", "googleapis.com",
                      "googleusercontent.com", "gstatic.com", "googlevideo.com"],
        "microsoft": ["live.com", "outlook.com", "office.com",
                      "microsoft365.com", "microsoftonline.com", "xbox.com",
                      "skype.com", "bing.com", "msn.com"],
        "amazon":    ["aws.amazon.com", "kindle.com", "audible.com",
                      "zappos.com", "twitch.tv"],
        "apple":     ["icloud.com", "me.com", "mac.com"],
        "facebook":  ["fb.com", "messenger.com", "instagram.com",
                      "whatsapp.com", "oculus.com"],
        "twitter":   ["x.com", "t.co"],
        "steam":     ["steamcommunity.com", "steampowered.com",
                      "steamstatic.com", "valvesoftware.com"],
    }

    # Brands with no extras — base match only
    BRANDS = {
        "paypal", "amazon", "microsoft", "google", "netflix",
        "apple", "facebook", "instagram", "twitter", "linkedin",
        "dropbox", "steam", "ebay", "hsbc", "barclays", "lloyds",
        "paloaltonetworks", "spotify", "tiktok", "snapchat", "discord",
    }

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        registered_domain = refined.get("registered_domain", "")

        # Extract the base name from the registered domain
        # e.g. "amazon.co.jp" → ext.domain = "amazon"
        # e.g. "amazon-login.com" → ext.domain = "amazon-login"
        try:
            ext = tldextract.extract(registered_domain)
            domain_base = ext.domain.lower()
        except Exception:
            domain_base = registered_domain.lower()

        for brand in self.BRANDS:
            # ── Check 1: base name exact match ──────────────────
            # amazon.co.jp passes (base == "amazon")
            # amazon-login.com fails (base == "amazon-login")
            if domain_base == brand:
                continue  # legitimate — skip

            # ── Check 2: brand keyword anywhere in base name ────
            # Only flag if brand appears in domain base
            if brand not in domain_base:
                continue  # brand not in this domain at all

            # brand IS in domain_base but is NOT an exact match
            # e.g. domain_base="amazon-secure", brand="amazon" → suspicious

            # ── Check 3: extra official domains ─────────────────
            extras = self.BRAND_EXTRAS.get(brand, [])
            if any(registered_domain == d or registered_domain.endswith("." + d)
                   for d in extras):
                continue  # legitimate extra domain

            # ── This is brand impersonation ──────────────────────
            reason = f"Brand impersonation: '{brand}' in domain '{registered_domain}'"

            if data.has_password_field:
                logger.info(f"[TIER1] BrandImpersonation BLOCK — {brand} in {registered_domain}")
                return CheckResult(
                    triggered=True, is_block=True, score=13,
                    reasons=[reason, "Credential harvesting risk"],
                    tier="RULE",
                )

            logger.info(f"[TIER1] BrandImpersonation WARN — {brand} in {registered_domain}")
            return CheckResult(
                triggered=True, is_block=False, score=2,
                reasons=[reason], tier="RULE",
            )

        return CheckResult.clean()
