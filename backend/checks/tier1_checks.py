"""
Tier 1 — Hard Rules.

Each check is self-contained: one class, one responsibility.
A triggered Tier 1 check sets is_block=True for immediate BLOCK.
"""

import logging
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
                reasons=["Known phishing domain"],
                tier="RULE",
            )
        return CheckResult.clean()


class IPAddressCheck(BaseCheck):
    """Blocks if the URL uses a raw IP address instead of a domain."""

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if refined.get("is_ip", False):
            logger.info("[TIER1] IPAddressCheck triggered")
            return CheckResult(
                triggered=True, is_block=True, score=14,
                reasons=["IP address used instead of domain"],
                tier="RULE",
            )
        return CheckResult.clean()


class IFrameTrapCheck(BaseCheck):
    """
    Blocks if a password field exists inside a non-main-frame iframe
    AND the iframe's domain is not in the trusted brand list.
    Avoids false positives on legitimate embedded payment widgets.
    """

    def __init__(self, trusted_domains: set = None):
        # Known legitimate iframe hosts (e.g. Stripe, PayPal payment widgets)
        self._trusted = trusted_domains or {
            "stripe.com", "paypal.com", "braintreegateway.com",
            "squareup.com", "adyen.com",
        }

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if data.is_main_frame or not data.has_password_field:
            return CheckResult.clean()

        # If the iframe's domain is a known legitimate payment provider, allow
        iframe_domain = refined.get("registered_domain", "")
        if any(iframe_domain == d or iframe_domain.endswith("." + d) for d in self._trusted):
            logger.info(f"[TIER1] IFrameTrapCheck — trusted iframe domain: {iframe_domain}")
            return CheckResult.clean()

        logger.info("[TIER1] IFrameTrapCheck triggered")
        return CheckResult(
            triggered=True, is_block=True, score=13,
            reasons=["Hidden login trap detected in iframe"],
            tier="RULE",
        )


class InsecurePasswordCheck(BaseCheck):
    """Blocks if a password field is served over plain HTTP."""

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if data.has_password_field and not data.is_https:
            logger.info("[TIER1] InsecurePasswordCheck triggered")
            return CheckResult(
                triggered=True, is_block=True, score=13,
                reasons=["Password field on insecure HTTP page"],
                tier="RULE",
            )
        return CheckResult.clean()


class BrandImpersonationCheck(BaseCheck):
    """
    Detects brand names in the DOMAIN only (not full URL path/query).
    Checking the full URL caused false positives on news articles and
    legitimate pages that mention brand names in their content/URL path.

    - With password field → immediate BLOCK
    - Without password field → warning only (score added, no block)
    """

    DEFAULT_BRANDS = {
        "paypal":    ["paypal.com", "paypal-corp.com"],
        "amazon":    ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "aws.amazon.com"],
        "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoft365.com"],
        "google":    ["google.com", "gmail.com", "youtube.com", "google.co.uk"],
        "netflix":   ["netflix.com"],
        "apple":     ["apple.com", "icloud.com"],
        "facebook":  ["facebook.com", "fb.com", "messenger.com"],
        "instagram": ["instagram.com"],
        "twitter":   ["twitter.com", "x.com"],
        "linkedin":  ["linkedin.com"],
        "dropbox":   ["dropbox.com"],
        "steam":     ["steampowered.com", "steamcommunity.com"],
        "ebay":      ["ebay.com", "ebay.co.uk"],
        "hsbc":      ["hsbc.com", "hsbc.co.uk"],
        "barclays":  ["barclays.com", "barclays.co.uk"],
        "lloyds":    ["lloyds.com", "lloydsbankinggroup.com"],
        "paloalto":  ["paloaltonetworks.com"],
    }

    def __init__(self, brands: dict = None):
        self._brands = brands or self.DEFAULT_BRANDS

    @staticmethod
    def _is_legit(domain: str, official: list) -> bool:
        return any(domain == d or domain.endswith("." + d) for d in official)

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        domain = refined.get("registered_domain", "")

        # FIX: only check domain and page title — NOT full URL path/query
        # Previously checking full URL caused false positives on news articles
        # mentioning brand names in their URL path (e.g. /article-about-paypal)
        domain_lower = domain.lower()
        title_lower  = data.title.lower()

        for brand, official_domains in self._brands.items():
            if brand not in domain_lower and brand not in title_lower:
                continue

            if self._is_legit(domain, official_domains):
                continue

            reason = f"Brand impersonation: '{brand}' detected on {domain}"

            if data.has_password_field:
                logger.info(f"[TIER1] BrandImpersonationCheck BLOCK — {brand} on {domain}")
                return CheckResult(
                    triggered=True, is_block=True, score=13,
                    reasons=[reason, "Credential harvesting risk"],
                    tier="RULE",
                )

            logger.info(f"[TIER1] BrandImpersonationCheck WARN — {brand} on {domain}")
            return CheckResult(
                triggered=True, is_block=False, score=2,
                reasons=[reason],
                tier="RULE",
            )

        return CheckResult.clean()
