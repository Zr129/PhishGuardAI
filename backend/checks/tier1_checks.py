"""
Tier 1 — Hard Rules.

Each check is self-contained: one class, one responsibility.
A triggered Tier 1 check sets is_block=True which causes the pipeline
to short-circuit and return BLOCK immediately without running further checks.

Hard blocks are reserved for objective, unambiguous technical violations
where there is no legitimate reason for the condition to exist on a safe page:

  BlacklistCheck       — domain is in a verified phishing feed
  IPAddressCheck       — raw IP address instead of domain name
  InsecurePasswordCheck — credentials transmitted unencrypted over HTTP
  IFrameTrapCheck      — password field inside an untrusted cross-domain iframe

BrandImpersonationCheck has been moved entirely to Tier 2 (HeuristicCheck).
Brand detection requires interpretation — a domain containing a brand name
may be legitimate (resellers, partner portals, awareness sites) — so it
contributes a weighted score rather than triggering an immediate hard block.
"""

import logging
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest

logger = logging.getLogger("PhishGuard")


class BlacklistCheck(BaseCheck):
    """
    Hard block if the registered domain is in the live phishing feed
    or the bundled blacklist file.
    Score 14 — highest possible, unambiguous threat.
    """

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
    """
    Hard block if the URL uses a raw IP address instead of a domain name.
    Legitimate websites do not serve content to end users via raw IPs.
    Score 14.
    """

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if refined.get("is_ip", False):
            logger.info("[TIER1] IPAddressCheck triggered")
            return CheckResult(
                triggered=True, is_block=True, score=14,
                reasons=["IP address used instead of domain name"], tier="RULE",
            )
        return CheckResult.clean()


class IFrameTrapCheck(BaseCheck):
    """
    Hard block if content.js is running inside a non-main-frame iframe
    that contains a password field, and the iframe domain is not a
    trusted payment provider.

    This detects the 'iframe trap' technique where a phishing page embeds
    a credential-harvesting form inside a cross-domain iframe to bypass
    same-origin protections.

    Trusted payment iframes (Stripe, PayPal etc.) are explicitly excluded
    because they legitimately embed password fields cross-domain.
    Score 13.
    """

    def __init__(self, trusted_domains: set = None):
        self._trusted = trusted_domains or {
            "stripe.com", "paypal.com", "braintreegateway.com",
            "squareup.com", "adyen.com", "checkout.com",
        }

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        # Only fires when running inside an iframe (not main frame)
        if data.is_main_frame or not data.has_password_field:
            return CheckResult.clean()

        iframe_domain = refined.get("registered_domain", "")
        if any(
            iframe_domain == d or iframe_domain.endswith("." + d)
            for d in self._trusted
        ):
            return CheckResult.clean()

        logger.info("[TIER1] IFrameTrapCheck triggered")
        return CheckResult(
            triggered=True, is_block=True, score=13,
            reasons=["Hidden login trap detected in iframe"], tier="RULE",
        )


class InsecurePasswordCheck(BaseCheck):
    """
    Hard block if a password field is served over plain HTTP.
    Transmitting credentials unencrypted is an objective security violation
    regardless of whether the page is malicious.
    Score 13.
    """

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if data.has_password_field and not data.is_https:
            logger.info("[TIER1] InsecurePasswordCheck triggered")
            return CheckResult(
                triggered=True, is_block=True, score=13,
                reasons=["Password field on insecure HTTP page"], tier="RULE",
            )
        return CheckResult.clean()