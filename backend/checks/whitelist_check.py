"""
WhitelistCheck — Tier 0.

Runs BEFORE all other checks. If the domain is on the user's
whitelist the pipeline stops immediately with ALLOW.
This means whitelisted sites are never scored, never ML-checked,
and never flagged — regardless of what other signals say.
"""

import logging
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest

logger = logging.getLogger("PhishGuard")


class WhitelistCheck(BaseCheck):
    """
    Short-circuits the pipeline for user-trusted domains.
    Injected with UserListProvider — no direct file access.
    """

    def __init__(self, user_list_provider):
        self._provider = user_list_provider

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        domain = refined.get("registered_domain", "")

        if self._provider.is_whitelisted(domain):
            logger.info(f"[TIER0] WhitelistCheck — trusted domain: {domain}")
            return CheckResult(
                triggered=True,
                is_block=False,
                score=-99,    # large negative forces ALLOW regardless of other scores
                reasons=[f"Trusted domain: {domain}"],
                tier="RULE",
            )

        return CheckResult.clean()


class UserBlacklistCheck(BaseCheck):
    """
    Blocks domains the user has manually added to their blacklist.
    Runs alongside the main BlacklistCheck at Tier 1.
    """

    def __init__(self, user_list_provider):
        self._provider = user_list_provider

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        domain = refined.get("registered_domain", "")

        if self._provider.is_blacklisted(domain):
            logger.info(f"[TIER1] UserBlacklistCheck triggered for {domain}")
            return CheckResult(
                triggered=True,
                is_block=True,
                score=14,
                reasons=["Manually blocked domain"],
                tier="RULE",
            )

        return CheckResult.clean()
