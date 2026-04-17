"""
Tier 2 — Heuristic Scoring.

Accumulates a risk score from multiple behavioural signals.
No single signal blocks — the combined score decides outcome.
"""

import logging
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest

logger = logging.getLogger("PhishGuard")


class HeuristicCheck(BaseCheck):
    """
    Runs all heuristic signals and returns a combined score.

    Signals checked:
      - URL obfuscation via '@'
      - Suspicious double-slash redirect
      - Excessive subdomains
      - Dashes in domain name
      - High external link ratio
      - High dead-link (empty anchor) ratio
      - Suspicious form behaviour (hidden / cross-domain submission)
    """

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        score = 0
        reasons = []

        # -- URL obfuscation via @ --
        if "@" in data.url:
            score += 2
            reasons.append("URL obfuscation using '@'")

        # -- Double-slash redirect --
        url_no_protocol = data.url.split("://", 1)[-1]
        if url_no_protocol.count("//") > 1:
            score += 1
            reasons.append("Suspicious redirect pattern in URL")

        # -- Excessive subdomains --
        if refined.get("subdomain_count", 0) > 3:
            score += 2
            reasons.append("Excessive subdomains")

        # -- Domain dashes --
        if refined.get("has_domain_dashes"):
            score += 1
            reasons.append("Domain contains dashes")

        # -- High external link ratio --
        if refined.get("external_ratio", 0) > 0.9 and data.total_anchors > 15:
            score += 2
            reasons.append("High external link ratio")

        # -- High dead-link ratio --
        if data.total_anchors > 15:
            ratio = data.empty_anchors / data.total_anchors
            if ratio > 0.7:
                score += 2
                reasons.append("High dead link ratio")

        # -- Form analysis --
        if data.has_password_field:
            if data.is_hidden_submission and data.action_to_different_domain:
                score += 4
                reasons.append("Hidden form submission to external domain")
            elif data.action_to_different_domain:
                score += 2
                reasons.append("Credentials sent to external domain")
            elif data.is_hidden_submission:
                score += 1
                reasons.append("Hidden form submission behaviour")

        triggered = score > 0

        if triggered:
            for r in reasons:
                logger.info(f"[TIER2] {r}")

        return CheckResult(
            triggered=triggered,
            is_block=False,
            score=score,
            reasons=reasons,
        )
