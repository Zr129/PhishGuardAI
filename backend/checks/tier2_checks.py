"""
Tier 2 — Heuristic Scoring.

Accumulates a risk score from multiple behavioural signals.
No single signal blocks — the combined score decides outcome.
"""

import logging
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest

logger = logging.getLogger("PhishGuard")

# URL length above this is suspicious (PhiUSIIL: 3rd most important feature)
SUSPICIOUS_URL_LENGTH = 300  # raised from 200 — avoids login pages with long query params


class HeuristicCheck(BaseCheck):
    """
    Runs all heuristic signals and returns a combined score.

    Signals:
      - Suspicious URL length (new)
      - URL obfuscation via '@'
      - Double-slash redirect pattern
      - Excessive subdomains
      - High external link ratio
      - High dead-link ratio (lowered threshold when password present)
      - Suspicious form behaviour
    Note: domain dashes removed — near-zero ML importance and too many
    false positives (coca-cola.com, bbc-news.com etc.)
    """

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        score   = 0
        reasons = []

        # -- Suspicious URL length --
        # Only flag if URL is very long AND contains suspicious query params
        # (= or & count > 5 suggests data harvesting, not just a long path)
        url_len = len(data.url)
        param_count = data.url.count("=") + data.url.count("&")
        if url_len > SUSPICIOUS_URL_LENGTH and param_count > 5:
            score += 1
            reasons.append(f"Unusually long URL with many parameters ({url_len} chars)")

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

        # -- High external link ratio (only meaningful with enough anchors) --
        if refined.get("external_ratio", 0) > 0.9 and data.total_anchors > 15:
            score += 2
            reasons.append("High external link ratio")

        # -- Dead-link ratio --
        # FIX: lower threshold when password is present — phishing pages
        # with few anchors shouldn't escape this check
        if data.total_anchors > 0:
            ratio = data.empty_anchors / data.total_anchors
            min_anchors = 5 if data.has_password_field else 15
            if data.total_anchors >= min_anchors and ratio > 0.7:
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
            tier="HEURISTIC",
        )
