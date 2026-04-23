"""
URLAnalyser — lean orchestrator.
"""

import logging
import math
from typing import List

from checks.base import BaseCheck, CheckResult
from models.models import URLRequest, AnalysisResult
from utils.url_features import URLFeatureExtractor

logger = logging.getLogger("PhishGuard")
logging.basicConfig(level=logging.INFO)

ML_SCORE_WEIGHT = 0.6


def sigmoid_confidence(score: float, max_score: float = 14.0) -> int:
    normalised = (score / max_score) * 10 - 5
    prob       = 1 / (1 + math.exp(-normalised))
    return min(round(prob * 100), 95)


class URLAnalyser:

    def __init__(self, checks: List[BaseCheck], extractor: URLFeatureExtractor):
        self._checks    = checks
        self._extractor = extractor

    def analyse(self, data: URLRequest) -> AnalysisResult:
        logger.info("=" * 60)
        logger.info("[ANALYSER] Starting analysis")
        logger.info(f"[ANALYSER] Input url    = {data.url!r}")
        logger.info(f"[ANALYSER] Input domain = {data.domain!r}")

        refined = self._extractor.extract(data.url, data.links)

        domain = refined.get("registered_domain") or data.domain or ""

        # DEBUG — confirm domain resolution (safe to keep permanently)
        logger.info(f"[ANALYSER] refined registered_domain = {refined.get('registered_domain')!r}")
        logger.info(f"[ANALYSER] resolved domain           = {domain!r}")

        cumulative_score   = 0.0
        cumulative_reasons: List[str] = []
        tagged_reasons:     List[dict] = []

        for check in self._checks:
            result: CheckResult = check.run(data, refined)

            # DEBUG — log every check result (remove before release — verbose)
            if result.triggered:
                logger.info(f"[CHECK] {check.__class__.__name__} TRIGGERED  score={result.score}  block={result.is_block}  reasons={result.reasons}")
            else:
                logger.info(f"[CHECK] {check.__class__.__name__} passed")

            if not result.triggered:
                continue

            weight = ML_SCORE_WEIGHT if result.tier == "ML" else 1.0
            cumulative_score += result.score * weight

            for reason in result.reasons:
                cumulative_reasons.append(reason)
                tagged_reasons.append({"text": reason, "tier": result.tier or "RULE"})

            if result.score == -99:
                logger.info(f"[ANALYSER] WHITELIST short-circuit — returning ALLOW")
                return self._make_result("ALLOW", "safe", 0, [], [], data.url, domain)

            if result.is_block:
                logger.info(f"[ANALYSER] HARD BLOCK by {check.__class__.__name__}")
                return self._make_result(
                    "BLOCK", "phishing",
                    cumulative_score, cumulative_reasons, tagged_reasons,
                    data.url, domain,
                )

        score = round(cumulative_score)
        logger.info(f"[ANALYSER] Final cumulative score = {score}")

        if score >= 9:
            decision = "BLOCK"
        elif score >= 6:
            decision = "WARN"
        else:
            decision = "ALLOW"

        logger.info(f"[ANALYSER] Decision = {decision}")

        prediction = {"BLOCK": "phishing", "WARN": "suspicious", "ALLOW": "safe"}[decision]
        info_reasons = [r for r in cumulative_reasons if r]

        result = self._make_result(decision, prediction, score, info_reasons, tagged_reasons, data.url, domain)

        # DEBUG — confirm url/domain are on the final result (remove before release)
        logger.info(f"[ANALYSER] Result url    = {result.url!r}")
        logger.info(f"[ANALYSER] Result domain = {result.domain!r}")
        logger.info(f"[ANALYSER] Result action = {result.action!r}  confidence={result.confidence}")
        logger.info("=" * 60)

        return result

    @staticmethod
    def _make_result(
        action, prediction, score, reasons,
        tagged_reasons=None, url: str = "", domain: str = "",
    ) -> AnalysisResult:
        return AnalysisResult(
            action=action,
            prediction=prediction,
            confidence=sigmoid_confidence(score),
            reasons=reasons,
            tagged_reasons=tagged_reasons or [],
            url=url,
            domain=domain,
        )
