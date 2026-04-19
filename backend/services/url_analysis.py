"""
URLAnalyser — lean orchestrator.

Responsibilities:
  - Iterate the injected check pipeline
  - Aggregate CheckResults
  - Decide BLOCK / WARN / ALLOW
  - Return a typed AnalysisResult

FIX: ALLOW no longer silently discards brand warning reasons.
FIX: ML score is weighted (0.6x) before adding to heuristic score
     to prevent the two differently-scaled systems from over-adding.
"""

import logging
import math
from typing import List

from checks.base import BaseCheck, CheckResult
from models.models import URLRequest, AnalysisResult
from utils.url_features import URLFeatureExtractor

logger = logging.getLogger("PhishGuard")
logging.basicConfig(level=logging.INFO)

# ML score weight — prevents raw ML probability score from dominating
# heuristic scores which use a different scale
ML_SCORE_WEIGHT = 0.65


def sigmoid_confidence(score: float, max_score: float = 14.0) -> int:
    """Sigmoid curve: maps raw score → calibrated 0–95% confidence."""
    normalised = (score / max_score) * 10 - 5
    prob       = 1 / (1 + math.exp(-normalised))
    return min(round(prob * 100), 95)


class URLAnalyser:
    """
    Orchestrates the phishing detection pipeline.
    All dependencies injected via constructor (DIP).
    """

    def __init__(self, checks: List[BaseCheck], extractor: URLFeatureExtractor):
        self._checks    = checks
        self._extractor = extractor

    def analyse(self, data: URLRequest) -> AnalysisResult:
        logger.info("========== NEW ANALYSIS ==========")
        logger.info(f"[URL] {data.url}")

        refined = self._extractor.extract(data.url, data.links)
        logger.info(f"[DOMAIN] {refined.get('registered_domain', '')}")

        cumulative_score   = 0.0
        cumulative_reasons: List[str] = []
        tagged_reasons:     List[dict] = []   # [{text, tier}]

        for check in self._checks:
            result: CheckResult = check.run(data, refined)

            if not result.triggered:
                continue

            # Apply weighting to ML scores to prevent scale mismatch
            weight = ML_SCORE_WEIGHT if result.tier == "ML" else 1.0
            cumulative_score += result.score * weight

            for reason in result.reasons:
                cumulative_reasons.append(reason)
                tagged_reasons.append({"text": reason, "tier": result.tier or "RULE"})

            # Whitelist short-circuit — score of -99 means instant ALLOW
            if result.score == -99:
                logger.info(f"[ALLOW] WhitelistCheck — trusted domain")
                return self._make_result(
                    "ALLOW", "safe", 0, result.reasons, tagged_reasons
                )

            if result.is_block:
                logger.info(f"[BLOCK] {check.__class__.__name__}")
                return self._make_result(
                    "BLOCK", "phishing",
                    cumulative_score, cumulative_reasons, tagged_reasons
                )

        score = round(cumulative_score)
        logger.info(f"[SCORE] {score}")

        if score >= 9:
            logger.info("[DECISION] BLOCK")
            return self._make_result("BLOCK", "phishing", score, cumulative_reasons, tagged_reasons)

        if score >= 5:
            logger.info("[DECISION] WARN")
            return self._make_result("WARN", "suspicious", score, cumulative_reasons, tagged_reasons)

        logger.info("[DECISION] ALLOW")
        # Pass through any informational reasons (e.g. brand warnings) even on ALLOW
        info_reasons = [r for r in cumulative_reasons if r]
        return self._make_result("ALLOW", "safe", score, info_reasons, tagged_reasons)

    @staticmethod
    def _make_result(action, prediction, score, reasons, tagged_reasons=None) -> AnalysisResult:
        return AnalysisResult(
            action=action,
            prediction=prediction,
            confidence=sigmoid_confidence(score),
            reasons=reasons,
            tagged_reasons=tagged_reasons or [],
        )
