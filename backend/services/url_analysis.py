"""
URLAnalyser — lean orchestrator.

Responsibilities:
  - Iterate the injected check pipeline
  - Aggregate CheckResults
  - Decide BLOCK / WARN / ALLOW
  - Return a typed AnalysisResult

It owns NO config loading, NO file I/O, and NO rule logic.
All of those live in their own classes (DIP + SRP).
"""

import logging
import math
from typing import List

from checks.base import BaseCheck, CheckResult
from models.models import URLRequest, AnalysisResult
from utils.url_features import URLFeatureExtractor

logger = logging.getLogger("PhishGuard")
logging.basicConfig(level=logging.INFO)


# -------------------------------------------------------
# Confidence scoring
# -------------------------------------------------------

def sigmoid_confidence(score: float, max_score: float = 14.0) -> int:
    """Sigmoid curve: maps raw score → calibrated 0–95% confidence."""
    normalised = (score / max_score) * 10 - 5
    prob = 1 / (1 + math.exp(-normalised))
    return min(round(prob * 100), 95)


# -------------------------------------------------------
# URLAnalyser
# -------------------------------------------------------

class URLAnalyser:
    """
    Orchestrates the phishing detection pipeline.

    Constructor accepts all dependencies — nothing is
    instantiated internally (Dependency Inversion Principle).

    Args:
        checks:    Ordered list of BaseCheck instances.
                   Tier 1 checks first (hard rules),
                   Tier 2 next (heuristics),
                   Tier 3 last (ML — optional).
        extractor: URLFeatureExtractor instance.
    """

    def __init__(
        self,
        checks: List[BaseCheck],
        extractor: URLFeatureExtractor,
    ):
        self._checks = checks
        self._extractor = extractor

    # --------------------------------------------------
    # Public API
    # --------------------------------------------------

    def analyse(self, data: URLRequest) -> AnalysisResult:
        logger.info("========== NEW ANALYSIS ==========")
        logger.info(f"[URL] {data.url}")

        refined = self._extractor.extract(data.url, data.links)
        logger.info(f"[DOMAIN] {refined.get('registered_domain', '')}")

        cumulative_score = 0
        cumulative_reasons: List[str] = []

        for check in self._checks:
            result: CheckResult = check.run(data, refined)

            if not result.triggered:
                continue

            cumulative_score += result.score
            cumulative_reasons.extend(result.reasons)

            # Hard block — stop pipeline immediately
            if result.is_block:
                logger.info(f"[BLOCK] {check.__class__.__name__}")
                return self._make_result("BLOCK", "phishing", cumulative_score, cumulative_reasons)

        logger.info(f"[SCORE] {cumulative_score}")

        # Threshold decision
        if cumulative_score >= 7:
            logger.info("[DECISION] BLOCK")
            return self._make_result("BLOCK", "phishing", cumulative_score, cumulative_reasons)

        if cumulative_score >= 3:
            logger.info("[DECISION] WARN")
            return self._make_result("WARN", "suspicious", cumulative_score, cumulative_reasons)

        logger.info("[DECISION] ALLOW")
        return self._make_result("ALLOW", "safe", cumulative_score, [])

    # --------------------------------------------------
    # Private helpers
    # --------------------------------------------------

    @staticmethod
    def _make_result(action, prediction, score, reasons) -> AnalysisResult:
        return AnalysisResult(
            action=action,
            prediction=prediction,
            confidence=sigmoid_confidence(score),
            reasons=reasons,
        )
