"""
test_url_analysis.py — integration tests for URLAnalyser pipeline.

Tests verify:
  - ALLOW / WARN / BLOCK thresholds (score < 6, 6-8, >= 9)
  - Short-circuit behaviour (hard block stops pipeline)
  - url and domain echoed on every result
  - Whitelist short-circuit returns ALLOW regardless of signals
  - ML score is weighted at 0.6x before accumulation
"""

import pytest

from unittest.mock import MagicMock, patch
from checks.base import CheckResult
from services.url_analysis import URLAnalyser


# ── Helpers ───────────────────────────────────────────────────────

def make_mock_check(triggered=False, is_block=False, score=0,
                    reasons=None, tier="RULE"):
    """Create a mock BaseCheck that returns a fixed CheckResult."""
    check  = MagicMock()
    result = CheckResult(
        triggered=triggered,
        is_block=is_block,
        score=score,
        reasons=reasons or [],
        tier=tier,
    )
    check.run.return_value = result
    return check


def make_analyser(checks):
    """Build a URLAnalyser with mock checks and a real extractor."""
    from utils.url_features import URLFeatureExtractor
    return URLAnalyser(checks=checks, extractor=URLFeatureExtractor())


# ── Decision thresholds ───────────────────────────────────────────

class TestDecisionThresholds:

    def test_score_below_6_is_allow(self, make_request, make_refined):
        """Score 5 → ALLOW."""
        checks   = [make_mock_check(triggered=True, score=5, tier="HEURISTIC")]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert result.action     == "ALLOW"
        assert result.prediction == "safe"

    def test_score_exactly_6_is_warn(self, make_request, make_refined):
        """Score 6 → WARN (at threshold)."""
        checks   = [make_mock_check(triggered=True, score=6, tier="HEURISTIC")]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert result.action     == "WARN"
        assert result.prediction == "suspicious"

    def test_score_8_is_warn(self, make_request, make_refined):
        """Score 8 → WARN (below block threshold)."""
        checks   = [make_mock_check(triggered=True, score=8, tier="HEURISTIC")]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert result.action == "WARN"

    def test_score_exactly_9_is_block(self, make_request, make_refined):
        """Score 9 → BLOCK (at block threshold)."""
        checks   = [make_mock_check(triggered=True, score=9, tier="HEURISTIC")]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert result.action     == "BLOCK"
        assert result.prediction == "phishing"

    def test_score_above_9_is_block(self, make_request, make_refined):
        """Score 14 → BLOCK."""
        checks   = [make_mock_check(triggered=True, score=14, tier="RULE")]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert result.action == "BLOCK"

    def test_no_triggers_is_allow(self, make_request, make_refined):
        """No checks triggered → ALLOW with 0 reasons."""
        checks   = [make_mock_check(triggered=False)]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert result.action  == "ALLOW"
        assert result.reasons == []


# ── Hard block short-circuit ──────────────────────────────────────

class TestHardBlockShortCircuit:

    def test_hard_block_stops_pipeline(self, make_request, make_refined):
        """
        A hard-blocking check (is_block=True) should stop the pipeline.
        Subsequent checks should NOT run.
        """
        block_check     = make_mock_check(triggered=True, is_block=True,
                                          score=14, reasons=["Hard block reason"])
        subsequent_check = make_mock_check(triggered=True, score=5)
        analyser        = make_analyser([block_check, subsequent_check])

        result = analyser.analyse(make_request())

        assert result.action    == "BLOCK"
        # Subsequent check should never have run
        subsequent_check.run.assert_not_called()

    def test_hard_block_returns_immediately_with_reason(self, make_request, make_refined):
        """Hard block result should include the blocking reason."""
        checks   = [make_mock_check(triggered=True, is_block=True,
                                    score=14, reasons=["Known phishing domain"])]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert result.action      == "BLOCK"
        assert "Known phishing domain" in result.reasons

    def test_non_blocking_check_does_not_stop_pipeline(self, make_request, make_refined):
        """A triggered but non-blocking check should allow pipeline to continue."""
        warn_check   = make_mock_check(triggered=True, is_block=False,
                                       score=3, tier="HEURISTIC")
        second_check = make_mock_check(triggered=True, is_block=False,
                                       score=3, tier="HEURISTIC")
        analyser     = make_analyser([warn_check, second_check])

        result = analyser.analyse(make_request())

        # Both checks ran and accumulated score 6 → WARN
        second_check.run.assert_called_once()
        assert result.action == "WARN"
        assert result.score  == 6 if hasattr(result, 'score') else True


# ── Whitelist short-circuit ───────────────────────────────────────

class TestWhitelistShortCircuit:

    def test_whitelist_score_minus99_returns_allow(self, make_request, make_refined):
        """
        WhitelistCheck returns score=-99 which should force ALLOW
        regardless of other accumulated scores.
        """
        whitelist_check = make_mock_check(triggered=True, is_block=False,
                                          score=-99, reasons=["Trusted domain"])
        # Even with a hard-blocking check next, whitelist should short-circuit
        block_check     = make_mock_check(triggered=True, is_block=True, score=14)
        analyser        = make_analyser([whitelist_check, block_check])

        result = analyser.analyse(make_request())

        assert result.action == "ALLOW"
        # Block check should never run
        block_check.run.assert_not_called()


# ── url and domain echoed on result ──────────────────────────────

class TestResultEchosUrlAndDomain:

    def test_url_echoed_on_allow(self, make_request, make_refined):
        """AnalysisResult.url must match the request URL on ALLOW."""
        checks   = [make_mock_check(triggered=False)]
        analyser = make_analyser(checks)
        data     = make_request(url="https://example.com/page",
                                domain="example.com")

        result = analyser.analyse(data)

        assert result.url    == "https://example.com/page"
        assert result.domain == "example.com"

    def test_url_echoed_on_block(self, make_request, make_refined):
        """AnalysisResult.url must match the request URL on BLOCK."""
        checks   = [make_mock_check(triggered=True, is_block=True, score=14)]
        analyser = make_analyser(checks)
        data     = make_request(url="http://phishing-site.com/login",
                                domain="phishing-site.com")

        result = analyser.analyse(data)

        assert result.url    == "http://phishing-site.com/login"
        assert result.domain == "phishing-site.com"

    def test_url_echoed_on_warn(self, make_request, make_refined):
        """AnalysisResult.url must match the request URL on WARN."""
        checks   = [make_mock_check(triggered=True, score=6, tier="HEURISTIC")]
        analyser = make_analyser(checks)
        data     = make_request(url="https://suspicious-site.com/",
                                domain="suspicious-site.com")

        result = analyser.analyse(data)

        assert result.url    == "https://suspicious-site.com/"
        assert result.domain == "suspicious-site.com"

    def test_url_never_empty_on_any_result(self, make_request, make_refined):
        """url field must never be empty string on a valid request."""
        for score, is_block in [(0, False), (6, False), (14, True)]:
            checks   = [make_mock_check(triggered=score > 0,
                                        is_block=is_block, score=score)]
            analyser = make_analyser(checks)
            data     = make_request(url="https://example.com/",
                                    domain="example.com")

            result = analyser.analyse(data)

            assert result.url    != "", f"url was empty for score={score}"
            assert result.domain != "", f"domain was empty for score={score}"


# ── ML score weighting ────────────────────────────────────────────

class TestMLScoreWeighting:

    def test_ml_score_weighted_at_0_6(self, make_request, make_refined):
        """
        ML scores are multiplied by 0.6 before accumulation.
        ML score=10 → contributes 6 to cumulative → WARN (not BLOCK).
        Without weighting it would be 10 → BLOCK.
        """
        ml_check = make_mock_check(triggered=True, score=10,
                                   is_block=False, tier="ML")
        analyser = make_analyser([ml_check])

        result = analyser.analyse(make_request())

        # 10 * 0.6 = 6 → WARN, not BLOCK
        assert result.action == "WARN"

    def test_non_ml_score_not_weighted(self, make_request, make_refined):
        """Non-ML scores are applied at full weight (1.0)."""
        heuristic_check = make_mock_check(triggered=True, score=9,
                                          is_block=False, tier="HEURISTIC")
        analyser        = make_analyser([heuristic_check])

        result = analyser.analyse(make_request())

        # 9 * 1.0 = 9 → BLOCK
        assert result.action == "BLOCK"


# ── Tagged reasons ────────────────────────────────────────────────

class TestTaggedReasons:

    def test_tagged_reasons_include_tier(self, make_request, make_refined):
        """tagged_reasons should have tier badges for popup display."""
        checks   = [make_mock_check(triggered=True, score=3,
                                    reasons=["Test flag"],
                                    tier="HEURISTIC")]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        assert len(result.tagged_reasons) > 0
        tag = result.tagged_reasons[0]
        assert "text" in tag
        assert "tier" in tag
        assert tag["tier"] == "HEURISTIC"
        assert tag["text"] == "Test flag"

    def test_reasons_and_tagged_reasons_consistent(self, make_request, make_refined):
        """reasons list and tagged_reasons should have the same items."""
        checks   = [make_mock_check(triggered=True, score=3,
                                    reasons=["Flag A", "Flag B"],
                                    tier="RULE")]
        analyser = make_analyser(checks)

        result = analyser.analyse(make_request())

        reason_texts = [t["text"] for t in result.tagged_reasons]
        for reason in result.reasons:
            assert reason in reason_texts


# ── Confidence ────────────────────────────────────────────────────

class TestConfidence:

    def test_confidence_is_between_0_and_95(self, make_request, make_refined):
        """Confidence should always be in range 0-95."""
        for score in [0, 3, 6, 9, 14, 20]:
            checks   = [make_mock_check(triggered=score > 0, score=score)]
            analyser = make_analyser(checks)

            result = analyser.analyse(make_request())

            assert 0 <= result.confidence <= 95, \
                f"Confidence {result.confidence} out of range for score {score}"

    def test_higher_score_gives_higher_confidence(self, make_request, make_refined):
        """Higher risk score should produce higher confidence percentage."""
        results = []
        for score in [0, 6, 9, 14]:
            checks   = [make_mock_check(triggered=score > 0, score=score)]
            analyser = make_analyser(checks)
            results.append(analyser.analyse(make_request()).confidence)

        assert results == sorted(results), \
            f"Confidence not monotonically increasing: {results}"