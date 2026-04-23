"""
test_tier2_checks.py — unit tests for Tier 2 heuristic scoring.

Tests verify the exact score contributed by each heuristic signal
and that combined signals produce the correct total score.
Scoring values taken directly from tier2_checks.py.
"""

import pytest


class TestHeuristicCheck:

    def setup_method(self):
        from checks.tier2_checks import HeuristicCheck
        self.check = HeuristicCheck()

    # ── Clean baseline ──────────────────────────────────────────────

    def test_clean_page_scores_zero(self, safe_request, safe_refined):
        """A page with no suspicious signals should score 0."""
        result = self.check.run(safe_request, safe_refined)

        assert result.triggered is False
        assert result.score     == 0

    # ── URL obfuscation via @ ───────────────────────────────────────

    def test_at_symbol_in_url_scores_2(self, make_request, make_refined):
        """@ in URL = obfuscation heuristic = score +2."""
        data    = make_request(url="https://trusted@example.com/login")
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.score     == 2
        assert any("@" in r for r in result.reasons)

    def test_normal_url_no_at_scores_zero(self, make_request, make_refined):
        data    = make_request(url="https://example.com/login")
        refined = make_refined()

        result = self.check.run(data, refined)

        # @ check only
        assert "@" not in data.url
        url_score = sum(1 for r in result.reasons if "@" in r)
        assert url_score == 0

    # ── Dead link ratio ─────────────────────────────────────────────

    def test_dead_link_ratio_scores_2_without_password(self, make_request, make_refined):
        """
        Without password field: min_anchors = 15.
        18 empty / 20 total = 90% > 70% threshold → score +2.
        """
        data    = make_request(empty_anchors=18, total_anchors=20,
                               has_password_field=False)
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.score     >= 2
        assert any("dead" in r.lower() or "link" in r.lower() for r in result.reasons)

    def test_dead_link_ratio_below_threshold_no_score(self, make_request, make_refined):
        """50% dead ratio is below 70% threshold — should not score."""
        data    = make_request(empty_anchors=8, total_anchors=16,
                               has_password_field=False)
        refined = make_refined()

        result = self.check.run(data, refined)

        assert not any("dead" in r.lower() or "link" in r.lower()
                       for r in result.reasons)

    def test_dead_link_lowered_threshold_with_password(self, make_request, make_refined):
        """
        With password field: min_anchors drops to 5.
        5 dead / 6 total = 83% > 70% → score +2 with only 6 anchors.
        Without password this would need 15+ anchors.
        """
        data    = make_request(empty_anchors=5, total_anchors=6,
                               has_password_field=True)
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert any("dead" in r.lower() or "link" in r.lower() for r in result.reasons)

    def test_dead_link_not_enough_anchors_without_password(self, make_request, make_refined):
        """
        5 anchors is below the 15-anchor min when no password.
        Even with 100% dead ratio this should not score.
        """
        data    = make_request(empty_anchors=5, total_anchors=5,
                               has_password_field=False)
        refined = make_refined()

        result = self.check.run(data, refined)

        assert not any("dead" in r.lower() for r in result.reasons)

    # ── Excessive subdomains ────────────────────────────────────────

    def test_excessive_subdomains_scores_2(self, make_request, make_refined):
        """More than 3 subdomains = score +2."""
        data    = make_request(url="https://a.b.c.d.example.com/")
        refined = make_refined(subdomain_count=4)

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert any("subdomain" in r.lower() for r in result.reasons)

    def test_three_subdomains_no_score(self, make_request, make_refined):
        """Exactly 3 subdomains is the threshold — should not score."""
        data    = make_request()
        refined = make_refined(subdomain_count=3)

        result = self.check.run(data, refined)

        assert not any("subdomain" in r.lower() for r in result.reasons)

    # ── High external link ratio ────────────────────────────────────

    def test_high_external_ratio_scores_2(self, make_request, make_refined):
        """External ratio > 0.9 with > 15 anchors = score +2."""
        data    = make_request(total_anchors=20)
        refined = make_refined(external_ratio=0.95, ExternalRatio=0.95)

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert any("external" in r.lower() for r in result.reasons)

    def test_high_external_ratio_not_enough_anchors(self, make_request, make_refined):
        """External ratio > 0.9 but only 10 anchors — should not score."""
        data    = make_request(total_anchors=10)
        refined = make_refined(external_ratio=0.95, ExternalRatio=0.95)

        result = self.check.run(data, refined)

        assert not any("external" in r.lower() for r in result.reasons)

    # ── Form analysis ───────────────────────────────────────────────

    def test_hidden_and_cross_domain_scores_4(self, make_request, make_refined):
        """
        Both hidden submission AND cross-domain action with password = score +4.
        This is the combined form score — highest possible from form signals.
        """
        data    = make_request(
            has_password_field=True,
            is_hidden_submission=True,
            action_to_different_domain=True,
        )
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.score     == 4
        assert any("external" in r.lower() or "hidden" in r.lower()
                   for r in result.reasons)

    def test_cross_domain_only_scores_2(self, make_request, make_refined):
        """Cross-domain action with password (no hidden submission) = score +2."""
        data    = make_request(
            has_password_field=True,
            is_hidden_submission=False,
            action_to_different_domain=True,
        )
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.score     == 2

    def test_hidden_submission_only_scores_1(self, make_request, make_refined):
        """Hidden submission with password (no cross-domain) = score +1."""
        data    = make_request(
            has_password_field=True,
            is_hidden_submission=True,
            action_to_different_domain=False,
        )
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.score     == 1

    def test_form_signals_require_password_field(self, make_request, make_refined):
        """Form signals should NOT score without a password field."""
        data    = make_request(
            has_password_field=False,
            is_hidden_submission=True,
            action_to_different_domain=True,
        )
        refined = make_refined()

        result = self.check.run(data, refined)

        # No form-related reasons should appear
        assert not any("form" in r.lower() or "credential" in r.lower()
                       or "hidden" in r.lower() or "external" in r.lower()
                       for r in result.reasons)

    # ── Combined scoring ────────────────────────────────────────────

    def test_combined_signals_accumulate(self, make_request, make_refined):
        """
        Multiple signals should accumulate correctly.
        @ URL (+2) + hidden+cross-domain form (+4) = score 6 → WARN territory.
        """
        data    = make_request(
            url="https://user@localhost/login",
            has_password_field=True,
            is_hidden_submission=True,
            action_to_different_domain=True,
        )
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.score     == 6

    def test_is_block_always_false_for_heuristics(self, make_request, make_refined):
        """
        Tier 2 heuristics never hard-block — only contribute score.
        is_block must always be False regardless of score.
        """
        data    = make_request(
            url="https://user@localhost/login",
            has_password_field=True,
            is_hidden_submission=True,
            action_to_different_domain=True,
            empty_anchors=18,
            total_anchors=20,
        )
        refined = make_refined(subdomain_count=4, external_ratio=0.95,
                               ExternalRatio=0.95)

        result = self.check.run(data, refined)

        assert result.is_block is False
        assert result.tier     == "HEURISTIC"