"""
test_tier1_checks.py — unit tests for Tier 1 hard rule checks.

Each test is isolated — it tests one check class with one specific
condition. The pipeline short-circuit is NOT tested here (that's in
test_url_analysis.py). These tests only verify that each check class
returns the correct CheckResult for its specific trigger conditions.
"""

import pytest


# ════════════════════════════════════════════════════════════════════
# IPAddressCheck
# ════════════════════════════════════════════════════════════════════

class TestIPAddressCheck:

    def setup_method(self):
        from checks.tier1_checks import IPAddressCheck
        self.check = IPAddressCheck()

    def test_triggers_on_ip_url(self, make_request, make_refined):
        """Raw IP address in URL should hard-block."""
        data    = make_request(url="http://192.168.1.1/login")
        refined = make_refined(is_ip=True, registered_domain="192.168.1.1")

        result = self.check.run(data, refined)

        assert result.triggered   is True
        assert result.is_block    is True
        assert result.score       == 14
        assert result.tier        == "RULE"
        assert any("IP" in r or "ip" in r.lower() for r in result.reasons)

    def test_does_not_trigger_on_normal_domain(self, safe_request, safe_refined):
        """Normal domain should not trigger."""
        result = self.check.run(safe_request, safe_refined)

        assert result.triggered is False
        assert result.is_block  is False
        assert result.score     == 0

    def test_does_not_trigger_on_localhost(self, make_request, make_refined):
        """localhost is not a raw IP — should not trigger."""
        data    = make_request(url="http://localhost:8080/test")
        refined = make_refined(is_ip=False, registered_domain="localhost")

        result = self.check.run(data, refined)

        assert result.triggered is False


# ════════════════════════════════════════════════════════════════════
# InsecurePasswordCheck
# ════════════════════════════════════════════════════════════════════

class TestInsecurePasswordCheck:

    def setup_method(self):
        from checks.tier1_checks import InsecurePasswordCheck
        self.check = InsecurePasswordCheck()

    def test_triggers_password_over_http(self, make_request, make_refined):
        """Password field over HTTP should hard-block."""
        data    = make_request(url="http://example.com/login",
                               is_https=False, has_password_field=True)
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.is_block  is True
        assert result.score     == 13
        assert result.tier      == "RULE"

    def test_does_not_trigger_password_over_https(self, make_request, make_refined):
        """Password field over HTTPS is fine."""
        data    = make_request(url="https://example.com/login",
                               is_https=True, has_password_field=True)
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is False

    def test_does_not_trigger_no_password_over_http(self, make_request, make_refined):
        """HTTP without a password field should not trigger."""
        data    = make_request(url="http://example.com/page",
                               is_https=False, has_password_field=False)
        refined = make_refined()

        result = self.check.run(data, refined)

        assert result.triggered is False

    def test_requires_both_conditions(self, make_request, make_refined):
        """Both HTTP AND password field are required — neither alone triggers."""
        # HTTP but no password
        r1 = self.check.run(
            make_request(is_https=False, has_password_field=False),
            make_refined()
        )
        # HTTPS with password
        r2 = self.check.run(
            make_request(is_https=True, has_password_field=True),
            make_refined()
        )
        assert r1.triggered is False
        assert r2.triggered is False



# ════════════════════════════════════════════════════════════════════
# IFrameTrapCheck
# ════════════════════════════════════════════════════════════════════

class TestIFrameTrapCheck:

    def setup_method(self):
        from checks.tier1_checks import IFrameTrapCheck
        self.check = IFrameTrapCheck()

    def test_triggers_on_iframe_with_password(self, make_request, make_refined):
        """Password field in non-main-frame non-trusted domain = hard block."""
        data    = make_request(is_main_frame=False, has_password_field=True)
        refined = make_refined(registered_domain="evil-phishing-site.com")

        result = self.check.run(data, refined)

        assert result.triggered is True
        assert result.is_block  is True
        assert result.score     == 13

    def test_does_not_trigger_on_main_frame(self, make_request, make_refined):
        """Main frame with password is handled by InsecurePasswordCheck, not IFrameTrapCheck."""
        data    = make_request(is_main_frame=True, has_password_field=True)
        refined = make_refined(registered_domain="evil-phishing-site.com")

        result = self.check.run(data, refined)

        assert result.triggered is False

    def test_does_not_trigger_on_trusted_payment_iframe(self, make_request, make_refined):
        """stripe.com iframe with password should NOT be flagged."""
        data    = make_request(is_main_frame=False, has_password_field=True)
        refined = make_refined(registered_domain="stripe.com")

        result = self.check.run(data, refined)

        assert result.triggered is False

    def test_does_not_trigger_without_password(self, make_request, make_refined):
        """Non-main-frame without password should not trigger."""
        data    = make_request(is_main_frame=False, has_password_field=False)
        refined = make_refined(registered_domain="evil-phishing-site.com")

        result = self.check.run(data, refined)

        assert result.triggered is False


# ════════════════════════════════════════════════════════════════════
# Tier 0 — WhitelistCheck and UserBlacklistCheck
# (These use UserListProvider — we mock it for isolation)
# ════════════════════════════════════════════════════════════════════

class MockUserListProvider:
    def __init__(self, whitelist=None, blacklist=None):
        self._whitelist = set(whitelist or [])
        self._blacklist = set(blacklist or [])

    def is_whitelisted(self, domain): return domain in self._whitelist
    def is_blacklisted(self, domain): return domain in self._blacklist


class TestWhitelistCheck:

    def test_trusted_domain_short_circuits(self, make_request, make_refined):
        from checks.whitelist_check import WhitelistCheck
        provider = MockUserListProvider(whitelist=["example.com"])
        check    = WhitelistCheck(provider)

        data    = make_request()
        refined = make_refined(registered_domain="example.com")

        result = check.run(data, refined)

        assert result.triggered is True
        assert result.score     == -99   # special value that forces ALLOW
        assert result.is_block  is False

    def test_non_whitelisted_domain_passes(self, make_request, make_refined):
        from checks.whitelist_check import WhitelistCheck
        provider = MockUserListProvider(whitelist=["trusted.com"])
        check    = WhitelistCheck(provider)

        data    = make_request()
        refined = make_refined(registered_domain="example.com")

        result = check.run(data, refined)

        assert result.triggered is False


class TestUserBlacklistCheck:

    def test_blacklisted_domain_hard_blocks(self, make_request, make_refined):
        from checks.whitelist_check import UserBlacklistCheck
        provider = MockUserListProvider(blacklist=["evil.com"])
        check    = UserBlacklistCheck(provider)

        data    = make_request()
        refined = make_refined(registered_domain="evil.com")

        result = check.run(data, refined)

        assert result.triggered is True
        assert result.is_block  is True
        assert result.score     == 14

    def test_non_blacklisted_domain_passes(self, make_request, make_refined):
        from checks.whitelist_check import UserBlacklistCheck
        provider = MockUserListProvider(blacklist=["evil.com"])
        check    = UserBlacklistCheck(provider)

        data    = make_request()
        refined = make_refined(registered_domain="example.com")

        result = check.run(data, refined)

        assert result.triggered is False