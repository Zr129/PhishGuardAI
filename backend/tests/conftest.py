"""
conftest.py — pytest fixtures shared across all test files.

Uses the fixture factory pattern so make_request and make_refined
can accept keyword arguments while still being proper pytest fixtures.

Usage in tests:
    def test_something(make_request, make_refined):
        data    = make_request(url="http://192.168.1.1/", has_password_field=True)
        refined = make_refined(is_ip=True, registered_domain="192.168.1.1")
"""

import sys
import os
import pytest

# Add backend root to path so all module imports resolve correctly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture
def make_request():
    """
    Fixture factory — returns a URLRequest builder function.
    Call it with keyword overrides for only the fields your test cares about.
    All other fields default to safe, non-triggering values.

    Example:
        data = make_request(url="http://192.168.1.1/", has_password_field=True)
    """
    def _build(**overrides):
        from models.models import URLRequest

        defaults = {
            # PageMeta
            "url":                      "https://example.com/page",
            "domain":                   "example.com",
            "title":                    "Example Page",
            "is_https":                 True,
            "is_main_frame":            True,
            "is_responsive":            True,
            "has_favicon":              True,
            "has_robots":               False,
            "has_description":          True,
            "has_title":                True,
            "domain_title_match_score": 0.5,
            "url_title_match_score":    0.2,
            # FormContext
            "has_password_field":         False,
            "is_hidden_submission":       False,
            "action_to_different_domain": False,
            "has_submit_button":          False,
            "has_hidden_fields":          False,
            # LinkContext
            "links":          [],
            "empty_anchors":  0,
            "total_anchors":  0,
            "no_of_self_ref": 5,
            "has_social_net": True,
            # ContentSignals
            "has_bank_keywords":      False,
            "has_pay_keywords":       False,
            "has_crypto_keywords":    False,
            "has_copyright":          True,
            "no_of_images":           8,
            "no_of_css":              3,
            "no_of_js":               4,
            "has_auto_download":      False,
            "has_meta_refresh":       False,
            "has_suspicious_scripts": False,
        }
        defaults.update(overrides)
        return URLRequest(**defaults)

    return _build


@pytest.fixture
def make_refined():
    """
    Fixture factory — returns a refined dict builder function.
    Call it with keyword overrides for only the fields your test needs.

    Example:
        refined = make_refined(is_ip=True, registered_domain="192.168.1.1")
    """
    def _build(**overrides):
        defaults = {
            "registered_domain": "example.com",
            "subdomain_count":   0,
            "is_ip":             False,
            "IsHTTPS":           1,
            "external_ratio":    0.1,
            "ExternalRatio":     0.1,
            "URLLength":         30,
            "NoOfSubDomain":     0,
            "HasDomainDashes":   0,
        }
        defaults.update(overrides)
        return defaults

    return _build


@pytest.fixture
def safe_request(make_request):
    """Pre-built safe request — scores ALLOW with zero flags."""
    return make_request()


@pytest.fixture
def safe_refined(make_refined):
    """Pre-built safe refined dict."""
    return make_refined()