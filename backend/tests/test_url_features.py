"""
test_url_features.py — unit tests for URLFeatureExtractor.

Verifies that URL parsing produces correct feature values.
These tests are important because the ML model depends entirely
on the feature vector — a wrong extraction silently breaks detection.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.url_features import URLFeatureExtractor


@pytest.fixture
def extractor():
    return URLFeatureExtractor()


# ── Domain extraction ─────────────────────────────────────────────

class TestDomainExtraction:

    def test_simple_domain(self, extractor):
        result = extractor.extract("https://example.com/page", [])
        assert result["registered_domain"] == "example.com"

    def test_www_prefix_stripped_from_registered_domain(self, extractor):
        result = extractor.extract("https://www.example.com/page", [])
        assert result["registered_domain"] == "example.com"

    def test_subdomain_not_in_registered_domain(self, extractor):
        result = extractor.extract("https://login.secure.example.com/page", [])
        assert result["registered_domain"] == "example.com"

    def test_country_tld_preserved(self, extractor):
        result = extractor.extract("https://amazon.co.uk/products", [])
        assert result["registered_domain"] == "amazon.co.uk"

    def test_subdomain_count_correct(self, extractor):
        # login.secure.example.com → subdomains: ["login", "secure"]
        result = extractor.extract("https://login.secure.example.com/", [])
        assert result["subdomain_count"] == 2

    def test_www_not_counted_as_subdomain(self, extractor):
        result = extractor.extract("https://www.example.com/", [])
        assert result["subdomain_count"] == 0

    def test_no_subdomains(self, extractor):
        result = extractor.extract("https://example.com/", [])
        assert result["subdomain_count"] == 0


# ── IP address detection ──────────────────────────────────────────

class TestIPDetection:

    def test_ip_address_detected(self, extractor):
        result = extractor.extract("http://192.168.1.1/login", [])
        assert result["is_ip"] == 1
        assert result["IsDomainIP"] == 1

    def test_normal_domain_not_ip(self, extractor):
        result = extractor.extract("https://example.com/page", [])
        assert result["is_ip"] == 0

    def test_localhost_not_ip(self, extractor):
        result = extractor.extract("http://localhost:8080/test", [])
        assert result["is_ip"] == 0


# ── HTTPS detection ───────────────────────────────────────────────

class TestHTTPSDetection:

    def test_https_url_flagged(self, extractor):
        result = extractor.extract("https://example.com/", [])
        assert result["IsHTTPS"] == 1

    def test_http_url_not_flagged(self, extractor):
        result = extractor.extract("http://example.com/", [])
        assert result["IsHTTPS"] == 0


# ── URL length ────────────────────────────────────────────────────

class TestURLLength:

    def test_url_length_correct(self, extractor):
        url    = "https://example.com/path"
        result = extractor.extract(url, [])
        assert result["URLLength"] == len(url)

    def test_long_url_length(self, extractor):
        url    = "https://example.com/" + "a" * 200
        result = extractor.extract(url, [])
        assert result["URLLength"] == len(url)


# ── Character ratios ──────────────────────────────────────────────

class TestCharacterRatios:

    def test_digit_ratio_calculated(self, extractor):
        # URL: "https://123.com/456" — count digits in full URL
        url    = "https://example.com/12345"
        result = extractor.extract(url, [])
        url_len = len(url)
        digits  = sum(c.isdigit() for c in url)
        expected = round(digits / url_len, 4)
        assert result["DegitRatioInURL"] == pytest.approx(expected, abs=0.001)

    def test_letter_ratio_calculated(self, extractor):
        url    = "https://example.com/page"
        result = extractor.extract(url, [])
        url_len = len(url)
        letters  = sum(c.isalpha() for c in url)
        expected = round(letters / url_len, 4)
        assert result["LetterRatioInURL"] == pytest.approx(expected, abs=0.001)


# ── Domain dashes ────────────────────────────────────────────────

class TestDomainDashes:

    def test_domain_with_dashes_flagged(self, extractor):
        result = extractor.extract("https://paypal-secure.com/", [])
        assert result["HasDomainDashes"] == 1

    def test_domain_without_dashes_not_flagged(self, extractor):
        result = extractor.extract("https://paypal.com/", [])
        assert result["HasDomainDashes"] == 0


# ── External link ratio ───────────────────────────────────────────

class TestExternalLinkRatio:

    def test_all_internal_links_zero_ratio(self, extractor):
        links  = ["https://example.com/page1", "https://example.com/page2"]
        result = extractor.extract("https://example.com/", links)
        assert result["ExternalRatio"] == 0.0

    def test_all_external_links_full_ratio(self, extractor):
        links  = ["https://other.com/a", "https://another.com/b",
                  "https://third.com/c"]
        result = extractor.extract("https://example.com/", links)
        assert result["ExternalRatio"] == pytest.approx(1.0, abs=0.01)

    def test_mixed_links_partial_ratio(self, extractor):
        links  = [
            "https://example.com/internal",    # internal
            "https://external1.com/page",      # external
            "https://external2.com/page",      # external
            "https://external3.com/page",      # external
        ]
        result = extractor.extract("https://example.com/", links)
        # 3 external / 4 total = 0.75
        assert result["ExternalRatio"] == pytest.approx(0.75, abs=0.01)

    def test_non_http_links_ignored(self, extractor):
        links  = ["mailto:test@example.com", "javascript:void(0)", "#anchor"]
        result = extractor.extract("https://example.com/", links)
        assert result["TotalLinks"] == 0
        assert result["ExternalRatio"] == 0.0


# ── Required keys present ─────────────────────────────────────────

class TestRequiredKeysPresent:

    def test_all_required_keys_present(self, extractor):
        """
        Verify the feature dict has all keys the ML model and checks expect.
        Missing keys would silently produce wrong ML scores.
        """
        required_keys = [
            # ML features (FIELD_MAP keys)
            "URLLength", "DegitRatioInURL", "IsHTTPS",
            "SpacialCharRatioInURL", "LetterRatioInURL", "NoOfSubDomain",
            # Check features
            "is_ip", "subdomain_count", "external_ratio",
            "ExternalRatio", "registered_domain",
            # Extra features used by checks
            "HasDomainDashes",
        ]
        result = extractor.extract("https://example.com/page", [])
        for key in required_keys:
            assert key in result, f"Missing key: {key}"
