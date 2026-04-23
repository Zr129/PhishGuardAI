"""
test_content_js_fields.py — validates content.js scraping contract.

Rather than unit-testing the browser DOM (which requires Jest/jsdom),
this test statically analyses content.js to verify:

  1. Every field in URLRequest is present in content.js
  2. No field name mismatches between what JS sends and what Python expects
  3. The ANALYZE_PAGE message uses the expected structure

This catches the most common integration bug — a field renamed in
Python but not updated in JS (or vice versa), which causes silent
null/undefined values in the backend.
"""

import re
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Load files ────────────────────────────────────────────────────

CONTENT_JS_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "phishguard", "content.js"
)

def _read_content_js():
    path = os.path.abspath(CONTENT_JS_PATH)
    if not os.path.exists(path):
        pytest.skip(f"content.js not found at {path} — run from backend/tests/")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _get_url_request_fields():
    """Return all field names declared on URLRequest and its parent models."""
    from models.models import URLRequest
    return set(URLRequest.model_fields.keys())


# ── Tests ─────────────────────────────────────────────────────────

class TestContentJSFieldContract:

    @pytest.fixture(autouse=True)
    def load(self):
        self.js_src = _read_content_js()
        self.model_fields = _get_url_request_fields()

    def test_all_url_request_fields_present_in_content_js(self):
        """
        Every field declared on URLRequest must appear somewhere in content.js.
        A missing field means the backend receives null/undefined for that signal.

        Note: some fields like `has_robots` are optional with defaults so a
        missing value doesn't break the pipeline — but it does mean the signal
        is never populated. This test surfaces those gaps explicitly.
        """
        missing = []
        for field in self.model_fields:
            # Check the field name appears as a JS object key (quoted or unquoted)
            # Patterns: `url:`, `"url":`, `has_password_field:`
            pattern = rf'["\']?{re.escape(field)}["\']?\s*:'
            if not re.search(pattern, self.js_src):
                missing.append(field)

        # These fields are intentionally set by the backend, not content.js
        backend_only = {"url", "domain"}  # echoed back on AnalysisResult
        missing = [f for f in missing if f not in backend_only]

        assert missing == [], (
            f"The following URLRequest fields are NOT found in content.js:\n"
            + "\n".join(f"  - {f}" for f in sorted(missing))
            + "\n\nThese fields will always be null/default in the backend."
        )

    def test_analyze_page_message_type_correct(self):
        """content.js must send ANALYZE_PAGE (not ANALYSE_PAGE or other variant)."""
        assert "ANALYZE_PAGE" in self.js_src, \
            "Message type ANALYZE_PAGE not found in content.js"

    def test_url_field_populated_from_location(self):
        """URL should come from window.location or window.top.location."""
        assert "location.href" in self.js_src, \
            "content.js does not use location.href — URL may not be scraped"

    def test_is_https_field_present(self):
        """is_https is critical — InsecurePasswordCheck depends on it."""
        assert "is_https" in self.js_src, \
            "is_https field not found in content.js"

    def test_is_main_frame_field_present(self):
        """is_main_frame is critical — controls iframe race condition fix."""
        assert "is_main_frame" in self.js_src, \
            "is_main_frame field not found in content.js"

    def test_password_field_detection_present(self):
        """has_password_field detection logic should be present."""
        assert "password" in self.js_src.lower(), \
            "Password field detection not found in content.js"

    def test_no_typos_in_critical_field_names(self):
        """
        Check for common typos in field names that have caused bugs before.
        These are the fields that Tier 1 and Tier 2 checks depend on most.
        """
        critical_fields = [
            "has_password_field",
            "is_hidden_submission",
            "action_to_different_domain",
            "has_auto_download",
            "has_meta_refresh",
            "no_of_self_ref",
            "has_social_net",
            "has_copyright",
        ]
        for field in critical_fields:
            pattern = rf'["\']?{re.escape(field)}["\']?\s*:'
            assert re.search(pattern, self.js_src), \
                f"Critical field '{field}' not found in content.js — " \
                f"check for typos or missing scraping logic"
