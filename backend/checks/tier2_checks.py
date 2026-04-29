"""
Tier 2 — Heuristic Scoring.

Accumulates a contextual risk score based on multiple behavioural signals.
No single signal causes a block — the combined cumulative score (across
Tier 2 and Tier 3 ML) determines the final verdict in url_analysis.py:

  score >= 9  → BLOCK
  score >= 6  → WARN
  score <  6  → ALLOW

This tier models phishing behaviour using weighted signals and
signal combinations (stacking), rather than relying on any single indicator.

Brand impersonation detection lives here (moved from Tier 1) because
brand detection requires interpretation — a domain containing a brand
name may be legitimate — so it contributes a scored signal rather than
triggering an immediate hard block.
"""

import logging
import tldextract
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest

logger = logging.getLogger("PhishGuard")


# ── Brand constants ────────────────────────────────────────────────────────────

# Known brands to check for impersonation.
BRANDS = {
    "paypal", "amazon", "microsoft", "google", "netflix",
    "apple", "facebook", "instagram", "twitter", "linkedin",
    "dropbox", "steam", "ebay", "hsbc", "barclays", "lloyds",
    "spotify", "tiktok", "snapchat", "discord",
}

# Official domains where the base name differs from the brand keyword.
# tldextract handles all country TLDs automatically (amazon.co.jp → base "amazon")
# so only list domains that genuinely have a different base name.
BRAND_EXTRAS = {
    "paypal":    ["paypal-corp.com"],
    "google":    ["gmail.com", "youtube.com", "googleapis.com",
                  "googleusercontent.com", "gstatic.com", "googlevideo.com"],
    "microsoft": ["live.com", "outlook.com", "office.com", "microsoft365.com",
                  "microsoftonline.com", "xbox.com", "skype.com", "bing.com", "msn.com"],
    "amazon":    ["kindle.com", "audible.com", "zappos.com", "twitch.tv"],
    "apple":     ["icloud.com", "me.com", "mac.com"],
    "facebook":  ["fb.com", "messenger.com", "whatsapp.com", "oculus.com"],
    "twitter":   ["x.com", "t.co"],
    "steam":     ["steamcommunity.com", "steampowered.com",
                  "steamstatic.com", "valvesoftware.com"],
}

# Brands excluded from title-only scoring — these appear legitimately in
# millions of page titles due to OAuth/SSO flows ("Sign in with Google",
# "Continue with Apple"). Domain-based detection still applies for these.
TITLE_BRAND_EXCLUDED = {"google", "apple", "facebook", "twitter"}

# URL length threshold for the long-URL heuristic.
# Kept at 300 — most legitimate URLs (e-commerce, news, social) exceed 120
# chars easily. Only fires when the URL is genuinely abnormal AND has many
# parameters (both conditions required — see URL signals section below).
SUSPICIOUS_URL_LENGTH = 300


def _extract_domain_base(registered_domain: str) -> str:
    """Extract the base domain name using tldextract."""
    try:
        return tldextract.extract(registered_domain).domain.lower()
    except Exception:
        return registered_domain.lower()


def _is_legitimate_brand_domain(brand: str, registered_domain: str, domain_base: str) -> bool:
    """
    Return True if the registered domain is a legitimate official domain
    for this brand — either an exact base match or listed in BRAND_EXTRAS.
    """
    # Exact base match — amazon.co.jp → base "amazon" → legitimate
    if domain_base == brand:
        return True
    # Listed extra domain — gmail.com for google, icloud.com for apple etc.
    extras = BRAND_EXTRAS.get(brand, [])
    if any(
        registered_domain == d or registered_domain.endswith("." + d)
        for d in extras
    ):
        return True
    return False


# ── HeuristicCheck ─────────────────────────────────────────────────────────────

class HeuristicCheck(BaseCheck):

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        score   = 0
        reasons = []

        registered_domain = refined.get("registered_domain", "")
        domain_base       = _extract_domain_base(registered_domain)

        # ── Brand impersonation (domain-based) ───────────────────────────────
        # Check whether a known brand name appears in the domain base without
        # being an exact match — e.g. "amazon-secure.com" contains "amazon"
        # but is not the legitimate amazon.com.
        #
        # Scoring:
        #   Brand in domain + password field  → +6  (strong signal)
        #   Brand in domain, no password      → +2  (suspicious domain alone)
        #
        # Not a hard block because some edge cases are legitimate:
        # resellers, partner portals, brand awareness sites.

        for brand in BRANDS:
            if _is_legitimate_brand_domain(brand, registered_domain, domain_base):
                continue  # legitimate — skip

            if brand not in domain_base:
                continue  # brand not in this domain — skip

            # Brand IS in domain base but NOT a legitimate domain
            reason = (
                f"Brand impersonation: '{brand}' in domain '{registered_domain}'"
            )
            if data.has_password_field:
                score += 6
                reasons.append(reason)
                reasons.append("Credential harvesting risk")
                logger.info(
                    f"[TIER2] Brand impersonation (domain+password): "
                    f"'{brand}' in '{registered_domain}' (+6)"
                )
            else:
                score += 2
                reasons.append(reason)
                logger.info(
                    f"[TIER2] Brand impersonation (domain only): "
                    f"'{brand}' in '{registered_domain}' (+2)"
                )
            break  # only score once per page

        # ── Brand impersonation (title-based) ───────────────────────────────
        # Weaker signal: brand name in page title when domain is unrelated.
        # Only scored when a password field is present — without one, a brand
        # name in the title is almost certainly legitimate content (news, docs).
        # Brands common in OAuth/SSO titles are excluded to prevent false
        # positives on legitimate sites that offer social login.
        #
        # Scoring: +2 (weaker than domain-based, requires password field)

        if data.has_password_field and data.title:
            title_lower  = data.title.lower()
            title_scored = False

            for brand in BRANDS:
                if title_scored:
                    break

                # Skip brands excluded from title-only checks
                if brand in TITLE_BRAND_EXCLUDED:
                    continue

                # Skip if domain already relates to this brand
                if _is_legitimate_brand_domain(brand, registered_domain, domain_base):
                    continue

                # Skip if domain-based check already scored this brand
                if brand in domain_base:
                    continue

                if brand in title_lower:
                    score += 2
                    reasons.append(
                        f"Brand '{brand}' in page title "
                        f"but domain '{registered_domain}' is unrelated"
                    )
                    logger.info(
                        f"[TIER2] Brand impersonation (title+password): "
                        f"'{brand}' in title, domain='{registered_domain}' (+2)"
                    )
                    title_scored = True

        # ── URL signals ──────────────────────────────────────────────────────

        # @ obfuscation — e.g. http://trusted.com@evil.com/login
        if "@" in data.url:
            score += 2
            reasons.append("URL obfuscation using '@'")
            logger.info("[TIER2] URL obfuscation using '@'")

        # Unusually long URL with many parameters
        url_len     = len(data.url)
        param_count = data.url.count("=") + data.url.count("&")
        if url_len > SUSPICIOUS_URL_LENGTH and param_count > 5:
            score += 1
            reasons.append(f"Unusually long URL with many parameters ({url_len} chars)")
            logger.info(f"[TIER2] Suspicious URL length: {url_len} chars")

        # Double-slash redirect pattern after the protocol
        url_no_protocol = data.url.split("://", 1)[-1]
        if url_no_protocol.count("//") > 1:
            score += 1
            reasons.append("Suspicious redirect pattern in URL")
            logger.info("[TIER2] Suspicious double-slash redirect")

        # Excessive subdomains — more than 3 levels deep
        if refined.get("subdomain_count", 0) > 3:
            score += 2
            reasons.append("Excessive subdomains")
            logger.info("[TIER2] Excessive subdomains")

        # High external link ratio — > 80% of links leave this domain
        if refined.get("external_ratio", 0) > 0.8 and data.total_anchors > 5:
            score += 2
            reasons.append("High external link ratio")
            logger.info("[TIER2] High external link ratio")

        # ── Iframe signals ───────────────────────────────────────────────────
        # Scores are NOT reduced for login pages — a hidden or external
        # iframe on a login page is MORE suspicious, not less.

        if data.has_hidden_iframe:
            score += 2
            reasons.append("Hidden iframe detected")
            logger.info("[TIER2] Hidden iframe detected")

        if data.has_external_iframe and data.has_password_field:
            score += 3
            reasons.append("Password field present alongside external domain iframe")
            logger.info("[TIER2] External iframe with password field")

        # ── Page behaviour signals ───────────────────────────────────────────

        if data.has_meta_refresh:
            score += 2
            reasons.append("Meta refresh redirect detected")
            logger.info("[TIER2] Meta refresh redirect detected")

        if data.has_auto_download:
            score += 3
            reasons.append("Auto-download link detected")
            logger.info("[TIER2] Auto-download link detected")

        # Dead link ratio — most anchors are empty (#) or javascript:void
        if data.total_anchors > 0:
            ratio = data.empty_anchors / data.total_anchors
            # Threshold drops from 10 to 5 when a password field is present —
            # phishing login pages are often minimal with very few anchors
            min_anchors = 5 if data.has_password_field else 10
            if data.total_anchors >= min_anchors and ratio > 0.7:
                score += 2
                reasons.append("High dead link ratio")
                logger.info("[TIER2] High dead link ratio")

        # ── Form signals (only when password field present) ──────────────────

        if data.has_password_field:

            if data.is_hidden_submission and data.action_to_different_domain:
                # Both together — strongest form signal
                score += 4
                reasons.append("Hidden form submission to external domain")
                logger.info("[TIER2] Hidden form submission to external domain")

            elif data.action_to_different_domain:
                score += 2
                reasons.append("Credentials sent to external domain")
                logger.info("[TIER2] Credentials sent to external domain")

            elif data.is_hidden_submission:
                score += 1
                reasons.append("Hidden form submission behaviour")
                logger.info("[TIER2] Hidden form submission behaviour")

        # ── Signal stacking ──────────────────────────────────────────────────
        # When multiple risk signals accumulate on a page that also has a
        # password field, the combination is more suspicious than the sum of
        # parts. These bonuses only apply on credential-harvesting pages.

        if data.has_password_field:

            # Multiple independent signals on a login page — amplify
            if score >= 5:
                score += 2
                reasons.append("Multiple risk signals on login page")
                logger.info("[TIER2] Signal stacking: multiple signals on login page (+2)")

            # @ in URL combined with a credential request — separate bonus
            # Note: the base @ signal (+2) is scored earlier in URL signals.
            # This stacking bonus only fires when BOTH conditions are present
            # together, treating the combination as a stronger compound signal.
            if "@" in data.url:
                score += 1
                reasons.append("Obfuscated URL combined with credential request")
                logger.info("[TIER2] Signal stacking: @ + password field (+1)")

        # ─────────────────────────────────────────────────────────────────────

        triggered = score > 0

        return CheckResult(
            triggered=triggered,
            is_block=False,
            score=score,
            reasons=reasons,
            tier="HEURISTIC",
        )