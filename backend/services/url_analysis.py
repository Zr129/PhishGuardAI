import logging
import re
from utils.url_features import extract_refined_features


# ---------------------------
# LOGGING CONFIGURATION
# ---------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhishGuard")


# ---------------------------
# CONSTANTS
# ---------------------------

PROTECTED_BRANDS = {
    'paypal': ['paypal.com', 'paypal-corp.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com'],
    'netflix': ['netflix.com'],
    'apple': ['apple.com', 'icloud.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'paloalto': ['paloaltonetworks.com']
}


class URLAnalyser:

    def __init__(self):
        self.blacklist = self.load_blacklist()
        self.protected_brands = PROTECTED_BRANDS

    # ---------------------------
    # LOAD BLACKLIST
    # ---------------------------

    def load_blacklist(self):
        try:
            with open("blacklist.txt", "r") as f:
                entries = [line.strip().lower() for line in f if line.strip()]

            logger.info(f"[INIT] Loaded {len(entries)} blacklist entries")
            return entries

        except FileNotFoundError:
            logger.warning("[INIT] blacklist.txt not found")
            return []

    # ---------------------------
    # DOMAIN HELPER
    # ---------------------------

    def is_legit_domain(self, domain, official_domains):
        return any(domain == d or domain.endswith("." + d) for d in official_domains)

    # ---------------------------
    # TIER 1 — HARD RULES
    # ---------------------------

    def check_blacklist(self, domain):
        return any(domain == bad or domain.endswith("." + bad) for bad in self.blacklist)

    def check_ip_address(self, refined):
        return refined.get("is_ip", False)

    def check_iframe_trap(self, data):
        return (not getattr(data, "is_main_frame", True)) and getattr(data, "has_password_field", False)

    def check_insecure_password(self, data):
        return getattr(data, "has_password_field", False) and not getattr(data, "is_https", True)

    def check_brand_impersonation(self, data, domain, title):
        url_lower = data.url.lower()
        title_lower = title.lower()

        for brand, domains in self.protected_brands.items():

            if brand in title_lower or brand in url_lower:

                is_official = self.is_legit_domain(domain, domains)

                if not is_official:
                    reason = f"Brand impersonation: {brand} detected on {domain}"

                    if getattr(data, "has_password_field", False):
                        return True, [
                            reason,
                            "Credential harvesting risk"
                        ]

                    return False, [reason]

        return False, []

    # ---------------------------
    # TIER 2 — HEURISTICS
    # ---------------------------

    def run_heuristics(self, data, refined, domain):

        score = 0
        reasons = []

        has_password = getattr(data, "has_password_field", False)
        hidden = getattr(data, "is_hidden_submission", False)
        external = getattr(data, "action_to_different_domain", False)

        # URL obfuscation
        if "@" in data.url:
            score += 2
            reasons.append("URL obfuscation using '@'")

        # Suspicious redirect pattern
        url_no_protocol = data.url.split("://", 1)[-1]
        if url_no_protocol.count("//") > 1:
            score += 1
            reasons.append("Suspicious redirect pattern")

        # Subdomains
        if refined.get("subdomain_count", 0) > 3:
            score += 2
            reasons.append("Excessive subdomains")

        # Domain dashes
        if refined.get("has_domain_dashes"):
            score += 1
            reasons.append("Domain contains dashes")

        # External links
        if refined.get("external_ratio", 0) > 0.9 and getattr(data, "total_anchors", 0) > 15:
            score += 2
            reasons.append("High external link ratio")

        # Dead links
        total = getattr(data, "total_anchors", 0)
        empty = getattr(data, "empty_anchors", 0)

        if total > 15:
            ratio = empty / total
            if ratio > 0.7:
                score += 2
                reasons.append("High dead link ratio")

        # ---------------------------
        # FORM ANALYSIS (CORE LOGIC)
        # ---------------------------

        if has_password:

            if hidden and external:
                score += 4
                reasons.append("Hidden submission to external domain")

            elif external:
                score += 2
                reasons.append("Credentials sent to external domain")

            elif hidden:
                score += 1
                reasons.append("Hidden form behaviour")

        return score, reasons

    # ---------------------------
    # CONFIDENCE FUNCTION
    # ---------------------------

    def confidence(self, score):
        return min(score * 12, 95)  # smoother scaling

    # ---------------------------
    # RESPONSE HELPERS
    # ---------------------------

    def block(self, score, reasons):
        return {
            "action": "BLOCK",
            "prediction": "phishing",
            "confidence": self.confidence(score),
            "reasons": reasons
        }

    def warn(self, score, reasons):
        return {
            "action": "WARN",
            "prediction": "suspicious",
            "confidence": self.confidence(score),
            "reasons": reasons
        }

    def allow(self, score=0):
        return {
            "action": "ALLOW",
            "prediction": "safe",
            "confidence": self.confidence(score),
            "reasons": []
        }

    # ---------------------------
    # MAIN PIPELINE
    # ---------------------------

    def analyse(self, data):

        logger.info("========== NEW ANALYSIS ==========")
        logger.info(f"[URL] {data.url}")

        refined = extract_refined_features(data.url, data.links)

        domain = refined.get("registered_domain", "")
        title = data.title.lower()

        logger.info(f"[DOMAIN] {domain}")

        # -------- TIER 1 --------

        if self.check_blacklist(domain):
            logger.info("[BLOCK] Blacklist")
            return self.block(10, ["Known phishing domain"])

        if self.check_ip_address(refined):
            logger.info("[BLOCK] IP address")
            return self.block(10, ["IP address used"])

        if self.check_iframe_trap(data):
            logger.info("[BLOCK] IFrame trap")
            return self.block(9, ["Hidden login trap"])

        if self.check_insecure_password(data):
            logger.info("[BLOCK] HTTP password")
            return self.block(9, ["Password over HTTP"])

        is_block, reasons = self.check_brand_impersonation(data, domain, title)

        if is_block:
            logger.info("[BLOCK] Brand impersonation")
            return self.block(9, reasons)

        logger.info("[TIER 1] Passed")

        # -------- TIER 2 --------

        score, reasons = self.run_heuristics(data, refined, domain)

        for r in reasons:
            logger.info(f"[FLAG] {r}")

        logger.info(f"[SCORE] {score}")

        # -------- DECISION --------

        if score >= 7:
            logger.info("[DECISION] BLOCK")
            return self.block(score, reasons)

        if score >= 3:
            logger.info("[DECISION] WARN")
            return self.warn(score, reasons)

        logger.info("[DECISION] ALLOW")
        return self.allow(score)