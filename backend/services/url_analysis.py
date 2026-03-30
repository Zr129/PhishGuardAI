from utils.url_features import extract_url_features

def load_blacklist():
    with open("blacklist.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

BLACKLIST = load_blacklist()


def analyse_url(data):
    url = data.url.lower()
    domain = data.domain.lower()
    suspicious_triggers = []

    # --- TIER 1: BLACKLIST (INSTANT EXIT) ---
    for bad_url in BLACKLIST:
        if bad_url in url:
            return {
                "action": "BLOCK",
                "prediction": "phishing",
                "confidence": 1.0,
                "reasons": ["URL identified in global phishing database"]
            }

    # --- TIER 2: CRITICAL THREATS (DETERMINISTIC BLOCKS) ---
    # Rule A: IP-Based Identity (Very high signal for phishing)
    if data.has_ip:
        return {
            "action": "BLOCK",
            "prediction": "phishing",
            "confidence": 1.0,
            "reasons": ["IP-Address Phishing: Form detected on a raw IP address instead of a domain"]
        }

    # Rule B: Credential Theft (Password + External Submission)
    if data.has_password_field and data.action_to_different_domain:
        return {
            "action": "BLOCK", 
            "prediction": "phishing",
            "confidence": 1.0,
            "reasons": ["Credential Harvesting: Login form submits data to an external domain"]
        }
    
    # Rule C: Protocol Downgrade
    if data.has_password_field and not data.is_https:
        return {
            "action": "BLOCK",
            "prediction": "phishing",
            "confidence": 0.98,
            "reasons": ["Insecure Harvesting: Password field detected on a non-encrypted (HTTP) page"]
        }

    # --- TIER 3: SMART BRAND ANALYSIS ---
    if data.brand_keyword:
        brand = data.brand_keyword.lower()
        # Official check: Does the domain end with the brand (e.g., 'amazon.com')?
        # This handles subdomains like 'aws.amazon.com' correctly.
        is_official = domain.endswith(f"{brand}.com") or domain.endswith(f"{brand}.co.uk") or domain.endswith(f"{brand}.net")
        
        if not is_official:
            reason = f"Brand Impersonation: Page claims to be {brand.capitalize()} but uses an unofficial domain ({domain})"
            # If there's a password field on a fake brand site, BLOCK immediately.
            if data.has_password_field:
                return {
                    "action": "BLOCK",
                    "prediction": "phishing",
                    "confidence": 1.0,
                    "reasons": [reason, "Credential Theft: Fake brand page requesting login details"]
                }
            suspicious_triggers.append(reason)

    # --- TIER 4: STRUCTURAL ANOMALIES (SUSPICIOUS) ---
    
    # Check for "Fake Nav" (Optimized for Amazon/Big sites)
    if data.total_anchors > 0:
        empty_percent = (data.empty_anchors / data.total_anchors) * 100 
        # Only flag if raw count is high (>30) AND ratio is high (>40%)
        if data.empty_anchors > 30 and empty_percent > 40:
            suspicious_triggers.append(f"Suspicious UI: {round(empty_percent)}% of navigation links are dead/empty placeholders")

    # Check for "Isolator" Kits (Template behavior)
    if data.ext_anchor_ratio > 0.85 and data.num_links_external > 10:
        suspicious_triggers.append("Structural Anomaly: High ratio of external links typical of phishing templates")

    # --- FINAL JUDGMENT ---
    if suspicious_triggers:
        return {
            "action": "WARN",
            "prediction": "suspicious",
            "confidence": min(0.7 + (len(suspicious_triggers) * 0.1), 0.95),
            "reasons": suspicious_triggers
        }

    # --- TIER 5: SAFE ---
    return {
        "action": "ALLOW",
        "prediction": "safe",
        "confidence": 0.0,
        "reasons": []
    }