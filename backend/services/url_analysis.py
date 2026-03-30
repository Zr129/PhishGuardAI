from utils.url_features import extract_refined_features


def load_blacklist():
    with open("blacklist.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

BLACKLIST = load_blacklist()


def analyse_url(data):
    # --- PRE-PROCESSING (Local & Instant) ---
    # We use our utility to get the "Real" Registered Domain (TLD+1)
    # This solves the Palo Alto subdomain issue immediately.
    refined = extract_refined_features(data.url, data.links)
    
    url = data.url.lower()
    domain = refined['registered_domain'] # Use cleaned domain from tldextract
    base_name = refined['base_domain']     # e.g., "paloaltonetworks"
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
    # Rule A: IP-Based Identity
    if refined['is_ip']:
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
            "reasons": ["Insecure Harvesting: Password field detected on non-encrypted (HTTP) page"]
        }

    # --- TIER 3: SMART BRAND ANALYSIS (TLD Optimized) ---
    if data.brand_keyword:
        brand = data.brand_keyword.lower()
        
        # We check if the brand is part of the 'base_domain' extracted by tldextract
        # This correctly allows 'sso.paloaltonetworks.com' because 'paloalto' is in 'paloaltonetworks'
        is_official = (brand in base_name)
        
        if not is_official:
            reason = f"Brand Impersonation: Page claims to be {brand.capitalize()} but uses an unofficial domain ({domain})"
            if data.has_password_field:
                return {
                    "action": "BLOCK",
                    "prediction": "phishing",
                    "confidence": 1.0,
                    "reasons": [reason, "Credential Theft: Fake brand page requesting login details"]
                }
            suspicious_triggers.append(reason)

    # --- TIER 4: STRUCTURAL ANOMALIES (TLD Optimized) ---
    
    # Check for "Fake Nav"
    if data.total_anchors > 0:
        empty_percent = (data.empty_anchors / data.total_anchors) * 100 
        if data.empty_anchors > 30 and empty_percent > 40:
            suspicious_triggers.append(f"Suspicious UI: {round(empty_percent)}% of links are dead placeholders")

    # Check for "Isolator" Kits
    # We use refined['external_ratio'] which correctly ignores subdomains
    if refined['external_ratio'] > 0.85 and refined['total_links'] > 10:
        suspicious_triggers.append("Structural Anomaly: High ratio of external links typical of phishing templates")

    # --- FINAL JUDGMENT ---
    if suspicious_triggers:
        base_confidence = 0.40 
        additional_weight = (len(suspicious_triggers) - 1) * 0.15
        calc_confidence = base_confidence + additional_weight
        
        final_score = min(calc_confidence, 0.95)
        return {
            "action": "WARN",
            "prediction": "suspicious",
            "confidence": round(final_score, 2),
            "reasons": suspicious_triggers
        }
    # --- TIER 5: SAFE ---
    return {
        "action": "ALLOW",
        "prediction": "safe",
        "confidence": 0.0,
        "reasons": []
    }