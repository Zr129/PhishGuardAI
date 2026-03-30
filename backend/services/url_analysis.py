from utils.url_features import extract_url_features

def load_blacklist():
    with open("blacklist.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

BLACKLIST = load_blacklist()


def analyse_url(data):
    url = data.url.lower()

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
    # These rules target the "Mechanism of Theft"
    
    if data.has_password_field:
        # Rule A: Cross-Domain Data Exfiltration
        if data.action_to_different_domain:
            return {
                "action": "BLOCK", 
                "prediction": "phishing",
                "confidence": 1.0,
                "reasons": ["Credential Harvesting: Login form submits data to an external domain"]
            }
        
        # Rule B: Protocol Downgrade (No Encryption)
        if not data.is_https:
            return {
                "action": "BLOCK",
                "prediction": "phishing",
                "confidence": 0.98,
                "reasons": ["Insecure Harvesting: Password field detected on a non-encrypted (HTTP) page"]
            }

        # Rule C: IP-Based Identity
        if data.has_ip:
            return {
                "action": "BLOCK",
                "prediction": "phishing",
                "confidence": 1.0,
                "reasons": ["IP-Address Phishing: Form detected on a raw IP address instead of a domain"]
            }

    # --- TIER 3: SUSPICIOUS ANOMALIES (DETERMINISTIC WARNINGS) ---
    # These rules target "Kit Characteristics" 
    
    suspicious_triggers = []

    # Check for Brand Spoofing (Mismatch between Title and Domain)
    if data.brand_keyword_count > 0 and data.brand_mismatch:
        suspicious_triggers.append(f"Identity Mismatch: Page content references a brand not found in the URL")

    # Check for "Isolator" Kits (High external link ratio + low internal content)
    if data.ext_anchor_ratio > 0.85 and data.num_links_external > 5:
        suspicious_triggers.append("Structural Anomaly: High ratio of external links typical of phishing templates")

    # Check for "Fake Nav" (High number of empty/dead links)
    if data.total_anchors > 0 and data.empty_anchors > 10:
       
        empty_percent = (data.empty_anchors / data.total_anchors) * 100 
    
        if empty_percent > 10: # Only flag if 10% or more are dead/empty
            suspicious_triggers.append("Suspicious UI: Excessive number of dead/empty navigation links")

    if suspicious_triggers:
        return {
            "action": "WARN",
            "prediction": "suspicious",
            "confidence": 0.8,
            "reasons": suspicious_triggers
        }

    # --- TIER 4: SAFE ---
    return {
        "action": "ALLOW",
        "prediction": "safe",
        "confidence": 0.0,
        "reasons": ["No deterministic threats or anomalies detected"]
    }