from utils.url_features import extract_refined_features
import traceback
import re

# Professional Brand List - Easier to manage on the backend
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

def load_blacklist():
    try:
        with open("blacklist.txt", "r") as f:
            return [line.strip().lower() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        return []

BLACKLIST = load_blacklist()

def analyse_url(data):
    print(f"--- Analysis Started: {data.domain} ---")
    
    try:
        refined = extract_refined_features(data.url, data.links)
        url_lower = data.url.lower()
        domain = refined['registered_domain'] # e.g., "palo-alto-login.com"
        base_name = refined['base_domain']     # e.g., "palo-alto-login"
        suspicious_triggers = []

        # --- TIER 1: BLACKLIST ---
        if any(bad_url in url_lower for bad_url in BLACKLIST):
            return {"action": "BLOCK", "prediction": "phishing", "confidence": 1.0, "reasons": ["Known Phishing Database Match"]}

        # --- TIER 2: IFRAME & FORM ANOMALIES (The "Behavioral" Trap) ---
        
        # Rule A: Malicious IFrame Overlay
        if not data.is_main_frame and data.has_password_field:
            print("TRIGGER: Malicious IFrame Login")
            return {
                "action": "BLOCK",
                "prediction": "phishing",
                "confidence": 1.0,
                "reasons": ["Hidden Login Trap: Password requested inside a sub-frame"]
            }

        if data.has_password_field:
            # Rule B: Hidden Submission (JS Cloaking)
            if data.is_hidden_submission:
                suspicious_triggers.append("Cloaked Form: Destination hidden via JavaScript")
            
            # Rule C: External Submission (Credential Harvesting)
            if data.action_to_different_domain:
                return {
                    "action": "BLOCK",
                    "prediction": "phishing",
                    "confidence": 1.0,
                    "reasons": ["Credential Harvesting: Form submits data to an external domain"]
                }

            # Rule D: Insecure Login
            if not data.is_https:
                return {"action": "BLOCK", "prediction": "phishing", "confidence": 0.95, "reasons": ["Insecure Harvesting: Password field on HTTP page"]}

        # --- TIER 3: SMART BRAND ANALYSIS (The "Identity" Check) ---
        
        # Logic: Check the Page Title for brands and verify the domain
        found_brand = None
        title_lower = data.title.lower()
        
        for brand_key, official_domains in PROTECTED_BRANDS.items():
            if brand_key in title_lower:
                found_brand = brand_key
                # Check if the current domain is in the list of official domains
                is_official = any(off_dom in domain for off_dom in official_domains)
                
                if not is_official:
                    reason = f"Brand Impersonation: Page claims to be {brand_key.capitalize()} but is hosted on {domain}"
                    if data.has_password_field:
                        return {
                            "action": "BLOCK",
                            "prediction": "phishing",
                            "confidence": 1.0,
                            "reasons": [reason, "Credential Theft: Fake brand login page"]
                        }
                    suspicious_triggers.append(reason)
                break

        # --- TIER 4: STRUCTURAL & URL ANOMALIES ---
        
        # Rule E: URL Character Tricks (@ symbol, IP address, dashes)
        if "@" in url_lower:
            suspicious_triggers.append("URL Obfuscation: Dangerous '@' symbol used")
        
        if refined['is_ip']:
            return {"action": "BLOCK", "prediction": "phishing", "confidence": 1.0, "reasons": ["IP-Address Phishing: Host is a raw IP address"]}

        # Rule F: Content "Hollowness" (Phishing Templates)
        if data.total_anchors > 5:
            empty_ratio = data.empty_anchors / data.total_anchors
            if empty_ratio > 0.5:
                suspicious_triggers.append(f"Structural Anomaly: {int(empty_ratio*100)}% of links are dead placeholders")

        if refined['external_ratio'] > 0.85 and data.total_anchors > 10:
            suspicious_triggers.append("Suspicious Content: Nearly all links point to external sites")

        # --- FINAL JUDGMENT ---
        if suspicious_triggers:
            # Score calculation: Starts at 0.5, adds 0.2 per trigger, caps at 0.98
            final_score = min(0.5 + (len(suspicious_triggers) * 0.2), 0.98)
            return {
                "action": "WARN",
                "prediction": "suspicious",
                "confidence": round(final_score, 2),
                "reasons": suspicious_triggers
            }

        return {"action": "ALLOW", "prediction": "safe", "confidence": 0.0, "reasons": []}

    except Exception as e:
        print(f"ERROR: {traceback.format_exc()}")
        return {"action": "ERROR", "prediction": "error", "confidence": 0, "reasons": [str(e)]}