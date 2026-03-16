from utils.url_features import extract_url_features

def analyse_url(url):

    features = extract_url_features(url)

    score = 0
    reasons = []

    if features["length"] > 75:
        score += 1
        reasons.append("URL unusually long")

    if features["num_dots"] > 3:
        score += 1
        reasons.append("Many subdomains detected")

    if features["has_ip"]:
        score += 2
        reasons.append("IP address used in URL")

    if features["suspicious_keywords"]:
        score += 1
        reasons.append("Suspicious keyword in URL")

    if score >= 3:
        classification = "phishing"
    elif score == 2:
        classification = "suspicious"
    else:
        classification = "benign"

    return {
        "classification": classification,
        "score": score,
        "reasons": reasons
    }