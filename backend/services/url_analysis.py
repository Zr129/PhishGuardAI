from utils.url_features import extract_url_features

def load_blacklist():
    with open("blacklist.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

BLACKLIST = load_blacklist()


def analyse_url(data):

    url = data.url.lower()

    # FIRST CHECK URL IN BLACKLIST
    for bad_url in BLACKLIST:
        if bad_url in url:
            return {
                "prediction": "phishing",
                "confidence": 1.0,
                "reasons": ["URL matches known phishing domain (blacklist)"]
            }

    # IF NOT IN LIST THEN PERFORM HEURSITICS

    score = 0
    reasons = []

    if data.numPasswordFields > 0:
        score += 2
        reasons.append("Login fields detected")

    if data.numForms > 2:
        score += 1
        reasons.append("Multiple forms detected")

    if data.externalAnchors > 10:
        score += 2
        reasons.append("Many external links")

    if data.emptyAnchors > 5:
        score += 1
        reasons.append("Suspicious empty links")

    if data.numIframes > 0:
        score += 1
        reasons.append("iFrames detected")

    # RISK SCORING CLASSIFICATION

    if score >= 4:
        prediction = "phishing"
    elif score >= 2:
        prediction = "suspicious"
    else:
        prediction = "safe"

    confidence = min(score / 6, 1.0)

    return {
        "prediction": prediction,
        "confidence": round(confidence, 2),
        "reasons": reasons if reasons else ["No suspicious features detected"]
    }