from utils.url_features import extract_url_features

def load_blacklist():
    with open("blacklist.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

BLACKLIST = load_blacklist()

def analyse_url(url: str):
    for bad_url in BLACKLIST:
        if bad_url in url:
            return {
                "prediction": "phishing",
                "confidence": 1.0,
                "reasons": ["URL matches known phishing domain"]
            }

    return {
        "prediction": "safe",
        "confidence": 0.9,
        "reasons": ["URL not found in blacklist"]
    }