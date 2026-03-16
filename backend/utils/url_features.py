import re
from urllib.parse import urlparse

def extract_url_features(url):

    parsed = urlparse(url)

    features = {}

    features["length"] = len(url)

    features["num_dots"] = url.count(".")

    features["has_ip"] = bool(re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc))

    suspicious_words = ["login", "verify", "secure", "update", "bank"]

    features["suspicious_keywords"] = any(word in url.lower() for word in suspicious_words)

    return features