import tldextract
import re
from urllib.parse import urlparse

def extract_refined_features(url, raw_links):
    """
    Extracts structured URL and link-based features for phishing detection.
    """

    ext_page = tldextract.extract(url)

    # Registered domain
    if ext_page.suffix:
        reg_domain = f"{ext_page.domain}.{ext_page.suffix}"
    else:
        reg_domain = ext_page.domain

    # --- External link analysis ---
    external_count = 0
    total_links = 0

    for link in raw_links:
        if not link or not isinstance(link, str):
            continue

        # Ignore non-web links
        if not link.startswith("http"):
            continue

        total_links += 1

        try:
            ext_link = tldextract.extract(link)

            if ext_link.suffix:
                link_reg = f"{ext_link.domain}.{ext_link.suffix}"
            else:
                link_reg = ext_link.domain

            if link_reg and link_reg != reg_domain:
                external_count += 1

        except Exception:
            continue

    # --- Subdomain depth ---
    subdomains = [
        s for s in ext_page.subdomain.split('.') 
        if s and s != 'www'
    ]
    sub_count = len(subdomains)

    # --- Domain tricks ---
    has_dashes = "-" in ext_page.domain

    # --- IP detection ---
    host = urlparse(url).hostname or ""
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    return {
        "registered_domain": reg_domain,
        "base_domain": ext_page.domain,
        "external_ratio": external_count / total_links if total_links > 0 else 0,
        "num_external": external_count,
        "total_links": total_links,
        "subdomain_count": sub_count,
        "has_domain_dashes": has_dashes,
        "is_ip": is_ip
    }