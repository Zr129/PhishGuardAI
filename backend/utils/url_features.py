import tldextract
import re

def extract_refined_features(url, raw_links):
    """
    Analyzes URL structure and link ratios locally.
    """
    # 1. Parse the main page URL
    ext_page = tldextract.extract(url)
    # reg_domain = "paloaltonetworks.com"
    reg_domain = f"{ext_page.domain}.{ext_page.suffix}"
    
    # 2. Count internal vs external based on the Registered Domain
    external_count = 0
    total_links = len(raw_links)
    
    for link in raw_links:
        try:
            ext_link = tldextract.extract(link)
            link_reg = f"{ext_link.domain}.{ext_link.suffix}".strip(".")
            
            # If the link's registered domain doesn't match the page, it's external
            if link_reg and link_reg != reg_domain:
                external_count += 1
        except:
            continue

    return {
        "registered_domain": reg_domain,
        "base_domain": ext_page.domain, # e.g., "paloaltonetworks"
        "external_ratio": external_count / total_links if total_links > 0 else 0,
        "num_external": external_count,
        "total_links": total_links,
        "subdomain_count": len(ext_page.subdomain.split('.')) if ext_page.subdomain else 0,
        "is_ip": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ext_page.domain))
    }