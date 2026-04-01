import tldextract
import re

def extract_refined_features(url, raw_links):
    """
    Analyzes URL structure, subdomain depth, and link ratios.
    """
    # 1. Parse the main page URL
    # tldextract is better than urlparse because it knows 'co.uk' is one suffix
    ext_page = tldextract.extract(url)
    
    # The 'Registered Domain' (e.g., google.com, amazon.co.uk)
    reg_domain = f"{ext_page.domain}.{ext_page.suffix}".strip(".")    
    
    # 2. Count internal vs external based on the Registered Domain
    external_count = 0
    total_links = len(raw_links)
    
    for link in raw_links:
        if not link or not isinstance(link, str):
            continue
        try:
            ext_link = tldextract.extract(link)
            link_reg = f"{ext_link.domain}.{ext_link.suffix}".strip(".")
            
            # Logic: If the link is a valid web URL and the domain doesn't match, it's external
            if link_reg and link_reg != reg_domain:
                external_count += 1
        except:
            continue

    # 3. Calculate Subdomain Depth (Academic Feature #7)
    # Filter out 'www' as it's not a malicious subdomain
    subdomains = [s for s in ext_page.subdomain.split('.') if s and s != 'www']
    sub_count = len(subdomains)

    # 4. Check for Dashes in Domain (Academic Feature #6)
    has_dashes = "-" in ext_page.domain

    return {
        "registered_domain": reg_domain,      # e.g., "paypal.com"
        "base_domain": ext_page.domain,       # e.g., "paypal"
        "external_ratio": external_count / total_links if total_links > 0 else 0,
        "num_external": external_count,
        "total_links": total_links,
        "subdomain_count": sub_count,         # High count = suspicious
        "has_domain_dashes": has_dashes,      # Common in 'secure-login-brand.com'
        "is_ip": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ext_page.domain))
    }