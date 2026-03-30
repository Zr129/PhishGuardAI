from pydantic import BaseModel
from typing import List, Optional

class URLRequest(BaseModel):
    url: str
    domain: str
    title: str
    is_https: bool
    has_password_field: bool
    action_to_different_domain: bool
    
    # --- ADD THIS LINE ---
    # This matches the rawLinks array from your JS
    links: List[str] = [] 
    
    ext_anchor_ratio: float
    num_links_external: int
    empty_anchors: int
    total_anchors: int
    
    # Use Optional or a default value for strings that might be empty
    brand_keyword: Optional[str] = "" 
    has_ip: bool