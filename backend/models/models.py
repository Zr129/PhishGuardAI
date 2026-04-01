from pydantic import BaseModel
from typing import List, Optional

class URLRequest(BaseModel):
    url: str
    domain: str
    title: str
    is_https: bool
    
    # --- NEW: FRAME & FORM LOGIC ---
    is_main_frame: bool              # Crucial for IFrame detection
    is_hidden_submission: bool        # Detects JS-based form cloaking
    
    has_password_field: bool
    action_to_different_domain: bool
    
    # --- LINK DATA ---
    links: List[str] = [] 
    ext_anchor_ratio: float
    num_links_external: int
    empty_anchors: int
    total_anchors: int
    
    has_ip: bool