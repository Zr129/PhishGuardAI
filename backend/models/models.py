from pydantic import BaseModel

from pydantic import BaseModel

class URLRequest(BaseModel):
    # These MUST match the keys in your JS console.log exactly
    url: str
    domain: str
    is_https: bool
    has_password_field: bool
    action_to_different_domain: bool
    ext_anchor_ratio: float
    num_links_external: int
    empty_anchors: int
    total_anchors: int
    brand_keyword_count: int
    brand_mismatch: bool
    has_ip: bool