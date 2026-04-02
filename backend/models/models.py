from pydantic import BaseModel, Field
from typing import List, Optional


class URLRequest(BaseModel):
    url: str
    domain: str
    title: str
    is_https: bool

    # --- FRAME & FORM LOGIC ---
    is_main_frame: bool
    has_password_field: bool

    is_hidden_submission: Optional[bool] = False
    action_to_different_domain: Optional[bool] = False

    # --- LINK DATA ---
    links: List[str] = Field(default_factory=list)
    empty_anchors: int
    total_anchors: int

    # --- URL FEATURES (from frontend) ---
    subdomain_count: int
    has_domain_dashes: bool