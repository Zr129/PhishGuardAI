from pydantic import BaseModel, Field, field_validator
from typing import List, Optional


class PageMeta(BaseModel):
    url:           str
    domain:        str
    title:         str
    is_https:      bool
    is_main_frame: bool
    # PhiUSIIL-aligned
    is_responsive:            Optional[bool]  = False
    has_favicon:              Optional[bool]  = False
    has_robots:               Optional[bool]  = False
    has_description:          Optional[bool]  = False
    has_title:                Optional[bool]  = True
    domain_title_match_score: Optional[float] = 0.0
    url_title_match_score:    Optional[float] = 0.0


class FormContext(BaseModel):
    has_password_field:         bool           = False
    is_hidden_submission:       Optional[bool] = False
    action_to_different_domain: Optional[bool] = False
    has_submit_button:          Optional[bool] = False
    has_hidden_fields:          Optional[bool] = False


class LinkContext(BaseModel):
    links:          List[str] = Field(default_factory=list)
    empty_anchors:  int       = 0
    total_anchors:  int       = 0
    no_of_self_ref: Optional[int]  = 0
    has_social_net: Optional[bool] = False


class ContentSignals(BaseModel):
    has_bank_keywords:   Optional[bool] = False
    has_pay_keywords:    Optional[bool] = False
    has_crypto_keywords: Optional[bool] = False
    has_copyright:       Optional[bool] = False
    no_of_images:        Optional[int]  = 0
    no_of_css:           Optional[int]  = 0
    no_of_js:            Optional[int]  = 0


class URLRequest(PageMeta, FormContext, LinkContext, ContentSignals):
    """
    Full request from the extension.
    Flat JSON for API compatibility; logically split across sub-models (ISP).
    Extra fields sent by content.js (has_ip, subdomain_count, has_domain_dashes)
    are silently ignored by FastAPI — the backend recomputes them from the URL.
    """

    @field_validator("url")
    @classmethod
    def validate_url_length(cls, v: str) -> str:
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        return v

    @field_validator("links")
    @classmethod
    def validate_links(cls, v: List[str]) -> List[str]:
        # Truncate oversized links, drop anything that isn't a string
        return [
            link[:1000] if isinstance(link, str) else ""
            for link in v[:500]   # cap at 500 links max
            if isinstance(link, str)
        ]

    class Config:
        extra = "ignore"   # silently drop unknown fields (has_ip, subdomain_count etc.)


class AnalysisResult(BaseModel):
    action:     str
    prediction: str
    confidence: int
    reasons:    List[str]
