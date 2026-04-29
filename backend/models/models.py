from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import List, Optional, Dict, Any


class PageMeta(BaseModel):
    url:           str
    domain:        str
    title:         str
    is_https:      bool
    is_main_frame: bool
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
    has_iframe:                 Optional[bool] = False
    has_hidden_iframe:          Optional[bool] = False
    has_external_iframe:        Optional[bool] = False


class LinkContext(BaseModel):
    links:          List[str] = Field(default_factory=list)
    empty_anchors:  int       = 0
    total_anchors:  int       = 0
    no_of_self_ref: Optional[int]  = 0
    has_social_net: Optional[bool] = False


class ContentSignals(BaseModel):
    has_bank_keywords:      Optional[bool] = False
    has_pay_keywords:       Optional[bool] = False
    has_crypto_keywords:    Optional[bool] = False
    has_copyright:          Optional[bool] = False
    no_of_images:           Optional[int]  = 0
    no_of_css:              Optional[int]  = 0
    no_of_js:               Optional[int]  = 0
    has_auto_download:      Optional[bool] = False
    has_meta_refresh:       Optional[bool] = False
    has_suspicious_scripts: Optional[bool] = False


class URLRequest(PageMeta, FormContext, LinkContext, ContentSignals):
    """Full request from the extension. extra=ignore drops unknown fields safely."""

    # Pydantic v2 config syntax — replaces the v1 `class Config` style
    model_config = ConfigDict(extra="ignore")

    @field_validator("url")
    @classmethod
    def validate_url_length(cls, v: str) -> str:
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        return v

    @field_validator("links")
    @classmethod
    def validate_links(cls, v: List[str]) -> List[str]:
        return [
            link[:1000] if isinstance(link, str) else ""
            for link in v[:500]
            if isinstance(link, str)
        ]


class AnalysisResult(BaseModel):
    """
    Response model for /analyse.

    `url` and `domain` are echoed back from the request so that any
    consumer (popup, report endpoint, future integrations) can render
    or persist the result without needing the original request payload.
    """
    action:         str
    prediction:     str
    confidence:     int
    reasons:        List[str]
    tagged_reasons: List[Dict[str, Any]] = Field(default_factory=list)
    # tagged_reasons: [{text: str, tier: "RULE"|"HEURISTIC"|"ML"}]
    # Allows the popup to show tier badges per reason

    # Echo the analysed target so the response is self-describing
    url:    str = ""
    domain: str = ""
