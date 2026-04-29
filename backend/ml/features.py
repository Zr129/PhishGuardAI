from typing import Callable

Extractor = Callable[[object, dict], float | int]

def _safe(val, default=0):
    return val if val is not None else default

FIELD_MAP: dict[str, Extractor] = {
    # ── URL string features ──────────────────────────────────
    "URLLength":             lambda data, refined: refined.get("URLLength", 0),
    "DegitRatioInURL":       lambda data, refined: refined.get("DegitRatioInURL", 0),
    "IsHTTPS":               lambda data, refined: refined.get("IsHTTPS", 0),
    "SpacialCharRatioInURL": lambda data, refined: refined.get("SpacialCharRatioInURL", 0),
    "LetterRatioInURL":      lambda data, refined: refined.get("LetterRatioInURL", 0),
    "NoOfSubDomain":         lambda data, refined: refined.get("NoOfSubDomain", 0),

    # ── Link / anchor features ───────────────────────────────
    "NoOfSelfRef":           lambda data, refined: getattr(data, "no_of_self_ref", 0) or 0,
    "HasSocialNet":          lambda data, refined: int(getattr(data, "has_social_net", False) or False),

    # ── Page meta ────────────────────────────────────────────
    "DomainTitleMatchScore": lambda data, refined: getattr(data, "domain_title_match_score", 0) or 0,
    "HasDescription":        lambda data, refined: int(getattr(data, "has_description", False) or False),

    # ── Form context ─────────────────────────────────────────
    "HasSubmitButton":       lambda data, refined: int(getattr(data, "has_submit_button", False) or False),

    # ── Content signals ──────────────────────────────────────
    "HasCopyrightInfo":      lambda data, refined: int(getattr(data, "has_copyright", False) or False),
    "NoOfImage":             lambda data, refined: getattr(data, "no_of_images", 0) or 0,
    "NoOfCSS":               lambda data, refined: getattr(data, "no_of_css", 0) or 0,
    "NoOfJS":                lambda data, refined: getattr(data, "no_of_js", 0) or 0,
}

# ORDER UNCHANGED (exactly what you wanted)
FEATURE_COLS = list(FIELD_MAP.keys())

CUSTOM_FIELDS: dict[str, Extractor] = {
    "IsHiddenSubmission":      lambda data, refined: int(getattr(data, "is_hidden_submission", False) or False),
    "ActionToDifferentDomain": lambda data, refined: int(getattr(data, "action_to_different_domain", False) or False),
    "HasDomainDashes":         lambda data, refined: refined.get("HasDomainDashes", 0),
}

CUSTOM_ADJUSTMENTS = {
    "IsHiddenSubmission":      +0.10,
    "ActionToDifferentDomain": +0.15,
    "HasDomainDashes":         +0.05,
}