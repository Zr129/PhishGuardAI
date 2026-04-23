"""
Single source of truth for the ML feature pipeline.

FIELD_MAP      — maps each PhiUSIIL column name to a callable that produces
                 its value at inference time.
                 Used by both train.py and tier3_ml.py — they can never diverge.

CUSTOM_FIELDS  — extension-only signals injected AFTER model inference
                 by CustomSignalPreprocessor. Never fed into the model.
"""

from typing import Callable

Extractor = Callable[[object, dict], float | int]

FIELD_MAP: dict[str, Extractor] = {
    # ── URL string features ──────────────────────────────────
    "URLLength":             lambda data, refined: refined["URLLength"],
    "DegitRatioInURL":       lambda data, refined: refined["DegitRatioInURL"],
    "IsHTTPS":               lambda data, refined: refined["IsHTTPS"],
    "SpacialCharRatioInURL": lambda data, refined: refined["SpacialCharRatioInURL"],
    "LetterRatioInURL":      lambda data, refined: refined["LetterRatioInURL"],
    "NoOfSubDomain":         lambda data, refined: refined["NoOfSubDomain"],

    # ── Link / anchor features ───────────────────────────────
    "NoOfSelfRef":           lambda data, refined: data.no_of_self_ref or 0,
    "HasSocialNet":          lambda data, refined: int(data.has_social_net or False),

    # ── Page meta ────────────────────────────────────────────
    "DomainTitleMatchScore": lambda data, refined: data.domain_title_match_score or 0,
    "HasDescription":        lambda data, refined: int(data.has_description or False),

    # ── Form context ─────────────────────────────────────────
    "HasSubmitButton":       lambda data, refined: int(data.has_submit_button or False),

    # ── Content signals ──────────────────────────────────────
    "HasCopyrightInfo":      lambda data, refined: int(data.has_copyright or False),
    "NoOfImage":             lambda data, refined: data.no_of_images or 0,
    "NoOfCSS":               lambda data, refined: data.no_of_css or 0,
    "NoOfJS":                lambda data, refined: data.no_of_js or 0,
}

FEATURE_COLS = list(FIELD_MAP.keys())

CUSTOM_FIELDS: dict[str, Extractor] = {
    "IsHiddenSubmission":      lambda data, refined: int(data.is_hidden_submission or False),
    "ActionToDifferentDomain": lambda data, refined: int(data.action_to_different_domain or False),
    "HasDomainDashes":         lambda data, refined: refined["HasDomainDashes"],
}

CUSTOM_ADJUSTMENTS = {
    "IsHiddenSubmission":      +0.10,
    "ActionToDifferentDomain": +0.15,
    "HasDomainDashes":         +0.05,
}
