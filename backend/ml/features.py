"""
Single source of truth for the ML feature pipeline.

CORE_FEATURES  — the 34 PhiUSIIL columns used to train the model.
                 Chosen to remove:
                   - raw/ratio pairs where the ratio subsumes the raw count
                   - zero-filled custom fields (no training signal)
                 Result: cleaner model, faster inference, no information loss.

CUSTOM_FIELDS  — our extension-only signals injected AFTER model inference
                 by CustomSignalPreprocessor. They never corrupt the model
                 because they're never fed into it.

FIELD_MAP      — maps each CORE_FEATURE dataset column name to the Python
                 expression that produces its value at inference time.
                 Used by both train.py and tier3_ml.py — they can never diverge.
"""

# ─────────────────────────────────────────────────────────────
# CORE features — fed into the RandomForest
#
# Removed from the full 45:
#   NoOfLettersInURL      → LetterRatioInURL subsumes it
#   NoOfDegitsInURL       → DegitRatioInURL subsumes it
#   NoOfObfuscatedChar    → ObfuscationRatio subsumes it
#   NoOfOtherSpecialCharsInURL → SpacialCharRatioInURL subsumes it
#   NoOfExternalRef       → ExternalRatio (derived) subsumes it
#   NoOfAnchor            → kept; raw count adds signal ratios don't capture
#   TotalLinks            → kept as NoOfAnchor already covers this
#   CharContinuationRate  → kept; independent signal
#   IsHiddenSubmission    → CUSTOM (zero-filled, moved to CustomSignalPreprocessor)
#   ActionToDifferentDomain → CUSTOM (same reason)
#   HasDomainDashes       → CUSTOM (same reason)
# ─────────────────────────────────────────────────────────────

FIELD_MAP = {
    # ── URL string features ──────────────────────────────────
    "URLLength":              "refined['URLLength']",
    "DomainLength":           "refined['DomainLength']",
    "TLDLength":              "refined['TLDLength']",
    "IsDomainIP":             "refined['IsDomainIP']",
    "IsHTTPS":                "refined['IsHTTPS']",
    "NoOfSubDomain":          "refined['NoOfSubDomain']",
    "HasObfuscation":         "refined['HasObfuscation']",
    "ObfuscationRatio":       "refined['ObfuscationRatio']",
    "LetterRatioInURL":       "refined['LetterRatioInURL']",
    "DegitRatioInURL":        "refined['DegitRatioInURL']",
    "NoOfEqualsInURL":        "refined['NoOfEqualsInURL']",
    "NoOfQMarkInURL":         "refined['NoOfQMarkInURL']",
    "NoOfAmpersandInURL":     "refined['NoOfAmpersandInURL']",
    "SpacialCharRatioInURL":  "refined['SpacialCharRatioInURL']",
    "CharContinuationRate":   "refined['CharContinuationRate']",

    # ── Link / anchor features ───────────────────────────────
    "NoOfAnchor":             "data.total_anchors",
    "NoOfEmptyRef":           "data.empty_anchors",
    "NoOfSelfRef":            "data.no_of_self_ref or 0",
    "HasSocialNet":           "int(data.has_social_net or False)",

    # ── Page meta ────────────────────────────────────────────
    "HasTitle":               "int(data.has_title or False)",
    "DomainTitleMatchScore":  "data.domain_title_match_score or 0",
    "URLTitleMatchScore":     "data.url_title_match_score or 0",
    "HasFavicon":             "int(data.has_favicon or False)",
    "Robots":                 "int(data.has_robots or False)",
    "IsResponsive":           "int(data.is_responsive or False)",
    "HasDescription":         "int(data.has_description or False)",
    "NoOfDomainComponents":   "refined['NoOfSubDomain'] + 1",

    # ── Form context ─────────────────────────────────────────
    "HasSubmitButton":        "int(data.has_submit_button or False)",
    "HasHiddenFields":        "int(data.has_hidden_fields or False)",
    "HasPasswordField":       "int(data.has_password_field)",

    # ── Content signals ──────────────────────────────────────
    "Bank":                   "int(data.has_bank_keywords or False)",
    "Pay":                    "int(data.has_pay_keywords or False)",
    "Crypto":                 "int(data.has_crypto_keywords or False)",
    "HasCopyrightInfo":       "int(data.has_copyright or False)",
    "NoOfImage":              "data.no_of_images or 0",
    "NoOfCSS":                "data.no_of_css or 0",
    "NoOfJS":                 "data.no_of_js or 0",
}

# Ordered list — column order is sacred for sklearn
FEATURE_COLS = list(FIELD_MAP.keys())

# ─────────────────────────────────────────────────────────────
# CUSTOM signals — injected AFTER model inference
# These are extension-only features with no PhiUSIIL equivalent.
# They never enter the model; instead CustomSignalPreprocessor
# adjusts the raw probability based on them.
# ─────────────────────────────────────────────────────────────

CUSTOM_FIELDS = {
    "IsHiddenSubmission":       "int(data.is_hidden_submission or False)",
    "ActionToDifferentDomain":  "int(data.action_to_different_domain or False)",
    "HasDomainDashes":          "refined['HasDomainDashes']",
}

# Score adjustments applied to model probability (additive, capped at 0.95)
CUSTOM_ADJUSTMENTS = {
    "IsHiddenSubmission":       +0.10,   # hidden form → +10% phishing probability
    "ActionToDifferentDomain":  +0.15,   # cross-domain submit → +15%
    "HasDomainDashes":          +0.05,   # dashes in domain → +5%
}
