"""
Single source of truth for the ML feature pipeline.

FIELD_MAP      — maps each PhiUSIIL column name to the Python expression
                 that produces its value at inference time.
                 Used by both train.py and tier3_ml.py — they can never diverge.

CUSTOM_FIELDS  — extension-only signals injected AFTER model inference
                 by CustomSignalPreprocessor. Never fed into the model.

Feature selection (based on importance scan on full PhiUSIIL dataset):
  Kept:    15 features with importance >= 0.005
  Removed: 22 features with importance < 0.005 (zero or near-zero signal)

  Removed (zero importance):
    HasObfuscation, ObfuscationRatio, NoOfAmpersandInURL,
    IsDomainIP, NoOfAnchor, NoOfDomainComponents

  Removed (below 0.005):
    HasFavicon, NoOfEmptyRef, URLTitleMatchScore, CharContinuationRate,
    DomainLength, HasHiddenFields, TLDLength, Bank, NoOfEqualsInURL,
    HasPasswordField, NoOfQMarkInURL, HasTitle, Pay, IsResponsive,
    Robots, Crypto
"""

FIELD_MAP = {
    # ── URL string features ──────────────────────────────────
    "URLLength":             "refined['URLLength']",              # importance 0.031
    "DegitRatioInURL":       "refined['DegitRatioInURL']",        # importance 0.027
    "IsHTTPS":               "refined['IsHTTPS']",                # importance 0.027
    "SpacialCharRatioInURL": "refined['SpacialCharRatioInURL']",  # importance 0.015
    "LetterRatioInURL":      "refined['LetterRatioInURL']",       # importance 0.013
    "NoOfSubDomain":         "refined['NoOfSubDomain']",          # importance 0.010

    # ── Link / anchor features ───────────────────────────────
    "NoOfSelfRef":           "data.no_of_self_ref or 0",          # importance 0.196
    "HasSocialNet":          "int(data.has_social_net or False)",  # importance 0.078

    # ── Page meta ────────────────────────────────────────────
    "DomainTitleMatchScore": "data.domain_title_match_score or 0", # importance 0.025
    "HasDescription":        "int(data.has_description or False)", # importance 0.019

    # ── Form context ─────────────────────────────────────────
    "HasSubmitButton":       "int(data.has_submit_button or False)", # importance 0.007

    # ── Content signals ──────────────────────────────────────
    "HasCopyrightInfo":      "int(data.has_copyright or False)",  # importance 0.066
    "NoOfImage":             "data.no_of_images or 0",            # importance 0.227
    "NoOfCSS":               "data.no_of_css or 0",               # importance 0.103
    "NoOfJS":                "data.no_of_js or 0",                # importance 0.136
}

# Ordered list — column order is sacred for sklearn
FEATURE_COLS = list(FIELD_MAP.keys())

# ─────────────────────────────────────────────────────────────
# CUSTOM signals — injected AFTER model inference
# Extension-only features with no PhiUSIIL equivalent.
# CustomSignalPreprocessor adjusts the raw probability based on them.
# ─────────────────────────────────────────────────────────────

CUSTOM_FIELDS = {
    "IsHiddenSubmission":      "int(data.is_hidden_submission or False)",
    "ActionToDifferentDomain": "int(data.action_to_different_domain or False)",
    "HasDomainDashes":         "refined['HasDomainDashes']",
}

# Probability adjustments applied post-inference (additive, capped at 0.95)
CUSTOM_ADJUSTMENTS = {
    "IsHiddenSubmission":      +0.10,  # hidden form → +10%
    "ActionToDifferentDomain": +0.15,  # cross-domain submit → +15%
    "HasDomainDashes":         +0.05,  # dashes in domain → +5%
}
