"""
CustomSignalPreprocessor
========================
Injects extension-only signals into the ML pipeline AFTER model inference.
Only fires on signals that Tier 2 heuristics do NOT already cover, preventing
duplicate reasons in the security report.
"""

import logging
from typing import TYPE_CHECKING
from ml.features import CUSTOM_FIELDS, CUSTOM_ADJUSTMENTS

if TYPE_CHECKING:
    from models.models import URLRequest

logger = logging.getLogger("PhishGuard")

_REASON_MAP = {
    "ActionToDifferentDomain": "Credentials sent to external domain (ML signal)",
    "HasDomainDashes":         "Domain contains dashes (ML signal)",
}

_SKIP_IF_TIER2_COVERS = {"IsHiddenSubmission"}

# Government and institutional TLDs — ML model is undertrained on these
# (PhiUSIIL dataset is commercial-heavy). A dampener prevents false positives
# on legitimate public-sector sites that may lack meta descriptions etc.
_TRUSTED_TLDS = {
    ".gov.uk", ".gov", ".ac.uk", ".nhs.uk", ".police.uk",
    ".mil", ".edu",
}
_TRUSTED_TLD_DAMPENER = -0.25


class CustomSignalPreprocessor:
    """
    Evaluates each custom field and applies its probability adjustment.
    Skips any field already covered by Tier 2 to avoid duplicate reasons.
    Adjustments are additive and hard-capped at 0.95.
    """

    def adjust(
        self,
        base_prob: float,
        data: "URLRequest",
        refined: dict,
        existing_reasons: list[str] = None,
    ) -> tuple[float, list[str]]:
        prob = base_prob
        reasons = []
        existing_reasons = existing_reasons or []

        # Dampen ML probability for verified government/institutional TLDs.
        # The PhiUSIIL training dataset is commercial-heavy so the model
        # under-represents public-sector sites and over-flags them when they
        # lack signals like meta descriptions that are common in commercial sites.
        registered = refined.get("registered_domain", "")
        if any(registered.endswith(tld) for tld in _TRUSTED_TLDS):
            prob = max(prob + _TRUSTED_TLD_DAMPENER, 0.0)
            logger.info(
                f"[PREPROCESS] Institutional TLD dampener applied: "
                f"'{registered}' → prob now {prob:.3f}"
            )

        for field, extractor in CUSTOM_FIELDS.items():
            if field in _SKIP_IF_TIER2_COVERS:
                continue

            try:
                triggered = bool(extractor(data, refined))
            except Exception as exc:
                logger.warning(f"[PREPROCESS] Custom signal failed for {field}: {exc}")
                triggered = False

            if triggered:
                delta = CUSTOM_ADJUSTMENTS.get(field, 0.0)
                prob += delta
                reason = _REASON_MAP.get(field, f"{field} detected")
                if reason not in existing_reasons:
                    reasons.append(reason)
                logger.debug(f"[PREPROCESS] {field} → +{delta:.0%}  prob now {prob:.3f}")

        return min(prob, 0.95), reasons