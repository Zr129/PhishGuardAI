"""
CustomSignalPreprocessor
========================
Injects extension-only signals into the ML pipeline AFTER model inference.
Only fires on signals that Tier 2 heuristics do NOT already cover, preventing
duplicate reasons in the security report.

Security note on eval():
  The expressions in CUSTOM_FIELDS are module-level string constants defined
  in ml/features.py — they are never user-supplied.
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

# IsHiddenSubmission is intentionally excluded here —
# Tier 2 HeuristicCheck already flags it with a reason and score.
# Only inject signals that Tier 2 does NOT cover.
_SKIP_IF_TIER2_COVERS = {"IsHiddenSubmission"}


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
        prob    = base_prob
        reasons = []
        existing_reasons = existing_reasons or []

        for field, expr in CUSTOM_FIELDS.items():
            # Skip signals already handled by Tier 2
            if field in _SKIP_IF_TIER2_COVERS:
                continue

            try:
                triggered = bool(eval(expr))  # noqa: S307
            except Exception:
                triggered = False

            if triggered:
                delta  = CUSTOM_ADJUSTMENTS.get(field, 0.0)
                prob  += delta
                reason = _REASON_MAP.get(field, f"{field} detected")
                # Only add reason if not already in the report
                if reason not in existing_reasons:
                    reasons.append(reason)
                logger.debug(f"[PREPROCESS] {field} → +{delta:.0%}  prob now {prob:.3f}")

        return min(prob, 0.95), reasons
