"""
CustomSignalPreprocessor
========================
Injects extension-only signals into the ML pipeline AFTER model inference.

Why post-injection rather than training on them?
  PhiUSIIL has no equivalent columns, so these fields would be all-zeros
  during training — the model learns nothing from them and they add noise.
  Post-injection keeps the trained model clean while preserving the signal.

Security note on eval():
  The expressions in CUSTOM_FIELDS are module-level string constants defined
  in ml/features.py — they are never user-supplied. eval() here is equivalent
  to calling the function directly; it is NOT evaluating untrusted input.
"""

import logging
from typing import TYPE_CHECKING
from ml.features import CUSTOM_FIELDS, CUSTOM_ADJUSTMENTS

if TYPE_CHECKING:
    from models.models import URLRequest

logger = logging.getLogger("PhishGuard")

_REASON_MAP = {
    "IsHiddenSubmission":      "Hidden form submission behaviour",
    "ActionToDifferentDomain": "Credentials sent to external domain",
    "HasDomainDashes":         "Domain contains dashes",
}


class CustomSignalPreprocessor:
    """
    Evaluates each custom field and applies its probability adjustment.
    Adjustments are additive and hard-capped at 0.95.
    """

    def adjust(
        self,
        base_prob: float,
        data: "URLRequest",
        refined: dict,
    ) -> tuple[float, list[str]]:
        """
        Args:
            base_prob: raw P(phishing) from the model (0.0–1.0)
            data:      URLRequest from the extension
            refined:   dict from URLFeatureExtractor.extract()

        Returns:
            (adjusted_prob, triggered_reason_strings)
        """
        prob    = base_prob
        reasons = []

        for field, expr in CUSTOM_FIELDS.items():
            try:
                # expr is a trusted constant string — not user input
                triggered = bool(eval(expr))  # noqa: S307
            except Exception:
                triggered = False

            if triggered:
                delta  = CUSTOM_ADJUSTMENTS.get(field, 0.0)
                prob  += delta
                reasons.append(_REASON_MAP.get(field, f"{field} detected"))
                logger.debug(f"[PREPROCESS] {field} → +{delta:.0%}  prob now {prob:.3f}")

        return min(prob, 0.95), reasons
