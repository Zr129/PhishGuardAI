"""
Tier 3 — ML Model Check.

Pipeline:
  1. Build core feature vector (15 PhiUSIIL features)
  2. model.predict_proba → base P(phishing)
  3. CustomSignalPreprocessor.adjust → inject extension-only signals
  4. Translate top contributing features into human-readable reasons
  5. Return CheckResult with tier="ML"
"""

import logging
import os
import pandas as pd
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest
from ml.preprocessor import CustomSignalPreprocessor

logger = logging.getLogger("PhishGuard")

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ml", "model.joblib"
)

MIN_TRIGGER_PROB  = 0.15   # below this ML stays silent — avoids noise on clean pages
BLOCK_THRESHOLD   = 0.85   # above this ML alone can hard-block

# Human-readable explanations for each ML feature
# Maps PhiUSIIL column name → plain English description of why it's suspicious
FEATURE_EXPLANATIONS = {
    "NoOfImage":             ("Very few images", "Phishing pages often have minimal images"),
    "NoOfSelfRef":           ("Few self-referencing links", "Legitimate sites link back to themselves frequently"),
    "NoOfJS":                ("Unusual JavaScript count", "Script count differs from legitimate sites"),
    "NoOfCSS":               ("Unusual stylesheet count", "Stylesheet count differs from legitimate sites"),
    "HasDescription":        ("Missing meta description", "Legitimate sites almost always have a description tag"),
    "HasSocialNet":          ("No social media links", "Phishing pages rarely link to social networks"),
    "HasCopyrightInfo":      ("No copyright information", "Legitimate sites typically include copyright notices"),
    "DomainTitleMatchScore": ("Title doesn't match domain", "Page title has low overlap with the domain name"),
    "IsHTTPS":               ("Not using HTTPS", "Connection is not secure"),
    "URLLength":             ("Unusually long URL", "URL length is abnormal"),
    "DegitRatioInURL":       ("High digit ratio in URL", "URL contains an unusual number of digits"),
    "SpacialCharRatioInURL": ("Special characters in URL", "URL contains an unusual number of special characters"),
    "LetterRatioInURL":      ("Low letter ratio in URL", "URL has an unusual character composition"),
    "HasSubmitButton":       ("No submit button found", "Form structure is unusual"),
    "NoOfSubDomain":         ("Multiple subdomains", "Excessive subdomain depth detected"),
}


class MLCheck(BaseCheck):

    def __init__(self, model=None):
        self._model        = model or self._try_load()
        self._preprocessor = CustomSignalPreprocessor()
        self._feature_importances = self._load_importances()

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    def _try_load(self):
        try:
            import joblib
            m = joblib.load(MODEL_PATH)
            logger.info(f"[ML] Model loaded from {MODEL_PATH}")
            return m
        except Exception as e:
            logger.info(f"[ML] No model loaded ({e}) — Tier 3 skipped")
            return None

    def _load_importances(self) -> dict:
        """Load feature importances from trained model for reason generation."""
        try:
            rf = self._model.named_steps["clf"]
            from ml.features import FEATURE_COLS
            return dict(zip(FEATURE_COLS, rf.feature_importances_))
        except Exception:
            return {}

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if not self.is_ready:
            return CheckResult.clean()

        try:
            from ml.features import FIELD_MAP, FEATURE_COLS
            vector = {}
            for col, expr in FIELD_MAP.items():
                try:
                    vector[col] = eval(expr)  # noqa: S307
                except Exception:
                    vector[col] = 0

            X         = pd.DataFrame([vector], columns=FEATURE_COLS)
            
            base_prob = self._model.predict_proba(X)[0][1]

            # Only continue if ML sees meaningful phishing signal
            if base_prob < MIN_TRIGGER_PROB:
                logger.info(f"[ML] Low probability ({base_prob:.3f}) — silent pass")
                return CheckResult.clean()

            adj_prob, custom_reasons = self._preprocessor.adjust(base_prob, data, refined)

            score = round(adj_prob * 14)

            logger.info(f"[ML] base={base_prob:.3f} → adjusted={adj_prob:.3f} score={score}")

            # Generate human-readable reasons from top contributing features
            reasons = self._explain(vector, adj_prob) + custom_reasons

            return CheckResult(
                triggered=True,
                is_block=adj_prob >= BLOCK_THRESHOLD,
                score=score,
                reasons=reasons,
                tier="ML",
            )

        except Exception as e:
            logger.error(f"[ML] Inference error: {e}")
            return CheckResult.clean()

    def _explain(self, vector: dict, prob: float) -> list[str]:
        """
        Translates the top contributing features into plain English.
        Only explains features that are actually suspicious (not the expected value).
        Returns at most 3 reasons to keep the popup readable.
        """
        if not self._feature_importances:
            return [f"ML model: {round(prob * 100)}% phishing probability"]

        explanations = []

        # Sort features by importance descending
        ranked = sorted(
            self._feature_importances.items(),
            key=lambda x: x[1],
            reverse=True
        )

        for feature, importance in ranked:
            if len(explanations) >= 2:
                break
            if importance < 0.01:
                continue

            val = vector.get(feature, 0)
            explanation = self._feature_to_reason(feature, val)
            if explanation:
                explanations.append(explanation)

        # Always prepend the probability summary
        summary = f"ML model: {round(prob * 100)}% phishing probability"
        return [summary] + explanations

    def _feature_to_reason(self, feature: str, value) -> str | None:
        """
        Returns a reason string only if the feature value looks suspicious.
        Returns None if the value is unremarkable.
        """
        # Thresholds that define 'suspicious' for each feature
        suspicious_conditions = {
            "NoOfImage":             lambda v: v < 3,
            "NoOfSelfRef":           lambda v: v == 0,
            "NoOfJS":                lambda v: v < 2 or v > 30,
            "NoOfCSS":               lambda v: v < 1 or v > 20,
            "HasDescription":        lambda v: v == 0,
            "HasSocialNet":          lambda v: v == 0,
            "HasCopyrightInfo":      lambda v: v == 0,
            "DomainTitleMatchScore": lambda v: v < 0.1,
            "IsHTTPS":               lambda v: v == 0,
            "URLLength":             lambda v: v > 200,
            "DegitRatioInURL":       lambda v: v > 0.15,
            "SpacialCharRatioInURL": lambda v: v > 0.05,
            "NoOfSubDomain":         lambda v: v > 2,
        }

        condition = suspicious_conditions.get(feature)
        if condition and condition(value):
            info = FEATURE_EXPLANATIONS.get(feature)
            if info:
                return info[0]  # short label

        return None
