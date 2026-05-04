"""
Tier 3 — ML Model Check.

Pipeline:
  1. Build core feature vector using the 15 PhiUSIIL features
  2. model.predict_proba → base P(phishing)
  3. CustomSignalPreprocessor.adjust → inject extension-only signals
  4. Check adjusted probability against threshold
  5. Translate top contributing features into human-readable reasons
  6. Return CheckResult with tier="ML"
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
    "ml",
    "model.joblib",
)

MIN_TRIGGER_PROB = 0.12   # below this ML stays silent
BLOCK_THRESHOLD = 0.97    # above this ML alone can hard-block — raised from 0.85
                           # to prevent legitimate OAuth/login pages (e.g. Microsoft,
                           # Outlook) being blocked by ML alone when loaded with
                           # minimal DOM content during authentication flows

PHISHING_LABEL = 1        # your fixed training convention: 1 = phishing


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
    "HasSubmitButton":       ("Submit button present", "Page contains a submit button"),
    "NoOfSubDomain":         ("Multiple subdomains", "Excessive subdomain depth detected"),
}


class MLCheck(BaseCheck):

    def __init__(self, model=None):
        self._model = model or self._try_load()
        self._preprocessor = CustomSignalPreprocessor()
        self._feature_importances = self._load_importances()

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    def _try_load(self):
        try:
            import joblib

            model = joblib.load(MODEL_PATH)
            logger.info(f"[ML] Model loaded from {MODEL_PATH}")

            try:
                classes = list(model.named_steps["clf"].classes_)
                logger.info(f"[ML] Model class order: {classes}")
                logger.info("[ML] Expected: 0=legitimate, 1=phishing")
            except Exception as e:
                logger.warning(f"[ML] Could not read model classes: {e}")

            return model

        except Exception as e:
            logger.info(f"[ML] No model loaded ({e}) — Tier 3 skipped")
            return None

    def _load_importances(self) -> dict:
        """Load feature importances from trained model for reason generation."""
        try:
            if self._model is None:
                return {}

            rf = self._model.named_steps["clf"]

            from ml.features import FEATURE_COLS

            return dict(zip(FEATURE_COLS, rf.feature_importances_))

        except Exception as e:
            logger.warning(f"[ML] Could not load feature importances: {e}")
            return {}

    def _get_phishing_probability(self, X: pd.DataFrame) -> float:
        """
        Safely returns P(phishing).

        Do not hardcode predict_proba(X)[0][1] unless you have checked
        model.classes_. This function finds the probability column for
        class 1, which PhishGuard uses as phishing.
        """
        clf = self._model.named_steps["clf"]
        classes = list(clf.classes_)

        if PHISHING_LABEL not in classes:
            raise ValueError(f"Phishing label {PHISHING_LABEL} not found in model classes: {classes}")

        phishing_index = classes.index(PHISHING_LABEL)

        probs = self._model.predict_proba(X)[0]
        phishing_prob = float(probs[phishing_index])

        return phishing_prob

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if not self.is_ready:
            return CheckResult.clean()

        try:
            from ml.features import FIELD_MAP, FEATURE_COLS

            vector = {}

            for col, extractor in FIELD_MAP.items():
                try:
                    vector[col] = extractor(data, refined)
                except Exception as e:
                    logger.error(f"[ML ERROR] Feature {col} failed: {e}")
                    vector[col] = 0

            X = pd.DataFrame([vector], columns=FEATURE_COLS)

            logger.info(
                f"[ML] Feature vector: "
                f"URLLength={vector.get('URLLength')} "
                f"DegitRatioInURL={vector.get('DegitRatioInURL')} "
                f"SpacialCharRatioInURL={vector.get('SpacialCharRatioInURL')} "
                f"LetterRatioInURL={vector.get('LetterRatioInURL')} "
                f"NoOfSubDomain={vector.get('NoOfSubDomain')} "
                f"DomainTitleMatchScore={vector.get('DomainTitleMatchScore')} "
                f"IsHTTPS={vector.get('IsHTTPS')} "
                f"NoOfImage={vector.get('NoOfImage')} "
                f"NoOfSelfRef={vector.get('NoOfSelfRef')} "
                f"NoOfJS={vector.get('NoOfJS')} "
                f"NoOfCSS={vector.get('NoOfCSS')} "
                f"HasCopyrightInfo={vector.get('HasCopyrightInfo')} "
                f"HasSocialNet={vector.get('HasSocialNet')} "
                f"HasDescription={vector.get('HasDescription')} "
                f"HasSubmitButton={vector.get('HasSubmitButton')}"
            )

            # 1. Get base ML probability safely.
            base_prob = self._get_phishing_probability(X)

            # 2. Apply custom extension-only ML signals BEFORE threshold check.
            adj_prob, custom_reasons = self._preprocessor.adjust(base_prob, data, refined)

            # 3. Clamp probability to valid range.
            adj_prob = max(0.0, min(1.0, float(adj_prob)))

            # 4. Threshold check uses adjusted probability, not base probability.
            if adj_prob < MIN_TRIGGER_PROB:
                logger.info(
                    f"[ML] base_prob={base_prob:.3f} → adjusted={adj_prob:.3f} "
                    f"below threshold, silent pass"
                )
                return CheckResult.clean()

            score = round(adj_prob * 10)

            logger.info(
                f"[ML] base_prob={base_prob:.3f} → adjusted={adj_prob:.3f} "
                f"score={score}"
            )

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
        Only explains features that are actually suspicious.
        The raw ML probability percentage is intentionally not shown —
        on legitimate sites with unusual feature profiles it produces
        misleading numbers that undermine trust in the overall verdict.
        """
        if not self._feature_importances:
            return []

        explanations = []

        ranked = sorted(
            self._feature_importances.items(),
            key=lambda x: x[1],
            reverse=True,
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

        return explanations

    def _feature_to_reason(self, feature: str, value) -> str | None:
        """
        Returns a reason string only if the feature value looks suspicious.
        Returns None if the value is normal.
        """
        suspicious_conditions = {
            "NoOfImage":             lambda v: v < 3,
            "NoOfSelfRef":           lambda v: v == 0,
            "NoOfJS":                lambda v: v < 2 or v > 30,
            "NoOfCSS":               lambda v: v < 1 or v > 20,

            # HasDescription is intentionally omitted because it is weak
            # and causes false positives on many legitimate pages.

            "HasSocialNet":          lambda v: v == 0,
            "HasCopyrightInfo":      lambda v: v == 0,
            "DomainTitleMatchScore": lambda v: v < 0.1,
            "IsHTTPS":               lambda v: v == 0,
            "URLLength":             lambda v: v > 200,
            "DegitRatioInURL":       lambda v: v > 0.15,
            "SpacialCharRatioInURL": lambda v: v > 0.05,
            "NoOfSubDomain":         lambda v: v > 2,
            # HasSubmitButton intentionally omitted — most legitimate pages
            # have submit buttons, flagging them causes too many false reasons
        }

        condition = suspicious_conditions.get(feature)

        if condition and condition(value):
            info = FEATURE_EXPLANATIONS.get(feature)

            if info:
                return info[0]

        return None