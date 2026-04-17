"""
Tier 3 — ML Model Check.

Pipeline:
  1. Build core feature vector (FIELD_MAP — 37 PhiUSIIL features)
  2. model.predict_proba → base P(phishing)
  3. CustomSignalPreprocessor.adjust → inject extension-only signals
  4. Return final adjusted probability as CheckResult
"""

import logging
import os
from checks.base import BaseCheck, CheckResult
from models.models import URLRequest
from ml.preprocessor import CustomSignalPreprocessor

logger = logging.getLogger("PhishGuard")

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ml", "model.joblib"
)

# Block threshold — if adjusted P(phishing) >= this, hard block
BLOCK_THRESHOLD = 0.85


class MLCheck(BaseCheck):

    def __init__(self, model=None):
        self._model       = model or self._try_load()
        self._preprocessor = CustomSignalPreprocessor()

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

    def run(self, data: URLRequest, refined: dict) -> CheckResult:
        if not self.is_ready:
            return CheckResult.clean()

        try:
            # Step 1 — core vector (PhiUSIIL features only)
            vector   = [self._build_vector(data, refined)]
            base_prob = self._model.predict_proba(vector)[0][1]

            # Step 2 — inject custom extension signals
            adj_prob, custom_reasons = self._preprocessor.adjust(base_prob, data, refined)

            score    = round(adj_prob * 14)
            is_block = adj_prob >= BLOCK_THRESHOLD

            logger.info(
                f"[ML] base={base_prob:.3f} → adjusted={adj_prob:.3f} "
                f"score={score} block={is_block}"
            )

            reasons = [f"ML model: {round(adj_prob * 100)}% phishing probability"]
            reasons.extend(custom_reasons)

            return CheckResult(
                triggered=True,
                is_block=is_block,
                score=score,
                reasons=reasons,
            )

        except Exception as e:
            logger.error(f"[ML] Inference error: {e}")
            return CheckResult.clean()

    def _build_vector(self, data: URLRequest, refined: dict) -> list:
        """
        Evaluates each expression in FIELD_MAP in FEATURE_COLS order.
        Guaranteed to match train.py since both import from features.py.
        """
        from ml.features import FIELD_MAP
        vector = []
        for col, expr in FIELD_MAP.items():
            try:
                vector.append(eval(expr))
            except Exception:
                vector.append(0)
        return vector
