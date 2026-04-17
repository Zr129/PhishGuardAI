"""
PhishGuard ML Training Script
==============================
Dataset : PhiUSIIL — UCI ML Repository id=967
          235,795 URLs | 134,850 legitimate | 100,945 phishing

Class balance note:
    PhiUSIIL is 57/43 (legitimate/phishing) — mild imbalance.
    A forced 50/50 undersampling would discard ~34,000 legitimate
    samples and reduce accuracy. class_weight='balanced' handles
    this imbalance mathematically without throwing away data.
    SMOTE is not needed unless imbalance exceeds ~80/20.

Feature set note:
    We use 37 core PhiUSIIL features (not all 45) — raw/ratio pairs
    are collapsed to the ratio only, and zero-filled custom fields
    are excluded. Custom extension signals (IsHiddenSubmission etc.)
    are injected post-inference by CustomSignalPreprocessor instead.

Usage:
    pip install ucimlrepo scikit-learn joblib pandas
    cd backend && python ml/train.py
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectFromModel

from ml.features import FEATURE_COLS, FIELD_MAP

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_COL = "label"   # 1 = legitimate, 0 = phishing

# PhiUSIIL columns we intentionally skip (too costly for real-time inference)
SKIP_COLS = {
    "URLSimilarityIndex", "TLDLegitimateProb", "URLCharProb",
    "LineOfCode", "LargestLineLength", "FILENAME",
}


# ─────────────────────────────────────────────────────────
# STEP 1 — Load
# ─────────────────────────────────────────────────────────

def load_dataset():
    print("Loading PhiUSIIL from UCI ML Repository ...")
    from ucimlrepo import fetch_ucirepo
    ds = fetch_ucirepo(id=967)
    X  = ds.data.features
    y  = ds.data.targets.squeeze()

    legit = (y == 1).sum()
    phish = (y == 0).sum()
    print(f"  Rows: {len(X):,}  |  Legit: {legit:,} ({legit/len(X)*100:.1f}%)  |  Phishing: {phish:,} ({phish/len(X)*100:.1f}%)")
    print(f"  Imbalance is mild (57/43) — class_weight='balanced' used, no SMOTE needed")
    return X, y


# ─────────────────────────────────────────────────────────
# STEP 2 — Align to FEATURE_COLS
# ─────────────────────────────────────────────────────────

def align_features(X: pd.DataFrame) -> pd.DataFrame:
    """
    Selects columns in exact FEATURE_COLS order.
    Missing columns (shouldn't happen) are zero-filled with a warning.
    """
    result = pd.DataFrame(index=X.index)

    for col in FEATURE_COLS:
        if col in X.columns:
            result[col] = X[col]
        else:
            result[col] = 0
            print(f"  [WARNING] '{col}' not found in dataset — zero-filled")

    assert list(result.columns) == FEATURE_COLS, "Column order mismatch!"
    result = result.fillna(0)
    print(f"  Feature matrix: {result.shape}  ({len(FEATURE_COLS)} features)")
    return result


# ─────────────────────────────────────────────────────────
# STEP 3 — Feature importance analysis + pruning
# ─────────────────────────────────────────────────────────

def prune_features(X: pd.DataFrame, y: pd.Series, threshold: float = 0.005):
    """
    Fits a lightweight RF to find low-importance features.
    Prints the full importance table so you can inspect it.
    Does NOT remove anything — returns the importance series
    so you can decide what to drop in FEATURE_COLS if desired.
    """
    print("\nRunning feature importance scan (quick RF, 50 trees) ...")
    quick_rf = RandomForestClassifier(n_estimators=50, max_depth=10, n_jobs=-1, random_state=42)
    quick_rf.fit(X, y)

    imps = pd.Series(quick_rf.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False)

    print(f"\n{'Feature':40s}  {'Importance':>10}  {'Keep?':>6}")
    print("-" * 62)
    for feat, imp in imps.items():
        keep = "✓" if imp >= threshold else f"⚠ <{threshold}"
        bar  = "█" * int(imp * 300)
        print(f"  {feat:38s}  {imp:10.4f}  {keep:6}  {bar}")

    low = imps[imps < threshold]
    if not low.empty:
        print(f"\n  {len(low)} features below threshold {threshold}:")
        for f in low.index:
            print(f"    - {f}")
        print("  To remove: delete them from FIELD_MAP in ml/features.py")

    return imps


# ─────────────────────────────────────────────────────────
# STEP 4 — Train
# ─────────────────────────────────────────────────────────

def train(X: pd.DataFrame, y: pd.Series):
    print("\nSplitting 80/20 stratified ...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")
    print(f"  Train phishing ratio: {(y_train==0).mean():.3f}")

    model = Pipeline([
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=5,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced",   # handles 57/43 imbalance — no SMOTE needed
        ))
    ])

    print("Training RandomForest (n=200, max_depth=20, balanced weights) ...")
    model.fit(X_train, y_train)

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    auc     = roc_auc_score(y_test, y_proba)
    report  = classification_report(
        y_test, y_pred,
        target_names=["phishing", "legitimate"],
        digits=4
    )

    print(f"\nTest AUC-ROC: {auc:.4f}")
    print(report)

    print("5-fold cross-validation ...")
    cv = cross_val_score(model, X, y, cv=5, scoring="roc_auc", n_jobs=-1)
    print(f"CV AUC: {cv.mean():.4f} ± {cv.std():.4f}")

    return model, report, auc, cv


# ─────────────────────────────────────────────────────────
# STEP 5 — Save
# ─────────────────────────────────────────────────────────

def save(model, report, importances, auc, cv):
    model_path  = os.path.join(OUTPUT_DIR, "model.joblib")
    report_path = os.path.join(OUTPUT_DIR, "report.txt")

    joblib.dump(model, model_path)
    print(f"\nModel saved → {model_path}")

    with open(report_path, "w") as f:
        f.write("PhishGuard ML Model — Training Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Dataset:    PhiUSIIL (UCI id=967)\n")
        f.write(f"Features:   {len(FEATURE_COLS)} core (custom signals injected post-inference)\n")
        f.write(f"Balance:    57/43 — class_weight='balanced', no SMOTE\n")
        f.write(f"AUC-ROC:    {auc:.4f} (test set)\n")
        f.write(f"CV AUC:     {cv.mean():.4f} ± {cv.std():.4f}\n\n")
        f.write("Classification Report:\n")
        f.write(report + "\n\n")
        f.write("Feature Importances (sorted):\n")
        f.write(importances.sort_values(ascending=False).to_string())

    print(f"Report saved → {report_path}")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    X, y       = load_dataset()
    X_aligned  = align_features(X)
    importances = prune_features(X_aligned, y)           # inspect, then prune FIELD_MAP if needed
    model, report, auc, cv = train(X_aligned, y)
    save(model, report, importances, auc, cv)
    print("\nDone. Restart backend — MLCheck will auto-load model.joblib.")
