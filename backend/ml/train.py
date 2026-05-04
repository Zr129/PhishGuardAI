"""
PhishGuard ML Training Script
==============================

Dataset : PhiUSIIL — UCI ML Repository id=967
          235,795 URLs | 134,850 legitimate | 100,945 phishing

Important label note:
    PhiUSIIL raw encoding:
        1 = legitimate
        0 = phishing

    PhishGuard internal encoding:
        0 = legitimate
        1 = phishing

    This script flips the labels using:
        y = 1 - y

    After training:
        predict_proba class 1 = P(phishing)
"""

import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.pipeline import Pipeline

from ml.features import FEATURE_COLS


OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

LEGITIMATE_LABEL = 0
PHISHING_LABEL = 1


# ─────────────────────────────────────────────────────────
# STEP 1 — Load Dataset
# ─────────────────────────────────────────────────────────

def load_dataset():
    print("Loading PhiUSIIL from UCI ML Repository ...")

    from ucimlrepo import fetch_ucirepo

    ds = fetch_ucirepo(id=967)

    X = ds.data.features
    y_raw = ds.data.targets.squeeze()

    raw_legit = (y_raw == 1).sum()
    raw_phish = (y_raw == 0).sum()

    print(
        f"  Raw rows: {len(X):,} | "
        f"Raw legitimate: {raw_legit:,} ({raw_legit / len(X) * 100:.1f}%) | "
        f"Raw phishing: {raw_phish:,} ({raw_phish / len(X) * 100:.1f}%)"
    )

    print("  Raw PhiUSIIL labels: 1=legitimate, 0=phishing")

    # Flip labels:
    # PhiUSIIL raw: 1=legitimate, 0=phishing
    # PhishGuard:   0=legitimate, 1=phishing
    y = 1 - y_raw

    internal_legit = (y == LEGITIMATE_LABEL).sum()
    internal_phish = (y == PHISHING_LABEL).sum()

    print("  Labels flipped for PhishGuard:")
    print("    0 = legitimate")
    print("    1 = phishing")
    print(
        f"  Internal legitimate: {internal_legit:,} | "
        f"Internal phishing: {internal_phish:,}"
    )

    print("  Imbalance is mild — class_weight='balanced' used, no SMOTE needed")

    return X, y


# ─────────────────────────────────────────────────────────
# STEP 2 — Align Features
# ─────────────────────────────────────────────────────────

def align_features(X: pd.DataFrame) -> pd.DataFrame:
    """
    Selects columns in exact FEATURE_COLS order.
    Missing columns are zero-filled with a warning.
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

    print(f"  Feature matrix: {result.shape} ({len(FEATURE_COLS)} features)")

    return result


# ─────────────────────────────────────────────────────────
# STEP 3 — Feature Importance Scan
# ─────────────────────────────────────────────────────────

def prune_features(X: pd.DataFrame, y: pd.Series, threshold: float = 0.005):
    """
    Runs quick feature importance scan.
    Does not remove features automatically.
    """

    print("\nRunning feature importance scan (quick RF, 50 trees) ...")

    quick_rf = RandomForestClassifier(
        n_estimators=50,
        max_depth=10,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )

    quick_rf.fit(X, y)

    importances = pd.Series(
        quick_rf.feature_importances_,
        index=FEATURE_COLS
    ).sort_values(ascending=False)

    print(f"\n{'Feature':40s} {'Importance':>10} {'Keep?':>8}")
    print("-" * 65)

    for feature, importance in importances.items():
        keep = "yes" if importance >= threshold else f"< {threshold}"
        bar = "█" * int(importance * 300)
        print(f"{feature:40s} {importance:10.4f} {keep:>8}  {bar}")

    low = importances[importances < threshold]

    if not low.empty:
        print(f"\n  {len(low)} features below threshold {threshold}:")
        for feature in low.index:
            print(f"    - {feature}")

    return importances


# ─────────────────────────────────────────────────────────
# STEP 4 — Safe Probability Helper
# ─────────────────────────────────────────────────────────

def get_phishing_probability(model, X: pd.DataFrame):
    """
    Safely returns P(phishing) using model.classes_.
    """

    clf = model.named_steps["clf"]
    classes = list(clf.classes_)

    if PHISHING_LABEL not in classes:
        raise ValueError(
            f"Phishing label {PHISHING_LABEL} not found in model classes: {classes}"
        )

    phishing_index = classes.index(PHISHING_LABEL)

    return model.predict_proba(X)[:, phishing_index]


# ─────────────────────────────────────────────────────────
# STEP 5 — Train
# ─────────────────────────────────────────────────────────

def train(X: pd.DataFrame, y: pd.Series):
    print("\nSplitting 80/20 stratified ...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )

    print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")
    print(f"  Train phishing ratio: {(y_train == PHISHING_LABEL).mean():.3f}")
    print(f"  Test phishing ratio:  {(y_test == PHISHING_LABEL).mean():.3f}")

    model = Pipeline([
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=5,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced",
        ))
    ])

    print("\nTraining RandomForest...")
    model.fit(X_train, y_train)

    clf = model.named_steps["clf"]
    classes = list(clf.classes_)

    print(f"\nModel class order: {classes}")
    print("Expected: 0=legitimate, 1=phishing")

    if set(classes) != {LEGITIMATE_LABEL, PHISHING_LABEL}:
        raise ValueError(f"Unexpected model classes: {classes}")

    y_proba_phishing = get_phishing_probability(model, X_test)

    threshold = 0.5
    y_pred = (y_proba_phishing >= threshold).astype(int)

    auc = roc_auc_score(y_test, y_proba_phishing)

    report = classification_report(
        y_test,
        y_pred,
        labels=[LEGITIMATE_LABEL, PHISHING_LABEL],
        target_names=["legitimate", "phishing"],
        digits=4,
    )

    print(f"\nTest AUC-ROC: {auc:.4f}")
    print(f"Decision threshold: {threshold:.2f}")
    print("\nClassification Report:")
    print(report)

    print("5-fold cross-validation ...")

    cv = cross_val_score(
        model,
        X,
        y,
        cv=5,
        scoring="roc_auc",
        n_jobs=-1,
    )

    print(f"CV AUC: {cv.mean():.4f} ± {cv.std():.4f}")

    return model, report, auc, cv, threshold


# ─────────────────────────────────────────────────────────
# STEP 6 — Save
# ─────────────────────────────────────────────────────────

def save(model, report, importances, auc, cv, threshold):
    model_path = os.path.join(OUTPUT_DIR, "model.joblib")
    report_path = os.path.join(OUTPUT_DIR, "report.txt")

    joblib.dump(model, model_path)

    print(f"\nModel saved → {model_path}")

    class_order = list(model.named_steps["clf"].classes_)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("PhishGuard ML Model — Training Report\n")
        f.write("=" * 60 + "\n\n")

        f.write("Dataset:\n")
        f.write("  PhiUSIIL — UCI ML Repository id=967\n")
        f.write("  Raw labels: 1=legitimate, 0=phishing\n")
        f.write("  Internal labels after flip: 0=legitimate, 1=phishing\n\n")

        f.write("Features:\n")
        f.write(f"  Features used: {len(FEATURE_COLS)}\n")
        for i, feature in enumerate(FEATURE_COLS, start=1):
            f.write(f"  {i}. {feature}\n")

        f.write("\nModel:\n")
        f.write("  Algorithm: RandomForestClassifier\n")
        f.write("  n_estimators: 200\n")
        f.write("  max_depth: 20\n")
        f.write("  min_samples_leaf: 5\n")
        f.write("  class_weight: balanced\n\n")

        f.write("Class Order:\n")
        f.write(f"  model.classes_: {class_order}\n")
        f.write("  0 = legitimate\n")
        f.write("  1 = phishing\n\n")

        f.write("Performance:\n")
        f.write(f"  AUC-ROC: {auc:.4f}\n")
        f.write(f"  CV AUC: {cv.mean():.4f} ± {cv.std():.4f}\n")
        f.write(f"  Decision threshold: {threshold:.2f}\n\n")

        f.write("Classification Report:\n")
        f.write(report)
        f.write("\n\n")

        f.write("Feature Importances:\n")
        f.write(importances.sort_values(ascending=False).to_string())

    print(f"Report saved → {report_path}")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    X, y = load_dataset()

    X_aligned = align_features(X)

    print("\nFeatures being used:")
    for i, feature in enumerate(FEATURE_COLS, start=1):
        print(f"{i}. {feature}")

    importances = prune_features(X_aligned, y)

    model, report, auc, cv, threshold = train(X_aligned, y)

    save(model, report, importances, auc, cv, threshold)

    print("\nDone. Restart backend — MLCheck will auto-load model.joblib.")