"""
PhishGuard ML Training Script — Real Data Augmented
====================================================

Dataset : PhiUSIIL — UCI ML Repository id=967
          235,795 URLs | 134,850 legitimate | 100,945 phishing

Augmentation:
    PhiUSIIL under-represents some large real legitimate websites that have
    unusual browser-extracted feature profiles. This script augments the
    training set with legitimate feature vectors collected from real live
    browsing through the PhishGuard extension/backend pipeline.

Label encoding:
    PhiUSIIL raw:
        1 = legitimate
        0 = phishing

    PhishGuard internal:
        0 = legitimate
        1 = phishing

    This script flips the raw labels using:
        y = 1 - y_raw

After training:
    predict_proba class 1 = P(phishing)

Usage:
    cd backend
    python -m ml.train_augmented
"""

import os
import hashlib
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from sklearn.pipeline import Pipeline

from ml.features import FEATURE_COLS


OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

LEGITIMATE_LABEL = 0
PHISHING_LABEL = 1


REAL_LEGIT_ROWS = [
    # Original real browser-extracted legitimate vectors

    # Amazon UK
    [25, 0, 1, 0.28, 0.72, 2, 333, 1, 0.0, 1, 1, 1, 181, 12, 30],
    [25, 0, 1, 0.28, 0.72, 2, 320, 1, 0.0, 1, 1, 1, 175, 12, 30],
    [28, 0, 1, 0.28, 0.72, 2, 300, 1, 0.0, 1, 1, 1, 190, 11, 29],
    [35, 0, 1, 0.27, 0.73, 2, 280, 1, 0.0, 1, 1, 1, 160, 12, 31],
    [42, 0, 1, 0.27, 0.73, 2, 310, 1, 0.0, 1, 1, 1, 200, 13, 28],

    # eBay UK
    [23, 0, 1, 0.304, 0.696, 2, 669, 0, 0.0, 1, 1, 1, 167, 2, 44],
    [23, 0, 1, 0.304, 0.696, 2, 650, 0, 0.0, 1, 1, 1, 155, 2, 43],
    [26, 0, 1, 0.30, 0.70, 2, 600, 0, 0.0, 1, 1, 1, 145, 2, 42],
    [30, 0, 1, 0.30, 0.70, 2, 580, 0, 0.0, 1, 1, 1, 170, 3, 45],

    # BBC
    [22, 0, 1, 0.318, 0.682, 2, 188, 0, 0.0, 1, 0, 1, 89, 0, 75],
    [22, 0, 1, 0.318, 0.682, 2, 195, 0, 0.0, 1, 0, 1, 95, 0, 74],
    [25, 0, 1, 0.31, 0.69, 2, 180, 0, 0.0, 1, 0, 1, 80, 0, 73],
    [30, 0, 1, 0.31, 0.69, 2, 200, 0, 0.333, 1, 0, 1, 100, 0, 76],

    # The Guardian
    [30, 0, 1, 0.2, 0.8, 1, 399, 1, 0.0, 1, 1, 1, 135, 1, 6],
    [30, 0, 1, 0.2, 0.8, 1, 380, 1, 0.0, 1, 1, 1, 125, 1, 6],
    [35, 0, 1, 0.2, 0.8, 1, 410, 1, 0.0, 1, 1, 1, 145, 1, 7],
    [45, 0, 1, 0.19, 0.81, 1, 350, 1, 0.333, 1, 0, 1, 110, 1, 6],

    # Gov.uk
    [19, 0, 1, 0.316, 0.684, 1, 106, 0, 0.5, 1, 1, 1, 4, 2, 5],
    [19, 0, 1, 0.316, 0.684, 1, 100, 0, 0.5, 1, 1, 1, 5, 2, 5],
    [25, 0, 1, 0.31, 0.69, 1, 90, 0, 0.4, 1, 1, 1, 3, 2, 5],
    [30, 0, 1, 0.31, 0.69, 2, 80, 0, 0.333, 1, 0, 1, 6, 3, 4],

    # NHS
    [19, 0, 1, 0.316, 0.684, 1, 51, 0, 0.25, 1, 1, 1, 0, 1, 5],
    [19, 0, 1, 0.316, 0.684, 1, 55, 0, 0.25, 1, 1, 1, 0, 1, 5],
    [25, 0, 1, 0.31, 0.69, 1, 45, 0, 0.2, 1, 1, 1, 2, 1, 4],
    [30, 0, 1, 0.31, 0.69, 1, 60, 0, 0.2, 1, 0, 1, 1, 2, 5],

    # GitHub
    [19, 0, 1, 0.263, 0.737, 0, 56, 0, 1.0, 1, 1, 1, 13, 54, 41],
    [19, 0, 1, 0.263, 0.737, 0, 60, 0, 1.0, 1, 1, 1, 12, 52, 40],
    [25, 0, 1, 0.26, 0.74, 0, 50, 0, 1.0, 1, 1, 1, 15, 55, 42],
    [30, 0, 1, 0.26, 0.74, 0, 65, 0, 0.5, 1, 1, 1, 10, 50, 38],

    # LinkedIn
    [30, 0, 1, 0.233, 0.767, 1, 61, 1, 0.5, 0, 1, 1, 14, 1, 22],
    [30, 0, 1, 0.233, 0.767, 1, 65, 1, 0.5, 0, 1, 1, 12, 1, 21],
    [35, 0, 1, 0.23, 0.77, 1, 55, 1, 0.4, 1, 1, 1, 16, 2, 23],
    [28, 0, 1, 0.24, 0.76, 1, 58, 1, 0.5, 1, 1, 1, 10, 1, 20],

    # HSBC
    [23, 0, 1, 0.304, 0.696, 2, 411, 1, 0.0, 1, 0, 1, 11, 2, 62],
    [23, 0, 1, 0.304, 0.696, 2, 400, 1, 0.0, 1, 0, 1, 10, 2, 61],
    [28, 0, 1, 0.30, 0.70, 2, 390, 1, 0.0, 1, 1, 1, 12, 3, 60],
    [30, 0, 1, 0.30, 0.70, 2, 380, 1, 0.0, 1, 0, 1, 8, 2, 63],

    # Barclays
    [27, 0, 1, 0.259, 0.741, 2, 190, 1, 0.0, 1, 0, 0, 20, 40, 24],
    [27, 0, 1, 0.259, 0.741, 2, 185, 1, 0.0, 1, 0, 1, 18, 38, 23],
    [30, 0, 1, 0.26, 0.74, 2, 200, 1, 0.0, 1, 0, 0, 22, 42, 25],
    [32, 0, 1, 0.26, 0.74, 2, 175, 1, 0.0, 1, 1, 1, 15, 39, 24],

    # Spotify
    [25, 0, 1, 0.24, 0.76, 1, 331, 1, 0.167, 0, 0, 1, 58, 13, 14],
    [25, 0, 1, 0.24, 0.76, 1, 320, 1, 0.167, 0, 0, 1, 55, 13, 14],
    [28, 0, 1, 0.24, 0.76, 1, 310, 1, 0.2, 0, 0, 1, 60, 14, 15],
    [30, 0, 1, 0.23, 0.77, 1, 300, 1, 0.1, 1, 0, 1, 50, 12, 13],

    # Booking.com
    [233, 0.167, 1, 0.086, 0.747, 1, 251, 0, 0.091, 1, 1, 1, 97, 31, 57],
    [180, 0.15, 1, 0.09, 0.75, 1, 240, 0, 0.1, 1, 1, 1, 90, 30, 55],
    [150, 0.12, 1, 0.10, 0.76, 1, 260, 0, 0.091, 1, 1, 1, 100, 32, 58],
    [200, 0.18, 1, 0.085, 0.74, 1, 230, 0, 0.091, 1, 1, 1, 85, 29, 56],

    # Real backend calibration vectors from live PhishGuard testing

    # Argos
    [24, 0.0, 1, 0.0, 0.7083, 0, 25, 1, 0.125, 1, 1, 1, 43, 4, 19],

    # Currys
    [25, 0.0, 1, 0.0, 0.72, 0, 134, 1, 0.167, 1, 1, 0, 116, 3, 28],

    # BBC backend
    [22, 0.0, 1, 0.0, 0.6818, 0, 47, 0, 0.333, 1, 1, 1, 89, 0, 59],

    # Guardian backend
    [30, 0.0, 1, 0.0, 0.8, 0, 49, 1, 0.0, 1, 1, 1, 135, 1, 18],

    # Sky News
    [21, 0.0, 1, 0.0, 0.7143, 1, 13, 1, 0.222, 1, 1, 1, 122, 1, 10],

    # Reuters fully loaded version
    [24, 0.0, 1, 0.0, 0.75, 0, 20, 1, 0.2, 1, 0, 1, 1, 2, 15],

    # Gov.uk backend
    [19, 0.0, 1, 0.0, 0.6842, 0, 0, 0, 0.5, 1, 1, 1, 4, 2, 5],

    # NHS backend
    [19, 0.0, 1, 0.0, 0.6842, 0, 9, 0, 0.25, 1, 1, 1, 0, 1, 5],

    # Police.uk
    [22, 0.0, 1, 0.0, 0.7273, 0, 0, 0, 0.667, 1, 1, 1, 6, 3, 6],

    # GitHub homepage backend
    [19, 0.0, 1, 0.0, 0.7368, 0, 3, 0, 0.5, 1, 1, 1, 3, 39, 48],

    # GitHub commits page backend
    [51, 0.0588, 1, 0.0, 0.7647, 0, 2, 0, 0.0, 1, 1, 1, 20, 36, 120],

    # StackOverflow questions page
    [35, 0.0, 1, 0.0, 0.8571, 0, 16, 1, 0.0, 0, 1, 1, 16, 3, 41],
    [35, 0.0, 1, 0.0, 0.8571, 0, 16, 1, 0.0, 0, 1, 1, 16, 4, 46],

    # MDN
    [36, 0.0, 1, 0.0, 0.7778, 1, 0, 1, 0.0, 1, 0, 1, 1, 20, 5],

    # HSBC backend
    [23, 0.0, 1, 0.0, 0.6957, 0, 142, 1, 0.4, 1, 1, 0, 9, 1, 28],

    # Barclays backend
    [27, 0.0, 1, 0.0, 0.7407, 0, 3, 1, 0.333, 1, 1, 0, 20, 40, 21],

    # Lloyds official bank site
    [27, 0.0, 1, 0.0, 0.7778, 0, 0, 1, 0.0, 1, 1, 0, 19, 2, 12],

    # NatWest
    [24, 0.0, 1, 0.0, 0.75, 0, 29, 1, 0.125, 1, 1, 1, 27, 29, 44],

    # LinkedIn
    [25, 0.0, 1, 0.0, 0.76, 0, 30, 1, 0.5, 0, 1, 1, 4, 1, 15],

    # Spotify web player
    [25, 0.0, 1, 0.0, 0.76, 1, 0, 0, 0.333, 0, 0, 0, 0, 1, 8],

    # Microsoft
    [31, 0.0, 1, 0.0, 0.7742, 0, 82, 1, 0.143, 1, 1, 1, 27, 16, 57],

    # PayPal homepage
    [30, 0.0, 1, 0.0, 0.7667, 0, 20, 0, 0.143, 1, 1, 1, 6, 15, 9],

    # PayPal official login
    [44, 0.0, 1, 0.0, 0.7727, 0, 0, 0, 0.0, 1, 1, 0, 5, 2, 16],
    [44, 0.0, 1, 0.0, 0.7727, 0, 0, 0, 0.0, 1, 1, 0, 5, 3, 18],

    # Booking.com backend
    [197, 0.132, 1, 0.0, 0.797, 0, 191, 0, 0.182, 1, 1, 1, 12, 29, 53],

    # eBay backend
    [23, 0.0, 1, 0.0, 0.6957, 0, 626, 0, 0.286, 1, 1, 1, 163, 2, 8],

    # Amazon UK backend
    [25, 0.0, 1, 0.0, 0.72, 0, 7, 0, 0.273, 1, 1, 1, 185, 12, 24],

    # Netflix UK — no copyright, minimal images, has social
    [27, 0, 1, 0.259, 0.741, 1, 23, 1, 0.143, 1, 1, 0, 3, 1, 7],
    [27, 0, 1, 0.259, 0.741, 1, 20, 1, 0.143, 1, 1, 0, 4, 1, 7],
    [30, 0, 1, 0.258, 0.742, 1, 25, 1, 0.143, 1, 1, 0, 3, 1, 8],

    # YouTube — perfect domain-title match, has social, has copyright
    [24, 0, 1, 0.25, 0.75, 1, 32, 1, 1.0, 1, 0, 1, 28, 6, 17],
    [24, 0, 1, 0.25, 0.75, 1, 30, 1, 1.0, 1, 0, 1, 25, 6, 16],
    [28, 0, 1, 0.25, 0.75, 1, 35, 1, 0.5, 1, 0, 1, 30, 7, 18],

    # Outlook live.com — loads with minimal content, no copyright, hidden iframe
    [30, 0.0, 1, 0.0, 0.7667, 1, 0, 0, 0.333, 0, 0, 0, 1, 0, 2],
    [51, 0.0, 1, 0.0, 0.8235, 1, 0, 0, 0.0,   0, 0, 0, 0, 0, 0],

    # login.live.com OAuth flow — long URL with token params, high digit ratio
    [245, 0.4286, 1, 0.0, 0.4449, 1, 0, 0, 0.0, 0, 0, 0, 0, 0, 0],
    [225, 0.4,    1, 0.0, 0.4667, 1, 0, 0, 0.0, 0, 0, 0, 0, 0, 0],
    [237, 0.3797, 1, 0.0, 0.4852, 1, 0, 0, 0.0, 0, 0, 0, 2, 0, 3],

    # login.microsoftonline.com — logout/redirect URLs
    [289, 0.1384, 1, 0.0, 0.7405, 1, 0, 0, 0.0, 0, 0, 0, 1, 1, 3],
    [288, 0.1632, 1, 0.0, 0.6979, 1, 0, 0, 0.0, 0, 0, 0, 1, 1, 3],

    # login.microsoft.com FIDO/passkey page
    [59, 0.0, 1, 0.0, 0.8136, 1, 0, 0, 0.0, 0, 0, 0, 0, 1, 2],

    # MSN — loads with minimal content
    [25, 0.0, 1, 0.0, 0.72, 0, 0, 0, 0.5, 0, 1, 0, 0, 0, 10],
    [25, 0.0, 1, 0.0, 0.72, 0, 0, 0, 0.111, 1, 1, 0, 2, 0, 19],

    # Amazon US backend
    [23, 0.0, 1, 0.0, 0.7391, 0, 9, 0, 0.333, 1, 1, 1, 233, 9, 8],

    # Santander — no copyright, few self-refs
    [28, 0.0, 1, 0.0, 0.75, 0, 5, 0, 0.667, 1, 1, 0, 9, 2, 9],

    # Nationwide — no CSS, has social, has copyright
    [29, 0.0, 1, 0.0, 0.7586, 0, 4, 1, 0.167, 1, 1, 1, 10, 0, 21],

    # Monzo — many images, no copyright
    [18, 0.0, 1, 0.0, 0.7222, 0, 7, 1, 0.2, 1, 1, 0, 82, 8, 28],

    # Starling Bank — few self-refs, high JS
    [29, 0.0, 1, 0.0, 0.7931, 0, 1, 1, 0.0, 1, 1, 1, 27, 5, 34],

    # Halifax — few self-refs, no copyright
    [26, 0.0, 1, 0.0, 0.7308, 0, 1, 1, 0.143, 1, 1, 0, 20, 2, 12],

    # Virgin Money — subdomain uk., no copyright
    [27, 0.0, 1, 0.0, 0.7778, 1, 2, 1, 0.143, 1, 1, 0, 28, 3, 18],

    # HMRC via gov.uk — long URL, good title match, dampener applies
    [62, 0.0, 1, 0.0, 0.8387, 0, 12, 1, 0.4, 1, 1, 1, 21, 2, 5],

    # Justice.gov.uk — few images, no social, dampener applies
    [27, 0.0, 1, 0.0, 0.7407, 0, 10, 0, 0.667, 0, 1, 1, 1, 2, 8],

    # Next — many self-refs, high JS/CSS
    [23, 0.0, 1, 0.0, 0.6957, 0, 81, 1, 0.125, 1, 1, 1, 74, 17, 97],

    # John Lewis — moderate content, high CSS/JS
    [26, 0.0, 1, 0.0, 0.7692, 0, 8, 1, 0.0, 1, 1, 1, 41, 21, 46],

    # Tesco — very high counts across all features
    [22, 0.0, 1, 0.0, 0.7273, 0, 138, 1, 0.167, 1, 1, 1, 78, 119, 153],

    # Etsy — many self-refs, no social
    [21, 0.0, 1, 0.0, 0.7143, 0, 72, 0, 0.091, 1, 1, 1, 18, 2, 8],

    # ASOS — very high self-refs (500+)
    [21, 0.0, 1, 0.0, 0.7143, 0, 567, 1, 0.125, 1, 1, 1, 80, 4, 29],

    # Apple — no social, no description, minimal links
    [22, 0.0, 1, 0.0, 0.7273, 0, 6, 0, 0.5, 0, 1, 1, 52, 10, 13],

    # X.com (Twitter) — no images, no self-refs, no copyright
    [14, 0.0, 1, 0.0, 0.6429, 0, 0, 0, 0.2, 1, 0, 0, 0, 0, 14],

    # Canva — many self-refs, very few images, no social
    [28, 0.0, 1, 0.0, 0.7143, 0, 223, 0, 0.2, 1, 1, 1, 1, 1, 11],

    # The Independent — no CSS, no copyright
    [30, 0.0, 1, 0.0, 0.7667, 0, 8, 1, 0.111, 1, 1, 0, 134, 0, 18],

    # BBC News article page — high JS, many images, no CSS
    [26, 0.0, 1, 0.0, 0.7308, 0, 54, 1, 0.333, 1, 1, 1, 119, 0, 66],

    # Airbnb — no self-refs, no social, very few images (loaded state)
    [25, 0.0, 1, 0.0, 0.72, 0, 0, 0, 0.111, 1, 0, 0, 1, 1, 54],

    # TripAdvisor — fully loaded state (0 self-refs, has social/copyright)
    [30, 0.0, 1, 0.0, 0.7667, 0, 0, 1, 0.083, 1, 1, 1, 43, 2, 8],

    # Outlook.com (Microsoft mail) — very few images, no social
    # Added explicitly because it was HARD BLOCKED — prob=0.869 before augmentation
    [37, 0.0, 1, 0.0, 0.8108, 1, 0, 0, 0.333, 0, 0, 0, 1, 3, 2],
]


def _row_hash(row):
    return hashlib.md5(str(row).encode()).hexdigest()


def load_dataset():
    print("Loading PhiUSIIL from UCI ML Repository ...")

    from ucimlrepo import fetch_ucirepo

    ds = fetch_ucirepo(id=967)
    X = ds.data.features
    y_raw = ds.data.targets.squeeze()

    raw_legit = (y_raw == 1).sum()
    raw_phish = (y_raw == 0).sum()

    print(
        f"  Rows: {len(X):,} | "
        f"Legit: {raw_legit:,} ({raw_legit / len(X) * 100:.1f}%) | "
        f"Phishing: {raw_phish:,} ({raw_phish / len(X) * 100:.1f}%)"
    )

    y = 1 - y_raw

    print("  Labels flipped: 0=legitimate, 1=phishing")

    return X, y


def align_features(X):
    result = pd.DataFrame(index=X.index)

    for col in FEATURE_COLS:
        result[col] = X[col] if col in X.columns else 0

    assert list(result.columns) == FEATURE_COLS

    result = result.fillna(0)

    print(f"  Feature matrix: {result.shape}")

    return result


def augment(X, y):
    print(f"\nAugmenting with {len(REAL_LEGIT_ROWS)} real browser-extracted legitimate vectors ...")

    existing_hashes = set(_row_hash(r) for r in X.values.tolist())

    new_rows = []
    skipped = 0

    for row in REAL_LEGIT_ROWS:
        h = _row_hash(row)

        if h in existing_hashes:
            skipped += 1
            continue

        existing_hashes.add(h)
        new_rows.append(row)

    print(f"  Added: {len(new_rows)} | Skipped: {skipped} duplicates")

    aug_X = pd.DataFrame(new_rows, columns=FEATURE_COLS)
    aug_y = pd.Series([LEGITIMATE_LABEL] * len(new_rows), dtype=int)

    X_combined = pd.concat([X, aug_X], ignore_index=True)
    y_combined = pd.concat([y.reset_index(drop=True), aug_y], ignore_index=True)

    print(f"  Combined: {len(X_combined):,} rows")

    return X_combined, y_combined


def train(X, y):
    print("\nSplitting 80/20 stratified ...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )

    print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

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

    print("Training RandomForest ...")
    model.fit(X_train, y_train)

    clf = model.named_steps["clf"]
    classes = list(clf.classes_)

    print(f"Model classes: {classes}  (0=legitimate, 1=phishing)")

    phishing_index = classes.index(PHISHING_LABEL)

    y_proba = model.predict_proba(X_test)[:, phishing_index]
    y_pred = (y_proba >= 0.5).astype(int)

    auc = roc_auc_score(y_test, y_proba)

    report = classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        digits=4,
    )

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    print(f"\nTest AUC-ROC: {auc:.4f}")
    print(report)

    fp = cm[0][1] / (cm[0][0] + cm[0][1]) * 100
    fn = cm[1][0] / (cm[1][0] + cm[1][1]) * 100

    print(f"FP rate: {fp:.2f}%  |  FN rate: {fn:.2f}%")

    print("\nConfusion Matrix:")
    print(f"                       Pred: Legit   Pred: Phishing")
    print(f"  Actual: Legit        {cm[0][0]:>10,}   {cm[0][1]:>14,}")
    print(f"  Actual: Phishing     {cm[1][0]:>10,}   {cm[1][1]:>14,}")

    print("\n5-fold CV ...")

    cv = cross_val_score(
        model,
        X,
        y,
        cv=5,
        scoring="roc_auc",
        n_jobs=-1,
    )

    print(f"CV AUC: {cv.mean():.4f} +/- {cv.std():.4f}")

    return model, report, auc, cv, cm, fp, fn


def sanity_check(model):
    clf = model.named_steps["clf"]
    pi = list(clf.classes_).index(PHISHING_LABEL)

    sites = [
        # Legitimate sites — expect P(phish) < 0.5
        ("Amazon UK",       [25, 0, 1, 0.28, 0.72, 2, 333, 1, 0.0, 1, 1, 1, 181, 12, 30],    False),
        ("Amazon US",       [23, 0.0, 1, 0.0, 0.7391, 0, 9, 0, 0.333, 1, 1, 1, 233, 9, 8],   False),
        ("eBay backend",    [23, 0.0, 1, 0.0, 0.6957, 0, 626, 0, 0.286, 1, 1, 1, 163, 2, 8], False),
        ("BBC backend",     [22, 0.0, 1, 0.0, 0.6818, 0, 47, 0, 0.333, 1, 1, 1, 89, 0, 59],  False),
        ("Gov.uk backend",  [19, 0.0, 1, 0.0, 0.6842, 0, 0, 0, 0.5, 1, 1, 1, 4, 2, 5],       False),
        ("NHS backend",     [19, 0.0, 1, 0.0, 0.6842, 0, 9, 0, 0.25, 1, 1, 1, 0, 1, 5],      False),
        ("HSBC backend",    [23, 0.0, 1, 0.0, 0.6957, 0, 142, 1, 0.4, 1, 1, 0, 9, 1, 28],    False),
        ("GitHub backend",  [19, 0.0, 1, 0.0, 0.7368, 0, 3, 0, 0.5, 1, 1, 1, 3, 39, 48],     False),
        ("PayPal homepage", [30, 0.0, 1, 0.0, 0.7667, 0, 20, 0, 0.143, 1, 1, 1, 6, 15, 9],   False),
        ("PayPal login",    [44, 0.0, 1, 0.0, 0.7727, 0, 0, 0, 0.0, 1, 1, 0, 5, 2, 16],      False),
        ("Microsoft",       [31, 0.0, 1, 0.0, 0.7742, 0, 82, 1, 0.143, 1, 1, 1, 27, 16, 57], False),
        ("Barclays",        [27, 0.0, 1, 0.0, 0.7407, 0, 3, 1, 0.333, 1, 1, 0, 20, 40, 21],  False),
        ("Lloyds",          [27, 0.0, 1, 0.0, 0.7778, 0, 0, 1, 0.0, 1, 1, 0, 19, 2, 12],     False),
        ("NatWest",         [24, 0.0, 1, 0.0, 0.75, 0, 29, 1, 0.125, 1, 1, 1, 27, 29, 44],   False),
        ("Netflix UK",      [27, 0, 1, 0.259, 0.741, 1, 23, 1, 0.143, 1, 1, 0, 3, 1, 7],     False),
        ("YouTube",         [24, 0, 1, 0.25, 0.75, 1, 32, 1, 1.0, 1, 0, 1, 28, 6, 17],       False),
        ("Spotify backend", [25, 0.0, 1, 0.0, 0.76, 1, 0, 0, 0.333, 0, 0, 0, 0, 1, 8],       False),
        ("Booking backend", [197, 0.132, 1, 0.0, 0.797, 0, 191, 0, 0.182, 1, 1, 1, 12, 29, 53], False),
        ("Apple",           [22, 0.0, 1, 0.0, 0.7273, 0, 6, 0, 0.5, 0, 1, 1, 52, 10, 13],    False),
        ("X.com",           [14, 0.0, 1, 0.0, 0.6429, 0, 0, 0, 0.2, 1, 0, 0, 0, 0, 14],      False),
        ("Airbnb",          [25, 0.0, 1, 0.0, 0.72, 0, 0, 0, 0.111, 1, 0, 0, 1, 1, 54],      False),
        ("TripAdvisor",     [30, 0.0, 1, 0.0, 0.7667, 0, 0, 1, 0.083, 1, 1, 1, 43, 2, 8],    False),
        ("Outlook live.com",    [30, 0.0, 1, 0.0, 0.7667, 1, 0, 0, 0.333, 0, 0, 0, 1, 0, 2],     False),
        ("login.live.com OAuth",[245, 0.4286, 1, 0.0, 0.4449, 1, 0, 0, 0.0, 0, 0, 0, 0, 0, 0],  False),
        ("MSN",                 [25, 0.0, 1, 0.0, 0.72, 0, 0, 0, 0.111, 1, 1, 0, 2, 0, 19],      False),
        ("Outlook",         [37, 0.0, 1, 0.0, 0.8108, 1, 0, 0, 0.333, 0, 0, 0, 1, 3, 2],     False),
        ("Santander",       [28, 0.0, 1, 0.0, 0.75, 0, 5, 0, 0.667, 1, 1, 0, 9, 2, 9],       False),
        ("Halifax",         [26, 0.0, 1, 0.0, 0.7308, 0, 1, 1, 0.143, 1, 1, 0, 20, 2, 12],   False),
        # T7 uses NoOfSelfRef=2 (after absolute URL fix in test7-control.html)
        ("T7 control",      [41, 0.0, 1, 0.02, 0.78, 0, 2, 1, 0.5, 1, 0, 1, 3, 0, 0],        False),
        # Phishing pages — expect P(phish) > 0.5
        ("T9 suspicious",   [54, 0.0, 1, 0.02, 0.72, 0, 0, 0, 0.0, 0, 1, 0, 0, 0, 0],        True),
        ("Obvious phishing",[150, 0.3, 0, 0.1, 0.5, 3, 0, 0, 0.0, 0, 1, 0, 0, 0, 0],         True),
    ]

    print("\nSanity check:")
    print(f"  {'Site':<25} {'P(phish)':>10} {'result'}")
    print("  " + "-" * 50)

    passed = 0
    failed = []

    for name, vals, expect_phish in sites:
        X_s = pd.DataFrame([dict(zip(FEATURE_COLS, vals))], columns=FEATURE_COLS)
        prob = float(model.predict_proba(X_s)[0][pi])
        ok = (expect_phish and prob > 0.5) or (not expect_phish and prob < 0.5)
        if ok:
            passed += 1
            status = "OK"
        else:
            failed.append(name)
            status = "PROBLEM ←"
        print(f"  {name:<25} {prob:>10.3f}   {status}")

    print(f"\n  {passed}/{len(sites)} sanity checks passed")
    if failed:
        print(f"  Failed: {failed}")


def save(model, report, auc, cv, cm, fp, fn):
    model_path = os.path.join(OUTPUT_DIR, "model.joblib")
    report_path = os.path.join(OUTPUT_DIR, "report.txt")

    joblib.dump(model, model_path)

    print(f"\nModel saved to {model_path}")

    clf = model.named_steps["clf"]
    imps = pd.Series(clf.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("PhishGuard ML Model - Real Data Augmented Training Report\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Dataset:    PhiUSIIL (UCI id=967) + {len(REAL_LEGIT_ROWS)} real browser-extracted vectors\n")
        f.write("Method:     Feature extraction via Chrome browser/backend logs using PhishGuard content extraction logic\n")
        f.write(f"Features:   {len(FEATURE_COLS)} core features\n")
        f.write("Labels:     0=legitimate, 1=phishing (PhiUSIIL raw flipped)\n")
        f.write(f"AUC-ROC:    {auc:.4f}\n")
        f.write(f"CV AUC:     {cv.mean():.4f} +/- {cv.std():.4f}\n")
        f.write(f"FP Rate:    {fp:.2f}%\n")
        f.write(f"FN Rate:    {fn:.2f}%\n\n")

        f.write("Confusion Matrix:\n")
        f.write(f"  Actual Legit  -> Pred Legit: {cm[0][0]:,} | Pred Phish: {cm[0][1]:,}\n")
        f.write(f"  Actual Phish  -> Pred Legit: {cm[1][0]:,} | Pred Phish: {cm[1][1]:,}\n\n")

        f.write("Classification Report:\n")
        f.write(report)
        f.write("\n\n")

        f.write("Feature Importances (sorted):\n")
        f.write(f"{'Feature':<30} {'Importance':>12}  Bar\n")
        f.write("-" * 70 + "\n")
        for feat, imp in imps.items():
            bar = "█" * int(imp * 200)
            f.write(f"  {feat:<28} {imp:>12.6f}  {bar}\n")

    print(f"Report saved to {report_path}")


if __name__ == "__main__":
    X, y = load_dataset()
    X_aligned = align_features(X)

    X_aug, y_aug = augment(X_aligned, y)

    model, report, auc, cv, cm, fp, fn = train(X_aug, y_aug)

    sanity_check(model)

    save(model, report, auc, cv, cm, fp, fn)

    print("\nDone. Restart uvicorn — backend/ml/model.joblib has been updated.")