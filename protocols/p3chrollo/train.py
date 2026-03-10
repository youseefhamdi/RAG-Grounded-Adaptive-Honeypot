"""
Chrollo Training Script.

Usage:
    python -m protocols.p3chrollo.train --data data/labeled_sessions.jsonl
"""
import json
import argparse
import joblib
import numpy as np
import logging
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.impute import KNNImputer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
from .feature_extractor import ChrolloFeatureExtractor

logger = logging.getLogger("ragin.chrollo.train")

def load_dataset(path: str):
    """Load labeled training dataset."""
    X, y = [], []
    with open(path) as f:
        for line in f:
            record = json.loads(line)
            extractor = ChrolloFeatureExtractor()
            feat = extractor.extract(record["session"])
            X.append(feat)
            y.append(record["label"])  # "malicious" | "benign"
    return np.array(X), np.array(y)

def train(data_path: str, model_out: str = "models/chrollo_rf.joblib",
         n_estimators: int = 100, max_depth: int = 15):
    """
    Train Chrollo Random Forest classifier.

    Args:
        data_path: Path to JSONL training data
        model_out: Output path for trained model
        n_estimators: Number of trees
        max_depth: Maximum tree depth
    """
    logger.info(f"Loading dataset: {data_path}")
    X, y = load_dataset(data_path)

    # Impute + normalize
    imputer = KNNImputer(n_neighbors=5)
    X_imp = imputer.fit_transform(X)

    scaler = StandardScaler()
    X_norm = scaler.fit_transform(X_imp)

    # RF
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )

    # 5-fold stratified cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf, X_norm, y, cv=cv, scoring="accuracy")
    logger.info(f"CV accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Final fit on all data
    rf.fit(X_norm, y)

    # Save
    Path(model_out).parent.mkdir(exist_ok=True)
    joblib.dump({"rf": rf, "scaler": scaler, "imputer": imputer}, model_out)
    logger.info(f"Model saved to {model_out}")

    # AUC
    proba = rf.predict_proba(X_norm)
    malicious_idx = list(rf.classes_).index("malicious")
    auc = roc_auc_score((y == "malicious").astype(int), proba[:, malicious_idx])
    logger.info(f"Train AUC-ROC: {auc:.4f}")

    print(classification_report(y, rf.predict(X_norm)))
    return rf

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--out", default="models/chrollo_rf.joblib")
    parser.add_argument("--trees", type=int, default=100)
    parser.add_argument("--depth", type=int, default=15)
    args = parser.parse_args()
    train(args.data, args.out, args.trees, args.depth)
