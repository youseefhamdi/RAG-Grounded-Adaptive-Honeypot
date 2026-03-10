"""
Chrollo 100-tree Random Forest session classifier.
Escalates sessions with confidence >= tau to Don (C2) and Hisoka (C3).
"""
import json
import joblib
import numpy as np
import redis
import yaml
import logging
from pathlib import Path
from typing import Tuple, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import KNNImputer
from sklearn.preprocessing import StandardScaler
from .feature_extractor import ChrolloFeatureExtractor

logger = logging.getLogger("ragin.chrollo")

class ChrolloClassifier:
    """
    Chrollo behavioral classifier.

    Uses 150-feature Random Forest to classify honeypot sessions
    as malicious or benign. Escalates high-confidence malicious
    sessions to Don (C2) for RAG enrichment.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize classifier with configuration."""
        with open(config_path) as f:
            cfg = yaml.safe_load(f)["chrollo"]
            rcfg = yaml.safe_load(open(config_path))["redis"]

        self.tau = cfg["escalation_threshold"]
        self.model_path = Path(cfg["model_path"])
        self.extractor = ChrolloFeatureExtractor()
        self.scaler = StandardScaler()
        self.imputer = KNNImputer(n_neighbors=cfg["knn_impute_k"])

        self.redis = redis.Redis(host=rcfg["host"], port=rcfg["port"], 
                                decode_responses=True)
        self.raw_queue = "ragin_raw_sessions"
        self.escalate_queue = rcfg["escalation_queue"]

        self.rf: Optional[RandomForestClassifier] = None
        if self.model_path.exists():
            self.load_model()

    def load_model(self):
        """Load trained model from disk."""
        bundle = joblib.load(self.model_path)
        self.rf = bundle["rf"]
        self.scaler = bundle["scaler"]
        self.imputer = bundle["imputer"]
        logger.info(f"Chrollo: loaded model from {self.model_path}")

    def classify(self, session: dict) -> Tuple[str, float]:
        """
        Classify a session.

        Args:
            session: Raw session dictionary

        Returns:
            (label, confidence) tuple where:
                label: "malicious" | "benign"
                confidence: float in [0, 1]
        """
        if self.rf is None:
            raise RuntimeError("Model not trained. Run train.py first.")

        X = self.extractor.extract(session).reshape(1, -1)
        X_imp = self.imputer.transform(X)
        X_norm = self.scaler.transform(X_imp)

        proba = self.rf.predict_proba(X_norm)[0]
        malicious_idx = list(self.rf.classes_).index("malicious")
        s = float(proba[malicious_idx])
        label = "malicious" if s >= self.tau else "benign"
        return label, s

    def run_pipeline(self):
        """Consume raw sessions from Redis, classify, escalate if needed."""
        logger.info("Chrollo pipeline running...")
        while True:
            item = self.redis.brpop(self.raw_queue, timeout=5)
            if item is None:
                continue

            _, raw = item
            session = json.loads(raw)
            label, confidence = self.classify(session)

            session["chrollo_label"] = label
            session["chrollo_confidence"] = confidence

            if label == "malicious" and confidence >= self.tau:
                logger.info(f"ESCALATE: session={session['session_id']} "
                          f"conf={confidence:.3f}")
                self.redis.lpush(self.escalate_queue, json.dumps(session))
            else:
                logger.debug(f"BENIGN: session={session['session_id']} "
                           f"conf={confidence:.3f}")

    def feature_importance_report(self) -> dict:
        """Returns top-10 features by Gini importance."""
        names = self.extractor.feature_names()
        importances = self.rf.feature_importances_
        ranked = sorted(zip(names, importances), key=lambda x: x[1], reverse=True)
        return {n: float(v) for n, v in ranked[:10]}
