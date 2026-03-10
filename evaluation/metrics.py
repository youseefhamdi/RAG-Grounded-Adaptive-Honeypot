"""RAGIN Evaluation Metrics: accuracy, FPR, F1, AUC-ROC, IQS."""
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, confusion_matrix
from typing import List, Dict

def compute_metrics(labels: List[str], preds: List[str]) -> Dict:
    y_true = [1 if l == "malicious" else 0 for l in labels]
    y_pred = [1 if p == "malicious" else 0 for p in preds]
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, sum(y_pred))
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fpr,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)
    }
