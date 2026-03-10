"""RAGIN Ablation Study - reproduces Table 17 from paper."""
import json, logging
from typing import List, Dict
from protocols.p3chrollo.chrollo_classifier import ChrolloClassifier
from protocols.p2don.don_rag_engine import DonRAGEngine
from protocols.p4hisoka.hisoka_deceptor import HisokaDeceptor
from evaluation.metrics import compute_metrics

logger = logging.getLogger("ragin.ablation")

def run_ablation(sessions: List[Dict], labels: List[str], 
                config_path="config/config.yaml") -> Dict:
    chrollo = ChrolloClassifier(config_path)
    don = DonRAGEngine(config_path)
    hisoka = HisokaDeceptor(config_path)

    results = {}

    # Config 1: Chrollo only
    preds_c = [chrollo.classify(s)[0] for s in sessions]
    results["chrollo_only"] = compute_metrics(labels, preds_c)

    # Config 2: Chrollo + Don
    preds_cd = []
    for s, pred in zip(sessions, preds_c):
        if pred == "malicious":
            enriched = don.enrich(s)
            final = "malicious" if enriched["iqs"] >= 0.4 else "benign"
            preds_cd.append(final)
        else:
            preds_cd.append(pred)
    results["chrollo_plus_don"] = compute_metrics(labels, preds_cd)

    # Config 3: Full RAGIN
    preds_full = []
    for s, pred in zip(sessions, preds_c):
        if pred == "malicious":
            don_out = don.enrich(s)
            h_out = hisoka.generate_response(s, don_out)
            skill_boost = {"Expert": 0.05, "Intermediate": 0.02, "Novice": 0.0}
            boost = skill_boost.get(h_out["skill_level"], 0)
            chrollo_conf = s.get("chrollo_confidence", 0.5)
            final = "malicious" if (chrollo_conf + boost) >= chrollo.tau else "benign"
            preds_full.append(final)
        else:
            preds_full.append(pred)
    results["full_ragin"] = compute_metrics(labels, preds_full)

    return results

def print_ablation_table(results: dict):
    print("-" * 65)
    print(f"{'Configuration':<35} {'Accuracy':<10} {'FPR':<8} {'F1':<8}")
    print("-" * 65)
    for config, m in results.items():
        print(f"{config:<35} {m['accuracy']:>9.1%} {m['fpr']:>7.1%} {m['f1']:>7.1%}")
    print("-" * 65)
