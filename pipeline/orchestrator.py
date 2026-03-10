"""RAGIN Orchestrator - Async pipeline wiring: C1 → C2 → C3 via Redis."""
import json, yaml, redis, logging
from protocols.p3chrollo.chrollo_classifier import ChrolloClassifier
from protocols.p2don.don_rag_engine import DonRAGEngine
from protocols.p4hisoka.hisoka_deceptor import HisokaDeceptor

logger = logging.getLogger("ragin.orchestrator")

class RAGINOrchestrator:
    def __init__(self, config_path="config/config.yaml"):
        logger.info("Initializing RAGIN Orchestrator...")
        self.chrollo = ChrolloClassifier(config_path)
        self.don = DonRAGEngine(config_path)
        self.hisoka = HisokaDeceptor(config_path)
        with open(config_path) as f:
            r_cfg = yaml.safe_load(f)["redis"]
        self.redis = redis.Redis(host=r_cfg["host"], port=r_cfg["port"], decode_responses=True)
        self.raw_queue = "ragin_raw_sessions"
        self.results_queue = "ragin_final_results"

    def process_session(self, session):
        import time
        t0 = time.time()
        label, confidence = self.chrollo.classify(session)
        session["chrollo_label"], session["chrollo_confidence"] = label, confidence
        t_chrollo = (time.time() - t0) * 1000
        if label != "malicious" or confidence < self.chrollo.tau:
            return {"session_id": session.get("session_id"), "verdict": "benign", 
                   "confidence": confidence, "latency_ms": {"chrollo": t_chrollo}}
        t1 = time.time()
        don_result = self.don.enrich(session)
        t_don = (time.time() - t1) * 1000
        t2 = time.time()
        hisoka_result = self.hisoka.generate_response(session, don_result)
        t_hisoka = (time.time() - t2) * 1000
        report = {
            "session_id": session.get("session_id"), "srcip": session.get("srcip"),
            "verdict": "malicious", "confidence": confidence,
            "skill_level": hisoka_result["skill_level"],
            "cves": don_result["cves"], "mitre_techniques": don_result["mitre_techniques"],
            "analysis": don_result["analysis"], "adaptive_response": hisoka_result["adaptive_response"],
            "iqs": don_result["iqs"],
            "latency_ms": {"chrollo": round(t_chrollo,1), "don": round(t_don,1), 
                          "hisoka": round(t_hisoka,1), "total": round((time.time()-t0)*1000,1)}
        }
        self.redis.lpush(self.results_queue, json.dumps(report))
        return report

    def run(self):
        logger.info("RAGIN Orchestrator running...")
        while True:
            item = self.redis.brpop(self.raw_queue, timeout=5)
            if item:
                _, raw = item
                try:
                    report = self.process_session(json.loads(raw))
                    logger.info(f"RAGIN: {report.get('session_id')} verdict={report.get('verdict')}")
                except Exception as e:
                    logger.error(f"Pipeline error: {e}")
