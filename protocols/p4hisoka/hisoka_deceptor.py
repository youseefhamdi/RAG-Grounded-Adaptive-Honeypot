"""
Hisoka Adaptive Deception Engine
Combines skill classification + tier-specific LLM prompts.
"""
import json
import yaml
import redis
import logging
from typing import Dict, Any
from core.modelprovider import get_provider
from .skill_classifier import HisokaSkillClassifier
from .prompt_templates import get_prompt

logger = logging.getLogger("ragin.hisoka")

class HisokaDeceptor:
    """
    Hisoka adaptive deception engine.

    Workflow:
    1. Receive enriched session from Don
    2. Classify attacker skill
    3. Generate tier-appropriate LLM response
    4. Log session for retraining
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        rcfg = cfg["redis"]
        self.redis = redis.Redis(host=rcfg["host"], port=rcfg["port"],
                                decode_responses=True)
        self.response_queue = rcfg["response_queue"]

        self.provider = get_provider(config_path)
        self.skill_classifier = HisokaSkillClassifier()
        self.log_path = cfg["hisoka"]["session_log_path"]

    def deceive(self, session: dict, don_report: dict) -> Dict[str, Any]:
        """
        Generate adaptive deception response.

        Args:
            session: Original session dict
            don_report: Don enrichment report

        Returns:
            Deception report with tier, response, and metadata
        """
        # Classify skill
        tier = self.skill_classifier.classify({**session, **don_report})

        # Get tier-specific prompt
        system_prompt, user_prompt = get_prompt(tier, session, don_report)

        # Generate LLM response
        response = self.provider.generate(
            prompt=user_prompt,
            system=system_prompt,
            max_tokens=256,
            temperature=0.7  # Higher temp for natural deception
        )

        # Log for retraining
        self._log_session(session, don_report, tier, response)

        return {
            "session_id": session.get("session_id"),
            "attacker_tier": tier,
            "deception_response": response,
            "chrollo_confidence": session.get("chrollo_confidence", 0),
            "don_iqs": don_report.get("iqs", 0),
            "mitre_techniques": don_report.get("mitre_techniques", []),
            "cves": don_report.get("cves", [])
        }

    def _log_session(self, session, don_report, tier, response):
        """Log enriched session for future retraining."""
        try:
            with open(self.log_path, "a") as f:
                log_entry = {
                    "session_id": session.get("session_id"),
                    "tier": tier,
                    "commands": session.get("commands", [])[:20],
                    "cves": don_report.get("cves", []),
                    "mitre": don_report.get("mitre_techniques", []),
                    "response": response,
                    "chrollo_conf": session.get("chrollo_confidence", 0),
                    "don_iqs": don_report.get("iqs", 0)
                }
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to log session: {e}")

    def run_pipeline(self):
        """Consume enriched sessions from Redis, generate responses."""
        logger.info("Hisoka pipeline running...")
        # Note: In full implementation, this would read from a
        # separate queue populated by Don after enrichment

        while True:
            # Placeholder: Real implementation would consume from
            # Redis queue with enriched sessions
            import time
            time.sleep(1)
