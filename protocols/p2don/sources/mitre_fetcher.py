"""
MITRE ATT&CK Fetcher
Downloads MITRE ATT&CK Enterprise matrix from official STIX bundle.
"""
import json
import requests
import logging
from typing import List, Dict, Any

logger = logging.getLogger("ragin.sources.mitre")

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

class MITREFetcher:
    """Fetch MITRE ATT&CK techniques from official STIX bundle."""

    def fetch(self) -> List[Dict[str, Any]]:
        """
        Download MITRE ATT&CK Enterprise JSON.

        Returns: List of technique documents.
        """
        try:
            resp = requests.get(MITRE_ATTACK_URL, timeout=60)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error(f"MITRE fetch failed: {e}")
            return []

        docs = []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            tid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break

            if not tid:
                continue

            name = obj.get("name", "Unknown")
            desc = obj.get("description", "")

            tactics = [p.split("/")[-1] for p in obj.get("kill_chain_phases", [])]

            content = f"MITRE ATT&CK Technique: {tid}\n" \
                     f"Name: {name}\n" \
                     f"Tactics: {', '.join(tactics)}\n" \
                     f"Description: {desc}"

            docs.append({
                "source": "mitre-attack",
                "source_url": f"https://attack.mitre.org/techniques/{tid.replace('.','/')}",
                "title": f"{tid}: {name}",
                "content": content,
                "doc_type": "mitre_technique",
                "cves": [],
                "mitre_techniques": [tid]
            })

        logger.info(f"Fetched {len(docs)} MITRE ATT&CK techniques")
        return docs
