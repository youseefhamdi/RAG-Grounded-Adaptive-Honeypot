"""
OSINT IP Reputation Fetcher
Integrates with AbuseIPDB, GreyNoise, or other IP reputation APIs.
"""
import os
import requests
import logging
from typing import List, Dict, Any

logger = logging.getLogger("ragin.sources.osint")

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"

class OSINTFetcher:
    """
    Fetch IP reputation data from OSINT sources.

    Requires ABUSEIPDB_API_KEY in environment.
    """

    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not self.api_key:
            logger.warning("ABUSEIPDB_API_KEY not set, OSINT disabled")

    def fetch_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation."""
        if not self.api_key:
            return {}

        try:
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            resp = requests.get(ABUSEIPDB_API, headers=headers, 
                              params=params, timeout=10)
            resp.raise_for_status()
            return resp.json().get("data", {})
        except Exception as e:
            logger.error(f"AbuseIPDB query failed for {ip}: {e}")
            return {}

    def fetch_batch(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Fetch reputation for multiple IPs and format as documents."""
        docs = []
        for ip in ips:
            data = self.fetch_ip_reputation(ip)
            if not data:
                continue

            abuse_score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "??")
            isp = data.get("isp", "Unknown")

            content = f"IP: {ip}\n" \
                     f"Abuse Score: {abuse_score}\n" \
                     f"Country: {country}\n" \
                     f"ISP: {isp}\n" \
                     f"Total Reports: {data.get('totalReports', 0)}"

            docs.append({
                "source": "abuseipdb",
                "source_url": f"https://www.abuseipdb.com/check/{ip}",
                "title": f"IP Reputation: {ip}",
                "content": content,
                "doc_type": "ip_reputation",
                "cves": [],
                "mitre_techniques": []
            })

        logger.info(f"Fetched OSINT data for {len(docs)} IPs")
        return docs
