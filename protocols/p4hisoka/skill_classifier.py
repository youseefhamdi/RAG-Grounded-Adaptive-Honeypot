"""
Hisoka Skill Classifier
Real-time attacker skill profiling: Novice / Intermediate / Expert.

Based on Algorithm 3 from paper:
- 12 behavioral features
- Rule-based tiers
"""
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger("ragin.hisoka.skill")

ADVANCED_TOOLS = [
    "metasploit", "msfconsole", "msfvenom", "empire", "cobalt", "bloodhound",
    "mimikatz", "powersploit", "impacket", "crackmapexec", "evil-winrm"
]

PRIVESC_PATTERNS = [
    r"sudo\s*-i", r"\bsu\b", r"chmod\s*[4-7]", r"setuid", r"pkexec",
    r"SUID", r"capabilities", r"kernel.*exploit"
]

OBFUSCATION_INDICATORS = [
    r"base64\s*-[de]", r"eval", r"\$\(.*\)", r"\$\{.*\}", r"[0-9a-fA-F]{20,}",
    r"openssl\s*enc", r"xxd", r"\\x[0-9a-fA-F]{2}"
]

LATERAL_MOVEMENT = [
    r"\bssh\b", r"\bscp\b", r"rsync", r"psexec", r"winrm", r"wmiexec",
    r"rdp", r"smb", r"netcat.*-e", r"nc\s*-e"
]

class HisokaSkillClassifier:
    """
    Classify attacker skill level based on session behavior.

    Tiers:
    - Novice: < 30 points
    - Intermediate: 30-60 points
    - Expert: > 60 points
    """

    TIER_THRESHOLDS = {"novice": 30, "intermediate": 60}

    def classify(self, session: Dict[str, Any]) -> str:
        """
        Classify attacker skill level.

        Args:
            session: Enriched session dict (post-Chrollo, post-Don)

        Returns:
            "novice" | "intermediate" | "expert"
        """
        score = self._compute_skill_score(session)

        if score < self.TIER_THRESHOLDS["novice"]:
            return "novice"
        elif score < self.TIER_THRESHOLDS["intermediate"]:
            return "intermediate"
        else:
            return "expert"

    def _compute_skill_score(self, s: Dict[str, Any]) -> int:
        """Compute 12-feature skill score."""
        cmds = s.get("commands", [])
        cmd_text = " ".join(cmds)
        cves = s.get("cves", [])
        ttp = s.get("mitre_techniques", [])

        score = 0

        # F1: Advanced tool usage (15 pts)
        if any(tool in cmd_text.lower() for tool in ADVANCED_TOOLS):
            score += 15

        # F2: Exploit pattern (10 pts)
        if len(cves) > 0:
            score += 10

        # F3: MITRE ATT&CK coverage (10 pts)
        if len(ttp) >= 3:
            score += 10
        elif len(ttp) >= 1:
            score += 5

        # F4: Privilege escalation attempts (10 pts)
        if any(re.search(p, cmd_text, re.I) for p in PRIVESC_PATTERNS):
            score += 10

        # F5: Obfuscation/evasion (10 pts)
        if sum(1 for p in OBFUSCATION_INDICATORS if re.search(p, cmd_text, re.I)) >= 2:
            score += 10

        # F6: Lateral movement (8 pts)
        if any(re.search(p, cmd_text, re.I) for p in LATERAL_MOVEMENT):
            score += 8

        # F7: Command chaining depth (5 pts)
        chain_depth = cmd_text.count("|") + cmd_text.count("&&") + cmd_text.count(";")
        if chain_depth > 5:
            score += 5

        # F8: Session persistence (5 pts)
        if re.search(r"cron|systemd.*timer|rc\.local|\.\.profile", cmd_text, re.I):
            score += 5

        # F9: Anti-forensics (5 pts)
        if re.search(r"\brm\b|shred|history.*-c|unset.*HISTFILE", cmd_text, re.I):
            score += 5

        # F10: Multiple auth vectors (4 pts)
        auth_vectors = set()
        if s.get("auth_attempts"):
            auth_vectors.add("ssh")
        if re.search(r"telnet", cmd_text, re.I):
            auth_vectors.add("telnet")
        if len(auth_vectors) > 1:
            score += 4

        # F11: Exfiltration setup (6 pts)
        if re.search(r"\.tar|\.zip|base64|\bftp\b|\bscp\b", cmd_text, re.I):
            score += 6

        # F12: Custom exploit code (12 pts)
        if re.search(r"shellcode|payload|msfvenom", cmd_text, re.I):
            score += 12

        logger.info(f"Skill score: {score} → tier={self._score_to_tier(score)}")
        return score

    def _score_to_tier(self, score: int) -> str:
        """Convert score to tier label."""
        if score < 30:
            return "novice"
        elif score < 60:
            return "intermediate"
        else:
            return "expert"
