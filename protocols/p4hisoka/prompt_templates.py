"""
Hisoka Tier-Specific Prompt Templates
Templates calibrated to attacker skill level.
"""

SYSTEM_PROMPT = """You are a deceptive honeypot system designed to engage attackers believably while gathering intelligence. Your responses must:
1. Match the attacker's skill level (avoid suspicion)
2. Encourage further interaction
3. Log reconnaissance for analysis
4. NEVER reveal you are a honeypot"""

TIER_TEMPLATES = {
    "novice": {
        "system": SYSTEM_PROMPT,
        "user": """Attacker Profile: **NOVICE** (script kiddie, basic tools, predictable patterns)

Session Context:
- Commands: {commands}
- Failed auth attempts: {auth_fails}
- Chrollo confidence: {chrollo_conf}

Don Analysis:
{don_analysis}

Generate a SIMPLE, ERROR-PRONE honeypot response that:
1. Shows realistic beginner mistakes (typos, permission denials)
2. Leaks minimal but enticing fake system info
3. Does NOT overwhelm with details (novices expect slow systems)
4. Encourages simple enumeration (ls, cat, whoami)
5. Max 3-4 lines

Response:""",
    },

    "intermediate": {
        "system": SYSTEM_PROMPT,
        "user": """Attacker Profile: **INTERMEDIATE** (experienced penetration tester, uses known exploits, methodical)

Session Context:
- Commands: {commands}
- CVEs attempted: {cves}
- MITRE techniques: {mitre}
- Chrollo confidence: {chrollo_conf}

Don Analysis:
{don_analysis}

Generate a MODERATELY SOPHISTICATED response that:
1. Shows patched vulnerabilities (frustrate CVE attempts slightly)
2. Provides plausible system details (kernel version, services)
3. Hints at misconfigurations (weak credentials, outdated software)
4. Responds believably to exploit attempts (error codes, partial output)
5. Max 5-6 lines

Response:""",
    },

    "expert": {
        "system": SYSTEM_PROMPT,
        "user": """Attacker Profile: **EXPERT** (APT-level, custom exploits, anti-forensics aware, evasive)

Session Context:
- Commands: {commands}
- CVEs: {cves}
- MITRE techniques: {mitre}
- Tools detected: {tools}
- Chrollo confidence: {chrollo_conf}

Don Intelligence:
{don_analysis}

Generate a HIGH-FIDELITY response that:
1. Mimics REAL production system behavior (timing, errors, logs)
2. Responds accurately to advanced recon (netstat, process trees)
3. Simulates defensive measures (IDS alerts, rate limiting)
4. Provides SUBTLE inconsistencies only an expert would notice
5. Matches expected infrastructure (cloud metadata, containerization)
6. Max 8-10 lines

Response:""",
    }
}

def get_prompt(tier: str, session: dict, don_report: dict) -> tuple:
    """
    Get tier-specific prompt for LLM deception.

    Args:
        tier: "novice" | "intermediate" | "expert"
        session: Session dict
        don_report: Don enrichment report

    Returns:
        (system_prompt, user_prompt) tuple
    """
    template = TIER_TEMPLATES.get(tier, TIER_TEMPLATES["intermediate"])

    user_prompt = template["user"].format(
        commands=" | ".join(session.get("commands", [])[:10]),
        auth_fails=len([a for a in session.get("auth_attempts", []) if not a.get("success")]),
        chrollo_conf=session.get("chrollo_confidence", 0.0),
        cves=", ".join(don_report.get("cves", [])[:5]) or "None",
        mitre=", ".join(don_report.get("mitre_techniques", [])[:5]) or "None",
        tools="metasploit, nmap" if tier == "expert" else "curl, wget",
        don_analysis=don_report.get("analysis", "No analysis available")[:500]
    )

    return template["system"], user_prompt
