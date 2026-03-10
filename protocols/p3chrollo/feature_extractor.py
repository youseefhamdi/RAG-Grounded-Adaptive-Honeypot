"""
Chrollo Feature Extractor
150 behavioral features from raw session dicts.

Categories:
- Network (45 features)
- Command (38 features)
- Session (32 features)
- Exfiltration (22 features)
- Anomaly (13 features)
"""
import re
import math
import json
import numpy as np
from collections import Counter
from typing import List, Dict, Any
import ipaddress

EXPLOIT_PATTERNS = [
    r"exploit", r"payload", r"msfvenom", r"metasploit", r"shellcode",
    r"wget.*\.sh", r"curl.*\.bash", r"/etc/passwd", r"/etc/shadow",
    r"chmod\s*[0-9]", r"sudo\s*-i", r"su\s*-", r"nc\s*-e",
    r"python.*import.*socket", r"perl.*socket", r"base64\s*-d"
]

PRIVESC_PATTERNS = [
    r"sudo", r"\bsu\b", r"chmod\s*[4-7][0-7][0-7]",
    r"chown.*root", r"setuid", r"pkexec", r"/etc/sudoers"
]

KNOWN_TOOLS = [
    "nmap", "hydra", "masscan", "sqlmap", "nikto", "dirb", "gobuster",
    "metasploit", "msfconsole", "burpsuite", "wireshark", "tcpdump",
    "john", "hashcat", "mimikatz", "bloodhound", "powersploit", "empire",
    "cobalt", "nessus", "openvas", "curl", "wget", "netcat", "nc"
]

EXFIL_PATTERNS = [
    r"\.tar", r"\.zip", r"\.gz", r"base64\s*-ew", r"openssl\s*enc",
    r"\bscp\b", r"rsync", r"\bftp\b"
]

def entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def command_entropy(commands: List[str]) -> float:
    """Calculate entropy across all commands."""
    all_text = " ".join(commands)
    return entropy(all_text)

def obfuscation_score(commands: List[str]) -> float:
    """Calculate obfuscation score based on patterns."""
    score = 0.0
    for cmd in commands:
        if re.search(r"[0-9a-fA-F]{2,}", cmd):
            score += 0.3
        if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", cmd):  # base64-like
            score += 0.2
        if cmd.count("\\") > 3:
            score += 0.1
        if re.search(r"\$\(.*\)", cmd):
            score += 0.15
        if re.search(r"eval", cmd):
            score += 0.25
    return min(score / max(len(commands), 1), 1.0)

class ChrolloFeatureExtractor:
    """Extracts 150-dim behavioral feature vector from a raw Cowrie session dict."""

    def extract(self, session: Dict[str, Any]) -> np.ndarray:
        """
        Extract 150 features from session.

        Args:
            session: Raw session dictionary

        Returns:
            numpy array of 150 float32 features
        """
        cmds = session.get("commands", [])
        auth = session.get("auth_attempts", [])
        files = session.get("files", [])
        net = session.get("network_events", [])
        srcip = session.get("srcip", "0.0.0.0")

        features = []

        # Category 1: Network (45 features)
        features += self._network_features(session, srcip, net)

        # Category 2: Command (38 features)
        features += self._command_features(cmds)

        # Category 3: Session (32 features)
        features += self._session_features(session, auth)

        # Category 4: Exfiltration (22 features)
        features += self._exfil_features(cmds, files)

        # Category 5: Anomaly (13 features)
        features += self._anomaly_features(cmds, session)

        vec = np.array(features, dtype=np.float32)
        assert len(vec) == 150, f"Feature vector length mismatch: {len(vec)}"
        return vec

    def _network_features(self, s, srcip, net) -> List[float]:
        """Extract 45 network-related features."""
        try:
            ip = ipaddress.ip_address(srcip)
            is_private = float(ip.is_private)
            is_loopback = float(ip.is_loopback)
        except Exception:
            is_private, is_loopback = 0.0, 0.0

        start = s.get("start_time", "")
        end = s.get("last_time", "")
        duration = self._parse_duration(start, end)

        n_reconnects = net.count("cowrie.session.connect")
        protocol_types = len(set(net))
        port_diversity = min(protocol_types / 10.0, 1.0)

        net_feats = [
            is_private,
            is_loopback,
            min(len(net) / 50.0, 1.0),  # network event count (norm)
            min(n_reconnects / 5.0, 1.0),  # reconnect count
            port_diversity,  # protocol diversity
            min(duration / 3600.0, 1.0),  # session duration (hours)
            entropy(srcip),  # GeoIP/IP entropy proxy
            float("scan" in " ".join(net)),  # port scan detected
            float("brute" in " ".join(net)),  # brute force detected
            min(len(set(net)) / 20.0, 1.0),  # unique event types
        ]

        # Pad to 45
        net_feats += [0.0] * (45 - len(net_feats))
        return net_feats[:45]

    def _command_features(self, cmds) -> List[float]:
        """Extract 38 command-related features."""
        if not cmds:
            return [0.0] * 38

        cmd_text = " ".join(cmds)
        n_cmds = len(cmds)

        exploit_hits = sum(1 for p in EXPLOIT_PATTERNS if re.search(p, cmd_text, re.I))
        privesc_hits = sum(1 for p in PRIVESC_PATTERNS if re.search(p, cmd_text, re.I))
        tool_hits = sum(1 for t in KNOWN_TOOLS if t in cmd_text.lower())
        chaining_depth = cmd_text.count("|") + cmd_text.count(";") + cmd_text.count("&&")

        cmd_feats = [
            min(n_cmds / 200.0, 1.0),  # command count
            command_entropy(cmds),  # command entropy
            obfuscation_score(cmds),  # obfuscation score
            min(exploit_hits / len(EXPLOIT_PATTERNS), 1.0),  # exploit patterns
            min(privesc_hits / len(PRIVESC_PATTERNS), 1.0),  # priv esc
            min(tool_hits / len(KNOWN_TOOLS), 1.0),  # tool diversity
            min(chaining_depth / 20.0, 1.0),  # chaining depth
            float(any(re.search(p, cmd_text, re.I) for p in EXPLOIT_PATTERNS)),
            min(sum(len(c) for c in cmds) / n_cmds / 100.0, 1.0),  # avg length
            min(len(set(cmds)) / n_cmds, 1.0),  # command uniqueness
        ]

        cmd_feats += [0.0] * (38 - len(cmd_feats))
        return cmd_feats[:38]

    def _session_features(self, s, auth) -> List[float]:
        """Extract 32 session-related features."""
        n_auth = len(auth)
        n_success = sum(1 for a in auth if a.get("success"))
        n_fail = n_auth - n_success
        unique_users = len(set(a.get("username", "") for a in auth))
        unique_passes = len(set(a.get("password", "") for a in auth))

        start = s.get("start_time", "")
        end = s.get("last_time", "")
        duration = self._parse_duration(start, end)

        sess_feats = [
            min(duration / 3600.0, 1.0),  # session duration
            min(n_auth / 100.0, 1.0),  # auth attempts
            min(n_fail / max(n_auth, 1), 1.0),  # fail ratio
            min(n_success / max(n_auth, 1), 1.0),  # success ratio
            min(unique_users / 20.0, 1.0),  # user diversity
            min(unique_passes / 20.0, 1.0),  # pass diversity
            float(n_auth > 10),  # high auth attempt flag
            float(n_success > 0),  # successful auth flag
            min(n_auth / max(duration / 1, 1), 1.0),  # auth rate
            float(unique_users > 5),  # credential spray
        ]

        sess_feats += [0.0] * (32 - len(sess_feats))
        return sess_feats[:32]

    def _exfil_features(self, cmds, files) -> List[float]:
        """Extract 22 exfiltration-related features."""
        cmd_text = " ".join(cmds)
        exfil_hits = sum(1 for p in EXFIL_PATTERNS if re.search(p, cmd_text, re.I))
        archive_creates = len(re.findall(r"\.tar|\.zip|\.gz|\.7z|\.rar", cmd_text))
        encoding_ops = len(re.findall(r"base64|xxd|od", cmd_text))
        sensitive_files = sum(1 for f in files if any(s in f for s in 
                             ["/etc/passwd", "/etc/shadow", ".ssh", ".bash_history", "id_rsa"]))

        exfil_feats = [
            min(exfil_hits / len(EXFIL_PATTERNS), 1.0),
            min(archive_creates / 5.0, 1.0),
            min(encoding_ops / 5.0, 1.0),
            min(sensitive_files / 5.0, 1.0),
            min(len(files) / 20.0, 1.0),
            float(exfil_hits > 0),
            float(sensitive_files > 0),
            float(encoding_ops > 0),
        ]

        exfil_feats += [0.0] * (22 - len(exfil_feats))
        return exfil_feats[:22]

    def _anomaly_features(self, cmds, s) -> List[float]:
        """Extract 13 anomaly detection features."""
        cmd_text = " ".join(cmds)

        # Anti-forensics signals
        log_tamper = float(bool(re.search(r"\brm\b|shred|truncate|history\s*-c", cmd_text)))
        proc_inspect = float(bool(re.search(r"/proc/cpuinfo|dmidecode|virt-what|systemd-detect-virt", cmd_text)))
        high_entropy = float(command_entropy(cmds) > 4.2)

        anom_feats = [
            log_tamper,
            proc_inspect,
            high_entropy,
            float(bool(re.search(r"getdents64|inotify", cmd_text))),
            float(bool(re.search(r"LD_PRELOAD|ptrace", cmd_text))),
            obfuscation_score(cmds),
            float(bool(re.search(r"\.onion|\btor\b", cmd_text))),
            float(bool(re.search(r"proxychains|socks5", cmd_text))),
        ]

        anom_feats += [0.0] * (13 - len(anom_feats))
        return anom_feats[:13]

    @staticmethod
    def _parse_duration(start: str, end: str) -> float:
        """Returns duration in seconds from ISO timestamps."""
        try:
            from datetime import datetime
            fmt = "%Y-%m-%dT%H:%M:%S.%f"
            t1 = datetime.fromisoformat(start)
            t2 = datetime.fromisoformat(end)
            return (t2 - t1).total_seconds()
        except Exception:
            return 0.0

    def feature_names(self) -> List[str]:
        """Returns list of 150 feature names for interpretability."""
        names = []
        cats = [("net", 45), ("cmd", 38), ("sess", 32), ("exfil", 22), ("anom", 13)]
        for cat, n in cats:
            names += [f"{cat}_{i}" for i in range(n)]
        return names
