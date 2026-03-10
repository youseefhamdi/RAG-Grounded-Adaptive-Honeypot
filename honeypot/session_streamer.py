"""Streams Cowrie JSON log lines into RAGIN pipeline via Redis."""
import json, time, redis, yaml, logging
from pathlib import Path
from typing import Generator
from collections import defaultdict

logger = logging.getLogger("ragin.sessionstreamer")

class CowrieSessionStreamer:
    def __init__(self, config_path="config/config.yaml"):
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        hp_cfg = cfg["honeypot"]
        r_cfg = cfg["redis"]
        self.log_dir = Path(hp_cfg["cowrie_log_dir"])
        self.poll_ms = hp_cfg["poll_interval_ms"] / 1000.0
        self.redis = redis.Redis(host=r_cfg["host"], port=r_cfg["port"], decode_responses=True)
        self.raw_queue = "ragin_raw_sessions"
        self.sessions = {}

    def tail_log(self, log_path):
        with open(log_path) as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    try:
                        yield json.loads(line.strip())
                    except json.JSONDecodeError:
                        pass
                else:
                    time.sleep(self.poll_ms)

    def aggregate_session(self, event):
        sid = event.get("session", "unknown")
        if sid not in self.sessions:
            self.sessions[sid] = {
                "session_id": sid, "srcip": event.get("src_ip"),
                "commands": [], "network_events": [], "files": [], 
                "auth_attempts": [], "start_time": event.get("timestamp"),
                "last_time": event.get("timestamp")
            }
        s = self.sessions[sid]
        s["last_time"] = event.get("timestamp")
        etype = event.get("eventid", "")
        if "command" in etype:
            s["commands"].append(event.get("input", ""))
        elif "login" in etype or "auth" in etype:
            s["auth_attempts"].append({
                "username": event.get("username"), 
                "password": event.get("password"),
                "success": event.get("success", False)
            })
        elif "file" in etype:
            s["files"].append(event.get("filename", ""))
        else:
            s["network_events"].append(etype)
        if "closed" in etype or "disconnect" in etype:
            self.redis.lpush(self.raw_queue, json.dumps(s))
            logger.info(f"Session {sid} flushed ({len(s['commands'])} commands)")
            del self.sessions[sid]

    def run(self):
        logfile = self.log_dir / "cowrie.json"
        logger.info(f"Streaming from {logfile}")
        for event in self.tail_log(logfile):
            self.aggregate_session(event)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    streamer = CowrieSessionStreamer()
    streamer.run()
