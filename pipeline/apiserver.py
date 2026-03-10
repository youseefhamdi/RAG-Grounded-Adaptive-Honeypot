"""RAGIN FastAPI REST Server"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import json, redis, yaml

app = FastAPI(title="RAGIN API", version="1.0.0")

class SessionInput(BaseModel):
    session_id: str
    srcip: str
    commands: List[str]
    auth_attempts: List[dict]
    files: List[str]
    start_time: Optional[str] = None
    last_time: Optional[str] = None

@app.post("/analyze")
async def analyze_session(session: SessionInput):
    r = redis.Redis(decode_responses=True)
    r.lpush("ragin_raw_sessions", json.dumps(session.dict()))
    return {"status": "queued", "session_id": session.session_id}

@app.get("/report/{session_id}")
async def get_report(session_id: str):
    r = redis.Redis(decode_responses=True)
    items = r.lrange("ragin_final_results", 0, 100)
    for item in items:
        report = json.loads(item)
        if report.get("session_id") == session_id:
            return report
    raise HTTPException(status_code=404, detail="Report not found")

@app.get("/health")
async def health():
    try:
        r = redis.Redis()
        r.ping()
        from qdrant_client import QdrantClient
        qc = QdrantClient(host="localhost", port=6333)
        collections = qc.get_collections()
        return {"status": "healthy", "qdrant_collections": [c.name for c in collections.collections]}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/stats")
async def stats():
    r = redis.Redis(decode_responses=True)
    return {
        "raw_queue_depth": r.llen("ragin_raw_sessions"),
        "escalation_queue_depth": r.llen("ragin_escalate"),
        "results_count": r.llen("ragin_final_results")
    }
